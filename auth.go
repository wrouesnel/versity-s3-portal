package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

var ErrBadCredentials = errors.New("invalid username or password")

// User is a logged-in person, with the Unix ids their files are owned by.
type User struct {
	Name string
	UID  int
	GID  int
	// Admin may see and revoke everyone's keys and manage every bucket.
	Admin bool `json:",omitempty"`
}

// Identity is who a login proved someone to be, and their groups.
type Identity struct {
	User
	Groups []string
}

// Authenticator checks a username and password.
type Authenticator interface {
	Authenticate(username, password string) (Identity, error)
}

// DirEntry is what the directory says about someone now.
type DirEntry struct {
	UID, GID int
	Groups   []string
	Admin    bool
	// Disabled, with why, when they may not use the service: they're not
	// in the directory, not in the allowed group, or their account is
	// locked or expired.
	Disabled bool
	Reason   string
}

// Directory can be asked about people after they've logged in, so their
// access follows the directory.
type Directory interface {
	// Check looks one person up.
	Check(username string) (DirEntry, error)
	// CheckAll looks everyone up at once. People missing from the result
	// aren't in the directory.
	CheckAll() (map[string]DirEntry, error)
	// Groups lists the directory's group names, for granting access.
	Groups() ([]string, error)
}

// LDAPAuth finds the user with a search account, then binds as them to check
// their password. Their uid and gid come from the directory's posixAccount
// attributes, which is what glauth serves.
type LDAPAuth struct {
	URL          string
	ServerName   string
	CAFile       string
	BaseDN       string
	BindDN       string
	BindPassword string
	// AllowedGroup, when set, is the group DN users must have in memberOf.
	AllowedGroup string
	// AdminGroup, when set, is the group DN that makes users admins.
	AdminGroup string
	// GroupFilter finds group entries for Groups (default posixGroup).
	GroupFilter string

	now func() time.Time
}

// userAttrs are read for every person: ids, groups, and the attributes
// directories use to mark an account locked or expired.
var userAttrs = []string{
	"uid", "uidNumber", "gidNumber", "memberOf",
	"accountStatus", "nsAccountLock", "pwdAccountLockedTime", "shadowExpire",
}

// userFilter matches the user's account entry, whether or not they may
// use the service. objectClass is needed because glauth's group entries
// also carry a uid attribute.
func userFilter(username string) string {
	return fmt.Sprintf("(&(objectClass=posixAccount)(uid=%s))", ldap.EscapeFilter(username))
}

func (a *LDAPAuth) dial() (*ldap.Conn, error) {
	tlsConfig := &tls.Config{ServerName: a.ServerName, MinVersion: tls.VersionTLS12}
	if a.CAFile != "" {
		pem, err := os.ReadFile(a.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", a.CAFile)
		}
		tlsConfig.RootCAs = pool
	}
	conn, err := ldap.DialURL(a.URL, ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("connect to LDAP: %w", err)
	}
	conn.SetTimeout(10 * time.Second)
	if err := conn.Bind(a.BindDN, a.BindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("LDAP bind as search account: %w", err)
	}
	return conn, nil
}

// find returns username's entry, or nil if there's none.
func (a *LDAPAuth) find(conn *ldap.Conn, username string) (*ldap.Entry, error) {
	result, err := conn.Search(ldap.NewSearchRequest(
		a.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false,
		userFilter(username), userAttrs, nil,
	))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, fmt.Errorf("LDAP search: %w", err)
	}
	if result == nil || len(result.Entries) == 0 {
		return nil, nil
	}
	if len(result.Entries) > 1 {
		return nil, fmt.Errorf("LDAP search found more than one account for %s", username)
	}
	return result.Entries[0], nil
}

func (a *LDAPAuth) Authenticate(username, password string) (Identity, error) {
	if !usernameRe.MatchString(username) || password == "" {
		return Identity{}, ErrBadCredentials
	}
	conn, err := a.dial()
	if err != nil {
		return Identity{}, err
	}
	defer conn.Close()
	entry, err := a.find(conn, username)
	if err != nil {
		return Identity{}, err
	}
	if entry == nil {
		return Identity{}, ErrBadCredentials
	}
	if entry.GetAttributeValue("uid") != username {
		return Identity{}, fmt.Errorf("LDAP returned %q for %s", entry.DN, username)
	}
	d, err := a.entry(entry)
	if err != nil {
		return Identity{}, err
	}
	if d.Disabled {
		// Unknown, locked, or not in the allowed group: say no more.
		return Identity{}, ErrBadCredentials
	}
	if err := conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return Identity{}, ErrBadCredentials
		}
		return Identity{}, fmt.Errorf("LDAP bind: %w", err)
	}
	return Identity{User: User{Name: username, UID: d.UID, GID: d.GID, Admin: d.Admin}, Groups: d.Groups}, nil
}

func (a *LDAPAuth) Check(username string) (DirEntry, error) {
	if !usernameRe.MatchString(username) {
		return DirEntry{Disabled: true, Reason: "not a valid username"}, nil
	}
	conn, err := a.dial()
	if err != nil {
		return DirEntry{}, err
	}
	defer conn.Close()
	entry, err := a.find(conn, username)
	if err != nil {
		return DirEntry{}, err
	}
	if entry == nil {
		return DirEntry{Disabled: true, Reason: "not in the directory"}, nil
	}
	return a.entry(entry)
}

func (a *LDAPAuth) CheckAll() (map[string]DirEntry, error) {
	conn, err := a.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	result, err := conn.SearchWithPaging(ldap.NewSearchRequest(
		a.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 60, false,
		"(objectClass=posixAccount)", userAttrs, nil,
	), 500)
	if err != nil {
		return nil, fmt.Errorf("LDAP search: %w", err)
	}
	out := map[string]DirEntry{}
	for _, e := range result.Entries {
		name := e.GetAttributeValue("uid")
		if !usernameRe.MatchString(name) {
			continue
		}
		if _, dup := out[name]; dup {
			out[name] = DirEntry{Disabled: true, Reason: "more than one account with this name"}
			continue
		}
		d, err := a.entry(e)
		if err != nil {
			d = DirEntry{Disabled: true, Reason: err.Error()}
		}
		out[name] = d
	}
	return out, nil
}

func (a *LDAPAuth) Groups() ([]string, error) {
	conn, err := a.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	filter := a.GroupFilter
	if filter == "" {
		filter = "(objectClass=posixGroup)"
	}
	result, err := conn.SearchWithPaging(ldap.NewSearchRequest(
		a.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false,
		filter, []string{"cn", "ou"}, nil,
	), 500)
	if err != nil {
		return nil, fmt.Errorf("LDAP group search: %w", err)
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range result.Entries {
		if g := groupName(e.DN); g != "" && !seen[strings.ToLower(g)] {
			seen[strings.ToLower(g)] = true
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out, nil
}

// groupName is a group DN's first value, e.g. s3-users for
// ou=s3-users,ou=groups,dc=example,dc=com.
func groupName(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return ""
	}
	return parsed.RDNs[0].Attributes[0].Value
}

// entry turns a directory entry into what the portal needs to know.
func (a *LDAPAuth) entry(e *ldap.Entry) (DirEntry, error) {
	uid, err1 := strconv.Atoi(strings.TrimSpace(e.GetAttributeValue("uidNumber")))
	gid, err2 := strconv.Atoi(strings.TrimSpace(e.GetAttributeValue("gidNumber")))
	if err1 != nil || err2 != nil {
		return DirEntry{}, fmt.Errorf("LDAP entry %s has no usable uidNumber/gidNumber", e.DN)
	}
	d := DirEntry{UID: uid, GID: gid}
	for _, g := range e.GetAttributeValues("memberOf") {
		if name := groupName(g); name != "" {
			d.Groups = append(d.Groups, name)
		}
	}
	sort.Strings(d.Groups)
	d.Admin = a.AdminGroup != "" && hasGroup(e, a.AdminGroup)
	now := time.Now
	if a.now != nil {
		now = a.now
	}
	switch {
	// Never map anyone onto root's files.
	case uid == 0 || gid == 0:
		d.Disabled, d.Reason = true, "root ids"
	case a.AllowedGroup != "" && !hasGroup(e, a.AllowedGroup):
		d.Disabled, d.Reason = true, "not in the allowed group"
	default:
		d.Disabled, d.Reason = accountLocked(e, now())
	}
	if d.Disabled {
		d.Admin = false
	}
	return d, nil
}

// accountLocked reads the attributes directories use to mark an account
// unusable: glauth's accountStatus, 389-ds's nsAccountLock, the password
// policy overlay's pwdAccountLockedTime, and shadowExpire.
func accountLocked(e *ldap.Entry, now time.Time) (bool, string) {
	if strings.EqualFold(e.GetAttributeValue("accountStatus"), "inactive") {
		return true, "account inactive"
	}
	if strings.EqualFold(e.GetAttributeValue("nsAccountLock"), "true") {
		return true, "account locked"
	}
	if e.GetAttributeValue("pwdAccountLockedTime") != "" {
		return true, "account locked"
	}
	if v := strings.TrimSpace(e.GetAttributeValue("shadowExpire")); v != "" {
		// Days since the epoch; -1 or empty means never.
		if days, err := strconv.ParseInt(v, 10, 64); err == nil && days >= 0 && now.Unix()/86400 >= days {
			return true, "account expired"
		}
	}
	return false, ""
}

func hasGroup(entry *ldap.Entry, group string) bool {
	for _, g := range entry.GetAttributeValues("memberOf") {
		if strings.EqualFold(g, group) {
			return true
		}
	}
	return false
}
