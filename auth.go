package main

import (
	"crypto/x509"
	"encoding/binary"
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

// LDAP schemas: how a directory names people, their groups and their ids.
const (
	// SchemaPosix is RFC 2307's, as glauth, OpenLDAP and 389-ds serve it:
	// posixAccount entries named by uid, with uidNumber and gidNumber.
	SchemaPosix = "posix"
	// SchemaAD is Active Directory's: user entries named by
	// sAMAccountName, nested groups, and userAccountControl.
	SchemaAD = "ad"
)

// adInChain is AD's LDAP_MATCHING_RULE_IN_CHAIN: memberOf matched through
// nested groups.
const adInChain = "1.2.840.113556.1.4.1941"

// LDAPAuth finds the user with a search account, then binds as them to check
// their password. With the posix schema their uid and gid come from the
// directory's posixAccount attributes, which is what glauth serves. With the
// ad schema, from uidNumber and gidNumber where AD has them (its RFC 2307
// attributes), else IDRangeBase plus the account's RID and its primary
// group's, else DefaultUID and DefaultGID.
type LDAPAuth struct {
	// URL is the directory's, or several, separated by spaces, tried in
	// turn (a domain's DCs, by the names their certificates have).
	URL          string
	ServerName   string
	CAFile       string
	BaseDN       string
	BindDN       string
	BindPassword string
	// AllowedGroup, when set, is the group DN users must have in memberOf,
	// unless they are in AdminGroup, which lets its members in too.
	AllowedGroup string
	// AdminGroup, when set, is the group DN that makes users admins.
	AdminGroup string
	// GroupFilter finds group entries for Groups (default posixGroup, or
	// AD's group).
	GroupFilter string
	// Schema is SchemaPosix (default) or SchemaAD.
	Schema string
	// IDRangeBase, with the ad schema, gives an account without uidNumber
	// the uid IDRangeBase+RID (its objectSid's last part) and the gid
	// IDRangeBase+primaryGroupID, as sssd's ID mapping does with a range of
	// its own: unique within one domain.
	IDRangeBase int
	// DefaultUID and DefaultGID are those of an account the directory gives
	// no ids for (with the ad schema): every file of theirs then belongs to
	// one service user.
	DefaultUID, DefaultGID int

	now func() time.Time
}

func (a *LDAPAuth) ad() bool { return a.Schema == SchemaAD }

// nameAttr is the attribute a person's username is.
func (a *LDAPAuth) nameAttr() string {
	if a.ad() {
		return "sAMAccountName"
	}
	return "uid"
}

// attrs are those read for every person.
func (a *LDAPAuth) attrs() []string {
	if a.ad() {
		return adUserAttrs
	}
	return userAttrs
}

// usersFilter matches every person's account entry.
func (a *LDAPAuth) usersFilter() string {
	if a.ad() {
		return "(&(objectCategory=person)(objectClass=user))"
	}
	return "(objectClass=posixAccount)"
}

// filterFor matches username's account entry, whether or not they may use
// the service.
func (a *LDAPAuth) filterFor(username string) string {
	if a.ad() {
		return fmt.Sprintf("(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(username))
	}
	return userFilter(username)
}

// normalize is the username as the portal knows it: AD's are matched
// without case, so they are lowercased.
func (a *LDAPAuth) normalize(username string) string {
	if a.ad() {
		return strings.ToLower(username)
	}
	return username
}

// userAttrs are read for every person: ids, groups, and the attributes
// directories use to mark an account locked or expired.
var userAttrs = []string{
	"uid", "uidNumber", "gidNumber", "memberOf",
	"accountStatus", "nsAccountLock", "pwdAccountLockedTime", "shadowExpire",
}

// adUserAttrs are AD's: its ids where it has them (RFC 2307), the SID and
// primary group for ID mapping, groups, and what marks an account disabled,
// expired or locked out.
var adUserAttrs = []string{
	"sAMAccountName", "uidNumber", "gidNumber", "objectSid", "primaryGroupID", "memberOf",
	"userAccountControl", "accountExpires", "msDS-User-Account-Control-Computed",
}

// userFilter matches the user's account entry, whether or not they may
// use the service. objectClass is needed because glauth's group entries
// also carry a uid attribute.
func userFilter(username string) string {
	return fmt.Sprintf("(&(objectClass=posixAccount)(uid=%s))", ldap.EscapeFilter(username))
}

func (a *LDAPAuth) dial() (*ldap.Conn, error) {
	var roots *x509.CertPool
	if a.CAFile != "" {
		pem, err := os.ReadFile(a.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", a.CAFile)
		}
		roots = pool
	}
	// URL may name several servers, separated by spaces (a domain's DCs):
	// each is tried in turn until one answers.
	var conn *ldap.Conn
	var errs []error
	for _, u := range strings.Fields(a.URL) {
		c, err := a.dialURL(u, roots)
		if err == nil {
			conn = c
			break
		}
		errs = append(errs, fmt.Errorf("%s: %w", u, err))
	}
	if conn == nil {
		return nil, fmt.Errorf("connect to LDAP: %w", errors.Join(errs...))
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
		a.filterFor(username), a.attrs(), nil,
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
	username = a.normalize(username)
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
	if a.normalize(entry.GetAttributeValue(a.nameAttr())) != username {
		return Identity{}, fmt.Errorf("LDAP returned %q for %s", entry.DN, username)
	}
	d, err := a.entry(entry, a.memberOf(conn, entry))
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
	username = a.normalize(username)
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
	return a.entry(entry, a.memberOf(conn, entry))
}

func (a *LDAPAuth) CheckAll() (map[string]DirEntry, error) {
	conn, err := a.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	result, err := conn.SearchWithPaging(ldap.NewSearchRequest(
		a.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 60, false,
		a.usersFilter(), a.attrs(), nil,
	), 500)
	if err != nil {
		return nil, fmt.Errorf("LDAP search: %w", err)
	}
	inGroup := func(e *ldap.Entry) func(string) bool { return func(g string) bool { return hasGroup(e, g) } }
	if a.ad() {
		// Each group's members, nested groups' too, in one search each, and
		// the groups whose members are in it by their primary group.
		members := map[string]map[string]bool{}
		primaries := map[string]map[string]bool{}
		for _, g := range []string{a.AllowedGroup, a.AdminGroup} {
			if g == "" {
				continue
			}
			key := strings.ToLower(g)
			if members[key], err = a.chainMembers(conn, g); err != nil {
				return nil, err
			}
			if primaries[key], err = a.chainGroupSIDs(conn, g); err != nil {
				return nil, err
			}
		}
		inGroup = func(e *ldap.Entry) func(string) bool {
			return func(g string) bool {
				key := strings.ToLower(g)
				if members[key][strings.ToLower(e.DN)] {
					return true
				}
				pg := primaryGroupSID(e)
				return pg != nil && primaries[key][string(pg)]
			}
		}
	}
	out := map[string]DirEntry{}
	for _, e := range result.Entries {
		name := a.normalize(e.GetAttributeValue(a.nameAttr()))
		if !usernameRe.MatchString(name) {
			continue
		}
		if _, dup := out[name]; dup {
			out[name] = DirEntry{Disabled: true, Reason: "more than one account with this name"}
			continue
		}
		d, err := a.entry(e, inGroup(e))
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
	switch {
	case filter != "":
	case a.ad():
		filter = "(objectClass=group)"
	default:
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

// memberOf is how a person's membership of a group is read: their own
// memberOf, or with the ad schema, AD's through nested groups, their primary
// group included.
func (a *LDAPAuth) memberOf(conn *ldap.Conn, e *ldap.Entry) func(string) bool {
	if !a.ad() {
		return func(g string) bool { return hasGroup(e, g) }
	}
	inChain := func(dn, g string) bool {
		result, err := conn.Search(ldap.NewSearchRequest(
			dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false,
			fmt.Sprintf("(memberOf:%s:=%s)", adInChain, ldap.EscapeFilter(g)), []string{"dn"}, nil,
		))
		return err == nil && len(result.Entries) > 0
	}
	// The primary group (usually Domain Users) is in no memberOf, and the
	// in-chain rule doesn't follow it: a group holding Domain Users holds
	// everyone, but only by way of their primary group. It's looked up once,
	// if needed.
	primary, looked := "", false
	return func(g string) bool {
		if inChain(e.DN, g) {
			return true
		}
		if !looked {
			primary, looked = a.primaryGroupDN(conn, e), true
		}
		return primary != "" && (strings.EqualFold(primary, g) || inChain(primary, g))
	}
}

// primaryGroupSID is an AD account's primary group's SID: its own SID with
// the last subauthority, its RID, made primaryGroupID. Nil if it has none.
func primaryGroupSID(e *ldap.Entry) []byte {
	sid := e.GetRawAttributeValue("objectSid")
	pg, err := strconv.ParseUint(strings.TrimSpace(e.GetAttributeValue("primaryGroupID")), 10, 32)
	if _, ok := sidRID(sid); !ok || err != nil {
		return nil
	}
	group := append([]byte{}, sid...)
	binary.LittleEndian.PutUint32(group[len(group)-4:], uint32(pg))
	return group
}

// escapeBinary escapes every byte of a binary value, such as a SID, for an
// LDAP filter.
func escapeBinary(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		fmt.Fprintf(&sb, "\\%02x", c)
	}
	return sb.String()
}

// primaryGroupDN is the DN of an AD account's primary group, or "" if it
// can't be found.
func (a *LDAPAuth) primaryGroupDN(conn *ldap.Conn, e *ldap.Entry) string {
	sid := primaryGroupSID(e)
	if sid == nil {
		return ""
	}
	result, err := conn.Search(ldap.NewSearchRequest(
		a.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false,
		"(&(objectClass=group)(objectSid="+escapeBinary(sid)+"))", []string{"dn"}, nil,
	))
	if err != nil || len(result.Entries) != 1 {
		return ""
	}
	return result.Entries[0].DN
}

// chainGroupSIDs are the SIDs (as strings of their bytes) of an AD group and
// every group nested in it: a person whose primary group is one of them is
// in the group.
func (a *LDAPAuth) chainGroupSIDs(conn *ldap.Conn, group string) (map[string]bool, error) {
	result, err := conn.SearchWithPaging(ldap.NewSearchRequest(
		a.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 60, false,
		fmt.Sprintf("(&(objectClass=group)(|(distinguishedName=%s)(memberOf:%s:=%s)))",
			ldap.EscapeFilter(group), adInChain, ldap.EscapeFilter(group)), []string{"objectSid"}, nil,
	), 500)
	if err != nil {
		return nil, fmt.Errorf("LDAP search for the groups in %s: %w", group, err)
	}
	out := map[string]bool{}
	for _, e := range result.Entries {
		if sid := e.GetRawAttributeValue("objectSid"); len(sid) > 0 {
			out[string(sid)] = true
		}
	}
	return out, nil
}

// chainMembers are the DNs (lowercased) of the people in an AD group,
// through nested groups.
func (a *LDAPAuth) chainMembers(conn *ldap.Conn, group string) (map[string]bool, error) {
	result, err := conn.SearchWithPaging(ldap.NewSearchRequest(
		a.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 60, false,
		fmt.Sprintf("(&%s(memberOf:%s:=%s))", a.usersFilter(), adInChain, ldap.EscapeFilter(group)), []string{"dn"}, nil,
	), 500)
	if err != nil {
		return nil, fmt.Errorf("LDAP search for %s's members: %w", group, err)
	}
	out := map[string]bool{}
	for _, e := range result.Entries {
		out[strings.ToLower(e.DN)] = true
	}
	return out, nil
}

// ids are a person's uid and gid: the directory's, or with the ad schema,
// mapped from their SID, or the defaults.
func (a *LDAPAuth) ids(e *ldap.Entry) (int, int, error) {
	uid, err1 := strconv.Atoi(strings.TrimSpace(e.GetAttributeValue("uidNumber")))
	gid, err2 := strconv.Atoi(strings.TrimSpace(e.GetAttributeValue("gidNumber")))
	if err1 == nil && err2 == nil {
		return uid, gid, nil
	}
	if !a.ad() {
		return 0, 0, fmt.Errorf("LDAP entry %s has no usable uidNumber/gidNumber", e.DN)
	}
	if a.IDRangeBase > 0 {
		rid, ok := sidRID(e.GetRawAttributeValue("objectSid"))
		pg, err := strconv.Atoi(strings.TrimSpace(e.GetAttributeValue("primaryGroupID")))
		if ok && err == nil {
			return a.IDRangeBase + int(rid), a.IDRangeBase + pg, nil
		}
	}
	if a.DefaultUID > 0 && a.DefaultGID > 0 {
		return a.DefaultUID, a.DefaultGID, nil
	}
	return 0, 0, fmt.Errorf("LDAP entry %s has no uidNumber/gidNumber, and neither LDAP_ID_RANGE_BASE nor LDAP_DEFAULT_UID/GID is set", e.DN)
}

// sidRID is a binary SID's last subauthority: the account's RID.
func sidRID(sid []byte) (uint32, bool) {
	if len(sid) < 8 {
		return 0, false
	}
	n := int(sid[1])
	if n == 0 || len(sid) != 8+4*n {
		return 0, false
	}
	return binary.LittleEndian.Uint32(sid[len(sid)-4:]), true
}

// entry turns a directory entry into what the portal needs to know, with
// inGroup saying whether they are in a group (by DN).
func (a *LDAPAuth) entry(e *ldap.Entry, inGroup func(string) bool) (DirEntry, error) {
	uid, gid, err := a.ids(e)
	if err != nil {
		return DirEntry{}, err
	}
	d := DirEntry{UID: uid, GID: gid}
	for _, g := range e.GetAttributeValues("memberOf") {
		if name := groupName(g); name != "" {
			d.Groups = append(d.Groups, name)
		}
	}
	sort.Strings(d.Groups)
	d.Admin = a.AdminGroup != "" && inGroup(a.AdminGroup)
	now := time.Now
	if a.now != nil {
		now = a.now
	}
	switch {
	// Never map anyone onto root's files.
	case uid == 0 || gid == 0:
		d.Disabled, d.Reason = true, "root ids"
	// The admins' group lets its members in too: an admin needn't be in
	// the allowed group as well.
	case a.AllowedGroup != "" && !d.Admin && !inGroup(a.AllowedGroup):
		d.Disabled, d.Reason = true, "not in the allowed group"
	case a.ad():
		d.Disabled, d.Reason = adAccountLocked(e, now())
	default:
		d.Disabled, d.Reason = accountLocked(e, now())
	}
	if d.Disabled {
		d.Admin = false
	}
	return d, nil
}

// AD's userAccountControl and msDS-User-Account-Control-Computed bits.
const (
	adAccountDisable = 0x2
	adLockout        = 0x10
)

// adAccountLocked reads AD's marks of an unusable account: disabled
// (userAccountControl), locked out (msDS-User-Account-Control-Computed,
// which AD works out from the lockout policy), or past accountExpires.
func adAccountLocked(e *ldap.Entry, now time.Time) (bool, string) {
	if uac, err := strconv.ParseInt(strings.TrimSpace(e.GetAttributeValue("userAccountControl")), 10, 64); err == nil && uac&adAccountDisable != 0 {
		return true, "account disabled"
	}
	if c, err := strconv.ParseInt(strings.TrimSpace(e.GetAttributeValue("msDS-User-Account-Control-Computed")), 10, 64); err == nil && c&adLockout != 0 {
		return true, "account locked"
	}
	// 100ns intervals since 1601; 0 or the largest int64 means never.
	if v, err := strconv.ParseInt(strings.TrimSpace(e.GetAttributeValue("accountExpires")), 10, 64); err == nil && v > 0 && v != 1<<63-1 {
		const fromWindowsEpoch = 11644473600
		if now.Unix() >= v/10_000_000-fromWindowsEpoch {
			return true, "account expired"
		}
	}
	return false, ""
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
