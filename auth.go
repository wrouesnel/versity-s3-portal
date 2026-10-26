package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"regexp"
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
}

// Authenticator checks a username and password.
type Authenticator interface {
	Authenticate(username, password string) (User, error)
}

// LDAPAuth finds the user with a search account, then binds as them to check
// their password. Their uid and gid come from the directory's posixAccount
// attributes, which is what glauth's PAM backend serves.
type LDAPAuth struct {
	URL          string
	ServerName   string
	CAFile       string
	BaseDN       string
	BindDN       string
	BindPassword string
	// AllowedGroup, when set, is the group DN users must have in memberOf.
	AllowedGroup string
}

// userFilter matches the user's account entry. objectClass is needed because
// glauth's group entries also carry a uid attribute.
func (a *LDAPAuth) userFilter(username string) string {
	filter := fmt.Sprintf("(objectClass=posixAccount)(uid=%s)", ldap.EscapeFilter(username))
	if a.AllowedGroup != "" {
		filter += fmt.Sprintf("(memberOf=%s)", ldap.EscapeFilter(a.AllowedGroup))
	}
	return "(&" + filter + ")"
}

func (a *LDAPAuth) Authenticate(username, password string) (User, error) {
	if !usernameRe.MatchString(username) || password == "" {
		return User{}, ErrBadCredentials
	}

	tlsConfig := &tls.Config{ServerName: a.ServerName, MinVersion: tls.VersionTLS12}
	if a.CAFile != "" {
		pem, err := os.ReadFile(a.CAFile)
		if err != nil {
			return User{}, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return User{}, fmt.Errorf("no certificates in %s", a.CAFile)
		}
		tlsConfig.RootCAs = pool
	}
	conn, err := ldap.DialURL(a.URL, ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return User{}, fmt.Errorf("connect to LDAP: %w", err)
	}
	defer conn.Close()
	conn.SetTimeout(10 * time.Second)

	if err := conn.Bind(a.BindDN, a.BindPassword); err != nil {
		return User{}, fmt.Errorf("LDAP bind as search account: %w", err)
	}
	result, err := conn.Search(ldap.NewSearchRequest(
		a.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false,
		a.userFilter(username), []string{"uid", "uidNumber", "gidNumber", "memberOf"}, nil,
	))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return User{}, fmt.Errorf("LDAP search: %w", err)
	}
	if result == nil || len(result.Entries) == 0 {
		// Unknown, or not in the allowed group.
		return User{}, ErrBadCredentials
	}
	if len(result.Entries) > 1 {
		return User{}, fmt.Errorf("LDAP search found more than one account for %s", username)
	}
	entry := result.Entries[0]
	user, err := userFromEntry(username, entry)
	if err != nil {
		return User{}, err
	}

	if err := conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return User{}, ErrBadCredentials
		}
		return User{}, fmt.Errorf("LDAP bind: %w", err)
	}
	return user, nil
}

func userFromEntry(username string, entry *ldap.Entry) (User, error) {
	if entry.GetAttributeValue("uid") != username {
		return User{}, fmt.Errorf("LDAP returned %q for %s", entry.DN, username)
	}
	uid, err1 := strconv.Atoi(strings.TrimSpace(entry.GetAttributeValue("uidNumber")))
	gid, err2 := strconv.Atoi(strings.TrimSpace(entry.GetAttributeValue("gidNumber")))
	if err1 != nil || err2 != nil {
		return User{}, fmt.Errorf("LDAP entry %s has no usable uidNumber/gidNumber", entry.DN)
	}
	// Never map anyone onto root's files.
	if uid == 0 || gid == 0 {
		return User{}, ErrBadCredentials
	}
	return User{Name: username, UID: uid, GID: gid}, nil
}
