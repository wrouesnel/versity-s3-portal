package main

import (
	"bufio"
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

// LDAPAuth binds to LDAP as the user, then reads their ids from the passwd
// file the LDAP server is backed by: glauth's PAM backend doesn't let
// ordinary users search.
type LDAPAuth struct {
	URL          string
	ServerName   string
	CAFile       string
	BaseDN       string
	PasswdFile   string
	GroupFile    string
	AllowedGroup string
}

func (a *LDAPAuth) Authenticate(username, password string) (User, error) {
	if !usernameRe.MatchString(username) || password == "" {
		return User{}, ErrBadCredentials
	}
	user, err := lookupPasswd(a.PasswdFile, username)
	if err != nil {
		return User{}, err
	}
	if a.AllowedGroup != "" {
		ok, err := inGroup(a.GroupFile, a.AllowedGroup, user)
		if err != nil {
			return User{}, err
		}
		if !ok {
			return User{}, ErrBadCredentials
		}
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

	dn := fmt.Sprintf("cn=%s,%s", ldap.EscapeDN(username), a.BaseDN)
	if err := conn.Bind(dn, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return User{}, ErrBadCredentials
		}
		return User{}, fmt.Errorf("LDAP bind: %w", err)
	}
	return user, nil
}

func lookupPasswd(path, username string) (User, error) {
	f, err := os.Open(path)
	if err != nil {
		return User{}, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 4 || fields[0] != username {
			continue
		}
		uid, err1 := strconv.Atoi(fields[2])
		gid, err2 := strconv.Atoi(fields[3])
		if err1 != nil || err2 != nil {
			return User{}, fmt.Errorf("bad passwd entry for %s", username)
		}
		// Never map anyone onto root's files.
		if uid == 0 || gid == 0 {
			return User{}, ErrBadCredentials
		}
		return User{Name: username, UID: uid, GID: gid}, nil
	}
	if err := scanner.Err(); err != nil {
		return User{}, err
	}
	return User{}, ErrBadCredentials
}

func inGroup(path, group string, user User) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 4 || fields[0] != group {
			continue
		}
		if gid, err := strconv.Atoi(fields[2]); err == nil && gid == user.GID {
			return true, nil
		}
		for _, member := range strings.Split(fields[3], ",") {
			if member == user.Name {
				return true, nil
			}
		}
		return false, nil
	}
	return false, scanner.Err()
}
