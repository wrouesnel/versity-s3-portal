package main

import (
	"os"
	"testing"
)

// Runs against glauth with its PAM backend.
// LDAP_TEST_URL, LDAP_TEST_BASE_DN, LDAP_TEST_BIND_DN and
// LDAP_TEST_BIND_PASSWORD point at it and its search account.
// LDAP_TEST_GROUP_DN is a group that LDAP_TEST_USER (password
// LDAP_TEST_PASSWORD) is in and LDAP_TEST_OUTSIDER (same password) isn't.
func TestLDAPAuthIntegration(t *testing.T) {
	url := os.Getenv("LDAP_TEST_URL")
	if url == "" {
		t.Skip("LDAP_TEST_URL not set")
	}
	a := &LDAPAuth{
		URL:          url,
		ServerName:   os.Getenv("LDAP_TEST_SERVER_NAME"),
		CAFile:       os.Getenv("LDAP_TEST_CA_FILE"),
		BaseDN:       os.Getenv("LDAP_TEST_BASE_DN"),
		BindDN:       os.Getenv("LDAP_TEST_BIND_DN"),
		BindPassword: os.Getenv("LDAP_TEST_BIND_PASSWORD"),
		AllowedGroup: os.Getenv("LDAP_TEST_GROUP_DN"),
	}
	user, password := os.Getenv("LDAP_TEST_USER"), os.Getenv("LDAP_TEST_PASSWORD")

	u, err := a.Authenticate(user, password)
	if err != nil {
		t.Fatalf("%s: %v", user, err)
	}
	if u.Name != user || u.UID == 0 || u.GID == 0 {
		t.Fatalf("%s: unexpected %+v", user, u)
	}
	t.Logf("%s is uid %d gid %d", u.Name, u.UID, u.GID)

	for name, pw := range map[string]string{
		user:                            "wrong",
		os.Getenv("LDAP_TEST_OUTSIDER"): password,
		"root":                          password,
		"nosuchuser":                    password,
	} {
		if _, err := a.Authenticate(name, pw); err != ErrBadCredentials {
			t.Errorf("%s: want bad credentials, got %v", name, err)
		}
	}

	bad := *a
	bad.BindPassword = "wrong"
	if _, err := bad.Authenticate(user, password); err == nil || err == ErrBadCredentials {
		t.Errorf("a bad search account should be a server error, got %v", err)
	}
}
