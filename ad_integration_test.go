package main

import (
	"os"
	"slices"
	"testing"
)

// Runs against an Active Directory domain controller (or Samba's), with
// the ad schema. AD_TEST_URL, AD_TEST_BASE_DN, AD_TEST_BIND_DN and
// AD_TEST_BIND_PASSWORD point at it and its search account. AD_TEST_GROUP_DN
// is the allowed group, which AD_TEST_USER is in only through a nested group;
// AD_TEST_ADMIN is in AD_TEST_ADMIN_GROUP_DN; AD_TEST_DISABLED's account is
// disabled; AD_TEST_OUTSIDER is in neither. All have AD_TEST_PASSWORD.
func TestADIntegration(t *testing.T) {
	url := os.Getenv("AD_TEST_URL")
	if url == "" {
		t.Skip("AD_TEST_URL not set")
	}
	a := &LDAPAuth{
		URL:          url,
		ServerName:   os.Getenv("AD_TEST_SERVER_NAME"),
		CAFile:       os.Getenv("AD_TEST_CA_FILE"),
		BaseDN:       os.Getenv("AD_TEST_BASE_DN"),
		BindDN:       os.Getenv("AD_TEST_BIND_DN"),
		BindPassword: os.Getenv("AD_TEST_BIND_PASSWORD"),
		AllowedGroup: os.Getenv("AD_TEST_GROUP_DN"),
		AdminGroup:   os.Getenv("AD_TEST_ADMIN_GROUP_DN"),
		Schema:       SchemaAD,
		IDRangeBase:  200000,
	}
	user, admin, password := os.Getenv("AD_TEST_USER"), os.Getenv("AD_TEST_ADMIN"), os.Getenv("AD_TEST_PASSWORD")
	disabled, outsider := os.Getenv("AD_TEST_DISABLED"), os.Getenv("AD_TEST_OUTSIDER")

	// Through the nested group, and by any case of the name.
	for _, name := range []string{user, upper(user)} {
		u, err := a.Authenticate(name, password)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if u.Name != user || u.UID <= 200000 || u.GID != 200513 || u.Admin {
			t.Fatalf("%s: unexpected %+v", name, u)
		}
		t.Logf("%s is uid %d gid %d, groups %v", u.Name, u.UID, u.GID, u.Groups)
	}
	if u, err := a.Authenticate(admin, password); err != nil || !u.Admin {
		t.Errorf("%s: want an admin, got %+v %v", admin, u, err)
	}
	for name, pw := range map[string]string{
		user: "wrong", disabled: password, outsider: password, "nosuchuser": password,
	} {
		if _, err := a.Authenticate(name, pw); err != ErrBadCredentials {
			t.Errorf("%s: want bad credentials, got %v", name, err)
		}
	}

	for name, want := range map[string]string{user: "", disabled: "account disabled", outsider: "not in the allowed group"} {
		d, err := a.Check(name)
		if err != nil || d.Reason != want || d.Disabled != (want != "") {
			t.Errorf("Check %s: want %q, got %+v %v", name, want, d, err)
		}
	}
	all, err := a.CheckAll()
	if err != nil {
		t.Fatal(err)
	}
	if d := all[user]; d.Disabled || d.Admin {
		t.Errorf("CheckAll %s: %+v", user, d)
	}
	if d := all[admin]; d.Disabled || !d.Admin {
		t.Errorf("CheckAll %s: %+v", admin, d)
	}
	if d := all[disabled]; !d.Disabled || d.Reason != "account disabled" {
		t.Errorf("CheckAll %s: %+v", disabled, d)
	}
	if d := all[outsider]; !d.Disabled || d.Reason != "not in the allowed group" {
		t.Errorf("CheckAll %s: %+v", outsider, d)
	}
	groups, err := a.Groups()
	if err != nil || !slices.Contains(groups, groupName(a.AllowedGroup)) {
		t.Errorf("Groups: %v %v", groups, err)
	}
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
