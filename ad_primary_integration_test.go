package main

import (
	"os"
	"testing"
)

// Runs against an Active Directory domain controller (or Samba's), with the ad schema, as
// TestADIntegration does (AD_TEST_URL and the rest). AD_TEST_PRIMARY_GROUP_DN is a group
// holding Domain Users, and AD_TEST_PRIMARY_USER is in it only that way: through their
// primary group, which AD lists in no memberOf and its in-chain rule doesn't follow.
// AD_TEST_OTHER_GROUP_DN, if set, is a group they're in neither way.
func TestADPrimaryGroupIntegration(t *testing.T) {
	url, group, user := os.Getenv("AD_TEST_URL"), os.Getenv("AD_TEST_PRIMARY_GROUP_DN"), os.Getenv("AD_TEST_PRIMARY_USER")
	if url == "" || group == "" || user == "" {
		t.Skip("AD_TEST_URL, AD_TEST_PRIMARY_GROUP_DN and AD_TEST_PRIMARY_USER not set")
	}
	newAuth := func(allowed, admin string) *LDAPAuth {
		return &LDAPAuth{
			URL: url, ServerName: os.Getenv("AD_TEST_SERVER_NAME"), CAFile: os.Getenv("AD_TEST_CA_FILE"),
			BaseDN: os.Getenv("AD_TEST_BASE_DN"), BindDN: os.Getenv("AD_TEST_BIND_DN"),
			BindPassword: os.Getenv("AD_TEST_BIND_PASSWORD"), AllowedGroup: allowed, AdminGroup: admin,
			Schema: SchemaAD, IDRangeBase: 200000,
		}
	}

	// Allowed through Domain Users nested in the allowed group: logging in, checked, and
	// in the directory sync.
	a := newAuth(group, "")
	if _, err := a.Authenticate(user, os.Getenv("AD_TEST_PASSWORD")); err != nil {
		t.Errorf("log in as %s: %v", user, err)
	}
	if d, err := a.Check(user); err != nil || d.Disabled {
		t.Errorf("check %s: %+v %v", user, d, err)
	}
	all, err := a.CheckAll()
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := all[user]; !ok || d.Disabled {
		t.Errorf("sync: %s: %+v (present %v)", user, d, ok)
	}

	// The same for admins.
	admins := newAuth("", group)
	if d, err := admins.Check(user); err != nil || d.Disabled || !d.Admin {
		t.Errorf("check %s as an admin: %+v %v", user, d, err)
	}
	all, err = admins.CheckAll()
	if err != nil {
		t.Fatal(err)
	}
	if d := all[user]; !d.Admin {
		t.Errorf("sync: %s should be an admin: %+v", user, d)
	}

	// And a group which doesn't hold their primary group still doesn't let them in.
	if other := os.Getenv("AD_TEST_OTHER_GROUP_DN"); other != "" {
		if d, err := newAuth(other, "").Check(user); err != nil || !d.Disabled {
			t.Errorf("check %s against %s: %+v %v", user, other, d, err)
		}
	}
}
