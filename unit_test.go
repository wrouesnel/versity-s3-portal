package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestBucketPolicy(t *testing.T) {
	if BucketPolicy("b", nil) != nil {
		t.Fatal("expected no policy without grants")
	}
	var doc policyDocument
	if err := json.Unmarshal(BucketPolicy("b", map[string]Perm{"R": PermRead, "W": PermReadWrite}), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Statement) != 4 {
		t.Fatalf("want 4 statements, got %d", len(doc.Statement))
	}
	for _, st := range doc.Statement {
		for _, a := range st.Action {
			switch a {
			case "s3:*", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketAcl", "s3:DeleteBucket":
				t.Errorf("statement %s grants %s", st.Sid, a)
			}
		}
		if (st.Sid == "WriteObjects" || st.Sid == "WriteBucket") && len(st.Principal["AWS"]) != 1 {
			t.Errorf("%s should only name the writer: %v", st.Sid, st.Principal["AWS"])
		}
	}
	var readOnly policyDocument
	json.Unmarshal(BucketPolicy("b", map[string]Perm{"R": PermRead}), &readOnly)
	if len(readOnly.Statement) != 2 {
		t.Fatalf("read-only policy should have 2 statements, got %d", len(readOnly.Statement))
	}
}

func TestSessions(t *testing.T) {
	s := &Sessions{Key: []byte("0123456789abcdef0123456789abcdef"), TTL: time.Hour}
	rec := httptest.NewRecorder()
	if err := s.Start(rec, User{Name: "alice", UID: 1001, GID: 1001}); err != nil {
		t.Fatal(err)
	}
	cookie := rec.Result().Cookies()[0]

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	sess, err := s.Get(req)
	if err != nil || sess.User.Name != "alice" || sess.CSRF == "" {
		t.Fatalf("valid session rejected: %v %+v", err, sess)
	}

	tampered := *cookie
	tampered.Value = "x" + cookie.Value[1:]
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&tampered)
	if _, err := s.Get(req); err == nil {
		t.Fatal("tampered session accepted")
	}

	other := &Sessions{Key: []byte("fedcba9876543210fedcba9876543210"), TTL: time.Hour}
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	if _, err := other.Get(req); err == nil {
		t.Fatal("session signed with another key accepted")
	}

	expired := &Sessions{Key: s.Key, TTL: -time.Minute}
	rec = httptest.NewRecorder()
	expired.Start(rec, User{Name: "alice"})
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(rec.Result().Cookies()[0])
	if _, err := s.Get(req); err == nil {
		t.Fatal("expired session accepted")
	}
}

func TestLDAPUser(t *testing.T) {
	a := &LDAPAuth{BaseDN: "dc=example,dc=com", AllowedGroup: "ou=s3-users,ou=groups,dc=example,dc=com"}
	want := "(&(objectClass=posixAccount)(uid=alice)(memberOf=ou=s3-users,ou=groups,dc=example,dc=com))"
	if got := a.userFilter("alice"); got != want {
		t.Fatalf("filter %s, want %s", got, want)
	}

	entry := func(uid, uidNumber, gidNumber string) *ldap.Entry {
		return ldap.NewEntry("cn="+uid+",ou="+uid+",ou=users,dc=example,dc=com", map[string][]string{
			"uid": {uid}, "uidNumber": {uidNumber}, "gidNumber": {gidNumber},
		})
	}
	u, err := userFromEntry("alice", entry("alice", "1001", "1001"))
	if err != nil || u.UID != 1001 || u.GID != 1001 || u.Name != "alice" {
		t.Fatalf("alice: %+v %v", u, err)
	}
	if _, err := userFromEntry("root", entry("root", "0", "0")); err != ErrBadCredentials {
		t.Fatalf("root should be refused, got %v", err)
	}
	if _, err := userFromEntry("bob", entry("bob", "1002", "0")); err != ErrBadCredentials {
		t.Fatalf("gid 0 should be refused, got %v", err)
	}
	if _, err := userFromEntry("alice", entry("bob", "1002", "1002")); err == nil {
		t.Fatal("an entry for someone else should be an error")
	}
	if _, err := userFromEntry("alice", entry("alice", "", "1001")); err == nil {
		t.Fatal("an entry without uidNumber should be an error")
	}

	for _, name := range []string{"Bad Name", "a,cn=admin", "*", ""} {
		if _, err := a.Authenticate(name, "pw"); err != ErrBadCredentials {
			t.Errorf("%q: want bad credentials before any LDAP call, got %v", name, err)
		}
	}
}

func TestStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Put("K1", &Key{Owner: "alice", Label: "one", Created: time.Unix(1, 0), Buckets: map[string]Perm{"a": PermRead}})
	s.Put("K2", &Key{Owner: "alice", Label: "two", Created: time.Unix(2, 0), Buckets: map[string]Perm{"a": PermReadWrite, "b": PermRead}})
	s.Put("K3", &Key{Owner: "bob", Label: "three", Created: time.Unix(3, 0), Buckets: map[string]Perm{}})

	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.KeysFor("alice"); len(got) != 2 || got[0].Access != "K1" {
		t.Fatalf("KeysFor: %+v", got)
	}
	if g := reopened.Grants("a"); len(g) != 2 || g["K2"] != PermReadWrite {
		t.Fatalf("Grants: %v", g)
	}
	reopened.Delete("K1")
	again, _ := OpenStore(path)
	if _, ok := again.Get("K1"); ok {
		t.Fatal("deleted key came back")
	}
}

func TestCSRFAndAuthRequired(t *testing.T) {
	sessions := &Sessions{Key: []byte("0123456789abcdef0123456789abcdef"), TTL: time.Hour}
	srv := NewServer(nil, nil, sessions, "t", "https://s3", "us-east-1")
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/keys/delete", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated POST: want redirect, got %d", rec.Code)
	}

	login := httptest.NewRecorder()
	sessions.Start(login, User{Name: "alice", UID: 1001, GID: 1001})
	req := httptest.NewRequest("POST", "/keys/delete", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(login.Result().Cookies()[0])
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF token: want 403, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP header")
	}
}

func TestAdminAndUploadGuards(t *testing.T) {
	sessions := &Sessions{Key: []byte("0123456789abcdef0123456789abcdef"), TTL: time.Hour}
	h := NewServer(nil, nil, sessions, "t", "https://s3", "us-east-1").Handler()
	login := httptest.NewRecorder()
	sessions.Start(login, User{Name: "alice", UID: 1001, GID: 1001})
	cookie := login.Result().Cookies()[0]

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin GET /admin: want 403, got %d", rec.Code)
	}

	req = httptest.NewRequest("PUT", "/upload?bucket=b&key=k", strings.NewReader("x"))
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("upload without CSRF header: want 403, got %d", rec.Code)
	}
}

func TestAdminGroup(t *testing.T) {
	entry := ldap.NewEntry("cn=will,ou=users,dc=example,dc=com", map[string][]string{
		"memberOf": {"ou=s3-users,ou=groups,dc=example,dc=com", "OU=S3-Admin,ou=groups,dc=example,dc=com"},
	})
	if !hasGroup(entry, "ou=s3-admin,ou=groups,dc=example,dc=com") {
		t.Error("admin group not found")
	}
	if hasGroup(entry, "ou=other,ou=groups,dc=example,dc=com") {
		t.Error("found a group the entry isn't in")
	}
}

func TestPaths(t *testing.T) {
	if got := s3Escape("dir/a b+c=d&é~.txt"); got != "dir/a%20b%2Bc%3Dd%26%C3%A9~.txt" {
		t.Errorf("s3Escape: %s", got)
	}
	if got := parentPrefix("a/b/c.txt"); got != "a/b/" {
		t.Errorf("parentPrefix: %s", got)
	}
	if got := parentPrefix("c.txt"); got != "" {
		t.Errorf("parentPrefix of a top-level key: %q", got)
	}
	if c := crumbs("a/b/"); len(c) != 2 || c[1].Name != "b" || c[1].Prefix != "a/b/" {
		t.Errorf("crumbs: %+v", c)
	}
	if got := humanSize(1536); got != "1.5 KiB" {
		t.Errorf("humanSize: %s", got)
	}
	for _, bad := range []string{"", "/abs", "a\x00b", "a\nb"} {
		if checkKey(bad) == nil {
			t.Errorf("checkKey accepted %q", bad)
		}
	}
	if checkPrefix("dir") == nil {
		t.Error("checkPrefix accepted a prefix without a trailing slash")
	}
}
