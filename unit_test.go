package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestPasswdLookup(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	group := filepath.Join(dir, "group")
	os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\nbob:x:1002:100::/home/bob:/bin/sh\n"), 0o644)
	os.WriteFile(group, []byte("s3:x:2000:bob\nalice:x:1001:\n"), 0o644)

	u, err := lookupPasswd(passwd, "alice")
	if err != nil || u.UID != 1001 || u.GID != 1001 {
		t.Fatalf("alice: %+v %v", u, err)
	}
	if _, err := lookupPasswd(passwd, "root"); err != ErrBadCredentials {
		t.Fatalf("root should be refused, got %v", err)
	}
	if _, err := lookupPasswd(passwd, "nobody"); err != ErrBadCredentials {
		t.Fatalf("unknown user should be refused, got %v", err)
	}
	bob, _ := lookupPasswd(passwd, "bob")
	if ok, _ := inGroup(group, "s3", bob); !ok {
		t.Fatal("bob is a member of s3")
	}
	if ok, _ := inGroup(group, "s3", u); ok {
		t.Fatal("alice isn't a member of s3")
	}
	if ok, _ := inGroup(group, "alice", u); !ok {
		t.Fatal("primary group should count")
	}

	a := &LDAPAuth{PasswdFile: passwd, GroupFile: group, AllowedGroup: "s3"}
	for _, name := range []string{"alice", "root", "Bad Name", "a,cn=admin", ""} {
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
