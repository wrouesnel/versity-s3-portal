package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Registering someone from the directory records them as their logging in would, refuses
// those the directory doesn't let use the service, and is only for admins.
func TestRegisterFromDirectory(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	p := NewPortal(nil, store)
	admin, bob := User{Name: "eve", Admin: true}, User{Name: "bob"}
	userError(t, "without a directory", firstErr(p.RegisterFromDirectory(ctx, admin, "alice")))
	p.dir = &fakeDir{entries: map[string]DirEntry{
		"alice": {UID: 1001, GID: 1001, Groups: []string{"photos", "staff"}},
		"carol": {UID: 1003, GID: 1003, Disabled: true, Reason: "account disabled"},
	}}

	userError(t, "not an admin", firstErr(p.RegisterFromDirectory(ctx, bob, "alice")))
	userError(t, "a directory check, not an admin", firstErr(p.DirectoryCheck(bob, "alice")))
	for name, want := range map[string]DirectoryStatus{
		"alice":     {User: "alice", Allowed: true},
		"carol":     {User: "carol", Reason: "account disabled"},
		"nobody":    {User: "nobody", Reason: "not in the directory"},
		"Bad Name!": {User: "Bad Name!", Reason: "not a valid username"},
	} {
		got, err := p.DirectoryCheck(admin, name)
		if err != nil || got != want {
			t.Errorf("directory check %s: %+v %v, want %+v", name, got, err, want)
		}
	}
	if _, known := store.Person("alice"); known {
		t.Fatal("a directory check recorded alice")
	}
	status, err := p.RegisterFromDirectory(ctx, admin, " alice ")
	ok(t, "register alice", err)
	person, known := store.Person("alice")
	if !known || person.Source != "ldap" || person.UID != 1001 || strings.Join(person.Groups, ",") != "photos,staff" || person.Disabled {
		t.Fatalf("alice as recorded: %+v", person)
	}
	if !status.Known || !status.Changed || status.User != "alice" {
		t.Errorf("alice's status: %+v", status)
	}
	if _, _, err := p.CreateKeyFor(ctx, admin, "alice", "x", nil); err == nil || strings.Contains(err.Error(), "logged in") {
		t.Errorf("alice registered should get past knownPerson: %v", err)
	}

	if got, _ := p.DirectoryCheck(admin, "alice"); !got.Known || !got.Allowed {
		t.Errorf("directory check after registering: %+v", got)
	}

	// Again: checked, not recorded twice.
	status, err = p.RegisterFromDirectory(ctx, admin, "alice")
	ok(t, "register alice again", err)
	if status.Changed {
		t.Errorf("registering again changed alice: %+v", status)
	}

	for name, reason := range map[string]string{"carol": "account disabled", "nobody": "not in the directory", "Bad Name!": "isn't a username"} {
		status, err := p.RegisterFromDirectory(ctx, admin, name)
		if err == nil || !strings.Contains(err.Error(), reason) {
			t.Errorf("%s: %v", name, err)
		}
		if _, known := store.Person(name); known || status.Known {
			t.Errorf("%s was recorded: %+v", name, status)
		}
	}
}

// The admin API, over HTTP with the token, does what a migration needs: register someone,
// make their bucket (again harmlessly), issue them a key on it, load data with it, and
// revoke it.
func TestAdminAPIAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	alice, bob := "alice"+suffix, "bob"+suffix
	p.dir = &fakeDir{entries: map[string]DirEntry{
		alice: {UID: 1011, GID: 1011},
		bob:   {UID: 1012, GID: 1012},
	}}
	srv := NewServer(p, stubAuth{}, nil, testSessions(t, store, "x"), "t", root.S3Endpoint, "us-east-1")
	srv.APIToken = "0123456789abcdef0123456789abcdef-token"
	h := srv.Handler()

	call := func(method, path, body string, out any) int {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+srv.APIToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if out != nil {
			if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
				t.Fatalf("%s %s: %v: %s", method, path, err, rec.Body.String())
			}
		}
		return rec.Code
	}

	bucket := "home-" + suffix
	var made APIBucketResult
	if c := call("POST", "/api/buckets", `{"owner":"`+alice+`","name":"`+bucket+`"}`, nil); c != http.StatusBadRequest {
		t.Fatalf("a bucket for someone not registered: %d", c)
	}
	var status PersonStatus
	if c := call("POST", "/api/users/"+alice+"/register", "", &status); c != http.StatusOK || !status.Known {
		t.Fatalf("register: %d %+v", c, status)
	}
	if c := call("POST", "/api/buckets", `{"owner":"`+alice+`","name":"`+bucket+`"}`, &made); c != http.StatusOK || !made.Created {
		t.Fatalf("make the bucket: %d %+v", c, made)
	}
	if c := call("POST", "/api/buckets", `{"owner":"`+alice+`","name":"`+bucket+`"}`, &made); c != http.StatusOK || made.Created {
		t.Fatalf("make it again: %d %+v", c, made)
	}
	call("POST", "/api/users/"+bob+"/register", "", nil)
	if c := call("POST", "/api/buckets", `{"owner":"`+bob+`","name":"`+bucket+`"}`, nil); c != http.StatusBadRequest {
		t.Fatalf("alice's bucket for bob: %d", c)
	}
	if c := call("POST", "/api/buckets", `{"owner":"`+alice+`","name":"`+bucket+`","extra":1}`, nil); c != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", c)
	}

	if c := call("POST", "/api/keys", `{"owner":"`+alice+`","buckets":{"`+bucket+`":"everything"}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("a bad level: %d", c)
	}
	var key APIKeyResult
	if c := call("POST", "/api/keys", `{"owner":"`+alice+`","label":"migration","buckets":{"`+bucket+`":"readwrite"}}`, &key); c != http.StatusOK || key.SecretKey == "" {
		t.Fatalf("issue a key: %d %+v", c, key)
	}
	if k, _ := store.Get(key.AccessKey); k.Owner != alice || k.IssuedBy != apiTokenAdmin.Name || k.Label != "migration" {
		t.Fatalf("the key as recorded: %+v", k)
	}
	s3 := as(root, key.AccessKey, key.SecretKey)
	ok(t, "load data with it", putObject(ctx, s3, bucket, "ws1/alice.tar.gz", "data"))
	if got, err := getObject(ctx, s3, bucket, "ws1/alice.tar.gz"); err != nil || got != "data" {
		t.Fatalf("read it back: %q %v", got, err)
	}

	if c := call("DELETE", "/api/keys/"+key.AccessKey, "", nil); c != http.StatusOK {
		t.Fatalf("revoke: %d", c)
	}
	denied(t, "the revoked key", putObject(ctx, s3, bucket, "after.txt", "x"))
	if c := call("DELETE", "/api/keys/"+key.AccessKey, "", nil); c != http.StatusOK {
		t.Fatalf("revoke again: %d", c)
	}

	// Importing a key from another server: its ID and secret kept, so its clients work.
	imp := "SVCIMPORT" + strings.ToUpper(suffix)
	impSecret := "imported-secret-" + suffix
	body := func(owner, access, secret string) string {
		return `{"owner":"` + owner + `","label":"MinIO: backup-bot","buckets":{"` + bucket + `":"read"},"access_key":"` + access + `","secret_key":"` + secret + `"}`
	}
	var imported APIKeyResult
	if c := call("POST", "/api/keys", body(alice, imp, impSecret), &imported); c != http.StatusOK || !imported.Imported || imported.Existing || imported.SecretKey != "" {
		t.Fatalf("import a key: %d %+v", c, imported)
	}
	t.Cleanup(func() { root.DeleteAccount(ctx, imp) })
	if k, _ := store.Get(imp); k == nil || k.Owner != alice || k.Label != "MinIO: backup-bot" || k.IssuedBy != apiTokenAdmin.Name {
		t.Fatalf("the imported key as recorded: %+v", k)
	}
	if got, err := getObject(ctx, as(root, imp, impSecret), bucket, "ws1/alice.tar.gz"); err != nil || got != "data" {
		t.Fatalf("read with the imported key: %q %v", got, err)
	}
	denied(t, "write with a read-only imported key", putObject(ctx, as(root, imp, impSecret), bucket, "no.txt", "x"))
	if c := call("POST", "/api/keys", body(alice, imp, impSecret), &imported); c != http.StatusOK || !imported.Existing {
		t.Fatalf("import it again: %d %+v", c, imported)
	}
	if state, _ := os.ReadFile(store.path); strings.Contains(string(state), impSecret) {
		t.Fatal("the imported secret is in the portal's state")
	}
	var live APIKeyResult
	call("POST", "/api/keys", `{"owner":"`+alice+`","label":"live","buckets":{"`+bucket+`":"read"}}`, &live)
	other := "OTHER" + strings.ToUpper(suffix)
	ok(t, "a gateway account the portal doesn't know", root.CreateAccount(ctx, Account{Access: other, Secret: "othersecret123", Role: "user", UserID: 2001, GroupID: 2001}))
	t.Cleanup(func() { root.DeleteAccount(ctx, other) })
	for what, b := range map[string]string{
		"with another secret":             body(alice, imp, "another-secret-1"),
		"for another owner":               body(bob, imp, impSecret),
		"over the portal's own key":       body(alice, live.AccessKey, impSecret),
		"over another gateway account":    body(alice, other, impSecret),
		"as a web account":                body(alice, "web."+alice, impSecret),
		"as the root account":             body(alice, root.Creds.AccessKeyID, impSecret),
		"with an ID URLs can't carry":     body(alice, "a/b/c", impSecret),
		"with a short secret":             body(alice, "NEW"+imp, "short"),
		"with a secret and no ID":         body(alice, "", impSecret),
		"on a bucket the owner can't use": strings.Replace(body(bob, "NEW"+imp, impSecret), bucket, "nosuch-"+suffix, 1),
	} {
		if c := call("POST", "/api/keys", b, nil); c != http.StatusBadRequest {
			t.Errorf("import %s: %d", what, c)
		}
	}

	// Without the token, none of it.
	req := httptest.NewRequest("POST", "/api/buckets", strings.NewReader(`{"owner":"`+alice+`","name":"x-`+suffix+`"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("without the token: %d", rec.Code)
	}
}
