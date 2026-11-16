package main

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// An admin makes a bucket for someone, and issues them a key on it, to load
// data in: theirs, recorded as issued by the admin, on their keys page, and
// reaching no more than they can.
func TestAdminBucketForAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	admin := User{Name: "eve" + suffix, UID: 1006, GID: 1006, Admin: true}
	alice := User{Name: "alice" + suffix, UID: 1007, GID: 1007}
	bob := User{Name: "bob" + suffix, UID: 1008, GID: 1008}
	enroll(t, p, admin)
	enroll(t, p, alice)
	enroll(t, p, bob)
	bucket, bobs := "for-"+suffix, "bobs-"+suffix
	ok(t, "bob's own bucket", p.CreateBucket(ctx, bob, bobs))

	userError(t, "not an admin", p.CreateBucketFor(ctx, bob, alice.Name, bucket))
	userError(t, "nobody", p.CreateBucketFor(ctx, admin, "nobody"+suffix, bucket))
	ok(t, "a bucket for alice", p.CreateBucketFor(ctx, admin, alice.Name, bucket))
	if v, err := p.Bucket(ctx, alice, bucket, true); err != nil || v.Caps != PermReadWrite.Caps() {
		t.Fatalf("alice's bucket, as she sees it: %+v %v", v, err)
	}
	userError(t, "a key, not as an admin", firstErr2(p.CreateKeyFor(ctx, bob, alice.Name, "x", map[string]Perm{bucket: PermReadWrite})))
	userError(t, "a key with no bucket", firstErr2(p.CreateKeyFor(ctx, admin, alice.Name, "x", nil)))
	userError(t, "a key for a bucket alice can't reach", firstErr2(p.CreateKeyFor(ctx, admin, alice.Name, "x", map[string]Perm{bobs: PermReadWrite})))
	access, secret, err := p.CreateKeyFor(ctx, admin, alice.Name, "Loading data into "+bucket, map[string]Perm{bucket: PermReadWrite})
	ok(t, "a key for alice", err)
	if k, _ := store.Get(access); k.Owner != alice.Name || k.IssuedBy != admin.Name {
		t.Fatalf("the key: %+v", k)
	}
	key := as(root, access, secret)
	ok(t, "load data with it", putObject(ctx, key, bucket, "loaded.txt", "data"))
	if got, err := getObject(ctx, key, bucket, "loaded.txt"); err != nil || got != "data" {
		t.Fatalf("read it back: %q %v", got, err)
	}
	denied(t, "the key in bob's bucket", putObject(ctx, key, bobs, "x.txt", "x"))

	// Disabled, alice is given nothing more.
	person, _ := store.Person(alice.Name)
	person.Disabled, person.DisabledReason = true, "left"
	ok(t, "disable alice", store.PutPerson(alice.Name, person))
	userError(t, "a bucket for someone disabled", p.CreateBucketFor(ctx, admin, alice.Name, "more-"+suffix))
	userError(t, "a key for someone disabled", firstErr2(p.CreateKeyFor(ctx, admin, alice.Name, "x", map[string]Perm{bucket: PermRead})))
	person.Disabled, person.DisabledReason = false, ""
	ok(t, "enable alice", store.PutPerson(alice.Name, person))

	// Over the web: the admin's form, the key form, the key, and alice's
	// keys page.
	sessions := &Sessions{Key: []byte("0123456789abcdef0123456789abcdef"), TTL: 3600e9, Store: store}
	login := func(u User) (*http.Client, string, string) {
		t.Helper()
		srv := httptest.NewServer(NewServer(p, stubAuth{user: u}, nil, sessions, "t", "https://s3", "us-east-1").Handler())
		t.Cleanup(srv.Close)
		jar, _ := cookiejar.New(nil)
		c := &http.Client{Jar: jar}
		resp, err := c.PostForm(srv.URL+"/login", url.Values{"username": {u.Name}, "password": {"pw"}})
		ok(t, "login", err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return c, srv.URL, string(regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(body)[1])
	}
	c, base, csrf := login(admin)
	post := func(path string, form url.Values) (int, string) {
		t.Helper()
		form.Set("csrf", csrf)
		resp, err := c.PostForm(base+path, form)
		ok(t, "POST "+path, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(body)
	}
	webBucket := "web-for-" + suffix
	code, body := post("/admin/buckets", url.Values{"name": {webBucket}, "owner": {alice.Name}})
	if code != 200 || !strings.Contains(body, "Made "+webBucket+" for "+alice.Name) || !strings.Contains(body, "Issue "+alice.Name+" a key") {
		t.Fatalf("after making the bucket: %d\n%s", code, body)
	}
	code, body = post("/admin/keys", url.Values{"owner": {alice.Name}, "bucket": {webBucket}, "level": {"readwrite"}, "label": {"migration"}})
	if code != 200 || !strings.Contains(body, "This is <strong>"+alice.Name+"</strong>'s key, issued by you") || !strings.Contains(body, "/admin?section=keys") {
		t.Fatalf("the key made: %d\n%s", code, body)
	}
	ac, abase, _ := login(alice)
	resp, err := ac.Get(abase + "/keys")
	ok(t, "alice's keys", err)
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), "migration") || !strings.Contains(string(page), admin.Name+", an admin") {
		t.Fatalf("alice's keys page doesn't show the admin's key:\n%s", page)
	}
}

// firstErr2 is the error of a call returning two values and an error.
func firstErr2[A, B any](_ A, _ B, err error) error { return err }
