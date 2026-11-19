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

// Buckets managed by groups, and transferred, on the scratch gateway: a group which
// manages alice's bucket lets bob change its access, see its keys and delete it, but not
// give a key "manages"; an admin transfers it to carol, and alice keeps only what her
// groups give her, her key with it.
func TestBucketManagersAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	team, readers := "team"+suffix, "readers"+suffix
	admin := User{Name: "bmadmin" + suffix, UID: 1060, GID: 1060, Admin: true}
	alice := User{Name: "bmalice" + suffix, UID: 1061, GID: 1061}
	bob := User{Name: "bmbob" + suffix, UID: 1062, GID: 1062}
	carol := User{Name: "bmcarol" + suffix, UID: 1063, GID: 1063}
	dave := User{Name: "bmdave" + suffix, UID: 1064, GID: 1064}
	enroll(t, p, admin)
	enroll(t, p, alice)
	enroll(t, p, bob, team)
	enroll(t, p, carol)
	enroll(t, p, dave)
	bucket, spare := "bm-"+suffix, "bm2-"+suffix
	ok(t, "bucket", p.CreateBucket(ctx, alice, bucket))
	ok(t, "spare bucket", p.CreateBucket(ctx, alice, spare))

	userError(t, "dave gives access to alice's bucket", p.SetGroupGrant(ctx, dave, bucket, readers, PermRead))
	ok(t, "alice gives the team manages", p.SetGroupGrant(ctx, alice, bucket, team, PermManage))
	ok(t, "alice gives the team manages on the spare", p.SetGroupGrant(ctx, alice, spare, team, PermManage))
	v, err := p.Bucket(ctx, bob, bucket, true)
	ok(t, "bob's view", err)
	if !v.Manage || !v.Manager || v.Level() != "manages" || !v.Caps.Covers(PermReadWrite.Caps()) || len(v.ManagedBy) != 1 {
		t.Fatalf("bob's view of a bucket his team manages: %+v", v)
	}
	if v, _ := p.Bucket(ctx, alice, bucket, true); v.Manager || !v.Manage || v.Level() != "read & write" {
		t.Errorf("alice's view of her own bucket: %+v (%s)", v, v.Level())
	}

	// Bob manages: access, and keys reaching it.
	ok(t, "bob gives readers read", p.SetGroupGrant(ctx, bob, bucket, readers, PermRead))
	userError(t, "a key which manages", firstErr2(p.CreateKey(ctx, bob, "manage", map[string]Perm{bucket: PermManage})))
	bobKey, bobSecret, err := p.CreateKey(ctx, bob, "bob rw", map[string]Perm{bucket: PermReadWrite})
	ok(t, "bob's read & write key", err)
	ok(t, "bob writes", putObject(ctx, as(root, bobKey, bobSecret), bucket, "bob.txt", "x"))
	aliceKey, aliceSecret, err := p.CreateKey(ctx, alice, "alice rw", map[string]Perm{bucket: PermReadWrite})
	ok(t, "alice's key", err)
	if keys, err := p.BucketKeys(ctx, bob, bucket); err != nil || len(keys) != 2 {
		t.Errorf("bob sees the bucket's keys: %d %v", len(keys), err)
	}
	ok(t, "bob deletes the empty spare", p.DeleteBucket(ctx, bob, spare))

	// Transfers: admins only, to someone enabled, not to its owner.
	userError(t, "a transfer, not as an admin", p.TransferBucket(ctx, bob, bucket, carol.Name))
	userError(t, "a transfer to nobody", p.TransferBucket(ctx, admin, bucket, "nobody"+suffix))
	userError(t, "a transfer to its owner", p.TransferBucket(ctx, admin, bucket, alice.Name))
	f, err := p.TransferForm(ctx, admin, bucket)
	if err != nil || f.Owner != alice.Name || f.OldOwnerVia != "" || f.OldOwnerKeys != 1 || len(f.ManagedBy) != 1 {
		t.Fatalf("the transfer form: %+v %v", f, err)
	}
	ok(t, "transfer to carol", p.TransferBucket(ctx, admin, bucket, carol.Name))
	if v, _ := p.Bucket(ctx, carol, bucket, true); v.Owner != carol.Name || !v.Manage || v.Manager {
		t.Fatalf("carol's view after: %+v", v)
	}
	// Alice is in no group with access: her key stops reaching it; bob's team still manages.
	denied(t, "alice's key after the transfer", putObject(ctx, as(root, aliceKey, aliceSecret), bucket, "a.txt", "x"))
	if _, err := p.Bucket(ctx, alice, bucket, true); err == nil {
		t.Error("alice still sees the bucket")
	}
	ok(t, "bob still writes", putObject(ctx, as(root, bobKey, bobSecret), bucket, "bob2.txt", "x"))
	if got, err := getObject(ctx, as(root, bobKey, bobSecret), bucket, "bob.txt"); err != nil || got != "x" {
		t.Errorf("a file from before the transfer: %q %v", got, err)
	}

	// The admin page and the API.
	sessions := &Sessions{Key: []byte("0123456789abcdef0123456789abcdef"), TTL: 3600e9, Store: store}
	srv := NewServer(p, stubAuth{user: admin}, nil, sessions, "t", root.S3Endpoint, "us-east-1")
	srv.APIToken = "0123456789abcdef0123456789abcdef-token"
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.PostForm(hs.URL+"/login", url.Values{"username": {admin.Name}, "password": {"pw"}})
	ok(t, "login", err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	resp, _ = c.Get(hs.URL + "/admin/buckets/transfer?bucket=" + bucket)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	page := string(b)
	if !strings.Contains(page, "Transfer "+bucket) || !strings.Contains(page, "managed by "+team) {
		t.Fatalf("the transfer page:\n%s", page)
	}
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page)[1]
	resp, _ = c.PostForm(hs.URL+"/admin/buckets/transfer", url.Values{"csrf": {csrf}, "bucket": {bucket}, "owner": {dave.Name}})
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), bucket+" is "+dave.Name+"&#39;s now") {
		t.Fatalf("after transferring on the page:\n%s", b)
	}
	req, _ := http.NewRequest("POST", hs.URL+"/api/buckets/"+bucket+"/owner", strings.NewReader(`{"owner":"`+alice.Name+`"}`))
	req.Header.Set("Authorization", "Bearer "+srv.APIToken)
	resp, err = http.DefaultClient.Do(req)
	ok(t, "transfer by the API", err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transfer by the API: %d", resp.StatusCode)
	}
	if v, _ := p.Bucket(ctx, alice, bucket, true); v.Owner != alice.Name {
		t.Errorf("after the API's transfer: %+v", v)
	}
	ok(t, "alice's key works again, as the owner", putObject(ctx, as(root, aliceKey, aliceSecret), bucket, "back.txt", "x"))
}
