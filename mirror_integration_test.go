package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Mirroring a bucket from another bucket on the scratch gateway, through
// every step, with the part size made small so multipart copies happen.
func TestMirrorAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	defer func(th, ps int64) { mirrorPartThreshold, mirrorPartSize = th, ps }(mirrorPartThreshold, mirrorPartSize)
	mirrorPartThreshold, mirrorPartSize = 6<<20, 5<<20

	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	admin := User{Name: "admin" + suffix, UID: 1000, GID: 1000, Admin: true}
	alice := User{Name: "alice" + suffix, UID: 1001, GID: 1001}
	enroll(t, p, admin)
	enroll(t, p, alice)

	// The source: a bucket on the same gateway, read with root's key.
	srcBucket := "src-" + suffix
	ok(t, "source bucket", root.CreateBucket(ctx, srcBucket, root.Creds.AccessKeyID))
	big := make([]byte, 12<<20)
	rand.Read(big)
	put := func(key, body string, headers map[string]string) {
		t.Helper()
		_, err := root.Put(ctx, srcBucket, key, strings.NewReader(body), int64(len(body)), headers)
		ok(t, "source put "+key, err)
	}
	put("top.txt", "top", map[string]string{"Content-Type": "text/plain", "X-Amz-Meta-Colour": "blue"})
	put("dir/a.txt", "a", nil)
	put("dir/b.txt", "bb", nil)
	put("gone.txt", "soon gone", nil)
	put("é (1).txt", "accent", nil)
	_, err := root.Put(ctx, srcBucket, "big.bin", bytes.NewReader(big), int64(len(big)), nil)
	ok(t, "source big", err)

	bucket := "mir-" + suffix
	src := MirrorSource{Endpoint: root.S3Endpoint, Region: "us-east-1", Bucket: srcBucket, Access: root.Creds.AccessKeyID, Secret: root.Creds.SecretAccessKey}
	userError(t, "register as non-admin", p.RegisterMirror(ctx, alice, MirrorRequest{Bucket: bucket, NewOwner: alice.Name, Source: src}))
	bad := src
	bad.Secret = "wrong"
	userError(t, "register with a bad key", p.RegisterMirror(ctx, admin, MirrorRequest{Bucket: bucket, NewOwner: alice.Name, Source: bad}))
	ok(t, "register", p.RegisterMirror(ctx, admin, MirrorRequest{Bucket: bucket, NewOwner: alice.Name, Source: src}))

	// While it mirrors, the owner can read but not write.
	v, err := p.Bucket(ctx, alice, bucket, true)
	ok(t, "bucket view", err)
	if v.Caps != PermRead.Caps() {
		t.Fatalf("owner has %+v while mirroring, want read only", v.Caps)
	}
	userError(t, "owner upload while mirroring", p.PutObject(ctx, alice, bucket, "mine.txt", strings.NewReader("x"), 1, ""))
	userError(t, "delete bucket while mirroring", p.DeleteBucket(ctx, alice, bucket))

	pass := func(want MirrorState) PassSummary {
		t.Helper()
		ok(t, "run pass", p.RunMirrorPass(admin, bucket))
		p.WaitMirror(bucket)
		m, _ := p.store.Mirror(bucket)
		last := *m.LastPass()
		if last.Error != "" {
			t.Fatalf("pass %d: %s", last.N, last.Error)
		}
		if m.State != want {
			t.Fatalf("after pass %d the state is %s, want %s", last.N, m.State, want)
		}
		return last
	}
	s := pass(MirrorSynced)
	if s.Copied != 6 || s.SourceObjects != 6 || s.MirroredObjects != 6 || s.Failed != 0 {
		t.Fatalf("first pass: %+v", s)
	}
	got, err := getObject(ctx, p.vgw.As(webAccount(t, p, alice)), bucket, "é (1).txt")
	ok(t, "read copy", err)
	if got != "accent" {
		t.Fatalf("copy holds %q", got)
	}
	h, err := root.Head(ctx, bucket, "top.txt")
	ok(t, "head copy", err)
	if h.Get("Content-Type") != "text/plain" || h.Get("X-Amz-Meta-Colour") != "blue" || h.Get("X-Amz-Meta-Mirror-Mtime") == "" {
		t.Fatalf("copy lost its headers: %v", h)
	}

	// Nothing changed: nothing to do.
	if s := pass(MirrorSynced); s.Changes() != 0 {
		t.Fatalf("idle pass changed things: %+v", s)
	}

	// Changes at the source come over; a deletion is deleted here.
	put("top.txt", "top, rewritten", nil)
	put("new.txt", "new", nil)
	ok(t, "source delete", root.Delete(ctx, srcBucket, "gone.txt"))
	s = pass(MirrorSynced)
	if s.Copied != 2 || s.Deleted != 1 || s.MirroredObjects != 6 {
		t.Fatalf("pass after changes: %+v", s)
	}

	// Something written here behind the mirror's back is reported, and
	// keeps it from counting as synced.
	_, err = root.Put(ctx, bucket, "sneaky.txt", strings.NewReader("x"), 1, nil)
	ok(t, "sneak", err)
	if s := pass(MirrorSyncing); s.Unexpected != 1 {
		t.Fatalf("unexpected object not reported: %+v", s)
	}
	ok(t, "unsneak", root.Delete(ctx, bucket, "sneaky.txt"))
	// A copy removed here is put back.
	ok(t, "remove a copy", root.Delete(ctx, bucket, "dir/a.txt"))
	if s := pass(MirrorSynced); s.Repaired != 1 {
		t.Fatalf("missing copy not repaired: %+v", s)
	}

	// The final pass copies the last change and verifies.
	put("late.txt", "late", nil)
	ok(t, "freeze", p.FreezeMirror(admin, bucket, true))
	p.WaitMirror(bucket)
	m, _ := p.store.Mirror(bucket)
	if m.State != MirrorVerified || m.Verification == nil || !m.Verification.Passed {
		t.Fatalf("final pass didn't verify: state %s, %+v", m.State, m.Verification)
	}
	ver := m.Verification
	if ver.Checked != 7 || ver.EndToEnd != 6 || ver.SizeOnly != 1 || ver.DeepChecked != 1 {
		t.Fatalf("verification: %+v", ver)
	}
	if last := m.LastPass(); last.Copied != 1 || last.Kind != "final-deep" {
		t.Fatalf("final pass: %+v", last)
	}

	// The quiet check catches a write after the final pass.
	put("later.txt", "too late", nil)
	again := p.verifyMirror(ctx, m, *m.LastPass(), false, newProgress("test"))
	if again.Passed || again.QuietChanges != 1 {
		t.Fatalf("quiet check missed a change: %+v", again)
	}
	ok(t, "source delete", root.Delete(ctx, srcBucket, "later.txt"))

	userError(t, "pass after freezing", p.RunMirrorPass(admin, bucket))
	ok(t, "complete", p.CompleteMirror(ctx, admin, bucket))
	m, _ = p.store.Mirror(bucket)
	if m.State != MirrorComplete || m.Source.Secret != "" || m.Account.Access != "" {
		t.Fatalf("after complete: %+v", m)
	}
	ok(t, "owner upload after complete", p.PutObject(ctx, alice, bucket, "mine.txt", strings.NewReader("x"), 1, ""))
	accounts, _ := root.ListAccounts(ctx)
	for _, a := range accounts {
		if a.Access == mirrorAccess(bucket) {
			t.Fatal("mirror account left behind")
		}
	}
	ok(t, "source removed", p.MarkSourceRemoved(admin, bucket))
	view, err := p.MirrorDetail(admin, bucket)
	ok(t, "detail", err)
	for _, st := range view.Steps {
		if !st.Done || st.Event == nil {
			t.Fatalf("step %s not done in the checklist: %+v", st.State, st)
		}
	}
}

// A mirror into an existing bucket, abandoned part way.
func TestMirrorAbandonAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	admin := User{Name: "admin" + suffix, UID: 1000, GID: 1000, Admin: true}
	bob := User{Name: "bob" + suffix, UID: 1002, GID: 1002}
	enroll(t, p, admin)
	enroll(t, p, bob)
	srcBucket := "src-" + suffix
	ok(t, "source bucket", root.CreateBucket(ctx, srcBucket, root.Creds.AccessKeyID))
	_, err := root.Put(ctx, srcBucket, "x.txt", strings.NewReader("x"), 1, nil)
	ok(t, "source put", err)
	src := MirrorSource{Endpoint: root.S3Endpoint, Bucket: srcBucket, Access: root.Creds.AccessKeyID, Secret: root.Creds.SecretAccessKey}

	bucket := "full-" + suffix
	ok(t, "create", p.CreateBucket(ctx, bob, bucket))
	ok(t, "fill", p.PutObject(ctx, bob, bucket, "already.txt", strings.NewReader("x"), 1, ""))
	userError(t, "mirror into a full bucket", p.RegisterMirror(ctx, admin, MirrorRequest{Bucket: bucket, Source: src}))
	ok(t, "empty", p.DeleteObject(ctx, bob, bucket, "already.txt"))
	ok(t, "register", p.RegisterMirror(ctx, admin, MirrorRequest{Bucket: bucket, Source: src}))
	p.WaitMirror(bucket)
	ok(t, "abandon", p.AbandonMirror(ctx, admin, bucket))
	m, _ := p.store.Mirror(bucket)
	if m.State != MirrorAbandoned || m.Source.Secret != "" {
		t.Fatalf("after abandon: %+v", m)
	}
	ok(t, "write after abandon", p.PutObject(ctx, bob, bucket, "mine.txt", strings.NewReader("x"), 1, ""))
	ok(t, "forget", p.ForgetMirror(admin, bucket))
	if _, ok := p.store.Mirror(bucket); ok {
		t.Fatal("mirror record left behind")
	}
}

func webAccount(t *testing.T, p *Portal, u User) (string, string) {
	t.Helper()
	w, found := p.store.Web(u.Name)
	if !found {
		t.Fatalf("%s has no web account", u.Name)
	}
	return w.Access, w.Secret
}

// The gateway's answers when a key would make a file where a folder is,
// or a folder where a file is, are what isPathConflict expects.
func TestPathConflictAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	b := "clash-" + strings.ToLower(newAccessKey()[3:9])
	ok(t, "bucket", root.CreateBucket(ctx, b, root.Creds.AccessKeyID))
	_, err := root.Put(ctx, b, "a", strings.NewReader("x"), 1, nil)
	ok(t, "put a", err)
	_, err = root.Put(ctx, b, "a/b", strings.NewReader("x"), 1, nil)
	if !isPathConflict(err) {
		t.Fatalf("a/b under file a: %v", err)
	}
	_, err = root.Put(ctx, b, "c/d", strings.NewReader("x"), 1, nil)
	ok(t, "put c/d", err)
	_, err = root.Put(ctx, b, "c", strings.NewReader("x"), 1, nil)
	if !isPathConflict(err) {
		t.Fatalf("file c over folder c/: %v", err)
	}
}

// A pass stopped part way leaves the last manifest, and the next pass
// finishes the job.
func TestMirrorStoppedPassAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	admin := User{Name: "admin" + suffix, UID: 1000, GID: 1000, Admin: true}
	enroll(t, p, admin)
	srcBucket := "src-" + suffix
	ok(t, "source bucket", root.CreateBucket(ctx, srcBucket, root.Creds.AccessKeyID))
	for i := range 30 {
		_, err := root.Put(ctx, srcBucket, "f"+strings.Repeat("x", i), strings.NewReader("x"), 1, nil)
		ok(t, "source put", err)
	}
	src := MirrorSource{Endpoint: root.S3Endpoint, Bucket: srcBucket, Access: root.Creds.AccessKeyID, Secret: root.Creds.SecretAccessKey}
	bucket := "stop-" + suffix
	ok(t, "register", p.RegisterMirror(ctx, admin, MirrorRequest{Bucket: bucket, NewOwner: admin.Name, Source: src}))
	m, _ := p.store.Mirror(bucket)

	stopped, cancel := context.WithCancel(ctx)
	prog := newProgress("test")
	go func() {
		for prog.copied.Load() < 5 {
		}
		cancel()
	}()
	s := p.runPass(stopped, m, "test", "test", prog)
	if s.Error == "" {
		t.Fatalf("stopped pass reported no error: %+v", s)
	}
	m.Passes = append(m.Passes, s)
	ok(t, "record", p.store.PutMirror(bucket, m))
	s = p.runPass(ctx, m, "test", "test", newProgress("test"))
	if s.Error != "" || s.MirroredObjects != 30 || s.Copied+s.Repaired != 30 {
		t.Fatalf("pass after a stopped one: %+v", s)
	}
	if s = p.runPass(ctx, m, "test", "test", newProgress("test")); s.Changes() != 0 {
		t.Fatalf("third pass: %+v", s)
	}
}

// Mirroring from another S3 service, such as MinIO, named by
// MIRROR_TEST_S3, MIRROR_TEST_ACCESS and MIRROR_TEST_SECRET: its ETags,
// multipart ETags, metadata and listing order.
func TestMirrorFromOtherServiceAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	endpoint := os.Getenv("MIRROR_TEST_S3")
	if endpoint == "" {
		t.Skip("MIRROR_TEST_S3 not set")
	}
	other := NewVGW(endpoint, "", "us-east-1", os.Getenv("MIRROR_TEST_ACCESS"), os.Getenv("MIRROR_TEST_SECRET"))
	suffix := strings.ToLower(newAccessKey()[3:9])
	srcBucket := "src-" + suffix
	endpointOf, path := other.loc(srcBucket, "")
	_, err := other.do(ctx, http.MethodPut, endpointOf, path, nil, nil, nil)
	ok(t, "source bucket", err)

	files := map[string]string{"top.txt": "top", "dir/a.txt": "a", "dir/": "", "z y/é+.txt": "accent", "a-b": "sort", "a/b": "sort"}
	for k, v := range files {
		_, err := other.Put(ctx, srcBucket, k, strings.NewReader(v), int64(len(v)), map[string]string{"X-Amz-Meta-Colour": "blue"})
		ok(t, "source put "+k, err)
	}
	// A multipart upload at the source has an ETag that isn't an MD5.
	part := make([]byte, 5<<20)
	rand.Read(part)
	up, err := other.CreateMultipart(ctx, srcBucket, "multi.bin", nil)
	ok(t, "source multipart", err)
	var parts []completedPart
	for n := 1; n <= 2; n++ {
		e, err := other.UploadPart(ctx, srcBucket, "multi.bin", up, n, bytes.NewReader(part), int64(len(part)))
		ok(t, "source part", err)
		parts = append(parts, completedPart{n, e})
	}
	_, err = other.CompleteMultipart(ctx, srcBucket, "multi.bin", up, parts)
	ok(t, "source complete", err)

	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	admin := User{Name: "admin" + suffix, UID: 1000, GID: 1000, Admin: true}
	enroll(t, p, admin)
	bucket := "from-" + suffix
	src := MirrorSource{Endpoint: endpoint, Bucket: srcBucket, Access: other.Creds.AccessKeyID, Secret: other.Creds.SecretAccessKey}
	ok(t, "register", p.RegisterMirror(ctx, admin, MirrorRequest{Bucket: bucket, NewOwner: admin.Name, Source: src}))
	m, _ := p.store.Mirror(bucket)
	t.Logf("found: %s", m.Found)
	ok(t, "pass", p.RunMirrorPass(admin, bucket))
	p.WaitMirror(bucket)
	m, _ = p.store.Mirror(bucket)
	s := m.LastPass()
	if s.Error != "" || s.Failed != 0 || s.SourceObjects != int64(len(files)+1) {
		r, _ := p.readReport(bucket, s.N)
		t.Fatalf("pass: %+v\n%+v", s, r)
	}
	h, err := root.Head(ctx, bucket, "z y/é+.txt")
	ok(t, "head copy", err)
	if h.Get("X-Amz-Meta-Colour") != "blue" {
		t.Fatalf("metadata lost: %v", h)
	}
	ok(t, "freeze", p.FreezeMirror(admin, bucket, false))
	p.WaitMirror(bucket)
	m, _ = p.store.Mirror(bucket)
	if m.State != MirrorVerified {
		t.Fatalf("not verified: %+v", m.Verification)
	}
	if v := m.Verification; v.SizeOnly != 1 || v.EndToEnd != int64(len(files)) {
		t.Fatalf("verification: %+v", v)
	}
	t.Logf("verification: %+v", m.Verification)
}
