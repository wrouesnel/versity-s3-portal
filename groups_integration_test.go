package main

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeDir is a directory the test edits.
type fakeDir struct {
	mu      sync.Mutex
	entries map[string]DirEntry
}

func (f *fakeDir) set(name string, d DirEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[name] = d
}

func (f *fakeDir) Check(name string) (DirEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.entries[name]
	if !ok {
		return DirEntry{Disabled: true, Reason: "not in the directory"}, nil
	}
	return d, nil
}

func (f *fakeDir) CheckAll() (map[string]DirEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]DirEntry{}
	for k, v := range f.entries {
		out[k] = v
	}
	return out, nil
}

func (f *fakeDir) Groups() ([]string, error) { return []string{"editors", "viewers"}, nil }

// Group grants at each level, keys limited by their owner's access, and
// the directory suspending and restoring people, against a real gateway.
func TestGroupsAndDirectoryAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	dir := &fakeDir{entries: map[string]DirEntry{}}
	p.dir = dir
	ok(t, "reconcile", p.Reconcile(ctx))

	sfx := strings.ToLower(newAccessKey()[3:9])
	bucket := "team-" + sfx
	person := func(name string, uid int, groups ...string) User {
		u := User{Name: name + sfx, UID: uid, GID: uid}
		dir.set(u.Name, DirEntry{UID: uid, GID: uid, Groups: groups})
		enroll(t, p, u, groups...)
		return u
	}
	alice := person("alice", 2001)
	bob := person("bob", 2002, "editors")
	carol := person("carol", 2003, "viewers")
	dave := person("dave", 2004, "drop")
	erin := person("erin", 2005, "archive")
	admin := User{Name: "admin" + sfx, UID: 2006, GID: 2006, Admin: true}
	dir.set(admin.Name, DirEntry{UID: 2006, GID: 2006, Admin: true})
	enroll(t, p, admin)

	ok(t, "create bucket", p.CreateBucket(ctx, alice, bucket))
	userError(t, "bob grants on alice's bucket", p.SetGroupGrant(ctx, bob, bucket, "editors", PermReadWrite))
	ok(t, "grant editors", p.SetGroupGrant(ctx, alice, bucket, "editors", PermReadWrite))
	ok(t, "grant viewers", p.SetGroupGrant(ctx, alice, bucket, "viewers", PermRead))
	ok(t, "admin grants drop", p.SetGroupGrant(ctx, admin, bucket, "drop", PermWriteOnly))
	ok(t, "grant archive", p.SetGroupGrant(ctx, alice, bucket, "archive", PermCreateOnly))

	// Everyone sees it at their level.
	for u, want := range map[User]string{bob: "read & write", carol: "read only", dave: "write only", erin: "add only"} {
		bs, err := p.Buckets(ctx, u)
		ok(t, "buckets for "+u.Name, err)
		if len(bs) != 1 || bs[0].Name != bucket || bs[0].Level() != want || bs[0].Manage {
			t.Errorf("%s sees %+v, want %s", u.Name, bs, want)
		}
	}

	// The file browser follows the levels.
	ok(t, "bob uploads", p.PutObject(ctx, bob, bucket, "a.txt", strings.NewReader("a"), 1, ""))
	_, err := p.ListObjects(ctx, carol, bucket, "", "")
	ok(t, "carol lists", err)
	userError(t, "carol uploads", p.PutObject(ctx, carol, bucket, "c.txt", strings.NewReader("c"), 1, ""))
	ok(t, "dave drops a file", p.PutObject(ctx, dave, bucket, "d.txt", strings.NewReader("d"), 1, ""))
	_, err = p.ListObjects(ctx, dave, bucket, "", "")
	userError(t, "dave lists", err)
	ok(t, "erin adds a file", p.PutObject(ctx, erin, bucket, "e.txt", strings.NewReader("e"), 1, ""))
	userError(t, "erin overwrites", p.PutObject(ctx, erin, bucket, "a.txt", strings.NewReader("x"), 1, ""))
	userError(t, "erin deletes", p.DeleteObject(ctx, erin, bucket, "a.txt"))

	// Keys can't be more than their owner has.
	_, _, err = p.CreateKey(ctx, carol, "too much", map[string]Perm{bucket: PermReadWrite})
	userError(t, "carol makes a read & write key", err)
	_, _, err = p.CreateKey(ctx, dave, "too much", map[string]Perm{bucket: PermCreateOnly})
	userError(t, "dave makes an add-only key", err)
	key := func(u User, perm Perm) *VGW {
		access, secret, err := p.CreateKey(ctx, u, u.Name+" key", map[string]Perm{bucket: perm})
		ok(t, "key for "+u.Name, err)
		return as(root, access, secret)
	}
	bobKey, carolKey, daveKey, erinKey := key(bob, PermReadWrite), key(carol, PermRead), key(dave, PermWriteOnly), key(erin, PermCreateOnly)
	ok(t, "bob's key writes", putObject(ctx, bobKey, bucket, "b.txt", "b"))
	ok(t, "carol's key reads", listObjects(ctx, carolKey, bucket))
	denied(t, "carol's key writes", putObject(ctx, carolKey, bucket, "c.txt", "c"))
	ok(t, "dave's key drops", putObject(ctx, daveKey, bucket, "d2.txt", "d"))
	denied(t, "dave's key lists", listObjects(ctx, daveKey, bucket))
	denied(t, "erin's key puts without If-None-Match", putObject(ctx, erinKey, bucket, "e2.txt", "e"))
	_, err = erinKey.do(ctx, http.MethodPut, erinKey.S3Endpoint, "/"+bucket+"/e2.txt", nil, []byte("e"), map[string]string{"If-None-Match": "*"})
	ok(t, "erin's key adds", err)
	_, err = erinKey.do(ctx, http.MethodPut, erinKey.S3Endpoint, "/"+bucket+"/a.txt", nil, []byte("x"), map[string]string{"If-None-Match": "*"})
	if !IsCode(err, "PreconditionFailed") {
		t.Errorf("erin's key overwrites: want PreconditionFailed, got %v", err)
	}
	denied(t, "erin's key deletes", deleteObject(ctx, erinKey, bucket, "a.txt"))

	// Disabling bob in the directory ends his sessions and suspends his key
	// and file access; re-enabling restores them.
	sessions := &Sessions{Key: []byte("0123456789abcdef0123456789abcdef"), TTL: 3600e9, Store: store}
	cookie := loginCookie(t, sessions, bob.Name)
	dir.set(bob.Name, DirEntry{Disabled: true, Reason: "account inactive"})
	st, err := p.CheckPerson(ctx, bob.Name)
	ok(t, "check bob", err)
	if !st.Disabled || !st.Changed || st.EndedSessions != 1 {
		t.Errorf("check bob: %+v", st)
	}
	denied(t, "disabled bob's key", listObjects(ctx, bobKey, bucket))
	req, _ := http.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	if _, err := sessions.Get(req); err == nil {
		t.Error("disabled bob's session still works")
	}
	if bs, _ := p.Buckets(ctx, bob); len(bs) != 0 {
		t.Errorf("disabled bob sees %v", bs)
	}
	dir.set(bob.Name, DirEntry{UID: 2002, GID: 2002, Groups: []string{"editors"}})
	report, err := p.SyncDirectory(ctx)
	ok(t, "sync", err)
	if report.Checked != 6 || len(report.Changed) != 1 || report.Changed[0].User != bob.Name {
		t.Errorf("sync report: %+v", report)
	}
	ok(t, "re-enabled bob's key", listObjects(ctx, bobKey, bucket))

	// Leaving a group takes the access away from keys too.
	dir.set(carol.Name, DirEntry{UID: 2003, GID: 2003})
	_, err = p.SyncDirectory(ctx)
	ok(t, "sync", err)
	denied(t, "carol's key after leaving viewers", listObjects(ctx, carolKey, bucket))
	if c := p.KeyAccess(ctx, &Key{Owner: carol.Name, Buckets: map[string]Perm{bucket: PermRead}}); c[bucket].Any() {
		t.Errorf("carol's key access: %+v", c)
	}

	// Taking a group's grant away.
	ok(t, "remove editors", p.SetGroupGrant(ctx, alice, bucket, "Editors", ""))
	denied(t, "bob's key after editors lose access", listObjects(ctx, bobKey, bucket))

	// A fresh portal over the same state writes the same policies.
	p2 := NewPortal(root, store)
	p2.dir = dir
	ok(t, "reconcile again", p2.Reconcile(ctx))
	ok(t, "dave's key after restart", putObject(ctx, daveKey, bucket, "d3.txt", "d"))

	// Clean up as the owner, with everything she can reach.
	for _, k := range []string{"a.txt", "b.txt", "d.txt", "d2.txt", "d3.txt", "e.txt", "e2.txt"} {
		ok(t, "clean "+k, deleteObject(ctx, root, bucket, k))
	}
	userError(t, "bob deletes alice's bucket", p.DeleteBucket(ctx, bob, bucket))
	ok(t, "delete bucket", p.DeleteBucket(ctx, alice, bucket))
}
