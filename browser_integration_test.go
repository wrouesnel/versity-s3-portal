package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Runs against the same scratch gateway as TestPortalAgainstGateway. With
// VGW_TEST_DATA naming the gateway's posix root as this test sees it, it
// also checks who owns uploaded files.
func TestBrowserAndAdminAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))

	suffix := strings.ToLower(newAccessKey()[3:9])
	files, bobs := "files-"+suffix, "bobs-"+suffix
	alice := User{Name: "alice" + suffix, UID: 1001, GID: 1001}
	bob := User{Name: "bob" + suffix, UID: 1002, GID: 1002}
	admin := User{Name: "admin" + suffix, UID: 1003, GID: 1003, Admin: true}
	enroll(t, p, alice)
	enroll(t, p, bob)
	enroll(t, p, admin)
	ok(t, "create files", p.CreateBucket(ctx, alice, files))
	ok(t, "create bobs", p.CreateBucket(ctx, bob, bobs))

	list, err := p.ListObjects(ctx, alice, files, "", "")
	ok(t, "list empty bucket", err)
	if len(list.Objects)+len(list.Prefixes) != 0 {
		t.Fatalf("new bucket not empty: %+v", list)
	}

	odd := "dir/a b+c=d&é (1).txt"
	ok(t, "upload odd name", p.PutObject(ctx, alice, files, odd, strings.NewReader("odd"), 3, "text/plain"))
	ok(t, "upload top", p.PutObject(ctx, alice, files, "top.txt", strings.NewReader("top"), 3, ""))
	big := bytes.Repeat([]byte("0123456789abcdef"), 1<<20/16*8) // 8 MiB
	ok(t, "upload big", p.PutObject(ctx, alice, files, "dir/big.bin", bytes.NewReader(big), int64(len(big)), ""))
	ok(t, "create folder", p.CreateFolder(ctx, alice, files, "", "empty"))
	userError(t, "folder with slash", p.CreateFolder(ctx, alice, files, "", "a/b"))
	userError(t, "control character", p.PutObject(ctx, alice, files, "bad\nname", strings.NewReader(""), 0, ""))

	list, err = p.ListObjects(ctx, alice, files, "", "")
	ok(t, "list top", err)
	if strings.Join(list.Prefixes, ",") != "dir/,empty/" || len(list.Objects) != 1 || list.Objects[0].Key != "top.txt" {
		t.Fatalf("top listing: %+v", list)
	}
	list, err = p.ListObjects(ctx, alice, files, "dir/", "")
	ok(t, "list dir", err)
	if len(list.Objects) != 2 {
		t.Fatalf("dir listing: %+v", list)
	}
	list, err = p.ListObjects(ctx, alice, files, "empty/", "")
	ok(t, "list empty folder", err)
	if len(list.Objects)+len(list.Prefixes) != 0 {
		t.Fatalf("empty folder lists its own marker: %+v", list)
	}

	resp, err := p.GetObject(ctx, alice, files, odd)
	ok(t, "download odd name", err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "odd" {
		t.Fatalf("downloaded %q", body)
	}
	resp, err = p.GetObject(ctx, alice, files, "dir/big.bin")
	ok(t, "download big", err)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(body, big) {
		t.Fatalf("big download: %d bytes, want %d", len(body), len(big))
	}

	if dataDir := os.Getenv("VGW_TEST_DATA"); dataDir != "" {
		fi, err := os.Stat(filepath.Join(dataDir, files, "top.txt"))
		ok(t, "stat uploaded file", err)
		st := fi.Sys().(*syscall.Stat_t)
		if st.Uid != uint32(alice.UID) || st.Gid != uint32(alice.GID) {
			t.Errorf("uploaded file owned by %d:%d, want %d:%d", st.Uid, st.Gid, alice.UID, alice.GID)
		}
	}

	// Nobody browses anyone else's buckets, through the portal or as their
	// web account directly.
	_, err = p.ListObjects(ctx, bob, files, "", "")
	userError(t, "bob lists alice's bucket", err)
	userError(t, "bob uploads to alice's bucket", p.PutObject(ctx, bob, files, "x", strings.NewReader("x"), 1, ""))
	w, _ := store.Web(alice.Name)
	aliceWeb := as(root, w.Access, w.Secret)
	denied(t, "alice's web account lists bob's bucket", listObjects(ctx, aliceWeb, bobs))
	denied(t, "alice's web account replaces policy", aliceWeb.DeleteBucketPolicy(ctx, files))

	userError(t, "delete the bucket's top as a folder", func() error { _, err := p.DeleteFolder(ctx, alice, files, ""); return err }())
	n, err := p.DeleteFolder(ctx, alice, files, "dir/")
	ok(t, "delete folder", err)
	if n != 2 {
		t.Errorf("deleted %d objects under dir/, want 2", n)
	}
	ok(t, "delete top", p.DeleteObject(ctx, alice, files, "top.txt"))
	_, err = p.DeleteFolder(ctx, alice, files, "empty/")
	ok(t, "delete empty folder", err)

	// Admins revoke one person's keys, then everyone's; the browser keeps
	// working.
	aliceAccess, aliceSecret, err := p.CreateKey(ctx, alice, "a", map[string]Perm{files: PermReadWrite})
	ok(t, "alice's key", err)
	bobAccess, bobSecret, err := p.CreateKey(ctx, bob, "b", map[string]Perm{bobs: PermRead})
	ok(t, "bob's key", err)
	if len(p.AllKeys()) != 2 {
		t.Fatalf("all keys: %v", p.AllKeys())
	}
	userError(t, "revoke unknown key", p.RevokeKey(ctx, admin, "nope"))
	got, err := p.RevokeKeys(ctx, admin, alice.Name)
	ok(t, "revoke alice's keys", err)
	if got != 1 {
		t.Errorf("revoked %d of alice's keys, want 1", got)
	}
	denied(t, "alice's revoked key", listObjects(ctx, as(root, aliceAccess, aliceSecret), files))
	ok(t, "bob's key survives", listObjects(ctx, as(root, bobAccess, bobSecret), bobs))
	got, err = p.RevokeKeys(ctx, admin, "")
	ok(t, "revoke every key", err)
	if got != 1 || len(p.AllKeys()) != 0 {
		t.Errorf("revoke all: %d revoked, %d left", got, len(p.AllKeys()))
	}
	denied(t, "bob's revoked key", listObjects(ctx, as(root, bobAccess, bobSecret), bobs))
	ok(t, "browser after revoke all", p.PutObject(ctx, alice, files, "after.txt", strings.NewReader("x"), 1, ""))

	// A fresh portal keeps the web accounts and their access.
	store2, _ := OpenStore(store.path)
	p2 := NewPortal(root, store2)
	ok(t, "reconcile again", p2.Reconcile(ctx))
	_, err = p2.ListObjects(ctx, alice, files, "", "")
	ok(t, "browse after reconcile", err)

	ok(t, "clean files", p2.DeleteObject(ctx, alice, files, "after.txt"))
	ok(t, "delete files", p2.DeleteBucket(ctx, alice, files))
	ok(t, "delete bobs", p2.DeleteBucket(ctx, bob, bobs))
}
