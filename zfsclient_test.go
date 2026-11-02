package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wrouesnel/versity-s3-portal/internal/zfshelper"
	"github.com/wrouesnel/versity-s3-portal/internal/zfshelper/zfstest"
)

// Drives the client against the real helper, over a unix socket, with a
// fake zfs command.
func TestZFSHelperClient(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	root := filepath.Join(dir, "buckets")
	fake, err := zfstest.New("storage/s3/buckets", root)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 11, 3, 7, 0, 0, 0, time.UTC)
	srv := zfshelper.New(zfshelper.Config{
		Parent: "storage/s3/buckets", Root: root, Run: fake.Run, Now: func() time.Time { return clock },
		Staging: filepath.Join(dir, "staging"), StateDir: filepath.Join(dir, "state"), SkipMountCheck: true,
		Trash: "storage/s3/trash", Mount: fake.Mounter("storage/s3/buckets", root, filepath.Join(dir, "staging")),
	})
	os.Mkdir(filepath.Join(dir, "staging"), 0o700)
	fake.AddUnmounted("storage/s3/trash")
	if err := srv.Check(ctx); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "h.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler()}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })

	z := NewZFSHelper(sock)
	if err := os.Mkdir(filepath.Join(root, "photos"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := z.Adopt(ctx, "photos"); err != nil {
		t.Fatal(err)
	}
	if err := z.Adopt(ctx, "photos"); err != nil {
		t.Fatal("adopt again:", err)
	}
	if err := z.Adopt(ctx, "missing"); !errors.Is(err, ErrZFSNotFound) {
		t.Fatalf("adopt missing: %v", err)
	}
	if _, err := z.Info(ctx, "other"); !errors.Is(err, ErrZFSNotDataset) {
		t.Fatalf("info on a non-dataset: %v", err)
	}
	if err := z.SetQuota(ctx, "photos", 1<<30); err != nil {
		t.Fatal(err)
	}
	if err := z.SetBackup(ctx, "photos", true); err != nil {
		t.Fatal(err)
	}
	info, err := z.Info(ctx, "photos")
	if err != nil || info.RefQuota != 1<<30 || !info.Backup {
		t.Fatalf("info %+v %v", info, err)
	}

	os.WriteFile(filepath.Join(root, "photos", "a.txt"), []byte("hello"), 0o640)
	snap, err := z.CreateSnapshot(ctx, "photos", "test")
	if err != nil || snap.Name != "s3portal-20261103T070000Z-test" {
		t.Fatalf("snapshot %+v %v", snap, err)
	}
	snaps, err := z.Snapshots(ctx, "photos")
	if err != nil || len(snaps) != 1 {
		t.Fatalf("snapshots %+v %v", snaps, err)
	}
	list, err := z.ListSnapshot(ctx, "photos", snap.Name, "", "/", "", 0)
	if err != nil || len(list.Objects) != 1 || list.Objects[0].Key != "a.txt" {
		t.Fatalf("list %+v %v", list, err)
	}
	resp, err := z.GetSnapshotObject(ctx, "photos", snap.Name, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello" || resp.ContentLength != 5 {
		t.Fatalf("object %q %d", body, resp.ContentLength)
	}
	if _, err := z.GetSnapshotObject(ctx, "photos", snap.Name, "nope"); !errors.Is(err, ErrZFSNotFound) {
		t.Fatalf("missing object: %v", err)
	}

	os.WriteFile(filepath.Join(root, "photos", "a.txt"), []byte("changed"), 0o640)
	if err := z.RestoreObject(ctx, "photos", snap.Name, "a.txt"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "photos", "a.txt")); string(b) != "hello" {
		t.Fatalf("restored %q", b)
	}
	if res, err := z.RestoreAll(ctx, "photos", snap.Name); err != nil || res.Objects != 1 || res.Skipped != 0 {
		t.Fatalf("restore all %+v %v", res, err)
	}
	if _, err := z.RestorePrefix(ctx, "photos", snap.Name, "nope/"); !errors.Is(err, ErrZFSNotFound) {
		t.Fatalf("restore missing prefix: %v", err)
	}

	if err := z.Destroy(ctx, "photos"); !errors.Is(err, ErrZFSNotEmpty) {
		t.Fatalf("destroy non-empty: %v", err)
	}
	fake.Snapshot("storage/s3/buckets/photos", "weekly_2026-11-01", clock)
	os.Remove(filepath.Join(root, "photos", "a.txt"))
	if err := z.Destroy(ctx, "photos"); err != nil {
		t.Fatal(err)
	}
	if fake.IsDataset("storage/s3/buckets/photos") {
		t.Fatal("still in the buckets")
	}
	trash, err := z.Trash(ctx)
	if err != nil || len(trash) != 1 || trash[0].Bucket != "photos" || trash[0].PortalSnapshots != 1 || trash[0].OtherSnapshots != 1 {
		t.Fatalf("trash %+v %v", trash, err)
	}
	if err := z.RestoreTrash(ctx, trash[0].Entry); err != nil {
		t.Fatal(err)
	}
	if _, err := z.Info(ctx, "photos"); err != nil {
		t.Fatal("restored bucket:", err)
	}
	clock = clock.Add(time.Minute)
	if err := z.Destroy(ctx, "photos"); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(root, "photos"), 0o750)
	z.Adopt(ctx, "photos")
	trash, _ = z.Trash(ctx)
	if err := z.RestoreTrash(ctx, trash[0].Entry); !errors.Is(err, ErrZFSExists) {
		t.Fatalf("restore over a bucket: %v", err)
	}
	if err := z.PurgeTrash(ctx, trash[0].Entry); err != nil {
		t.Fatal(err)
	}
	if trash, _ = z.Trash(ctx); len(trash) != 0 {
		t.Fatalf("trash after purge %+v", trash)
	}
	if err := z.PurgeTrash(ctx, "photos-20200101T000000Z"); !errors.Is(err, ErrZFSNotFound) {
		t.Fatalf("purge missing: %v", err)
	}
}
