package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wrouesnel/versity-s3-portal/internal/zfshelper"
	"github.com/wrouesnel/versity-s3-portal/internal/zfshelper/zfstest"
)

// Runs the portal with the real s3-zfs-helper, over its socket, against
// the scratch gateway. The helper drives a fake zfs, whose datasets are
// directories in the gateway's posix root, so this needs VGW_TEST_DATA:
// the gateway's root as this test sees it, writable by the test.
func TestZFSAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	data := os.Getenv("VGW_TEST_DATA")
	if data == "" {
		t.Skip("VGW_TEST_DATA not set")
	}
	os.MkdirAll(filepath.Join(filepath.Dir(data), ".s3-zfs-staging"), 0o700)
	fake, err := zfstest.New("storage/s3/buckets", data)
	ok(t, "fake zfs", err)
	fake.AddUnmounted("storage/s3/trash")
	clock := time.Now().UTC()
	fake.Now = func() time.Time { return clock }
	staging := filepath.Join(filepath.Dir(data), ".s3-zfs-staging")
	helper := zfshelper.New(zfshelper.Config{
		Parent: "storage/s3/buckets", Root: data, Run: fake.Run, Now: func() time.Time { return clock },
		Mount:   fake.Mounter("storage/s3/buckets", data, staging),
		Staging: staging, StateDir: t.TempDir(), Trash: "storage/s3/trash",
		// The fake's datasets are directories on the same filesystem.
		SkipMountCheck: true,
	})
	sock := filepath.Join(t.TempDir(), "helper.sock")
	l, err := net.Listen("unix", sock)
	ok(t, "listen", err)
	srv := &http.Server{Handler: helper.Handler()}
	go srv.Serve(l)
	defer srv.Close()

	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	p.zfs = NewZFSHelper(sock)
	p.zfsDefaults = ZFSDefaults{Quota: 10 << 30, Snapshots: SnapshotSchedule{Every: "daily", Keep: 2}}
	ok(t, "reconcile", p.Reconcile(ctx))

	sfx := strings.ToLower(newAccessKey()[3:9])
	bucket := "zfs-" + sfx
	alice := User{Name: "alice" + sfx, UID: 3001, GID: 3001}
	bob := User{Name: "bob" + sfx, UID: 3002, GID: 3002}
	admin := User{Name: "admin" + sfx, UID: 3003, GID: 3003, Admin: true}
	enroll(t, p, alice)
	enroll(t, p, bob, "readers")
	enroll(t, p, admin)

	// A new bucket becomes a dataset, with the defaults, and the gateway
	// still knows it: its owner and policy survived the move.
	ok(t, "create bucket", p.CreateBucket(ctx, alice, bucket))
	ds := "storage/s3/buckets/" + bucket
	if !fake.IsDataset(ds) || fake.Prop(ds, "refquota") != "10737418240" {
		t.Fatalf("bucket isn't a dataset with the default quota: %v %q", fake.IsDataset(ds), fake.Prop(ds, "refquota"))
	}
	if m := store.BucketMeta(bucket); m.Snapshots != (SnapshotSchedule{Every: "daily", Keep: 2}) {
		t.Errorf("default schedule: %+v", m.Snapshots)
	}
	access, secret, err := p.CreateKey(ctx, alice, "k", map[string]Perm{bucket: PermReadWrite})
	ok(t, "key", err)
	key := as(root, access, secret)
	ok(t, "key writes v1", putObject(ctx, key, bucket, "doc.txt", "version one"))
	ok(t, "grant readers", p.SetGroupGrant(ctx, alice, bucket, "readers", PermRead))

	// Snapshot, change, then read the old version and restore it.
	snap, err := p.TakeSnapshot(ctx, alice, bucket)
	ok(t, "snapshot", err)
	if snapshotKind(snap.Name) != manualLabel {
		t.Errorf("manual snapshot name %s", snap.Name)
	}
	_, err = p.TakeSnapshot(ctx, bob, bucket)
	userError(t, "bob snapshots alice's bucket", err)
	ok(t, "key writes v2", putObject(ctx, key, bucket, "doc.txt", "version two"))

	list, err := p.ListSnapshot(ctx, bob, bucket, snap.Name, "", "")
	ok(t, "bob lists the snapshot", err)
	if len(list.Objects) != 1 || list.Objects[0].Key != "doc.txt" {
		t.Fatalf("snapshot listing: %+v", list)
	}
	resp, err := p.GetSnapshotObject(ctx, bob, bucket, snap.Name, "doc.txt")
	ok(t, "bob reads the old version", err)
	old, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(old) != "version one" {
		t.Fatalf("old version: %q", old)
	}
	_, err = p.Restore(ctx, bob, bucket, snap.Name, "doc.txt", "")
	userError(t, "read-only bob restores", err)
	res, err := p.Restore(ctx, alice, bucket, snap.Name, "doc.txt", "")
	ok(t, "alice restores", err)
	if body, err := getObject(ctx, key, bucket, "doc.txt"); err != nil || body != "version one" || res.Objects != 1 {
		t.Fatalf("after restore: %q %v (%+v)", body, err, res)
	}

	// Quotas and backups are for admins.
	userError(t, "owner sets quota", p.SetQuota(ctx, alice, bucket, 1<<30))
	ok(t, "admin sets quota", p.SetQuota(ctx, admin, bucket, 1<<30))
	ok(t, "admin marks for backup", p.SetBackup(ctx, admin, bucket, true))
	st, err := p.Storage(ctx, alice, bucket)
	ok(t, "storage", err)
	if st.Info.RefQuota != 1<<30 || !st.Info.Backup || len(st.Snapshots) != 1 {
		t.Errorf("storage: %+v %+v", st.Info, st.Snapshots)
	}

	// Scheduled snapshots: one when due, none when not, and only the
	// newest Keep scheduled ones survive. Manual ones are left alone.
	countAuto := func() int {
		snaps, err := p.zfs.Snapshots(ctx, bucket)
		ok(t, "snapshots", err)
		n := 0
		for _, s := range snaps {
			if snapshotKind(s.Name) == autoLabel {
				n++
			}
		}
		return n
	}
	for i, want := range []int{1, 1, 2, 2, 2} {
		p.snapshotRound(ctx, clock)
		if got := countAuto(); got != want {
			t.Fatalf("round %d: %d scheduled snapshots, want %d", i, got, want)
		}
		if i%2 == 0 {
			clock = clock.Add(12 * time.Hour)
		} else {
			clock = clock.Add(13 * time.Hour)
		}
	}
	if st, _ := p.Storage(ctx, alice, bucket); len(st.Snapshots) != 3 {
		t.Errorf("want 2 scheduled + 1 manual snapshot, got %+v", st.Snapshots)
	}

	// Deleting: refused while it has files, then the dataset goes.
	userError(t, "delete non-empty bucket", p.DeleteBucket(ctx, alice, bucket))
	ok(t, "empty it", deleteObject(ctx, key, bucket, "doc.txt"))
	ok(t, "delete bucket", p.DeleteBucket(ctx, alice, bucket))
	if fake.IsDataset(ds) {
		t.Error("dataset survived the bucket")
	}
	if bs, _ := p.Buckets(ctx, alice); len(bs) != 0 {
		t.Errorf("gateway still has %v", bs)
	}

	// It's in the trash, where only admins can see, restore or purge it.
	if tr, _ := p.Trash(ctx, alice); tr != nil {
		t.Error("non-admin sees the trash")
	}
	trash, err := p.Trash(ctx, admin)
	ok(t, "trash", err)
	var entry string
	for _, e := range trash {
		if e.Bucket == bucket {
			entry = e.Entry
		}
	}
	if entry == "" {
		t.Fatalf("deleted bucket isn't in the trash: %+v", trash)
	}
	userError(t, "owner restores", p.RestoreTrash(ctx, alice, entry))
	userError(t, "restore no entry", p.RestoreTrash(ctx, admin, ""))
	userError(t, "purge no entry", p.PurgeTrash(ctx, admin, ""))
	ok(t, "admin restores", p.RestoreTrash(ctx, admin, entry))
	bs, err := p.Buckets(ctx, alice)
	ok(t, "buckets after restore", err)
	if len(bs) != 1 || bs[0].Name != bucket || bs[0].Owner != alice.Name {
		t.Fatalf("after restore alice sees %+v", bs)
	}
	ok(t, "alice writes to the restored bucket", p.PutObject(ctx, alice, bucket, "back.txt", strings.NewReader("back"), 4, ""))
	if st, _ := p.Storage(ctx, alice, bucket); st == nil || len(st.Snapshots) != 3 {
		t.Errorf("snapshots after restore: %+v", st)
	}

	// Delete again, then purge.
	ok(t, "empty it", p.DeleteObject(ctx, alice, bucket, "back.txt"))
	ok(t, "delete again", p.DeleteBucket(ctx, alice, bucket))
	trash, _ = p.Trash(ctx, admin)
	for _, e := range trash {
		if e.Bucket == bucket {
			ok(t, "purge", p.PurgeTrash(ctx, admin, e.Entry))
		}
	}
	if trash, _ = p.Trash(ctx, admin); len(trash) != 0 {
		t.Errorf("trash after purge: %+v", trash)
	}
}
