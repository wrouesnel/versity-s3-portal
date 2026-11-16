package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAdminMigrateSetup makes, as an admin, a bucket for alice and two keys
// of hers on it (read & write, and write only), on the scratch gateway, and
// writes them to MIGRATE_OUT as shell variables: for standard S3 tools to
// load data in with, as a migration would. Skipped without MIGRATE_OUT.
func TestAdminMigrateSetup(t *testing.T) {
	out := os.Getenv("MIGRATE_OUT")
	if out == "" {
		t.Skip("MIGRATE_OUT not set")
	}
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	admin := User{Name: "admin" + suffix, UID: 1000, GID: 1000, Admin: true}
	alice := User{Name: "alice" + suffix, UID: 1001, GID: 1001}
	enroll(t, p, admin)
	enroll(t, p, alice)
	bucket := "app-data-" + suffix
	userError(t, "alice makes a bucket for the admin", p.CreateBucketFor(ctx, alice, admin.Name, bucket))
	userError(t, "a bucket for nobody", p.CreateBucketFor(ctx, admin, "nobody", bucket))
	ok(t, "bucket for alice", p.CreateBucketFor(ctx, admin, alice.Name, bucket))
	rw, rwSecret, err := p.CreateKeyFor(ctx, admin, alice.Name, "Loading data into "+bucket, map[string]Perm{bucket: PermReadWrite})
	ok(t, "read & write key", err)
	wo, woSecret, err := p.CreateKeyFor(ctx, admin, alice.Name, "Write-only loader", map[string]Perm{bucket: PermWriteOnly})
	ok(t, "write-only key", err)
	if k, _ := store.Get(rw); k.Owner != alice.Name || k.IssuedBy != admin.Name {
		t.Fatalf("the key: %+v", k)
	}
	if keys := p.Keys(alice); len(keys) != 2 {
		t.Fatalf("alice's keys page has %d keys", len(keys))
	}
	data := fmt.Sprintf("BUCKET=%s\nRW_ACCESS=%s\nRW_SECRET=%s\nWO_ACCESS=%s\nWO_SECRET=%s\nOWNER_UID=%d\n",
		bucket, rw, rwSecret, wo, woSecret, alice.UID)
	if err := os.WriteFile(out, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
