package main

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Runs against a scratch versitygw started with --iam-cache-disable, e.g.
//
//	versitygw --port :7070 --admin-port :7071 --iam-dir /iam --iam-cache-disable posix --chuid --chgid /data
//
// VGW_TEST_S3, VGW_TEST_ADMIN, VGW_TEST_ACCESS and VGW_TEST_SECRET point at it.
func testGateway(t *testing.T) *VGW {
	s3, admin := os.Getenv("VGW_TEST_S3"), os.Getenv("VGW_TEST_ADMIN")
	if s3 == "" || admin == "" {
		t.Skip("VGW_TEST_S3 and VGW_TEST_ADMIN not set")
	}
	return NewVGW(s3, admin, "us-east-1", os.Getenv("VGW_TEST_ACCESS"), os.Getenv("VGW_TEST_SECRET"))
}

func as(root *VGW, access, secret string) *VGW {
	return NewVGW(root.S3Endpoint, root.AdminEndpoint, root.Region, access, secret)
}

func putObject(ctx context.Context, v *VGW, bucket, key, body string) error {
	_, err := v.do(ctx, http.MethodPut, v.S3Endpoint, "/"+bucket+"/"+key, nil, []byte(body), nil)
	return err
}

func getObject(ctx context.Context, v *VGW, bucket, key string) (string, error) {
	b, err := v.do(ctx, http.MethodGet, v.S3Endpoint, "/"+bucket+"/"+key, nil, nil, nil)
	return string(b), err
}

func listObjects(ctx context.Context, v *VGW, bucket string) error {
	_, err := v.do(ctx, http.MethodGet, v.S3Endpoint, "/"+bucket, url.Values{"list-type": {"2"}}, nil, nil)
	return err
}

func deleteObject(ctx context.Context, v *VGW, bucket, key string) error {
	_, err := v.do(ctx, http.MethodDelete, v.S3Endpoint, "/"+bucket+"/"+key, nil, nil, nil)
	return err
}

func denied(t *testing.T, what string, err error) {
	t.Helper()
	if !IsCode(err, "AccessDenied") && !IsCode(err, "InvalidAccessKeyId") && !IsCode(err, "XAdminAccessDenied") {
		t.Errorf("%s: want access denied, got %v", what, err)
	}
}

func ok(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func userError(t *testing.T, what string, err error) {
	t.Helper()
	if _, isUser := err.(*UserError); !isUser {
		t.Errorf("%s: want a user error, got %v", what, err)
	}
}

func TestPortalAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	store, _ := OpenStore(statePath)
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))

	suffix := strings.ToLower(newAccessKey()[3:9])
	photos, docs, bobs := "photos-"+suffix, "docs-"+suffix, "bobs-"+suffix
	alice := User{Name: "alice" + suffix, UID: 1001, GID: 1001}
	bob := User{Name: "bob" + suffix, UID: 1002, GID: 1002}

	ok(t, "create photos", p.CreateBucket(ctx, alice, photos))
	ok(t, "create docs", p.CreateBucket(ctx, alice, docs))
	ok(t, "create bobs", p.CreateBucket(ctx, bob, bobs))
	userError(t, "duplicate bucket", p.CreateBucket(ctx, bob, photos))
	userError(t, "bad bucket name", p.CreateBucket(ctx, bob, "Bad_Name"))

	if got, _ := p.Buckets(ctx, alice); len(got) != 2 {
		t.Fatalf("alice's buckets: %v", got)
	}

	rwAccess, rwSecret, err := p.CreateKey(ctx, alice, "photos rw", map[string]Perm{photos: PermReadWrite})
	ok(t, "create rw key", err)
	rw := as(root, rwAccess, rwSecret)
	ok(t, "rw put", putObject(ctx, rw, photos, "dir/a.txt", "hello"))
	if body, err := getObject(ctx, rw, photos, "dir/a.txt"); err != nil || body != "hello" {
		t.Fatalf("rw get: %q %v", body, err)
	}
	ok(t, "rw list", listObjects(ctx, rw, photos))
	denied(t, "rw put in ungranted bucket", putObject(ctx, rw, docs, "x", "x"))
	denied(t, "rw list bob's bucket", listObjects(ctx, rw, bobs))
	denied(t, "rw replaces policy", rw.PutBucketPolicy(ctx, photos, []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:*"],"Resource":["arn:aws:s3:::`+photos+`/*"]}]}`)))
	denied(t, "rw deletes policy", rw.DeleteBucketPolicy(ctx, photos))
	denied(t, "rw deletes bucket", rw.DeleteBucket(ctx, photos))
	denied(t, "rw creates bucket", rw.CreateBucket(ctx, "sneaky-"+suffix, rwAccess))
	if _, err := rw.do(ctx, http.MethodPut, rw.S3Endpoint, "/sneaky-"+suffix, nil, nil, nil); err == nil {
		t.Error("rw key created a bucket over S3")
	}

	roAccess, roSecret, err := p.CreateKey(ctx, alice, "read all", map[string]Perm{photos: PermRead, docs: PermRead})
	ok(t, "create ro key", err)
	ro := as(root, roAccess, roSecret)
	if body, err := getObject(ctx, ro, photos, "dir/a.txt"); err != nil || body != "hello" {
		t.Fatalf("ro get: %q %v", body, err)
	}
	ok(t, "ro list docs", listObjects(ctx, ro, docs))
	denied(t, "ro put", putObject(ctx, ro, photos, "b.txt", "x"))
	denied(t, "ro delete", deleteObject(ctx, ro, photos, "dir/a.txt"))

	_, _, err = p.CreateKey(ctx, bob, "steal", map[string]Perm{photos: PermRead})
	userError(t, "bob grants alice's bucket", err)
	userError(t, "bob deletes alice's bucket", p.DeleteBucket(ctx, bob, photos))
	userError(t, "bob edits alice's key", p.UpdateKey(ctx, bob, roAccess, "x", nil))
	userError(t, "bob revokes alice's key", p.DeleteKey(ctx, bob, roAccess))
	_, _, err = p.CreateKey(ctx, alice, "", nil)
	userError(t, "empty label", err)

	ok(t, "update ro key", p.UpdateKey(ctx, alice, roAccess, "docs writer", map[string]Perm{docs: PermReadWrite}))
	denied(t, "updated key reads photos", listObjects(ctx, ro, photos))
	ok(t, "updated key writes docs", putObject(ctx, ro, docs, "d.txt", "doc"))

	ok(t, "revoke rw", p.DeleteKey(ctx, alice, rwAccess))
	denied(t, "revoked key", listObjects(ctx, rw, photos))

	userError(t, "delete non-empty bucket", p.DeleteBucket(ctx, alice, docs))
	ok(t, "empty docs", deleteObject(ctx, root, docs, "d.txt"))
	ok(t, "delete docs", p.DeleteBucket(ctx, alice, docs))
	if k, _ := p.Key(alice, roAccess); len(k.Buckets) != 0 {
		t.Errorf("deleted bucket still granted: %v", k.Buckets)
	}

	// A fresh portal over the same state reconciles cleanly, and drops keys
	// the gateway lost.
	ok(t, "remove key behind the portal's back", root.DeleteAccount(ctx, roAccess))
	store2, _ := OpenStore(statePath)
	p2 := NewPortal(root, store2)
	ok(t, "reconcile again", p2.Reconcile(ctx))
	if _, err := p2.Key(alice, roAccess); err == nil {
		t.Error("reconcile kept a key the gateway doesn't have")
	}

	ok(t, "clean photos", deleteObject(ctx, root, photos, "dir/a.txt"))
	ok(t, "delete photos", p2.DeleteBucket(ctx, alice, photos))
	ok(t, "delete bobs", p2.DeleteBucket(ctx, bob, bobs))
}
