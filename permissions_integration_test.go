package main

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Pins down what the keys, web accounts and anonymous callers the portal
// sets up can and can't do on versitygw (checked against v1.10.0 with
// --iam-cache-disable posix --chuid --chgid). Every expectation here is the
// gateway's behaviour as observed; a failure means the gateway or the
// portal's policies changed and the permissions model needs another look.
// Runs against the same scratch gateway as TestPortalAgainstGateway.
func TestPermissionsAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))

	// alice owns a1 (her rw key's), a2 (her ro key's) and a3 (no key);
	// bob owns b1.
	sfx := strings.ToLower(newAccessKey()[3:9])
	a1, a2, a3, b1 := "a1-"+sfx, "a2-"+sfx, "a3-"+sfx, "b1-"+sfx
	alice := User{Name: "alice" + sfx, UID: 1001, GID: 1001}
	bob := User{Name: "bob" + sfx, UID: 1002, GID: 1002}
	enroll(t, p, alice)
	enroll(t, p, bob)
	for _, b := range []string{a1, a2, a3} {
		ok(t, "create "+b, p.CreateBucket(ctx, alice, b))
	}
	ok(t, "create "+b1, p.CreateBucket(ctx, bob, b1))
	for _, b := range []string{a1, a2, a3, b1} {
		ok(t, "seed "+b, putObject(ctx, root, b, "secret.txt", "secret of "+b))
	}
	t.Cleanup(func() {
		for _, b := range []string{a1, a2, a3, b1} {
			emptyBucket(ctx, t, root, b)
			root.DeleteBucket(ctx, b)
		}
	})

	rwA, rwS, err := p.CreateKey(ctx, alice, "rw", map[string]Perm{a1: PermReadWrite})
	ok(t, "rw key", err)
	roA, roS, err := p.CreateKey(ctx, alice, "ro", map[string]Perm{a2: PermRead})
	ok(t, "ro key", err)
	bobA, bobS, err := p.CreateKey(ctx, bob, "bob", map[string]Perm{b1: PermReadWrite})
	ok(t, "bob key", err)
	rw, ro, bk := as(root, rwA, rwS), as(root, roA, roS), as(root, bobA, bobS)
	w, _ := store.Web(alice.Name)
	web := as(root, w.Access, w.Secret)

	allow := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: want allowed, got %v", what, err)
		}
	}
	deny := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: want refused, but it was allowed", what)
		}
	}
	exists := func(bucket, key string) bool {
		_, err := getObject(ctx, root, bucket, key)
		return err == nil
	}
	copyFrom := func(src string) map[string]string { return map[string]string{"x-amz-copy-source": src} }

	t.Run("ListBuckets shows keys nothing", func(t *testing.T) {
		for name, v := range map[string]*VGW{"rw key": rw, "web account": web} {
			body, err := rawBody(ctx, v, "GET", "/", nil, "", nil)
			allow(name+" ListBuckets", err)
			if names := xmlValues(body, "Name"); len(names) != 0 {
				t.Errorf("%s ListBuckets shows %v", name, names)
			}
		}
	})

	t.Run("copy needs read on the source and write on the target", func(t *testing.T) {
		denied(t, "rw copy from own ungranted bucket", raw(ctx, rw, "PUT", "/"+a1+"/c1", nil, "", copyFrom("/"+a3+"/secret.txt")))
		denied(t, "rw copy from bob's bucket", raw(ctx, rw, "PUT", "/"+a1+"/c2", nil, "", copyFrom("/"+b1+"/secret.txt")))
		denied(t, "web copy from bob's bucket", raw(ctx, web, "PUT", "/"+a1+"/c3", nil, "", copyFrom("/"+b1+"/secret.txt")))
		denied(t, "rw copy into ungranted bucket", raw(ctx, rw, "PUT", "/"+a3+"/c4", nil, "", copyFrom("/"+a1+"/secret.txt")))
		denied(t, "ro copy within its bucket", raw(ctx, ro, "PUT", "/"+a2+"/c5", nil, "", copyFrom("/"+a2+"/secret.txt")))
		body, err := rawBody(ctx, rw, "POST", "/"+a1+"/mpc", q("uploads", ""), "", nil)
		ok(t, "rw start upload", err)
		up := xmlValue(body, "UploadId")
		denied(t, "rw UploadPartCopy from bob's bucket", raw(ctx, rw, "PUT", "/"+a1+"/mpc", q("partNumber", "1", "uploadId", up), "", copyFrom("/"+b1+"/secret.txt")))
		ok(t, "abort", raw(ctx, rw, "DELETE", "/"+a1+"/mpc", q("uploadId", up), "", nil))
	})

	t.Run("multipart is write-only", func(t *testing.T) {
		body, err := rawBody(ctx, rw, "POST", "/"+a1+"/mp", q("uploads", ""), "", nil)
		allow("rw CreateMultipartUpload", err)
		up := xmlValue(body, "UploadId")
		allow("rw UploadPart", raw(ctx, rw, "PUT", "/"+a1+"/mp", q("partNumber", "1", "uploadId", up), "part1", nil))
		parts, err := rawBody(ctx, rw, "GET", "/"+a1+"/mp", q("uploadId", up), "", nil)
		allow("rw ListParts", err)
		allow("rw ListMultipartUploads", raw(ctx, rw, "GET", "/"+a1, q("uploads", ""), "", nil))
		denied(t, "ro aborts an upload in another bucket", raw(ctx, ro, "DELETE", "/"+a1+"/mp", q("uploadId", up), "", nil))
		done := fmt.Sprintf(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, xmlValue(parts, "ETag"))
		allow("rw CompleteMultipartUpload", raw(ctx, rw, "POST", "/"+a1+"/mp", q("uploadId", up), done, nil))

		body, err = rawBody(ctx, root, "POST", "/"+a2+"/mp", q("uploads", ""), "", nil)
		ok(t, "root starts an upload in a2", err)
		up2 := xmlValue(body, "UploadId")
		denied(t, "ro CreateMultipartUpload", raw(ctx, ro, "POST", "/"+a2+"/mp", q("uploads", ""), "", nil))
		denied(t, "ro UploadPart", raw(ctx, ro, "PUT", "/"+a2+"/mp", q("partNumber", "1", "uploadId", up2), "x", nil))
		denied(t, "ro AbortMultipartUpload", raw(ctx, ro, "DELETE", "/"+a2+"/mp", q("uploadId", up2), "", nil))
		denied(t, "ro ListParts", raw(ctx, ro, "GET", "/"+a2+"/mp", q("uploadId", up2), "", nil))
		denied(t, "ro ListMultipartUploads", raw(ctx, ro, "GET", "/"+a2, q("uploads", ""), "", nil))
		ok(t, "abort", raw(ctx, root, "DELETE", "/"+a2+"/mp", q("uploadId", up2), "", nil))
	})

	t.Run("ACLs can't be read or changed", func(t *testing.T) {
		denied(t, "rw GetObjectAcl", raw(ctx, rw, "GET", "/"+a1+"/secret.txt", q("acl", ""), "", nil))
		denied(t, "rw PutObjectAcl public-read", raw(ctx, rw, "PUT", "/"+a1+"/secret.txt", q("acl", ""), "", map[string]string{"x-amz-acl": "public-read"}))
		denied(t, "rw GetBucketAcl", raw(ctx, rw, "GET", "/"+a1, q("acl", ""), "", nil))
		denied(t, "rw PutBucketAcl public-read", raw(ctx, rw, "PUT", "/"+a1, q("acl", ""), "", map[string]string{"x-amz-acl": "public-read"}))
		denied(t, "rw PutBucketAcl grant to bob", raw(ctx, rw, "PUT", "/"+a1, q("acl", ""), "", map[string]string{"x-amz-grant-full-control": "id=" + bobA}))
		// Accepted, but the canned ACL is ignored: the object stays private
		// (checked under anonymous below).
		allow("rw PutObject with x-amz-acl public-read", raw(ctx, rw, "PUT", "/"+a1+"/pub.txt", nil, "pub", map[string]string{"x-amz-acl": "public-read"}))
	})

	t.Run("tags but no locks or bucket configuration", func(t *testing.T) {
		tag := `<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>`
		allow("rw PutObjectTagging", raw(ctx, rw, "PUT", "/"+a1+"/secret.txt", q("tagging", ""), tag, md5h(tag)))
		denied(t, "ro PutObjectTagging", raw(ctx, ro, "PUT", "/"+a2+"/secret.txt", q("tagging", ""), tag, md5h(tag)))
		allow("ro GetObjectTagging", raw(ctx, ro, "GET", "/"+a2+"/secret.txt", q("tagging", ""), "", nil))
		denied(t, "ro DeleteObjectTagging", raw(ctx, ro, "DELETE", "/"+a2+"/secret.txt", q("tagging", ""), "", nil))
		for _, c := range []struct{ name, path, sub, body string }{
			{"PutObjectLegalHold", "/" + a1 + "/secret.txt", "legal-hold", `<LegalHold><Status>ON</Status></LegalHold>`},
			{"PutObjectRetention", "/" + a1 + "/secret.txt", "retention", `<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-01-01T00:00:00Z</RetainUntilDate></Retention>`},
			{"PutObjectLockConfiguration", "/" + a1, "object-lock", `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`},
			{"PutBucketVersioning", "/" + a1, "versioning", `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`},
			{"PutBucketTagging", "/" + a1, "tagging", tag},
			{"PutBucketCors", "/" + a1, "cors", `<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`},
			{"PutBucketOwnershipControls", "/" + a1, "ownershipControls", `<OwnershipControls><Rule><ObjectOwnership>BucketOwnerPreferred</ObjectOwnership></Rule></OwnershipControls>`},
		} {
			denied(t, "rw "+c.name, raw(ctx, rw, "PUT", c.path, q(c.sub, ""), c.body, md5h(c.body)))
		}
		for _, sub := range []string{"policy", "tagging", "ownershipControls"} {
			denied(t, "rw GetBucket "+sub, raw(ctx, rw, "GET", "/"+a1, q(sub, ""), "", nil))
		}
		denied(t, "ro GetBucketPolicy", raw(ctx, ro, "GET", "/"+a2, q("policy", ""), "", nil))
		allow("rw GetBucketVersioning", raw(ctx, rw, "GET", "/"+a1, q("versioning", ""), "", nil))
		allow("rw GetBucketLocation", raw(ctx, rw, "GET", "/"+a1, q("location", ""), "", nil))
		allow("rw HeadBucket", raw(ctx, rw, "HEAD", "/"+a1, nil, "", nil))
	})

	t.Run("read-only keys can't delete", func(t *testing.T) {
		denied(t, "ro DeleteObject", deleteObject(ctx, ro, a2, "secret.txt"))
		denied(t, "ro DeleteObject with versionId", raw(ctx, ro, "DELETE", "/"+a2+"/secret.txt", q("versionId", "null"), "", nil))
		// DeleteObjects answers 200 with an AccessDenied per key, as S3 does.
		del := `<Delete><Object><Key>secret.txt</Key></Object></Delete>`
		body, err := rawBody(ctx, ro, "POST", "/"+a2, q("delete", ""), del, md5h(del))
		ok(t, "ro DeleteObjects", err)
		if !strings.Contains(body, "<Code>AccessDenied</Code>") || !exists(a2, "secret.txt") {
			t.Errorf("ro DeleteObjects deleted something: %s", body)
		}
		body, err = rawBody(ctx, rw, "POST", "/"+b1, q("delete", ""), del, md5h(del))
		ok(t, "rw DeleteObjects in bob's bucket", err)
		if !strings.Contains(body, "<Code>AccessDenied</Code>") || !exists(b1, "secret.txt") {
			t.Errorf("rw DeleteObjects deleted from bob's bucket: %s", body)
		}
	})

	t.Run("nothing crosses between people or ungranted buckets", func(t *testing.T) {
		denied(t, "bob's key reads alice's bucket", raw(ctx, bk, "GET", "/"+a1+"/secret.txt", nil, "", nil))
		denied(t, "alice's web account reads bob's bucket", raw(ctx, web, "GET", "/"+b1+"/secret.txt", nil, "", nil))
		denied(t, "rw key reads alice's ungranted bucket", raw(ctx, rw, "GET", "/"+a3+"/secret.txt", nil, "", nil))
		deny("rw HeadBucket bob's", raw(ctx, rw, "HEAD", "/"+b1, nil, "", nil))
		deny("rw HeadObject bob's", raw(ctx, rw, "HEAD", "/"+b1+"/secret.txt", nil, "", nil))
		// The web account reaches all of its person's buckets, whatever keys
		// have.
		allow("alice's web account reads a3", raw(ctx, web, "GET", "/"+a3+"/secret.txt", nil, "", nil))
	})

	t.Run("keys can't escape their bucket by path", func(t *testing.T) {
		for _, path := range []string{
			"/" + a1 + "/../" + b1 + "/trav1.txt",
			"/" + a1 + "/x/../../" + b1 + "/trav2.txt",
			"/" + a1 + "/%2E%2E%2F" + b1 + "/trav3.txt",
		} {
			deny("rw PUT "+path, raw(ctx, rw, "PUT", path, nil, "x", nil))
		}
		for _, key := range []string{"trav1.txt", "trav2.txt", "trav3.txt"} {
			if exists(b1, key) {
				t.Errorf("path traversal wrote %s/%s", b1, key)
			}
		}
		deny("rw PUT into .sgwtmp", raw(ctx, rw, "PUT", "/"+a1+"/.sgwtmp/x", nil, "x", nil))
	})

	t.Run("anonymous requests are refused", func(t *testing.T) {
		for _, path := range []string{"/", "/" + a1, "/" + a1 + "/secret.txt", "/" + a1 + "/pub.txt"} {
			if code, _ := anon(ctx, "GET", root.S3Endpoint+path); code != http.StatusForbidden {
				t.Errorf("anonymous GET %s: %d, want 403", path, code)
			}
		}
	})

	t.Run("user keys can't use the admin API", func(t *testing.T) {
		_, err := rw.do(ctx, "PATCH", rw.AdminEndpoint, "/list-users", nil, nil, nil)
		denied(t, "rw list-users", err)
		denied(t, "rw create admin", rw.CreateAccount(ctx, Account{Access: "evil" + sfx, Secret: "evilsecret0123456789", Role: "admin"}))
		_, err = rw.do(ctx, "PATCH", rw.AdminEndpoint, "/update-user", q("access", rwA), []byte(`<MutableProps><UserID>0</UserID><GroupID>0</GroupID></MutableProps>`), nil)
		denied(t, "rw sets its uid to 0", err)
		_, err = rw.do(ctx, "PATCH", rw.AdminEndpoint, "/change-bucket-owner", q("bucket", b1, "owner", rwA), nil, nil)
		denied(t, "rw takes bob's bucket", err)
	})

	// Runs last: it revokes the rw key.
	t.Run("presigned URLs last up to a week, unless the key goes", func(t *testing.T) {
		u, _ := presignFor(ctx, rw, "GET", "/"+a1+"/secret.txt", 300)
		_, err := anon(ctx, "GET", u)
		allow("presigned GET", err)
		u, _ = presignFor(ctx, rw, "PUT", "/"+a1+"/presigned.txt", 300)
		_, err = anon(ctx, "PUT", u)
		allow("presigned PUT", err)
		u, _ = presignFor(ctx, rw, "GET", "/"+b1+"/secret.txt", 300)
		_, err = anon(ctx, "GET", u)
		deny("presigned GET of bob's object", err)
		week, _ := presignFor(ctx, rw, "GET", "/"+a1+"/secret.txt", 604800)
		_, err = anon(ctx, "GET", week)
		allow("presigned GET valid for a week", err)
		u, _ = presignFor(ctx, rw, "GET", "/"+a1+"/secret.txt", 604801)
		_, err = anon(ctx, "GET", u)
		deny("presigned GET valid for more than a week", err)
		ok(t, "revoke rw", p.DeleteKey(ctx, alice, rwA))
		_, err = anon(ctx, "GET", week)
		deny("presigned GET after its key was revoked", err)
	})

	// SURPRISING: the gateway runs as root and follows symlinks inside
	// bucket directories. Bucket directories are owned by their person
	// (--chuid), so anyone who can run a process as them on the host can
	// plant a link, then read anything the gateway can see through any key
	// or the file browser: the IAM file with every account's secret, other
	// people's buckets. Writes replace the link rather than following it.
	// The fix is on the host: keep people out of the buckets directory.
	// This asserts the current behaviour so a gateway change gets noticed.
	t.Run("gateway follows planted symlinks", func(t *testing.T) {
		dataDir := os.Getenv("VGW_TEST_DATA")
		if dataDir == "" {
			t.Skip("VGW_TEST_DATA not set")
		}
		// The paths are as the gateway sees them.
		if err := errors.Join(
			os.Symlink("/data/"+b1, filepath.Join(dataDir, a2, "bob-dir")),
			os.Symlink("/tmp/s3-audit-victim", filepath.Join(dataDir, a2, "write-link")),
		); err != nil {
			t.Skipf("can't write to the gateway's data directory: %v", err)
		}
		body, err := getObject(ctx, ro, a2, "bob-dir/secret.txt")
		if err != nil || body != "secret of "+b1 {
			t.Errorf("read through a planted directory symlink: %q %v (fixed upstream?)", body, err)
		}
		ok(t, "write through planted symlink", putObject(ctx, root, a2, "write-link", "x"))
		if fi, err := os.Lstat(filepath.Join(dataDir, a2, "write-link")); err != nil || fi.Mode()&os.ModeSymlink != 0 {
			t.Errorf("a write followed a planted symlink: %v", err)
		}
		os.Remove(filepath.Join(dataDir, a2, "bob-dir"))
		os.Remove(filepath.Join(dataDir, a2, "write-link"))
	})
}

func q(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func raw(ctx context.Context, v *VGW, method, path string, query url.Values, body string, headers map[string]string) error {
	_, err := rawBody(ctx, v, method, path, query, body, headers)
	return err
}

func rawBody(ctx context.Context, v *VGW, method, path string, query url.Values, body string, headers map[string]string) (string, error) {
	b, err := v.do(ctx, method, v.S3Endpoint, path, query, []byte(body), headers)
	return string(b), err
}

// anon sends an unsigned request, as a browser following a link would.
func anon(ctx context.Context, method, u string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return resp.StatusCode, apiError(resp)
	}
	return resp.StatusCode, nil
}

func presignFor(ctx context.Context, v *VGW, method, path string, seconds int) (string, error) {
	req, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("%s%s?X-Amz-Expires=%d", v.S3Endpoint, path, seconds), nil)
	if err != nil {
		return "", err
	}
	u, _, err := v.signer.PresignHTTP(ctx, v.Creds, req, "UNSIGNED-PAYLOAD", "s3", v.Region, time.Now())
	return u, err
}

func md5h(s string) map[string]string {
	sum := md5.Sum([]byte(s))
	return map[string]string{"Content-MD5": base64.StdEncoding.EncodeToString(sum[:])}
}

func xmlValue(body, tag string) string {
	if v := xmlValues(body, tag); len(v) > 0 {
		return v[0]
	}
	return ""
}

func xmlValues(body, tag string) []string {
	var out []string
	for {
		_, after, ok := strings.Cut(body, "<"+tag+">")
		if !ok {
			return out
		}
		v, rest, _ := strings.Cut(after, "</"+tag+">")
		out = append(out, v)
		body = rest
	}
}

// emptyBucket deletes everything in bucket, multipart uploads included.
func emptyBucket(ctx context.Context, t *testing.T, root *VGW, bucket string) {
	t.Helper()
	for range 10 {
		list, err := root.ListObjects(ctx, bucket, "", "", "", 1000)
		if err != nil || len(list.Objects) == 0 {
			break
		}
		for _, o := range list.Objects {
			root.DeleteObject(ctx, bucket, o.Key)
		}
	}
	body, _ := rawBody(ctx, root, "GET", "/"+bucket, q("uploads", ""), "", nil)
	keys, ids := xmlValues(body, "Key"), xmlValues(body, "UploadId")
	for i := range ids {
		if i < len(keys) {
			raw(ctx, root, "DELETE", "/"+bucket+"/"+keys[i], q("uploadId", ids[i]), "", nil)
		}
	}
}
