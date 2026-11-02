package zfshelper

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wrouesnel/versity-s3-portal/internal/zfsapi"
	"github.com/wrouesnel/versity-s3-portal/internal/zfshelper/zfstest"
)

const parent = "storage/s3/buckets"

type env struct {
	t     *testing.T
	root  string
	fake  *zfstest.Fake
	srv   *httptest.Server
	clock time.Time
	// xattrs says whether the test filesystem takes user xattrs.
	xattrs bool
}

func newEnv(t *testing.T) *env {
	root := filepath.Join(t.TempDir(), "buckets")
	fake, err := zfstest.New(parent, root)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, root: root, fake: fake, clock: time.Date(2026, 11, 3, 6, 30, 0, 0, time.UTC)}
	s := New(Config{Parent: parent, Root: root, Run: fake.Run, Now: func() time.Time { return e.clock }})
	if err := s.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(s.Handler())
	t.Cleanup(e.srv.Close)
	probe := filepath.Join(root, ".probe")
	os.WriteFile(probe, nil, 0o600)
	e.xattrs = syscall.Setxattr(probe, "user.probe", []byte("1"), 0) == nil
	os.Remove(probe)
	if !e.xattrs {
		t.Log("no user xattrs on the test filesystem; not checking them")
	}
	return e
}

func (e *env) do(method, path string, body any) (int, []byte) {
	e.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (e *env) want(status int, method, path string, body any) []byte {
	e.t.Helper()
	got, out := e.do(method, path, body)
	if got != status {
		e.t.Fatalf("%s %s: want %d, got %d: %s", method, path, status, got, out)
	}
	return out
}

func code(out []byte) string {
	var e zfsapi.Error
	json.Unmarshal(out, &e)
	return e.Code
}

// mkBucket makes a bucket directory as the gateway would.
func (e *env) mkBucket(name string) string {
	dir := filepath.Join(e.root, name)
	if err := os.Mkdir(dir, 0o750); err != nil {
		e.t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".sgwtmp", "multipart"), 0o700); err != nil {
		e.t.Fatal(err)
	}
	if e.xattrs {
		syscall.Setxattr(dir, "user.acl", []byte(`{"Owner":"owner.alice"}`), 0)
		syscall.Setxattr(dir, "user.policy", []byte(`{"Version":"2012-10-17"}`), 0)
	}
	return dir
}

func (e *env) write(rel, body string) {
	e.t.Helper()
	p := filepath.Join(e.root, rel)
	os.MkdirAll(filepath.Dir(p), 0o750)
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		e.t.Fatal(err)
	}
	if e.xattrs {
		syscall.Setxattr(p, "user.etag", []byte("etag-"+body), 0)
	}
}

func getxattr(path, name string) string {
	buf := make([]byte, 4096)
	n, err := syscall.Getxattr(path, name, buf)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

func TestAdopt(t *testing.T) {
	e := newEnv(t)
	dir := e.mkBucket("photos")
	e.want(201, "POST", "/buckets/photos/adopt", nil)
	if !e.fake.IsDataset(parent + "/photos") {
		t.Fatal("not a dataset after adopting")
	}
	st, err := os.Lstat(dir)
	if err != nil || st.Mode().Perm() != 0o750 || !st.IsDir() {
		t.Fatalf("bucket root after adopting: %v %v", st, err)
	}
	if e.xattrs && getxattr(dir, "user.acl") != `{"Owner":"owner.alice"}` {
		t.Errorf("acl xattr lost: %q", getxattr(dir, "user.acl"))
	}
	if _, err := os.Lstat(filepath.Join(dir, ".sgwtmp")); !errors.Is(err, os.ErrNotExist) {
		t.Error("gateway temp dir should be gone; the gateway makes it again")
	}
	// Again: nothing to do.
	e.want(200, "POST", "/buckets/photos/adopt", nil)

	// Not empty: refused, untouched.
	e.mkBucket("docs")
	e.write("docs/a.txt", "x")
	if out := e.want(409, "POST", "/buckets/docs/adopt", nil); code(out) != zfsapi.CodeNotEmpty {
		t.Errorf("code %s", out)
	}
	if e.fake.IsDataset(parent + "/docs") {
		t.Error("non-empty bucket adopted")
	}
	// A file in the temp dir (an upload in progress) also counts.
	e.mkBucket("busy")
	e.write("busy/.sgwtmp/multipart/part", "x")
	e.want(409, "POST", "/buckets/busy/adopt", nil)

	e.want(404, "POST", "/buckets/nothere/adopt", nil)
	e.want(400, "POST", "/buckets/Bad_Name/adopt", nil)
	e.want(400, "POST", "/buckets/..%2Fescape/adopt", nil)

	// zfs create fails: the directory comes back as it was.
	dir = e.mkBucket("broken")
	e.fake.FailNext = map[string]error{"create": errors.New("out of space")}
	e.want(500, "POST", "/buckets/broken/adopt", nil)
	st, err = os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0o750 {
		t.Fatalf("directory not put back: %v %v", st, err)
	}
	if e.xattrs && getxattr(dir, "user.policy") != `{"Version":"2012-10-17"}` {
		t.Error("xattrs not put back")
	}

	// A symlink where the bucket should be is refused.
	os.Symlink("/etc", filepath.Join(e.root, "linked"))
	if got, _ := e.do("POST", "/buckets/linked/adopt", nil); got < 400 {
		t.Fatalf("symlinked bucket adopted: %d", got)
	}
}

func TestDestroy(t *testing.T) {
	e := newEnv(t)
	e.mkBucket("photos")
	e.want(201, "POST", "/buckets/photos/adopt", nil)
	e.write("photos/a.txt", "x")
	if out := e.want(409, "DELETE", "/buckets/photos", nil); code(out) != zfsapi.CodeNotEmpty {
		t.Fatalf("code %s", out)
	}
	os.Remove(filepath.Join(e.root, "photos/a.txt"))
	// An empty folder is a folder object: still not empty.
	os.Mkdir(filepath.Join(e.root, "photos/folder"), 0o750)
	e.want(409, "DELETE", "/buckets/photos", nil)
	os.Remove(filepath.Join(e.root, "photos/folder"))
	// The gateway's temp dir doesn't count.
	os.MkdirAll(filepath.Join(e.root, "photos/.sgwtmp/multipart"), 0o700)
	e.fake.Snapshot(parent+"/photos", "weekly_2026-11-01", e.clock)
	e.want(204, "DELETE", "/buckets/photos", nil)
	if e.fake.IsDataset(parent + "/photos") {
		t.Fatal("dataset still there")
	}
	if _, err := os.Lstat(filepath.Join(e.root, "photos")); !errors.Is(err, os.ErrNotExist) {
		t.Error("mountpoint left behind")
	}
	calls := e.fake.Calls()
	last := calls[len(calls)-1]
	if strings.Join(last, " ") != "destroy -r "+parent+"/photos" {
		t.Errorf("last call %v", last)
	}
	// Plain directories aren't ours to destroy.
	e.mkBucket("plain")
	if out := e.want(404, "DELETE", "/buckets/plain", nil); code(out) != zfsapi.CodeNotDataset {
		t.Errorf("code %s", out)
	}
}

func TestQuotaAndBackup(t *testing.T) {
	e := newEnv(t)
	e.mkBucket("photos")
	e.want(201, "POST", "/buckets/photos/adopt", nil)
	ds := parent + "/photos"

	e.want(204, "PUT", "/buckets/photos/quota", zfsapi.Quota{Bytes: 10 << 30})
	if got := e.fake.Prop(ds, "refquota"); got != "10737418240" {
		t.Errorf("refquota %q", got)
	}
	e.want(204, "PUT", "/buckets/photos/backup", zfsapi.Backup{Include: true})
	var info zfsapi.BucketInfo
	json.Unmarshal(e.want(200, "GET", "/buckets/photos", nil), &info)
	if !info.Backup || info.RefQuota != 10<<30 || info.Dataset != ds || info.Available == 0 {
		t.Errorf("info %+v", info)
	}

	e.want(204, "PUT", "/buckets/photos/quota", zfsapi.Quota{Bytes: 0})
	if got := e.fake.Prop(ds, "refquota"); got != "none" {
		t.Errorf("refquota %q", got)
	}
	e.want(204, "PUT", "/buckets/photos/backup", zfsapi.Backup{Include: false})
	if got := e.fake.Prop(ds, "backupctl:include"); got != "" {
		t.Errorf("backup prop should be inherited, is %q", got)
	}
	e.want(400, "PUT", "/buckets/photos/quota", zfsapi.Quota{Bytes: -1})
	e.want(400, "PUT", "/buckets/photos/quota", map[string]any{"bytes": 1, "extra": true})
	e.want(404, "GET", "/buckets/nothere", nil)
}

func TestSnapshots(t *testing.T) {
	e := newEnv(t)
	e.mkBucket("photos")
	e.want(201, "POST", "/buckets/photos/adopt", nil)
	ds := parent + "/photos"
	e.write("photos/a.txt", "one")
	e.write("photos/dir/b.txt", "two")
	e.write("photos/dir/sub/c.txt", "three")
	os.MkdirAll(filepath.Join(e.root, "photos/.sgwtmp"), 0o700)
	os.Chtimes(filepath.Join(e.root, "photos/a.txt"), e.clock.Add(-time.Hour), e.clock.Add(-time.Hour))
	e.fake.Snapshot(ds, "weekly_2026-11-01", e.clock.Add(-48*time.Hour))

	var snap zfsapi.Snapshot
	json.Unmarshal(e.want(201, "POST", "/buckets/photos/snapshots", zfsapi.NewSnapshot{Label: "before"}), &snap)
	if snap.Name != "s3portal-20261103T063000Z-before" {
		t.Fatalf("name %q", snap.Name)
	}
	e.want(409, "POST", "/buckets/photos/snapshots", zfsapi.NewSnapshot{Label: "before"})
	e.want(400, "POST", "/buckets/photos/snapshots", zfsapi.NewSnapshot{Label: "Bad Label"})
	e.clock = e.clock.Add(time.Minute)
	e.want(201, "POST", "/buckets/photos/snapshots", zfsapi.NewSnapshot{})

	var snaps []zfsapi.Snapshot
	json.Unmarshal(e.want(200, "GET", "/buckets/photos/snapshots", nil), &snaps)
	if len(snaps) != 2 || snaps[0].Name != "s3portal-20261103T063100Z" || snaps[1].Name != snap.Name {
		t.Fatalf("snapshots %+v", snaps)
	}

	base := "/buckets/photos/snapshots/" + snap.Name
	var list zfsapi.ObjectList
	json.Unmarshal(e.want(200, "GET", base+"/list?delimiter=/", nil), &list)
	if len(list.Objects) != 1 || list.Objects[0].Key != "a.txt" || list.Objects[0].Size != 3 ||
		!list.Objects[0].Modified.Equal(e.clock.Add(-time.Hour-time.Minute)) {
		t.Errorf("top objects %+v", list.Objects)
	}
	if strings.Join(list.Prefixes, ",") != "dir/" {
		t.Errorf("top prefixes %v", list.Prefixes)
	}
	json.Unmarshal(e.want(200, "GET", base+"/list?prefix=dir/&delimiter=/", nil), &list)
	if len(list.Objects) != 1 || list.Objects[0].Key != "dir/b.txt" || strings.Join(list.Prefixes, ",") != "dir/sub/" {
		t.Errorf("dir/ listing %+v", list)
	}
	list = zfsapi.ObjectList{}
	json.Unmarshal(e.want(200, "GET", base+"/list", nil), &list)
	var keys []string
	for _, o := range list.Objects {
		keys = append(keys, o.Key)
	}
	if strings.Join(keys, ",") != "a.txt,dir/b.txt,dir/sub/c.txt" {
		t.Errorf("recursive keys %v", keys)
	}
	list = zfsapi.ObjectList{}
	json.Unmarshal(e.want(200, "GET", base+"/list?max-keys=2", nil), &list)
	if len(list.Objects) != 2 || list.NextStartAfter != "dir/b.txt" {
		t.Errorf("page 1 %+v", list)
	}
	list = zfsapi.ObjectList{}
	json.Unmarshal(e.want(200, "GET", base+"/list?max-keys=2&start-after=dir/b.txt", nil), &list)
	if len(list.Objects) != 1 || list.NextStartAfter != "" {
		t.Errorf("page 2 %+v", list)
	}
	list = zfsapi.ObjectList{}
	json.Unmarshal(e.want(200, "GET", base+"/list?prefix=nothing/&delimiter=/", nil), &list)
	if len(list.Objects)+len(list.Prefixes) != 0 {
		t.Errorf("missing prefix %+v", list)
	}

	if body := e.want(200, "GET", base+"/object?key=dir/b.txt", nil); string(body) != "two" {
		t.Errorf("object %q", body)
	}
	e.want(404, "GET", base+"/object?key=dir/none.txt", nil)
	e.want(404, "GET", base+"/object?key=.sgwtmp/x", nil)
	e.want(400, "GET", base+"/object?key=../a.txt", nil)
	e.want(400, "GET", base+"/object?key=dir", nil)

	// The host's snapshots are out of reach.
	e.want(400, "GET", "/buckets/photos/snapshots/weekly_2026-11-01/list", nil)
	e.want(400, "DELETE", "/buckets/photos/snapshots/weekly_2026-11-01", nil)
	e.want(404, "GET", "/buckets/photos/snapshots/s3portal-20200101T000000Z/list", nil)

	e.want(204, "DELETE", base, nil)
	json.Unmarshal(e.want(200, "GET", "/buckets/photos/snapshots", nil), &snaps)
	if len(snaps) != 1 {
		t.Errorf("after delete %+v", snaps)
	}
}

func TestRestore(t *testing.T) {
	e := newEnv(t)
	e.mkBucket("photos")
	e.want(201, "POST", "/buckets/photos/adopt", nil)
	e.write("photos/a.txt", "one")
	e.write("photos/dir/b.txt", "two")
	e.write("photos/dir/sub/c.txt", "three")
	old := e.clock.Add(-time.Hour)
	os.Chtimes(filepath.Join(e.root, "photos/a.txt"), old, old)
	var snap zfsapi.Snapshot
	json.Unmarshal(e.want(201, "POST", "/buckets/photos/snapshots", zfsapi.NewSnapshot{}), &snap)
	base := "/buckets/photos/snapshots/" + snap.Name

	// Change things after the snapshot.
	e.write("photos/a.txt", "changed")
	os.Chmod(filepath.Join(e.root, "photos/a.txt"), 0o600)
	os.RemoveAll(filepath.Join(e.root, "photos/dir"))
	e.write("photos/new.txt", "new")

	var res zfsapi.Restored
	json.Unmarshal(e.want(200, "POST", base+"/restore", zfsapi.Restore{Key: "a.txt"}), &res)
	a := filepath.Join(e.root, "photos/a.txt")
	body, _ := os.ReadFile(a)
	st, _ := os.Stat(a)
	if res.Objects != 1 || string(body) != "one" || st.Mode().Perm() != 0o640 || !st.ModTime().Equal(old) {
		t.Errorf("restored a.txt: %d %q %v %v", res.Objects, body, st.Mode(), st.ModTime())
	}
	if e.xattrs && getxattr(a, "user.etag") != "etag-one" {
		t.Errorf("etag xattr %q", getxattr(a, "user.etag"))
	}

	json.Unmarshal(e.want(200, "POST", base+"/restore", zfsapi.Restore{Prefix: "dir/"}), &res)
	if res.Objects != 2 {
		t.Errorf("restored %d from dir/", res.Objects)
	}
	if b, _ := os.ReadFile(filepath.Join(e.root, "photos/dir/sub/c.txt")); string(b) != "three" {
		t.Errorf("c.txt %q", b)
	}
	if st, err := os.Stat(filepath.Join(e.root, "photos/dir")); err != nil || st.Mode().Perm() != 0o750 {
		t.Errorf("recreated folder: %v %v", st, err)
	}

	os.RemoveAll(filepath.Join(e.root, "photos/dir"))
	json.Unmarshal(e.want(200, "POST", base+"/restore", zfsapi.Restore{All: true}), &res)
	if res.Objects != 3 {
		t.Errorf("restored %d of all", res.Objects)
	}
	if b, _ := os.ReadFile(filepath.Join(e.root, "photos/new.txt")); string(b) != "new" {
		t.Error("restore removed an object that's only live")
	}
	// No temporary files left about.
	filepath.Walk(filepath.Join(e.root, "photos"), func(p string, info os.FileInfo, err error) error {
		if err == nil && strings.Contains(p, ".s3zfs-restore-") {
			t.Errorf("left %s", p)
		}
		return nil
	})

	e.want(400, "POST", base+"/restore", zfsapi.Restore{})
	e.want(400, "POST", base+"/restore", zfsapi.Restore{Key: "a.txt", Prefix: "dir/"})
	e.want(400, "POST", base+"/restore", zfsapi.Restore{Prefix: "dir"})
	e.want(404, "POST", base+"/restore", zfsapi.Restore{Key: "missing.txt"})
	e.want(404, "POST", base+"/restore", zfsapi.Restore{Prefix: "missing/"})
}

func TestSymlinksRefused(t *testing.T) {
	e := newEnv(t)
	e.mkBucket("photos")
	e.want(201, "POST", "/buckets/photos/adopt", nil)
	outside := filepath.Join(t.TempDir(), "secret")
	os.MkdirAll(outside, 0o700)
	os.WriteFile(filepath.Join(outside, "key"), []byte("secret"), 0o600)
	live := filepath.Join(e.root, "photos")
	os.Symlink(filepath.Join(outside, "key"), filepath.Join(live, "file-link"))
	os.Symlink(outside, filepath.Join(live, "dir-link"))
	e.write("photos/ok.txt", "ok")
	var snap zfsapi.Snapshot
	json.Unmarshal(e.want(201, "POST", "/buckets/photos/snapshots", zfsapi.NewSnapshot{}), &snap)
	base := "/buckets/photos/snapshots/" + snap.Name

	var list zfsapi.ObjectList
	json.Unmarshal(e.want(200, "GET", base+"/list?delimiter=/", nil), &list)
	if len(list.Objects) != 1 || len(list.Prefixes) != 0 {
		t.Errorf("links listed: %+v", list)
	}
	json.Unmarshal(e.want(200, "GET", base+"/list?prefix=dir-link/", nil), &list)
	if len(list.Objects) != 0 {
		t.Errorf("listed through a link: %+v", list)
	}
	for _, key := range []string{"file-link", "dir-link/key"} {
		if got, body := e.do("GET", base+"/object?key="+key, nil); got == 200 || strings.Contains(string(body), "secret") {
			t.Errorf("read %s through a link: %d %s", key, got, body)
		}
		if got, _ := e.do("POST", base+"/restore", zfsapi.Restore{Key: key}); got == 200 {
			t.Errorf("restored %s through a link", key)
		}
	}

	// A link planted in the live bucket isn't followed when restoring
	// into it, either.
	e.write("photos/dir/x.txt", "x")
	var snap2 zfsapi.Snapshot
	e.clock = e.clock.Add(time.Minute)
	json.Unmarshal(e.want(201, "POST", "/buckets/photos/snapshots", zfsapi.NewSnapshot{}), &snap2)
	os.RemoveAll(filepath.Join(live, "dir"))
	os.Symlink(outside, filepath.Join(live, "dir"))
	if got, _ := e.do("POST", "/buckets/photos/snapshots/"+snap2.Name+"/restore", zfsapi.Restore{Key: "dir/x.txt"}); got == 200 {
		t.Error("restored through a link in the live bucket")
	}
	if _, err := os.Lstat(filepath.Join(outside, "x.txt")); err == nil {
		t.Error("wrote outside the bucket")
	}
}
