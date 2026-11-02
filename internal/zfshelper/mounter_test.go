package zfshelper

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/wrouesnel/versity-s3-portal/internal/zfsapi"
)

// mountEnv is a MountServer whose mount system calls only record what
// they'd do, against a mount table the test controls.
type mountEnv struct {
	t           *testing.T
	m           *MountServer
	srv         *httptest.Server
	root        string
	staging     string
	table       []mountEntry
	mounts      []string // "source target data flags"
	unmounts    []string
	failUnmount map[string]error
}

func newMountEnv(t *testing.T) *mountEnv {
	dir := t.TempDir()
	e := &mountEnv{t: t, root: filepath.Join(dir, "buckets"), staging: filepath.Join(dir, "staging")}
	os.Mkdir(e.root, 0o700)
	e.table = []mountEntry{{mountpoint: e.root, fstype: "zfs", source: parent}}
	e.m = NewMountServer(MountConfig{
		Parent: parent, Root: e.root, Staging: e.staging, StagingOwner: os.Getuid(),
		Mountinfo: func() ([]byte, error) {
			var b strings.Builder
			for i, x := range e.table {
				fmt.Fprintf(&b, "%d 1 0:%d / %s rw,relatime shared:1 - %s %s rw\n", 100+i, 50+i,
					strings.ReplaceAll(x.mountpoint, " ", `\040`), x.fstype, x.source)
			}
			return []byte(b.String()), nil
		},
		Mount: func(source, target, fstype string, flags uintptr, data string) error {
			if strings.HasSuffix(source, "/nosuch") {
				return syscall.ENOENT
			}
			// Resolve the fd target as the kernel would.
			real, err := os.Readlink(target)
			if err != nil {
				return err
			}
			e.mounts = append(e.mounts, fmt.Sprintf("%s %s %s %s %#x", source, real, fstype, data, flags))
			e.table = append(e.table, mountEntry{mountpoint: real, fstype: fstype, source: source})
			return nil
		},
		Unmount: func(target string, flags int) error {
			if err := e.failUnmount[target]; err != nil {
				return err
			}
			e.unmounts = append(e.unmounts, target)
			for i := len(e.table) - 1; i >= 0; i-- {
				if e.table[i].mountpoint == target {
					e.table = append(e.table[:i], e.table[i+1:]...)
					return nil
				}
			}
			return syscall.EINVAL
		},
	})
	if err := e.m.Check(); err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(e.m.Handler())
	t.Cleanup(e.srv.Close)
	return e
}

func (e *mountEnv) call(op, place, bucket string) (int, string) {
	e.t.Helper()
	resp, err := http.Post(e.srv.URL+"/"+op+"/"+place+"/"+bucket, "", nil)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf [4096]byte
	n, _ := resp.Body.Read(buf[:])
	return resp.StatusCode, string(buf[:n])
}

func (e *mountEnv) want(status int, op, place, bucket string) string {
	e.t.Helper()
	got, body := e.call(op, place, bucket)
	if got != status {
		e.t.Fatalf("%s %s %s: want %d, got %d: %s", op, place, bucket, status, got, body)
	}
	return body
}

func TestMounter(t *testing.T) {
	e := newMountEnv(t)
	st, err := os.Stat(e.staging)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("staging %v %v", st, err)
	}
	flags := fmt.Sprintf("%#x", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC)

	// Staging: made, mounted with the dataset it works out itself, the
	// safe flags, and mntpoint so snapshots can be automounted.
	e.want(204, "mount", "staging", "photos")
	stage := filepath.Join(e.staging, "photos")
	want := parent + "/photos " + stage + " zfs zfsutil,mntpoint=" + stage + " " + flags
	if len(e.mounts) != 1 || e.mounts[0] != want {
		t.Fatalf("mounts %q, want %q", e.mounts, want)
	}
	// Again: already there, nothing to do. Elsewhere: refused.
	e.want(204, "mount", "staging", "photos")
	if len(e.mounts) != 1 {
		t.Error("mounted twice")
	}
	e.want(409, "mount", "bucket", "photos")
	e.want(204, "unmount", "staging", "photos")
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Error("staging directory left")
	}

	// The bucket's place: an existing empty directory is fine.
	os.Mkdir(filepath.Join(e.root, "photos"), 0o755)
	e.want(204, "mount", "bucket", "photos")
	dir := filepath.Join(e.root, "photos")
	if got := e.mounts[len(e.mounts)-1]; got != parent+"/photos "+dir+" zfs zfsutil,mntpoint="+dir+" "+flags {
		t.Errorf("mount %q", got)
	}

	// Unmounting takes the automounted snapshots first.
	e.unmounts = nil
	snap := dir + "/.zfs/snapshot/s3portal-20261103T000000Z"
	e.table = append(e.table, mountEntry{mountpoint: snap, fstype: "zfs", source: parent + "/photos@s3portal-20261103T000000Z"})
	e.want(204, "unmount", "bucket", "photos")
	if strings.Join(e.unmounts, " ") != snap+" "+dir {
		t.Errorf("unmounts %q", e.unmounts)
	}
	// Not mounted: fine.
	e.want(204, "unmount", "bucket", "photos")

	// Busy.
	e.want(204, "mount", "bucket", "photos")
	e.failUnmount = map[string]error{dir: syscall.EBUSY}
	if body := e.want(409, "unmount", "bucket", "photos"); !strings.Contains(body, zfsapi.CodeBusy) {
		t.Errorf("busy: %s", body)
	}
	e.failUnmount = nil
	e.want(204, "unmount", "bucket", "photos")

	// Something else mounted there isn't ours to unmount, nor to mount on.
	os.Mkdir(filepath.Join(e.root, "other"), 0o700)
	e.table = append(e.table, mountEntry{mountpoint: filepath.Join(e.root, "other"), fstype: "tmpfs", source: "tmpfs"})
	e.want(409, "unmount", "bucket", "other")
	e.want(409, "mount", "bucket", "other")

	// Not empty, a file, or a link: refused, untouched.
	os.MkdirAll(filepath.Join(e.root, "full", "x"), 0o700)
	e.want(409, "mount", "bucket", "full")
	os.WriteFile(filepath.Join(e.root, "afile"), nil, 0o600)
	e.want(409, "mount", "bucket", "afile")
	os.Symlink("/etc", filepath.Join(e.root, "linked"))
	e.want(409, "mount", "bucket", "linked")
	if lt, err := os.Lstat(filepath.Join(e.root, "linked")); err != nil || lt.Mode()&os.ModeSymlink == 0 {
		t.Error("link touched")
	}

	// Bad names and places.
	e.want(400, "mount", "bucket", "Bad_Name")
	e.want(400, "mount", "bucket", "..%2Fetc")
	e.want(400, "mount", "elsewhere", "photos")

	// No such dataset: 404, and the directory it made is gone again, so
	// the gateway doesn't see a bucket. One that was there stays.
	e.want(404, "mount", "bucket", "nosuch")
	if _, err := os.Lstat(filepath.Join(e.root, "nosuch")); !os.IsNotExist(err) {
		t.Error("directory left behind after a failed mount")
	}
	os.Mkdir(filepath.Join(e.root, "nosuch"), 0o755)
	e.want(404, "mount", "bucket", "nosuch")
	if _, err := os.Lstat(filepath.Join(e.root, "nosuch")); err != nil {
		t.Error("existing directory removed")
	}

	// The root's device, for the helper's staleness check.
	resp, err := http.Get(e.srv.URL + "/root")
	if err != nil {
		t.Fatal(err)
	}
	var root zfsapi.MountRoot
	json.NewDecoder(resp.Body).Decode(&root)
	resp.Body.Close()
	var rst syscall.Stat_t
	syscall.Stat(e.root, &rst)
	if root.Dev == 0 || root.Dev != rst.Dev {
		t.Errorf("root dev %d, want %d", root.Dev, rst.Dev)
	}

	n := len(e.mounts)
	// The buckets' parent isn't mounted: nothing goes on the bare
	// directory.
	e.table = e.table[1:]
	e.want(409, "mount", "bucket", "late")
	// Staging loosened: refused.
	os.Chmod(e.staging, 0o755)
	e.want(500, "mount", "staging", "late")
	if len(e.mounts) != n {
		t.Errorf("mounted anyway: %q", e.mounts[n:])
	}
}

func TestMounterConfig(t *testing.T) {
	dir := t.TempDir()
	m := NewMountServer(MountConfig{Parent: parent, Root: dir + "/buckets", Staging: dir + "/buckets/.staging",
		Mountinfo: func() ([]byte, error) { return nil, nil }})
	if err := m.Check(); err == nil {
		t.Error("staging inside the root accepted")
	}
	m = NewMountServer(MountConfig{Parent: parent, Root: dir + "/buckets", Staging: dir + "/staging",
		Mountinfo: func() ([]byte, error) { return nil, nil }})
	if err := m.Check(); err == nil {
		t.Error("unmounted root accepted")
	}
}

func TestUnescapeMount(t *testing.T) {
	for in, want := range map[string]string{`/a\040b`: "/a b", `/plain`: "/plain", `/x\134y`: `/x\y`, `/end\04`: `/end\04`} {
		if got := unescapeMount(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
