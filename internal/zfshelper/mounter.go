package zfshelper

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/wrouesnel/versity-s3-portal/internal/zfsapi"
)

// MountServer is s3-zfs-mounter's server. It mounts and unmounts the
// buckets' datasets for the helper, which can't: mounting needs
// CAP_SYS_ADMIN, and ZFS lets a process holding that do anything to any
// pool. The mounter has CAP_SYS_ADMIN but no access to /dev/zfs, so it
// can't issue a single ZFS command; it can only mount.
//
// So it trusts nothing it's sent. A request names a place and a bucket;
// the mounter works out the dataset (<Parent>/<bucket>) and the directory
// (<Root>/<bucket> or <Staging>/<bucket>) itself, never from a dataset's
// mountpoint property. It reaches the directory one component at a time
// without following links, mounts only over an empty directory that isn't
// already a mount, and always with nosuid, nodev and noexec, which a raw
// mount(2) doesn't take from the dataset's properties.
type MountServer struct {
	MountConfig
	mu sync.Mutex
}

// MountConfig sets up a MountServer.
type MountConfig struct {
	// Parent is the dataset whose children are buckets, and Root where
	// it's mounted.
	Parent, Root string
	// Staging is a directory outside Root, owned by root and 0700, where
	// new datasets are mounted to be set up.
	Staging string
	// StagingOwner is the uid that must own Staging: root (0), except in
	// tests.
	StagingOwner int
	Log          *slog.Logger
	// Mountinfo reads /proc/self/mountinfo; Mount and Unmount are the
	// system calls. Tests replace them.
	Mountinfo func() ([]byte, error)
	Mount     func(source, target, fstype string, flags uintptr, data string) error
	Unmount   func(target string, flags int) error
}

// umountNoFollow is UMOUNT_NOFOLLOW, which package syscall doesn't name.
const umountNoFollow = 0x8

func NewMountServer(c MountConfig) *MountServer {
	if c.Log == nil {
		c.Log = slog.Default()
	}
	c.Root = strings.TrimRight(c.Root, "/")
	c.Staging = strings.TrimRight(c.Staging, "/")
	if c.Mountinfo == nil {
		c.Mountinfo = func() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") }
	}
	if c.Mount == nil {
		c.Mount = syscall.Mount
	}
	if c.Unmount == nil {
		c.Unmount = syscall.Unmount
	}
	return &MountServer{MountConfig: c}
}

// mountEntry is a line of /proc/self/mountinfo.
type mountEntry struct {
	mountpoint, fstype, source string
}

func (m *MountServer) mounts() ([]mountEntry, error) {
	data, err := m.Mountinfo()
	if err != nil {
		return nil, err
	}
	var out []mountEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		// id parent maj:min root mountpoint opts [optional...] - fstype source superopts
		f := strings.Fields(sc.Text())
		sep := -1
		for i, x := range f {
			if x == "-" && i >= 6 {
				sep = i
				break
			}
		}
		if len(f) < 5 || sep < 0 || len(f) < sep+3 {
			continue
		}
		out = append(out, mountEntry{mountpoint: unescapeMount(f[4]), fstype: f[sep+1], source: unescapeMount(f[sep+2])})
	}
	return out, sc.Err()
}

// unescapeMount undoes mountinfo's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// at returns what's mounted at dir (the topmost mount), if anything.
func at(mounts []mountEntry, dir string) (mountEntry, bool) {
	var found mountEntry
	ok := false
	for _, e := range mounts {
		if e.mountpoint == dir {
			found, ok = e, true
		}
	}
	return found, ok
}

// openPath opens an absolute directory path from /, one component at a
// time, refusing links.
func openPath(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("%s isn't a clean absolute path", path)
	}
	root, err := syscall.Open("/", dirFlags, 0)
	if err != nil {
		return -1, err
	}
	defer syscall.Close(root)
	if path == "/" {
		return syscall.Dup(root)
	}
	fd, err := openDirAt(root, strings.Split(path[1:], "/"), nil)
	if err != nil {
		return -1, fmt.Errorf("open %s: %w", path, err)
	}
	return fd, nil
}

// Check makes sure Parent is mounted at Root, and makes the staging
// directory if it's missing, owned by root and 0700.
func (m *MountServer) Check() error {
	if strings.HasPrefix(m.Staging+"/", m.Root+"/") || strings.HasPrefix(m.Root+"/", m.Staging+"/") {
		return fmt.Errorf("the staging directory %s must be outside %s", m.Staging, m.Root)
	}
	if err := m.checkRoot(); err != nil {
		return err
	}
	if err := os.Mkdir(m.Staging, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fd, err := m.openStaging()
	if err != nil {
		return err
	}
	syscall.Close(fd)
	return nil
}

func (m *MountServer) checkRoot() error {
	mounts, err := m.mounts()
	if err != nil {
		return err
	}
	if e, ok := at(mounts, m.Root); !ok || e.fstype != "zfs" || e.source != m.Parent {
		return &apiError{http.StatusConflict, zfsapi.CodeConflict, fmt.Sprintf("%s isn't mounted at %s", m.Parent, m.Root)}
	}
	return nil
}

// openStaging opens the staging directory, checking only root can use it.
func (m *MountServer) openStaging() (int, error) {
	fd, err := openPath(m.Staging)
	if err != nil {
		return -1, err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	if st.Uid != uint32(m.StagingOwner) || st.Mode&0o077 != 0 {
		syscall.Close(fd)
		return -1, fmt.Errorf("the staging directory %s must be owned by root and mode 0700", m.Staging)
	}
	return fd, nil
}

// place validates a request and opens the directory the bucket's
// dataset goes in.
func (m *MountServer) place(place, bucket string) (base, target, ds string, fd int, err error) {
	if !zfsapi.BucketName.MatchString(bucket) {
		return "", "", "", -1, badRequest("bad bucket name %q", bucket)
	}
	switch place {
	case zfsapi.PlaceBucket:
		if err := m.checkRoot(); err != nil {
			return "", "", "", -1, err
		}
		base = m.Root
		fd, err = openPath(base)
	case zfsapi.PlaceStaging:
		base = m.Staging
		fd, err = m.openStaging()
	default:
		return "", "", "", -1, badRequest("bad place %q", place)
	}
	if err != nil {
		return "", "", "", -1, err
	}
	return base, base + "/" + bucket, m.Parent + "/" + bucket, fd, nil
}

func (m *MountServer) mount(place, bucket string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, target, ds, bfd, err := m.place(place, bucket)
	if err != nil {
		return err
	}
	defer syscall.Close(bfd)
	mounts, err := m.mounts()
	if err != nil {
		return err
	}
	for _, e := range mounts {
		if e.fstype == "zfs" && e.source == ds {
			if e.mountpoint == target {
				return nil
			}
			return &apiError{http.StatusConflict, zfsapi.CodeConflict, fmt.Sprintf("%s is already mounted at %s", ds, e.mountpoint)}
		}
	}
	if e, ok := at(mounts, target); ok {
		return &apiError{http.StatusConflict, zfsapi.CodeConflict, fmt.Sprintf("%s already has %s mounted on it", target, e.source)}
	}
	// A directory left behind in the root would look like a bucket to the
	// gateway: remove it if this made it and the mount doesn't happen.
	created := false
	if err := syscall.Mkdirat(bfd, bucket, 0o700); err == nil {
		created = true
	} else if !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("make %s: %w", target, err)
	}
	mounted := false
	defer func() {
		if created && !mounted {
			unlinkatDir(bfd, bucket)
		}
	}()
	tfd, err := syscall.Openat(bfd, bucket, dirFlags, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) {
			return &apiError{http.StatusConflict, zfsapi.CodeConflict, fmt.Sprintf("%s isn't a directory", target)}
		}
		return fmt.Errorf("open %s: %w", target, err)
	}
	defer syscall.Close(tfd)
	same, err := sameFilesystem(tfd, bfd)
	if err != nil {
		return err
	}
	if !same {
		return &apiError{http.StatusConflict, zfsapi.CodeConflict, fmt.Sprintf("%s is already a mount", target)}
	}
	ents, err := readDirAt(tfd)
	if err != nil {
		return err
	}
	if len(ents) > 0 {
		return &apiError{http.StatusConflict, zfsapi.CodeNotEmpty, fmt.Sprintf("%s isn't empty", target)}
	}
	// Mount on the directory just checked, through its fd, so nothing can
	// swap it in between. mntpoint tells ZFS where it is, for mounting
	// snapshots under .zfs; zfsutil lets it mount a dataset whose
	// mountpoint isn't legacy.
	err = m.Mount(ds, "/proc/self/fd/"+strconv.Itoa(tfd), "zfs",
		syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "zfsutil,mntpoint="+target)
	if errors.Is(err, syscall.ENOENT) {
		return notFound("no dataset %s", ds)
	}
	if err != nil {
		return fmt.Errorf("mount %s at %s: %w", ds, target, err)
	}
	mounted = true
	m.Log.Info("mounted", "dataset", ds, "at", target)
	return nil
}

func (m *MountServer) unmount(place, bucket string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, target, ds, bfd, err := m.place(place, bucket)
	if err != nil {
		return err
	}
	defer syscall.Close(bfd)
	mounts, err := m.mounts()
	if err != nil {
		return err
	}
	if e, ok := at(mounts, target); ok {
		if e.fstype != "zfs" || e.source != ds {
			return &apiError{http.StatusConflict, zfsapi.CodeConflict, fmt.Sprintf("%s has %s mounted on it, not %s", target, e.source, ds)}
		}
		// Snapshots ZFS mounted under .zfs/snapshot hold it busy.
		for _, s := range mounts {
			if strings.HasPrefix(s.mountpoint, target+"/.zfs/snapshot/") && strings.HasPrefix(s.source, ds+"@") {
				if err := m.Unmount(s.mountpoint, umountNoFollow); err != nil && !errors.Is(err, syscall.EINVAL) {
					return busy(fmt.Sprintf("unmount snapshot %s: %v", s.source, err))
				}
			}
		}
		if err := m.Unmount(target, umountNoFollow); err != nil {
			if errors.Is(err, syscall.EBUSY) {
				return busy(fmt.Sprintf("%s is in use", target))
			}
			return fmt.Errorf("unmount %s: %w", target, err)
		}
		m.Log.Info("unmounted", "dataset", ds, "from", target)
	}
	if err := unlinkatDir(bfd, bucket); err != nil &&
		!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ENOTEMPTY) && !errors.Is(err, syscall.EEXIST) {
		m.Log.Warn("couldn't remove the mount directory", "dir", target, "err", err)
	}
	return nil
}

// rootDev is the device number of the filesystem mounted at Root, as
// the host sees it. The helper compares it with what it sees at Root in
// its own mount namespace, which goes stale if the host remounts the
// parent after the helper started.
func (m *MountServer) rootDev() (uint64, error) {
	if err := m.checkRoot(); err != nil {
		return 0, err
	}
	fd, err := openPath(m.Root)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return 0, err
	}
	return st.Dev, nil
}

func busy(msg string) error {
	return &apiError{http.StatusConflict, zfsapi.CodeBusy, msg}
}

func (m *MountServer) Handler() http.Handler {
	mux := http.NewServeMux()
	h := func(pattern string, fn func(place, bucket string) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if err := fn(r.PathValue("p"), r.PathValue("b")); err != nil {
				var ae *apiError
				if !errors.As(err, &ae) {
					ae = &apiError{http.StatusInternalServerError, zfsapi.CodeInternal, err.Error()}
				}
				if ae.status >= 500 {
					m.Log.Error("request failed", "path", r.URL.Path, "err", err)
				}
				writeJSON(w, ae.status, zfsapi.Error{Error: ae.msg, Code: ae.code})
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /root", func(w http.ResponseWriter, r *http.Request) {
		dev, err := m.rootDev()
		if err != nil {
			var ae *apiError
			if !errors.As(err, &ae) {
				ae = &apiError{http.StatusInternalServerError, zfsapi.CodeInternal, err.Error()}
			}
			writeJSON(w, ae.status, zfsapi.Error{Error: ae.msg, Code: ae.code})
			return
		}
		writeJSON(w, http.StatusOK, zfsapi.MountRoot{Dev: dev})
	})
	h("POST /mount/{p}/{b}", m.mount)
	h("POST /unmount/{p}/{b}", m.unmount)
	return mux
}
