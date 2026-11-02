package zfshelper

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// The helper runs as root over directories whose contents belong to other
// people. Everything below a bucket's root is reached one component at a
// time with openat and O_NOFOLLOW, so a symlink anywhere in a path is
// refused rather than followed, and nothing can be swapped for a link
// between a check and its use.

var errSymlink = errors.New("refusing to follow a symlink")

const (
	dirFlags  = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	maxKeyLen = 1024
	// oPath is O_PATH, which package syscall doesn't name.
	oPath = 0x200000
	// atRemoveDir is AT_REMOVEDIR, for unlinkat.
	atRemoveDir = 0x200
)

// splitKey splits an object key into path components. A trailing slash
// (a directory object) is dropped; dir reports it.
func splitKey(key string) (parts []string, dir bool, err error) {
	if key == "" || len(key) > maxKeyLen || strings.HasPrefix(key, "/") || strings.ContainsRune(key, 0) {
		return nil, false, fmt.Errorf("bad key %q", key)
	}
	dir = strings.HasSuffix(key, "/")
	parts = strings.Split(strings.TrimSuffix(key, "/"), "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, false, fmt.Errorf("bad key %q", key)
		}
	}
	return parts, dir, nil
}

// splitPrefix accepts "" or a folder path ending in "/".
func splitPrefix(prefix string) ([]string, error) {
	if prefix == "" {
		return nil, nil
	}
	if !strings.HasSuffix(prefix, "/") {
		return nil, fmt.Errorf("prefix %q must end in /", prefix)
	}
	parts, _, err := splitKey(prefix)
	return parts, err
}

func symlinkErr(err error) error {
	if errors.Is(err, syscall.ELOOP) {
		return errSymlink
	}
	return err
}

// openRoot opens a directory the helper trusts by path: the buckets root,
// a bucket's root or the staging directory, whose parents only root can
// change. The last component must not be a link.
func openRoot(path string) (int, error) {
	fd, err := syscall.Open(path, dirFlags, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOTDIR) {
			err = errSymlink
		}
		return -1, &os.PathError{Op: "open", Path: path, Err: symlinkErr(err)}
	}
	return fd, nil
}

// openDirAt opens the directory parts below dirfd, refusing links.
// mkdir, when set, creates missing directories, and is given each one's
// relative path and fd to set its owner and mode.
func openDirAt(dirfd int, parts []string, mkdir func(rel string, fd int) error) (int, error) {
	fd, err := syscall.Dup(dirfd)
	if err != nil {
		return -1, err
	}
	syscall.CloseOnExec(fd)
	for i, p := range parts {
		next, err := syscall.Openat(fd, p, dirFlags, 0)
		if errors.Is(err, syscall.ENOENT) && mkdir != nil {
			if err = syscall.Mkdirat(fd, p, 0o700); err == nil || errors.Is(err, syscall.EEXIST) {
				next, err = syscall.Openat(fd, p, dirFlags, 0)
				if err == nil {
					err = mkdir(strings.Join(parts[:i+1], "/"), next)
					if err != nil {
						syscall.Close(next)
					}
				}
			}
		}
		syscall.Close(fd)
		if err != nil {
			if errors.Is(err, syscall.ENOTDIR) {
				err = fmt.Errorf("%s is not a folder (or is a link): %w", strings.Join(parts[:i+1], "/"), syscall.ENOTDIR)
			}
			return -1, symlinkErr(err)
		}
		fd = next
	}
	return fd, nil
}

// openFileAt opens the regular file parts below dirfd for reading. It
// first takes an O_PATH handle and checks that's a regular file, so a
// FIFO or device is never opened, then reopens that same inode for
// reading through /proc/self/fd and checks it's still the same one.
func openFileAt(dirfd int, parts []string) (*os.File, error) {
	dir, err := openDirAt(dirfd, parts[:len(parts)-1], nil)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dir)
	name := strings.Join(parts, "/")
	pfd, err := syscall.Openat(dir, parts[len(parts)-1], oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, symlinkErr(err)
	}
	defer syscall.Close(pfd)
	var want syscall.Stat_t
	if err := syscall.Fstat(pfd, &want); err != nil {
		return nil, err
	}
	if want.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		return nil, errSymlink
	}
	if want.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, fmt.Errorf("%s is not a file", name)
	}
	fd, err := syscall.Open(fmt.Sprintf("/proc/self/fd/%d", pfd), syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var got syscall.Stat_t
	if err := syscall.Fstat(fd, &got); err != nil || got.Dev != want.Dev || got.Ino != want.Ino {
		syscall.Close(fd)
		return nil, fmt.Errorf("%s changed while it was being opened", name)
	}
	return os.NewFile(uintptr(fd), name), nil
}

// sameFilesystem says whether two open directories are on the same
// filesystem. Each ZFS dataset has its own fsid, so a bucket's root is on
// a different one from its parent only when its dataset is really
// mounted there.
func sameFilesystem(a, b int) (bool, error) {
	var sa, sb syscall.Statfs_t
	if err := syscall.Fstatfs(a, &sa); err != nil {
		return false, err
	}
	if err := syscall.Fstatfs(b, &sb); err != nil {
		return false, err
	}
	var da, db syscall.Stat_t
	if err := syscall.Fstat(a, &da); err != nil {
		return false, err
	}
	if err := syscall.Fstat(b, &db); err != nil {
		return false, err
	}
	return sa.Fsid == sb.Fsid && da.Dev == db.Dev, nil
}

// lstatAt stats name in dirfd without following a symlink. (Package
// syscall has no portable fstatat, so this opens an O_PATH handle.)
func lstatAt(dirfd int, name string, st *syscall.Stat_t) error {
	fd, err := syscall.Openat(dirfd, name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return syscall.Fstat(fd, st)
}

func unlinkatDir(dirfd int, name string) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(dirfd), uintptr(unsafe.Pointer(p)), atRemoveDir)
	if errno != 0 {
		return errno
	}
	return nil
}

// ------------------------------------------------------------------ xattrs

func flistxattr(fd int) ([]string, error) {
	for size := 1024; size <= 1<<20; size *= 4 {
		buf := make([]byte, size)
		n, _, errno := syscall.Syscall(syscall.SYS_FLISTXATTR, uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if errno == syscall.ERANGE {
			continue
		}
		if errno == syscall.ENOTSUP {
			return nil, nil
		}
		if errno != 0 {
			return nil, errno
		}
		var names []string
		for _, name := range strings.Split(string(buf[:n]), "\x00") {
			if name != "" {
				names = append(names, name)
			}
		}
		return names, nil
	}
	return nil, syscall.ERANGE
}

func fgetxattr(fd int, name string) ([]byte, error) {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	for size := 4096; size <= 1<<20; size *= 4 {
		buf := make([]byte, size)
		n, _, errno := syscall.Syscall6(syscall.SYS_FGETXATTR, uintptr(fd), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
		if errno == syscall.ERANGE {
			continue
		}
		if errno != 0 {
			return nil, errno
		}
		return buf[:n], nil
	}
	return nil, syscall.ERANGE
}

func fsetxattr(fd int, name string, value []byte) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	var v unsafe.Pointer
	if len(value) > 0 {
		v = unsafe.Pointer(&value[0])
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_FSETXATTR, uintptr(fd), uintptr(unsafe.Pointer(p)), uintptr(v), uintptr(len(value)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// copiedXattr says whether an xattr is carried over when a file or
// directory is copied or moved: the gateway's own (user.*) and POSIX
// ACLs, and nothing else (never security.* or trusted.*).
func copiedXattr(name string) bool {
	return strings.HasPrefix(name, "user.") || strings.HasPrefix(name, "system.posix_acl_")
}

// xattrs is a file's extended attributes.
type xattrs map[string][]byte

func readXattrs(fd int) (xattrs, error) {
	names, err := flistxattr(fd)
	if err != nil {
		return nil, fmt.Errorf("list xattrs: %w", err)
	}
	out := xattrs{}
	for _, n := range names {
		if !copiedXattr(n) {
			continue
		}
		v, err := fgetxattr(fd, n)
		if errors.Is(err, syscall.ENODATA) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("get xattr %s: %w", n, err)
		}
		out[n] = v
	}
	return out, nil
}

// writeXattrs sets attrs on fd. The gateway's own attributes (user.*)
// must all be set; POSIX ACLs are copied when the filesystem allows.
func writeXattrs(fd int, attrs xattrs) error {
	for n, v := range attrs {
		if !copiedXattr(n) {
			continue
		}
		if err := fsetxattr(fd, n, v); err != nil && strings.HasPrefix(n, "user.") {
			return fmt.Errorf("set xattr %s: %w", n, err)
		}
	}
	return nil
}

// meta is what's kept of a file or directory when it's copied or moved.
type meta struct {
	UID    int              `json:"uid"`
	GID    int              `json:"gid"`
	Mode   uint32           `json:"mode"` // permission bits, and sticky on directories
	Mtime  syscall.Timespec `json:"mtime"`
	Atime  syscall.Timespec `json:"atime"`
	Xattrs xattrs           `json:"xattrs"`
}

// readMeta reads fd's metadata. Setuid and setgid bits are never kept,
// and sticky only on directories.
func readMeta(fd int) (*meta, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, err
	}
	x, err := readXattrs(fd)
	if err != nil {
		return nil, err
	}
	mode := st.Mode & 0o777
	if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
		mode |= st.Mode & syscall.S_ISVTX
	}
	return &meta{
		UID: int(st.Uid), GID: int(st.Gid), Mode: mode,
		Mtime: st.Mtim, Atime: st.Atim, Xattrs: x,
	}, nil
}

// apply sets m on fd, times last since setting the others can bump them.
func (m *meta) apply(fd int, times bool) error {
	if err := syscall.Fchown(fd, m.UID, m.GID); err != nil {
		return fmt.Errorf("chown: %w", err)
	}
	if err := syscall.Fchmod(fd, m.Mode&(0o777|syscall.S_ISVTX)); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if err := writeXattrs(fd, m.Xattrs); err != nil {
		return err
	}
	if times {
		tv := []syscall.Timeval{syscall.NsecToTimeval(syscall.TimespecToNsec(m.Atime)), syscall.NsecToTimeval(syscall.TimespecToNsec(m.Mtime))}
		if err := syscall.Futimes(fd, tv); err != nil {
			return fmt.Errorf("set times: %w", err)
		}
	}
	return nil
}

// copyFileInto copies src into the directory dirfd as name: written to a
// temporary file beside it with src's owner, mode, xattrs and times, then
// renamed over whatever was there. A directory in the way is an error.
func copyFileInto(src *os.File, dirfd int, name string) error {
	m, err := readMeta(int(src.Fd()))
	if err != nil {
		return err
	}
	m.Mode &= 0o777
	var st syscall.Stat_t
	if err := lstatAt(dirfd, name, &st); err == nil && st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
		return fmt.Errorf("%s is a folder in the live bucket", name)
	}
	tmp := ".s3zfs-restore-" + randomSuffix()
	fd, err := syscall.Openat(dirfd, tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	dst := os.NewFile(uintptr(fd), tmp)
	ok := false
	defer func() {
		if !ok {
			dst.Close()
			syscall.Unlinkat(dirfd, tmp)
		}
	}()
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	if err := m.apply(fd, true); err != nil {
		return err
	}
	if err := dst.Sync(); err != nil {
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	if err := syscall.Renameat(dirfd, tmp, dirfd, name); err != nil {
		return err
	}
	ok = true
	return nil
}

func randomSuffix() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b)
}

// maxDirEntries bounds how many entries one directory may have before the
// helper gives up on it.
var maxDirEntries = 100000

var errTooManyEntries = errors.New("a folder has too many entries")

// readDirAt lists the directory fd (without . and ..), with each entry's
// lstat, reading in batches and stopping at maxDirEntries. The fd is left
// open.
func readDirAt(fd int) ([]dirEntry, error) {
	dup, err := syscall.Dup(fd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "dir")
	defer f.Close()
	// A dup shares the original's offset.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var out []dirEntry
	for {
		names, err := f.Readdirnames(1024)
		for _, n := range names {
			var st syscall.Stat_t
			if err := lstatAt(fd, n, &st); err != nil {
				if errors.Is(err, syscall.ENOENT) {
					continue
				}
				return nil, err
			}
			out = append(out, dirEntry{name: n, st: st})
		}
		if len(out) > maxDirEntries {
			return nil, errTooManyEntries
		}
		if errors.Is(err, io.EOF) || (err == nil && len(names) == 0) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

type dirEntry struct {
	name string
	st   syscall.Stat_t
}

func (e dirEntry) isDir() bool     { return e.st.Mode&syscall.S_IFMT == syscall.S_IFDIR }
func (e dirEntry) isRegular() bool { return e.st.Mode&syscall.S_IFMT == syscall.S_IFREG }
