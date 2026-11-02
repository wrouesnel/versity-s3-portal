// Package zfshelper is s3-zfs-helper's server: a small JSON API, served to
// the portal over a unix socket, that keeps each S3 bucket in its own ZFS
// dataset, with quotas, a backup flag and snapshots the portal can browse
// and restore from.
//
// It runs as root on the host, so it trusts nothing it's sent: bucket and
// snapshot names must match zfsapi's patterns, it only touches datasets
// that are direct children of its parent dataset, and every path below a
// bucket is walked without following symlinks.
package zfshelper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wrouesnel/versity-s3-portal/internal/zfsapi"
)

// Config sets up a Server.
type Config struct {
	// Parent is the dataset whose children are buckets, e.g.
	// storage/s3/buckets.
	Parent string
	// Root is where Parent is mounted, and so where the gateway keeps
	// buckets, e.g. /storage/s3/buckets.
	Root string
	// Run runs zfs.
	Run Runner
	Log *slog.Logger
	// Now is the clock, for snapshot names.
	Now func() time.Time
}

type Server struct {
	Config
	// mu serialises everything that changes datasets or files.
	mu sync.Mutex
}

func New(c Config) *Server {
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	c.Root = strings.TrimRight(c.Root, "/")
	return &Server{Config: c}
}

func (s *Server) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	return s.Run(ctx, args...)
}

// Check makes sure the parent dataset is mounted where Root says.
func (s *Server) Check(ctx context.Context) error {
	mp, ok, err := s.mountpoint(ctx, s.Parent)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("parent dataset %s doesn't exist", s.Parent)
	}
	if mp != s.Root {
		return fmt.Errorf("parent dataset %s is mounted at %s, not %s", s.Parent, mp, s.Root)
	}
	return nil
}

// apiError is an error with the response it should get.
type apiError struct {
	status int
	code   string
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return &apiError{http.StatusBadRequest, zfsapi.CodeBadRequest, fmt.Sprintf(format, args...)}
}

func notFound(format string, args ...any) error {
	return &apiError{http.StatusNotFound, zfsapi.CodeNotFound, fmt.Sprintf(format, args...)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	h := func(pattern string, fn func(w http.ResponseWriter, r *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := fn(w, r); err != nil {
				s.fail(w, r, err)
			}
		})
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	h("POST /buckets/{b}/adopt", s.adopt)
	h("GET /buckets/{b}", s.getBucket)
	h("DELETE /buckets/{b}", s.destroy)
	h("PUT /buckets/{b}/quota", s.putQuota)
	h("PUT /buckets/{b}/backup", s.putBackup)
	h("GET /buckets/{b}/snapshots", s.listSnapshots)
	h("POST /buckets/{b}/snapshots", s.createSnapshot)
	h("DELETE /buckets/{b}/snapshots/{s}", s.deleteSnapshot)
	h("GET /buckets/{b}/snapshots/{s}/list", s.listSnapshotObjects)
	h("GET /buckets/{b}/snapshots/{s}/object", s.getSnapshotObject)
	h("POST /buckets/{b}/snapshots/{s}/restore", s.restore)
	return mux
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		ae = &apiError{http.StatusInternalServerError, zfsapi.CodeInternal, err.Error()}
		s.Log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	} else if ae.status >= 500 {
		s.Log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	}
	writeJSON(w, ae.status, zfsapi.Error{Error: ae.msg, Code: ae.code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest("bad request body: %v", err)
	}
	return nil
}

// bucket validates the request's bucket and returns its dataset and path.
func (s *Server) bucket(r *http.Request) (name, ds, dir string, err error) {
	name = r.PathValue("b")
	if !zfsapi.BucketName.MatchString(name) {
		return "", "", "", badRequest("bad bucket name %q", name)
	}
	return name, s.Parent + "/" + name, s.Root + "/" + name, nil
}

// dataset is bucket, also requiring the bucket to be one of our datasets.
func (s *Server) dataset(r *http.Request) (name, ds, dir string, err error) {
	name, ds, dir, err = s.bucket(r)
	if err != nil {
		return
	}
	mp, ok, err := s.mountpoint(r.Context(), ds)
	if err != nil {
		return
	}
	if !ok {
		return "", "", "", &apiError{http.StatusNotFound, zfsapi.CodeNotDataset, fmt.Sprintf("bucket %s isn't a dataset", name)}
	}
	if mp != dir {
		return "", "", "", &apiError{http.StatusConflict, zfsapi.CodeConflict, fmt.Sprintf("dataset %s is mounted at %s, not %s", ds, mp, dir)}
	}
	return
}

// snapshot validates the request's snapshot name and checks it exists.
func (s *Server) snapshot(r *http.Request, ds string) (string, error) {
	snap := r.PathValue("s")
	if !zfsapi.SnapshotName.MatchString(snap) {
		return "", badRequest("bad snapshot name %q", snap)
	}
	ok, err := s.hasSnapshot(r.Context(), ds, snap)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", notFound("no snapshot %s", snap)
	}
	return snap, nil
}

// internal says whether a name at a bucket's root is the gateway's or
// ZFS's rather than an object.
func internal(name string) bool { return name == ".sgwtmp" || name == ".zfs" }

// ------------------------------------------------------------------ adopt

// adopt turns a bucket the gateway just made, still an empty directory,
// into a dataset mounted in its place, carrying over the directory's
// owner, mode and xattrs (where the gateway keeps the bucket's owner, ACL
// and policy). If it's already a dataset, it does nothing.
func (s *Server) adopt(w http.ResponseWriter, r *http.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := r.Context()
	name, ds, dir, err := s.bucket(r)
	if err != nil {
		return err
	}
	mp, exists, err := s.mountpoint(ctx, ds)
	if err != nil {
		return err
	}
	if exists {
		if mp != dir {
			return &apiError{http.StatusConflict, zfsapi.CodeConflict, fmt.Sprintf("dataset %s is mounted at %s, not %s", ds, mp, dir)}
		}
		writeJSON(w, http.StatusOK, map[string]string{"dataset": ds})
		return nil
	}

	fd, err := openRoot(dir)
	if errors.Is(err, syscall.ENOENT) {
		return notFound("no bucket directory %s", dir)
	}
	if err != nil {
		return err
	}
	m, err := readMeta(fd)
	if err == nil {
		err = removeEmptyInternals(fd)
	}
	syscall.Close(fd)
	if err != nil {
		return err
	}

	if err := syscall.Rmdir(dir); err != nil {
		return fmt.Errorf("remove bucket directory: %w", err)
	}
	// putBack restores the directory as it was, if adopting fails.
	putBack := func() {
		if err := syscall.Mkdir(dir, 0o700); err != nil {
			s.Log.Error("couldn't recreate bucket directory", "bucket", name, "err", err)
			return
		}
		fd, err := openRoot(dir)
		if err == nil {
			err = m.apply(fd, true)
			syscall.Close(fd)
		}
		if err != nil {
			s.Log.Error("couldn't restore bucket directory's metadata", "bucket", name, "err", err)
		}
	}
	if _, err := s.run(ctx, "create", "-o", "mountpoint="+dir, ds); err != nil {
		putBack()
		return err
	}
	fd, err = openRoot(dir)
	if err == nil {
		err = m.apply(fd, true)
		syscall.Close(fd)
	}
	if err != nil {
		if _, derr := s.run(context.WithoutCancel(ctx), "destroy", ds); derr != nil {
			s.Log.Error("couldn't destroy half-adopted dataset", "dataset", ds, "err", derr)
		} else {
			syscall.Rmdir(dir)
			putBack()
		}
		return fmt.Errorf("set up dataset root: %w", err)
	}
	s.Log.Info("adopted bucket", "bucket", name, "dataset", ds)
	writeJSON(w, http.StatusCreated, map[string]string{"dataset": ds})
	return nil
}

// removeEmptyInternals checks the bucket directory fd holds nothing but
// the gateway's temporary directory, itself holding only directories, and
// removes those. Anything else means it isn't a new, empty bucket.
func removeEmptyInternals(fd int) error {
	ents, err := readDirAt(fd)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.name != ".sgwtmp" || !e.isDir() {
			return &apiError{http.StatusConflict, zfsapi.CodeNotEmpty, "the bucket directory isn't empty"}
		}
	}
	for _, e := range ents {
		if err := removeDirsOnly(fd, e.name); err != nil {
			return err
		}
	}
	return nil
}

// removeDirsOnly removes the directory name below dirfd, and directories
// in it, failing if it holds anything else.
func removeDirsOnly(dirfd int, name string) error {
	fd, err := openDirAt(dirfd, []string{name}, nil)
	if err != nil {
		return err
	}
	ents, err := readDirAt(fd)
	if err == nil {
		for _, e := range ents {
			if !e.isDir() {
				err = &apiError{http.StatusConflict, zfsapi.CodeNotEmpty, "the bucket has uploads in progress"}
				break
			}
			if err = removeDirsOnly(fd, e.name); err != nil {
				break
			}
		}
	}
	syscall.Close(fd)
	if err != nil {
		return err
	}
	return unlinkatDir(dirfd, name)
}

const atRemoveDir = 0x200

func unlinkatDir(dirfd int, name string) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(dirfd), uintptr(unsafePointer(p)), atRemoveDir)
	if errno != 0 {
		return errno
	}
	return nil
}

// ---------------------------------------------------------------- buckets

func (s *Server) getBucket(w http.ResponseWriter, r *http.Request) error {
	_, ds, _, err := s.dataset(r)
	if err != nil {
		return err
	}
	info, err := s.info(r.Context(), ds)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, info)
	return nil
}

// destroy destroys an empty bucket's dataset, with its snapshots (the
// host's included). Empty means what the gateway means: nothing at the
// dataset's root but the gateway's temporary directory. An empty folder
// is a folder object, so it counts.
func (s *Server) destroy(w http.ResponseWriter, r *http.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, ds, dir, err := s.dataset(r)
	if err != nil {
		return err
	}
	fd, err := openRoot(dir)
	if err != nil {
		return err
	}
	ents, err := readDirAt(fd)
	syscall.Close(fd)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if !internal(e.name) {
			return &apiError{http.StatusConflict, zfsapi.CodeNotEmpty, fmt.Sprintf("bucket %s isn't empty", name)}
		}
	}
	if _, err := s.run(r.Context(), "destroy", "-r", ds); err != nil {
		return err
	}
	// zfs normally removes the mountpoint; if it's left, remove it so the
	// gateway no longer sees a bucket there.
	if err := syscall.Rmdir(dir); err != nil && !errors.Is(err, syscall.ENOENT) {
		s.Log.Warn("couldn't remove the old mountpoint", "dir", dir, "err", err)
	}
	s.Log.Info("destroyed bucket dataset", "bucket", name, "dataset", ds)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) putQuota(w http.ResponseWriter, r *http.Request) error {
	var q zfsapi.Quota
	if err := readJSON(r, &q); err != nil {
		return err
	}
	if q.Bytes < 0 {
		return badRequest("quota can't be negative")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, ds, _, err := s.dataset(r)
	if err != nil {
		return err
	}
	if err := s.setRefquota(r.Context(), ds, q.Bytes); err != nil {
		return err
	}
	s.Log.Info("set quota", "bucket", name, "bytes", q.Bytes)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) putBackup(w http.ResponseWriter, r *http.Request) error {
	var b zfsapi.Backup
	if err := readJSON(r, &b); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, ds, _, err := s.dataset(r)
	if err != nil {
		return err
	}
	if err := s.setBackup(r.Context(), ds, b.Include); err != nil {
		return err
	}
	s.Log.Info("set backup", "bucket", name, "include", b.Include)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// -------------------------------------------------------------- snapshots

func (s *Server) listSnapshots(w http.ResponseWriter, r *http.Request) error {
	_, ds, _, err := s.dataset(r)
	if err != nil {
		return err
	}
	snaps, err := s.snapshots(r.Context(), ds)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, snaps)
	return nil
}

func (s *Server) createSnapshot(w http.ResponseWriter, r *http.Request) error {
	var req zfsapi.NewSnapshot
	if err := readJSON(r, &req); err != nil {
		return err
	}
	if req.Label != "" && !zfsapi.SnapshotLabel.MatchString(req.Label) {
		return badRequest("labels are up to 32 lowercase letters, digits and hyphens")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket, ds, _, err := s.dataset(r)
	if err != nil {
		return err
	}
	now := s.Now().UTC()
	name := zfsapi.SnapshotPrefix + now.Format(zfsapi.SnapshotTimeFormat)
	if req.Label != "" {
		name += "-" + req.Label
	}
	if _, err := s.run(r.Context(), "snapshot", ds+"@"+name); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return &apiError{http.StatusConflict, zfsapi.CodeConflict, "a snapshot with that name already exists; try again in a second"}
		}
		return err
	}
	s.Log.Info("created snapshot", "bucket", bucket, "snapshot", name)
	writeJSON(w, http.StatusCreated, zfsapi.Snapshot{Name: name, Created: now.Truncate(time.Second)})
	return nil
}

func (s *Server) deleteSnapshot(w http.ResponseWriter, r *http.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket, ds, _, err := s.dataset(r)
	if err != nil {
		return err
	}
	snap, err := s.snapshot(r, ds)
	if err != nil {
		return err
	}
	if _, err := s.run(r.Context(), "destroy", ds+"@"+snap); err != nil {
		return err
	}
	s.Log.Info("destroyed snapshot", "bucket", bucket, "snapshot", snap)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// snapRoot opens a snapshot's root directory.
func (s *Server) snapRoot(r *http.Request) (fd int, dir string, err error) {
	_, ds, dir, err := s.dataset(r)
	if err != nil {
		return -1, "", err
	}
	snap, err := s.snapshot(r, ds)
	if err != nil {
		return -1, "", err
	}
	fd, err = openRoot(dir + "/.zfs/snapshot/" + snap)
	return fd, dir, err
}

const maxListKeys = 1000

// maxWalk bounds a recursive listing or restore.
const maxWalk = 200000

func (s *Server) listSnapshotObjects(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	prefix, delimiter, startAfter := q.Get("prefix"), q.Get("delimiter"), q.Get("start-after")
	if delimiter != "" && delimiter != "/" {
		return badRequest("the delimiter can only be / or nothing")
	}
	max := maxListKeys
	if v := q.Get("max-keys"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return badRequest("bad max-keys")
		}
		max = min(n, maxListKeys)
	}
	if len(prefix) > maxKeyLen || strings.ContainsRune(prefix, 0) || strings.HasPrefix(prefix, "/") {
		return badRequest("bad prefix")
	}
	root, _, err := s.snapRoot(r)
	if err != nil {
		return err
	}
	defer syscall.Close(root)

	dirPart, namePart := "", prefix
	if i := strings.LastIndex(prefix, "/"); i >= 0 {
		dirPart, namePart = prefix[:i+1], prefix[i+1:]
	}
	parts, err := splitPrefix(dirPart)
	if err != nil {
		return badRequest("%v", err)
	}
	out := zfsapi.ObjectList{Objects: []zfsapi.Object{}, Prefixes: []string{}}
	dirfd, err := openDirAt(root, parts, nil)
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR) {
		writeJSON(w, http.StatusOK, out)
		return nil
	}
	if err != nil {
		return err
	}
	defer syscall.Close(dirfd)

	// Every key or common prefix, then sorted and paged.
	type item struct {
		key    string
		prefix bool
		obj    zfsapi.Object
	}
	var items []item
	ents, err := readDirAt(dirfd)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if (dirPart == "" && internal(e.name)) || !strings.HasPrefix(e.name, namePart) {
			continue
		}
		key := dirPart + e.name
		switch {
		case e.isDir() && delimiter == "/":
			items = append(items, item{key: key + "/", prefix: true})
		case e.isDir():
			var objs []zfsapi.Object
			if err := walkObjects(dirfd, e.name, key+"/", &objs); err != nil {
				return err
			}
			for _, o := range objs {
				items = append(items, item{key: o.Key, obj: o})
			}
		case e.isRegular():
			items = append(items, item{key: key, obj: objectOf(key, e.st)})
		}
		if len(items) > maxWalk {
			return badRequest("too many objects to list at once; use a longer prefix or a delimiter")
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })
	for _, it := range items {
		if it.key <= startAfter {
			continue
		}
		if len(out.Objects)+len(out.Prefixes) == max {
			out.NextStartAfter = lastKey(out)
			break
		}
		if it.prefix {
			out.Prefixes = append(out.Prefixes, it.key)
		} else {
			out.Objects = append(out.Objects, it.obj)
		}
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func lastKey(l zfsapi.ObjectList) string {
	last := ""
	if n := len(l.Objects); n > 0 {
		last = l.Objects[n-1].Key
	}
	if n := len(l.Prefixes); n > 0 && l.Prefixes[n-1] > last {
		last = l.Prefixes[n-1]
	}
	return last
}

func objectOf(key string, st syscall.Stat_t) zfsapi.Object {
	return zfsapi.Object{Key: key, Size: st.Size, Modified: time.Unix(st.Mtim.Unix()).UTC()}
}

// walkObjects lists every object under the directory name in dirfd, whose
// key prefix is keyPrefix. A directory carrying the gateway's etag xattr
// is a folder object in its own right.
func walkObjects(dirfd int, name, keyPrefix string, out *[]zfsapi.Object) error {
	fd, err := openDirAt(dirfd, []string{name}, nil)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if _, err := fgetxattr(fd, "user.etag"); err == nil {
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			return err
		}
		o := objectOf(keyPrefix, st)
		o.Size = 0
		*out = append(*out, o)
	}
	ents, err := readDirAt(fd)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if len(*out) > maxWalk {
			return badRequest("too many objects to list at once; use a longer prefix")
		}
		switch {
		case e.isDir():
			if err := walkObjects(fd, e.name, keyPrefix+e.name+"/", out); err != nil {
				return err
			}
		case e.isRegular():
			*out = append(*out, objectOf(keyPrefix+e.name, e.st))
		}
	}
	return nil
}

func (s *Server) getSnapshotObject(w http.ResponseWriter, r *http.Request) error {
	parts, dir, err := splitKey(r.URL.Query().Get("key"))
	if err != nil || dir {
		return badRequest("bad key")
	}
	root, _, err := s.snapRoot(r)
	if err != nil {
		return err
	}
	defer syscall.Close(root)
	if internal(parts[0]) {
		return notFound("no such object")
	}
	f, err := openFileAt(root, parts)
	if errors.Is(err, syscall.ENOENT) {
		return notFound("no such object")
	}
	if err != nil {
		return badRequest("%v", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	w.Header().Set("Last-Modified", st.ModTime().UTC().Format(http.TimeFormat))
	if _, err := io.Copy(w, f); err != nil {
		s.Log.Warn("snapshot download cut short", "path", r.URL.Path, "err", err)
	}
	return nil
}

// restore copies an object, or everything under a prefix, from a snapshot
// back into the live bucket, overwriting what's there. Objects only in
// the live bucket are left alone. Each file is written beside its target
// and renamed into place, with the snapshot's owner, mode, times and
// xattrs (the gateway's etag and content type among them).
func (s *Server) restore(w http.ResponseWriter, r *http.Request) error {
	var req zfsapi.Restore
	if err := readJSON(r, &req); err != nil {
		return err
	}
	if (req.Key != "") == (req.Prefix != "" || req.All) {
		return badRequest("give a key, or a prefix (or all for the whole bucket)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	root, dir, err := s.snapRoot(r)
	if err != nil {
		return err
	}
	defer syscall.Close(root)
	live, err := openRoot(dir)
	if err != nil {
		return err
	}
	defer syscall.Close(live)

	n := 0
	if req.Key != "" {
		parts, isDir, err := splitKey(req.Key)
		if err != nil {
			return badRequest("%v", err)
		}
		if internal(parts[0]) {
			return notFound("no such object")
		}
		if err := restoreOne(root, live, parts, isDir); err != nil {
			if errors.Is(err, syscall.ENOENT) {
				return notFound("no such object in the snapshot")
			}
			return err
		}
		n = 1
	} else {
		parts, err := splitPrefix(req.Prefix)
		if err != nil {
			return badRequest("%v", err)
		}
		if len(parts) > 0 && internal(parts[0]) {
			return notFound("no such folder")
		}
		var objs []zfsapi.Object
		if len(parts) == 0 {
			ents, err := readDirAt(root)
			if err != nil {
				return err
			}
			for _, e := range ents {
				switch {
				case internal(e.name):
				case e.isDir():
					if err := walkObjects(root, e.name, e.name+"/", &objs); err != nil {
						return err
					}
				case e.isRegular():
					objs = append(objs, zfsapi.Object{Key: e.name})
				}
			}
		} else {
			parent, err := openDirAt(root, parts[:len(parts)-1], nil)
			if err != nil {
				if errors.Is(err, syscall.ENOENT) {
					return notFound("no such folder in the snapshot")
				}
				return err
			}
			err = walkObjects(parent, parts[len(parts)-1], req.Prefix, &objs)
			syscall.Close(parent)
			if errors.Is(err, syscall.ENOENT) {
				return notFound("no such folder in the snapshot")
			}
			if err != nil {
				return err
			}
		}
		for _, o := range objs {
			p, isDir, err := splitKey(o.Key)
			if err != nil {
				return err
			}
			if err := restoreOne(root, live, p, isDir); err != nil {
				return fmt.Errorf("restore %s: %w", o.Key, err)
			}
			n++
		}
	}
	s.Log.Info("restored from snapshot", "path", r.URL.Path, "key", req.Key, "prefix", req.Prefix, "all", req.All, "objects", n)
	writeJSON(w, http.StatusOK, zfsapi.Restored{Objects: n})
	return nil
}

// restoreOne restores the object parts (a folder object if isDir) from the
// snapshot root into live, creating missing folders with the snapshot's
// metadata.
func restoreOne(root, live int, parts []string, isDir bool) error {
	dirParts := parts
	if !isDir {
		dirParts = parts[:len(parts)-1]
	}
	// Copy each created folder's metadata from the snapshot.
	mkdir := func(rel string, fd int) error {
		src, err := openDirAt(root, strings.Split(rel, "/"), nil)
		if err != nil {
			return err
		}
		defer syscall.Close(src)
		m, err := readMeta(src)
		if err != nil {
			return err
		}
		return m.apply(fd, true)
	}
	dirfd, err := openDirAt(live, dirParts, mkdir)
	if err != nil {
		return err
	}
	defer syscall.Close(dirfd)
	if isDir {
		// The folder exists now; bring back its own metadata too.
		return mkdir(strings.Join(parts, "/"), dirfd)
	}
	src, err := openFileAt(root, parts)
	if err != nil {
		return err
	}
	defer src.Close()
	return copyFileInto(src, dirfd, path.Base(strings.Join(parts, "/")))
}
