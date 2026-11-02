// Package zfshelper is s3-zfs-helper's server: a small JSON API, served to
// the portal over a unix socket, that keeps each S3 bucket in its own ZFS
// dataset, with quotas, a backup flag and snapshots the portal can browse
// and restore from.
//
// It runs as root on the host, so it trusts nothing it's sent: bucket and
// snapshot names must match zfsapi's patterns, it only touches datasets
// that are direct children of its parent dataset and really mounted where
// they should be, and every path below a bucket is walked without
// following symlinks.
package zfshelper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
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
	// Trash is the dataset deleted buckets are moved under, unmounted,
	// e.g. storage/s3/trash. It must be in Parent's pool and not inside
	// Parent, and should have canmount=off and mountpoint=none. Default:
	// "trash" beside Parent.
	Trash string
	// Staging is a root-only (0700) directory on the same host, outside
	// Root, where new datasets are first mounted and set up before they
	// take a bucket's place. Default: .s3-zfs-staging beside Root.
	Staging string
	// StateDir keeps a bucket directory's metadata while it's being
	// adopted, so a crash can't lose it. Default /var/lib/s3-zfs-helper.
	StateDir string
	// Run runs zfs.
	Run Runner
	Log *slog.Logger
	// Now is the clock, for snapshot names.
	Now func() time.Time
	// MaxReads bounds concurrent read requests (default 8), and
	// MaxRestores concurrent restores (default 2).
	MaxReads, MaxRestores int
	// SkipMountCheck turns off the check that a bucket's dataset is a
	// different filesystem from its parent, for tests with a fake zfs.
	SkipMountCheck bool
}

type Server struct {
	Config

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex
	reads   chan struct{}
	restore chan struct{}
}

func New(c Config) *Server {
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	c.Root = strings.TrimRight(c.Root, "/")
	if c.Staging == "" {
		c.Staging = filepath.Join(filepath.Dir(c.Root), ".s3-zfs-staging")
	}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/s3-zfs-helper"
	}
	if c.Trash == "" {
		c.Trash = path.Join(path.Dir(c.Parent), "trash")
	}
	if c.MaxReads <= 0 {
		c.MaxReads = 8
	}
	if c.MaxRestores <= 0 {
		c.MaxRestores = 2
	}
	return &Server{
		Config:  c,
		locks:   map[string]*sync.Mutex{},
		reads:   make(chan struct{}, c.MaxReads),
		restore: make(chan struct{}, c.MaxRestores),
	}
}

// lock serialises changes to one bucket, so a long restore in one bucket
// doesn't hold up the others.
func (s *Server) lock(bucket string) func() {
	s.locksMu.Lock()
	m, ok := s.locks[bucket]
	if !ok {
		m = &sync.Mutex{}
		s.locks[bucket] = m
	}
	s.locksMu.Unlock()
	m.Lock()
	return m.Unlock
}

// acquire takes a slot in sem, waiting a little, or reports the helper
// busy.
func acquire(ctx context.Context, sem chan struct{}) (func(), error) {
	t := time.NewTimer(10 * time.Second)
	defer t.Stop()
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.C:
		return nil, &apiError{http.StatusServiceUnavailable, zfsapi.CodeBusy, "the zfs helper is busy; try again shortly"}
	}
}

func (s *Server) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	return s.Run(ctx, args...)
}

// Check makes sure the parent dataset is mounted where Root says, sets up
// the staging and state directories, and finishes or undoes any adoption
// a crash interrupted.
func (s *Server) Check(ctx context.Context) error {
	st, err := s.state(ctx, s.Parent)
	if err != nil {
		return err
	}
	if !st.exists {
		return fmt.Errorf("parent dataset %s doesn't exist", s.Parent)
	}
	if st.mountpoint != s.Root || !st.mounted {
		return fmt.Errorf("parent dataset %s isn't mounted at %s (mountpoint %s, mounted %v)", s.Parent, s.Root, st.mountpoint, st.mounted)
	}
	if strings.HasPrefix(s.Staging+"/", s.Root+"/") {
		return fmt.Errorf("the staging directory %s must be outside %s", s.Staging, s.Root)
	}
	if err := s.checkTrash(ctx); err != nil {
		return err
	}
	for _, dir := range []string{s.Staging, s.StateDir} {
		if err := rootOnlyDir(dir); err != nil {
			return err
		}
	}
	return s.Recover(ctx)
}

// rootOnlyDir makes dir if it's missing, and makes sure it's a directory
// (not a link) only its owner can use.
func rootOnlyDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fd, err := openRoot(dir)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s isn't owned by uid %d", dir, os.Geteuid())
	}
	if st.Mode&0o077 != 0 {
		if err := syscall.Fchmod(fd, 0o700); err != nil {
			return err
		}
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

func notDataset(bucket, why string) error {
	return &apiError{http.StatusNotFound, zfsapi.CodeNotDataset, fmt.Sprintf("bucket %s isn't a dataset: %s", bucket, why)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	h := func(pattern string, read bool, fn func(w http.ResponseWriter, r *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if read {
				release, err := acquire(r.Context(), s.reads)
				if err != nil {
					s.fail(w, r, err)
					return
				}
				defer release()
			}
			if err := fn(w, r); err != nil {
				s.fail(w, r, err)
			}
		})
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	h("POST /buckets/{b}/adopt", false, s.adopt)
	h("GET /buckets/{b}", true, s.getBucket)
	h("DELETE /buckets/{b}", false, s.destroy)
	h("PUT /buckets/{b}/quota", false, s.putQuota)
	h("PUT /buckets/{b}/backup", false, s.putBackup)
	h("GET /buckets/{b}/snapshots", true, s.listSnapshots)
	h("POST /buckets/{b}/snapshots", false, s.createSnapshot)
	h("DELETE /buckets/{b}/snapshots/{s}", false, s.deleteSnapshot)
	h("GET /buckets/{b}/snapshots/{s}/list", true, s.listSnapshotObjects)
	h("GET /buckets/{b}/snapshots/{s}/object", true, s.getSnapshotObject)
	h("POST /buckets/{b}/snapshots/{s}/restore", false, s.restoreHandler)
	h("GET /trash", true, s.listTrash)
	h("DELETE /trash/{e}", false, s.purgeTrash)
	h("POST /trash/{e}/restore", false, s.restoreTrash)
	return mux
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
		if ae.status >= 500 {
			s.Log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		}
	case errors.Is(err, errTooManyEntries):
		ae = &apiError{http.StatusBadRequest, zfsapi.CodeBadRequest, err.Error()}
	case errors.Is(err, errSymlink):
		ae = &apiError{http.StatusBadRequest, zfsapi.CodeBadRequest, err.Error()}
	case errors.Is(err, context.Canceled):
		s.Log.Warn("request cancelled", "method", r.Method, "path", r.URL.Path)
		ae = &apiError{http.StatusServiceUnavailable, zfsapi.CodeBusy, "cancelled"}
	default:
		ae = &apiError{http.StatusInternalServerError, zfsapi.CodeInternal, err.Error()}
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

// bucketName validates the request's bucket and returns its dataset and
// directory.
func (s *Server) bucketName(r *http.Request) (name, ds, dir string, err error) {
	name = r.PathValue("b")
	if !zfsapi.BucketName.MatchString(name) {
		return "", "", "", badRequest("bad bucket name %q", name)
	}
	return name, s.Parent + "/" + name, s.Root + "/" + name, nil
}

// bucket is a bucket that's one of our datasets, mounted where it should
// be, with its root open.
type bucket struct {
	name, ds, dir string
	fd            int
}

func (b *bucket) close() { syscall.Close(b.fd) }

// dataset checks the request's bucket is a dataset mounted at its
// directory, and opens its root. Callers close it.
func (s *Server) dataset(r *http.Request) (*bucket, error) {
	name, ds, dir, err := s.bucketName(r)
	if err != nil {
		return nil, err
	}
	return s.openDataset(r.Context(), name, ds, dir)
}

func (s *Server) openDataset(ctx context.Context, name, ds, dir string) (*bucket, error) {
	st, err := s.state(ctx, ds)
	if err != nil {
		return nil, err
	}
	switch {
	case !st.exists:
		return nil, notDataset(name, "no such dataset")
	case st.mountpoint != dir:
		return nil, &apiError{http.StatusConflict, zfsapi.CodeConflict, fmt.Sprintf("dataset %s is mounted at %s, not %s", ds, st.mountpoint, dir)}
	case !st.mounted:
		return nil, notDataset(name, "its dataset isn't mounted")
	}
	fd, err := s.openMounted(dir, s.Root)
	if err != nil {
		if errors.Is(err, errNotMounted) {
			return nil, notDataset(name, "its directory isn't the dataset's mount")
		}
		return nil, err
	}
	return &bucket{name: name, ds: ds, dir: dir, fd: fd}, nil
}

var errNotMounted = errors.New("not a separate mount")

// openMounted opens dir, a dataset's mountpoint, and checks it's really a
// different filesystem from parentDir, so the helper never mistakes a
// plain directory in the parent for a dataset.
func (s *Server) openMounted(dir, parentDir string) (int, error) {
	fd, err := openRoot(dir)
	if err != nil {
		return -1, err
	}
	if s.SkipMountCheck {
		return fd, nil
	}
	pfd, err := openRoot(parentDir)
	if err != nil {
		syscall.Close(fd)
		return -1, err
	}
	same, err := sameFilesystem(fd, pfd)
	syscall.Close(pfd)
	if err == nil && same {
		err = errNotMounted
	}
	if err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

// snapshotName validates the request's snapshot name and checks ds has
// it.
func (s *Server) snapshotName(r *http.Request, ds string) (string, error) {
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

// snapRoot opens a snapshot's root, reached from the bucket's root one
// component at a time (.zfs, snapshot, the name) without following links.
func (s *Server) snapRoot(r *http.Request, b *bucket) (int, error) {
	snap, err := s.snapshotName(r, b.ds)
	if err != nil {
		return -1, err
	}
	return openDirAt(b.fd, []string{".zfs", "snapshot", snap}, nil)
}

// internal says whether a name at a bucket's root is the gateway's or
// ZFS's rather than an object.
func internal(name string) bool { return name == ".sgwtmp" || name == ".zfs" }

// ---------------------------------------------------------------- buckets

func (s *Server) getBucket(w http.ResponseWriter, r *http.Request) error {
	b, err := s.dataset(r)
	if err != nil {
		return err
	}
	b.close()
	info, err := s.info(r.Context(), b.ds)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, info)
	return nil
}

// isEmpty says whether a bucket's root holds nothing but the gateway's
// and ZFS's internals, which is what empty means to the gateway. An empty
// folder is a folder object, so it counts.
func isEmpty(fd int) (bool, error) {
	ents, err := readDirAt(fd)
	if err != nil {
		return false, err
	}
	for _, e := range ents {
		if !internal(e.name) {
			return false, nil
		}
	}
	return true, nil
}

func (s *Server) putQuota(w http.ResponseWriter, r *http.Request) error {
	var q zfsapi.Quota
	if err := readJSON(r, &q); err != nil {
		return err
	}
	if q.Bytes < 0 {
		return badRequest("quota can't be negative")
	}
	name, _, _, err := s.bucketName(r)
	if err != nil {
		return err
	}
	defer s.lock(name)()
	b, err := s.dataset(r)
	if err != nil {
		return err
	}
	b.close()
	if err := s.setRefquota(r.Context(), b.ds, q.Bytes); err != nil {
		return err
	}
	s.Log.Info("set quota", "bucket", name, "bytes", q.Bytes)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) putBackup(w http.ResponseWriter, r *http.Request) error {
	var req zfsapi.Backup
	if err := readJSON(r, &req); err != nil {
		return err
	}
	name, _, _, err := s.bucketName(r)
	if err != nil {
		return err
	}
	defer s.lock(name)()
	b, err := s.dataset(r)
	if err != nil {
		return err
	}
	b.close()
	if err := s.setBackup(r.Context(), b.ds, req.Include); err != nil {
		return err
	}
	s.Log.Info("set backup", "bucket", name, "include", req.Include)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// -------------------------------------------------------------- snapshots

func (s *Server) listSnapshots(w http.ResponseWriter, r *http.Request) error {
	b, err := s.dataset(r)
	if err != nil {
		return err
	}
	b.close()
	snaps, err := s.snapshots(r.Context(), b.ds)
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
	name, _, _, err := s.bucketName(r)
	if err != nil {
		return err
	}
	defer s.lock(name)()
	b, err := s.dataset(r)
	if err != nil {
		return err
	}
	b.close()
	now := s.Now().UTC()
	snap := zfsapi.SnapshotPrefix + now.Format(zfsapi.SnapshotTimeFormat)
	if req.Label != "" {
		snap += "-" + req.Label
	}
	if _, err := s.run(r.Context(), "snapshot", b.ds+"@"+snap); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return &apiError{http.StatusConflict, zfsapi.CodeConflict, "a snapshot with that name already exists; try again in a second"}
		}
		return err
	}
	s.Log.Info("created snapshot", "bucket", name, "snapshot", snap)
	writeJSON(w, http.StatusCreated, zfsapi.Snapshot{Name: snap, Created: now.Truncate(time.Second)})
	return nil
}

func (s *Server) deleteSnapshot(w http.ResponseWriter, r *http.Request) error {
	name, _, _, err := s.bucketName(r)
	if err != nil {
		return err
	}
	defer s.lock(name)()
	b, err := s.dataset(r)
	if err != nil {
		return err
	}
	b.close()
	snap, err := s.snapshotName(r, b.ds)
	if err != nil {
		return err
	}
	if _, err := s.run(r.Context(), "destroy", b.ds+"@"+snap); err != nil {
		return err
	}
	s.Log.Info("destroyed snapshot", "bucket", name, "snapshot", snap)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

const maxListKeys = 1000

// maxWalk bounds a recursive listing or restore.
var maxWalk = 200000

var errTooMany = &apiError{http.StatusBadRequest, zfsapi.CodeBadRequest, "too many objects at once; use a longer prefix"}

// walk collects objects from a snapshot, honouring cancellation and
// maxWalk. Files whose keys would be too long to be objects are skipped
// and counted.
type walk struct {
	ctx     context.Context
	log     *slog.Logger
	objs    []zfsapi.Object
	skipped int
}

func (w *walk) add(o zfsapi.Object) error {
	if len(w.objs) >= maxWalk {
		return errTooMany
	}
	w.objs = append(w.objs, o)
	return nil
}

// skip reports whether key is too long to be an object, logging it.
func (w *walk) skip(key string) bool {
	if len(key) <= maxKeyLen {
		return false
	}
	w.skipped++
	w.log.Warn("skipping a path too long to be an object", "path", key[:64]+"…", "length", len(key))
	return true
}

// dir walks the directory name in dirfd, whose key prefix is keyPrefix. A
// directory carrying the gateway's etag xattr is a folder object in its
// own right.
func (w *walk) dir(dirfd int, name, keyPrefix string) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if w.skip(keyPrefix) {
		return nil
	}
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
		if err := w.add(o); err != nil {
			return err
		}
	}
	ents, err := readDirAt(fd)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if err := w.entry(fd, e, keyPrefix+e.name); err != nil {
			return err
		}
	}
	return nil
}

// entry adds one directory entry, recursing into directories.
func (w *walk) entry(dirfd int, e dirEntry, key string) error {
	switch {
	case e.isDir():
		return w.dir(dirfd, e.name, key+"/")
	case e.isRegular():
		if w.skip(key) {
			return nil
		}
		return w.add(objectOf(key, e.st))
	}
	return nil
}

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
	b, err := s.dataset(r)
	if err != nil {
		return err
	}
	defer b.close()
	root, err := s.snapRoot(r, b)
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
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, errSymlink) {
		writeJSON(w, http.StatusOK, out)
		return nil
	}
	if err != nil {
		return err
	}
	defer syscall.Close(dirfd)

	ents, err := readDirAt(dirfd)
	if err != nil {
		return err
	}
	var prefixes []string
	wk := &walk{ctx: r.Context(), log: s.Log}
	for _, e := range ents {
		if (dirPart == "" && internal(e.name)) || !strings.HasPrefix(e.name, namePart) {
			continue
		}
		key := dirPart + e.name
		if e.isDir() && delimiter == "/" {
			prefixes = append(prefixes, key+"/")
			continue
		}
		if err := wk.entry(dirfd, e, key); err != nil {
			return err
		}
	}
	type item struct {
		key    string
		prefix bool
		obj    zfsapi.Object
	}
	items := make([]item, 0, len(prefixes)+len(wk.objs))
	for _, p := range prefixes {
		items = append(items, item{key: p, prefix: true})
	}
	for _, o := range wk.objs {
		items = append(items, item{key: o.Key, obj: o})
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

func (s *Server) getSnapshotObject(w http.ResponseWriter, r *http.Request) error {
	parts, dir, err := splitKey(r.URL.Query().Get("key"))
	if err != nil || dir {
		return badRequest("bad key")
	}
	if internal(parts[0]) {
		return notFound("no such object")
	}
	b, err := s.dataset(r)
	if err != nil {
		return err
	}
	defer b.close()
	root, err := s.snapRoot(r, b)
	if err != nil {
		return err
	}
	defer syscall.Close(root)
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

// restoreHandler copies an object, or everything under a prefix, from a
// snapshot back into the live bucket, overwriting what's there. Objects
// only in the live bucket are left alone. Each file is written beside its
// target and renamed into place, with the snapshot's owner, permission
// bits, times and xattrs (the gateway's etag and content type among
// them). Only this bucket is locked meanwhile, at most MaxRestores run at
// once, and a cancelled request stops between files.
func (s *Server) restoreHandler(w http.ResponseWriter, r *http.Request) error {
	var req zfsapi.Restore
	if err := readJSON(r, &req); err != nil {
		return err
	}
	if (req.Key != "") == (req.Prefix != "" || req.All) {
		return badRequest("give a key, or a prefix (or all for the whole bucket)")
	}
	name, _, _, err := s.bucketName(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	release, err := acquire(ctx, s.restore)
	if err != nil {
		return err
	}
	defer release()
	defer s.lock(name)()
	b, err := s.dataset(r)
	if err != nil {
		return err
	}
	defer b.close()
	root, err := s.snapRoot(r, b)
	if err != nil {
		return err
	}
	defer syscall.Close(root)

	res := zfsapi.Restored{}
	if req.Key != "" {
		parts, isDir, err := splitKey(req.Key)
		if err != nil {
			return badRequest("%v", err)
		}
		if internal(parts[0]) {
			return notFound("no such object")
		}
		if err := restoreOne(root, b.fd, parts, isDir); err != nil {
			if errors.Is(err, syscall.ENOENT) {
				return notFound("no such object in the snapshot")
			}
			return err
		}
		res.Objects = 1
	} else {
		parts, err := splitPrefix(req.Prefix)
		if err != nil {
			return badRequest("%v", err)
		}
		if len(parts) > 0 && internal(parts[0]) {
			return notFound("no such folder")
		}
		wk := &walk{ctx: ctx, log: s.Log}
		if len(parts) == 0 {
			ents, err := readDirAt(root)
			if err != nil {
				return err
			}
			for _, e := range ents {
				if internal(e.name) {
					continue
				}
				if err := wk.entry(root, e, e.name); err != nil {
					return err
				}
			}
		} else {
			parent, err := openDirAt(root, parts[:len(parts)-1], nil)
			if err == nil {
				err = wk.dir(parent, parts[len(parts)-1], req.Prefix)
				syscall.Close(parent)
			}
			if errors.Is(err, syscall.ENOENT) {
				return notFound("no such folder in the snapshot")
			}
			if err != nil {
				return err
			}
		}
		res.Skipped = wk.skipped
		for _, o := range wk.objs {
			if err := ctx.Err(); err != nil {
				s.Log.Warn("restore cancelled", "bucket", name, "restored", res.Objects, "of", len(wk.objs))
				return err
			}
			p, isDir, err := splitKey(o.Key)
			if err != nil {
				res.Skipped++
				s.Log.Warn("skipping an unusable key", "key", o.Key, "err", err)
				continue
			}
			if err := restoreOne(root, b.fd, p, isDir); err != nil {
				return fmt.Errorf("restore %s (after %d objects): %w", o.Key, res.Objects, err)
			}
			res.Objects++
		}
	}
	s.Log.Info("restored from snapshot", "path", r.URL.Path, "key", req.Key, "prefix", req.Prefix, "all", req.All, "objects", res.Objects, "skipped", res.Skipped)
	writeJSON(w, http.StatusOK, res)
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
