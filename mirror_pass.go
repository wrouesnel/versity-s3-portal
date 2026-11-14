package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ------------------------------------------------------------- manifest

// mEntry is one object the mirror copied: what the source said about it
// when it was read, and what was written here.
type mEntry struct {
	Key string `json:"k"`
	// SourceETag, Size and Modified are the source's, from the read.
	SourceETag string    `json:"se"`
	Size       int64     `json:"sz"`
	Modified   time.Time `json:"sm"`
	// MD5 is of the bytes read from the source and written here.
	MD5 string `json:"md5"`
	// TargetETag is what the gateway answered the write with.
	TargetETag string `json:"te"`
}

const manifestName = "manifest.jsonl.gz"

// manifestReader reads a manifest a batch at a time.
type manifestReader struct {
	f   *os.File
	gz  *gzip.Reader
	sc  *bufio.Scanner
	eof bool
}

func openManifest(path string) (*manifestReader, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return &manifestReader{eof: true}, nil
	}
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	return &manifestReader{f: f, gz: gz, sc: sc}, nil
}

func (r *manifestReader) batch() ([]mEntry, bool, error) {
	if r.eof {
		return nil, false, nil
	}
	var out []mEntry
	for len(out) < 1000 {
		if !r.sc.Scan() {
			r.eof = true
			if err := r.sc.Err(); err != nil {
				return nil, false, fmt.Errorf("read manifest: %w", err)
			}
			return out, false, nil
		}
		var e mEntry
		if err := json.Unmarshal(r.sc.Bytes(), &e); err != nil {
			return nil, false, fmt.Errorf("read manifest: %w", err)
		}
		out = append(out, e)
	}
	return out, true, nil
}

func (r *manifestReader) Close() {
	if r.f != nil {
		r.gz.Close()
		r.f.Close()
	}
}

// manifestWriter writes a manifest to a temporary file, renamed into place
// only when the pass finishes.
type manifestWriter struct {
	f       *os.File
	gz      *gzip.Writer
	bw      *bufio.Writer
	objects int64
	bytes   int64
}

func newManifestWriter(dir string) (*manifestWriter, error) {
	f, err := os.CreateTemp(dir, ".manifest-*")
	if err != nil {
		return nil, err
	}
	gz := gzip.NewWriter(f)
	return &manifestWriter{f: f, gz: gz, bw: bufio.NewWriter(gz)}, nil
}

func (w *manifestWriter) write(e mEntry) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	w.objects++
	w.bytes += e.Size
	w.bw.Write(data)
	return w.bw.WriteByte('\n')
}

// commit finishes the file and puts it in place as path.
func (w *manifestWriter) commit(path string) error {
	if err := w.bw.Flush(); err != nil {
		return err
	}
	if err := w.gz.Close(); err != nil {
		return err
	}
	if err := w.f.Sync(); err != nil {
		return err
	}
	if err := w.f.Close(); err != nil {
		return err
	}
	return os.Rename(w.f.Name(), path)
}

func (w *manifestWriter) discard() {
	w.f.Close()
	os.Remove(w.f.Name())
}

// ---------------------------------------------------------------- merge

// sorted is a key-ordered stream, read a batch at a time, that fails if
// it ever goes backwards: a merge of listings is only right if each is in
// order.
type sorted[T any] struct {
	name  string
	keyOf func(T) string
	fetch func() ([]T, bool, error)
	buf   []T
	more  bool
	last  string
	begun bool
	err   error
}

func newSorted[T any](name string, keyOf func(T) string, fetch func() ([]T, bool, error)) *sorted[T] {
	return &sorted[T]{name: name, keyOf: keyOf, fetch: fetch, more: true}
}

// peek returns the next item, if there is one and nothing has failed.
func (s *sorted[T]) peek() (T, bool) {
	for len(s.buf) == 0 && s.more && s.err == nil {
		s.buf, s.more, s.err = s.fetch()
	}
	if len(s.buf) == 0 || s.err != nil {
		var zero T
		return zero, false
	}
	return s.buf[0], true
}

func (s *sorted[T]) pop() {
	k := s.keyOf(s.buf[0])
	if s.begun && k <= s.last {
		s.err = fmt.Errorf("the %s listing went out of order at %q, after %q", s.name, k, s.last)
	}
	s.last, s.begun = k, true
	s.buf = s.buf[1:]
}

// reservedPrefix says whether key is in a folder the gateway's posix
// backend keeps for itself: ZFS's snapshot directory, and the gateway's
// temporary files. They aren't objects here, and can't be written.
func reservedPrefix(key string) bool {
	return strings.HasPrefix(key, ".zfs/") || strings.HasPrefix(key, ".sgwtmp/")
}

// targetListing is the bucket's objects, without reserved folders.
func targetListing(ctx context.Context, v *VGW, bucket string) *sorted[ListedObject] {
	s := listing(ctx, "target", v, bucket, nil)
	fetch := s.fetch
	s.fetch = func() ([]ListedObject, bool, error) {
		objs, more, err := fetch()
		kept := objs[:0]
		for _, o := range objs {
			if !reservedPrefix(o.Key) {
				kept = append(kept, o)
			}
		}
		return kept, more, err
	}
	return s
}

func listing(ctx context.Context, name string, v *VGW, bucket string, listed func(ListedObject)) *sorted[ListedObject] {
	token, first := "", true
	return newSorted(name, func(o ListedObject) string { return o.Key }, func() ([]ListedObject, bool, error) {
		if !first && token == "" {
			return nil, false, nil
		}
		first = false
		objs, next, err := v.ListPage(ctx, bucket, token, 1000)
		if err != nil {
			return nil, false, fmt.Errorf("list %s: %w", name, err)
		}
		token = next
		if listed != nil {
			for _, o := range objs {
				listed(o)
			}
		}
		return objs, next != "", nil
	})
}

func manifestStream(r *manifestReader) *sorted[mEntry] {
	return newSorted("manifest", func(e mEntry) string { return e.Key }, r.batch)
}

// smallest is the least key among the streams' next items.
func smallest(keys ...*string) (string, bool) {
	var min string
	found := false
	for _, k := range keys {
		if k != nil && (!found || *k < min) {
			min, found = *k, true
		}
	}
	return min, found
}

// --------------------------------------------------------------- checks

// uncopyable says why a key can't be an object here, where objects are
// files: a path segment too long for a file name, or one that a file
// system path can't hold.
func uncopyable(key string) string {
	if strings.HasPrefix(key, "/") {
		return "it starts with a slash"
	}
	if reservedPrefix(key) {
		return "the folder is reserved here"
	}
	segs := strings.Split(strings.TrimSuffix(key, "/"), "/")
	for _, s := range segs {
		switch {
		case s == "":
			return "it has an empty folder name (two slashes in a row)"
		case s == "." || s == "..":
			return "it has a . or .. folder"
		case len(s) > 255:
			return "a name in it is over 255 bytes"
		}
	}
	if len(key) > 1024 {
		return "it's over 1024 bytes"
	}
	return ""
}

// conflictCodes are what the gateway answers when a key would make a
// file where a folder is, or the other way round.
func isPathConflict(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.Code {
	case "ExistingObjectIsDirectory", "ObjectParentIsFile", "DirectoryObjectContainsData":
		return true
	}
	return false
}

var md5Re = regexp.MustCompile(`^[0-9a-f]{32}$`)

// sameSource says whether a listed source object is the one the manifest
// recorded.
func sameSource(e mEntry, o ListedObject) bool {
	if e.Size != o.Size {
		return false
	}
	if o.ETag != "" {
		return e.SourceETag == o.ETag
	}
	return e.Modified.Equal(o.LastModified)
}

// ------------------------------------------------------------- progress

type passProgress struct {
	kind        string
	started     time.Time
	phase       atomic.Value
	listed      atomic.Int64
	listedBytes atomic.Int64
	copied      atomic.Int64
	copiedBytes atomic.Int64
	deleted     atomic.Int64
	failed      atomic.Int64
	checked     atomic.Int64
}

func newProgress(kind string) *passProgress {
	p := &passProgress{kind: kind, started: time.Now()}
	p.phase.Store("copying")
	return p
}

func (p *passProgress) setPhase(s string) { p.phase.Store(s) }

// ProgressView is a running job's progress, for the page.
type ProgressView struct {
	Kind, Phase                  string
	Started                      time.Time
	Listed, ListedBytes          int64
	Copied, CopiedBytes, Deleted int64
	Failed, Checked              int64
}

func (p *passProgress) view() ProgressView {
	return ProgressView{
		Kind: p.kind, Phase: p.phase.Load().(string), Started: p.started,
		Listed: p.listed.Load(), ListedBytes: p.listedBytes.Load(),
		Copied: p.copied.Load(), CopiedBytes: p.copiedBytes.Load(), Deleted: p.deleted.Load(),
		Failed: p.failed.Load(), Checked: p.checked.Load(),
	}
}

// ---------------------------------------------------------------- report

// PassReport is the full account of a pass, kept beside the manifest.
type PassReport struct {
	Summary    PassSummary  `json:"summary"`
	Copied     []string     `json:"copied"`
	Repaired   []string     `json:"repaired"`
	Deleted    []string     `json:"deleted"`
	Failures   []KeyProblem `json:"failures"`
	Uncopyable []KeyProblem `json:"uncopyable"`
	Unexpected []string     `json:"unexpected"`
	// Truncated is set when a list was cut short at reportLimit.
	Truncated bool `json:"truncated,omitempty"`
	// Verification, for a final pass.
	Verification *Verification `json:"verification,omitempty"`
}

// KeyProblem is a key and what went wrong with it.
type KeyProblem struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

const reportLimit = 10000

func (r *PassReport) trim(n int) {
	cut := func(s []string) []string { return s[:min(len(s), n)] }
	cutP := func(s []KeyProblem) []KeyProblem { return s[:min(len(s), n)] }
	r.Copied, r.Repaired, r.Deleted, r.Unexpected = cut(r.Copied), cut(r.Repaired), cut(r.Deleted), cut(r.Unexpected)
	r.Failures, r.Uncopyable = cutP(r.Failures), cutP(r.Uncopyable)
}

func (p *Portal) readReport(bucket string, n int) (*PassReport, error) {
	data, err := os.ReadFile(filepath.Join(p.mirrorDir(bucket), fmt.Sprintf("pass-%d.json", n)))
	if err != nil {
		return nil, err
	}
	var r PassReport
	return &r, json.Unmarshal(data, &r)
}

func (p *Portal) writeReport(bucket string, r *PassReport) error {
	data, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	path := filepath.Join(p.mirrorDir(bucket), fmt.Sprintf("pass-%d.json", r.Summary.N))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// reportList collects keys up to reportLimit.
type reportList struct {
	mu        sync.Mutex
	r         *PassReport
	truncated bool
}

func (l *reportList) add(list *[]string, key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(*list) < reportLimit {
		*list = append(*list, key)
	} else {
		l.r.Truncated = true
	}
}

func (l *reportList) problem(list *[]KeyProblem, key, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(*list) < reportLimit {
		*list = append(*list, KeyProblem{key, reason})
	} else {
		l.r.Truncated = true
	}
}

// ------------------------------------------------------------------ pass

// Copying tunables; tests make them small.
var (
	// mirrorPartThreshold is the size above which objects are written as
	// multipart uploads. 5 GiB is the most one PUT may carry.
	mirrorPartThreshold int64 = 5 << 30
	// mirrorPartSize is the smallest part; big objects get bigger parts,
	// to stay within 10,000.
	mirrorPartSize int64 = 64 << 20
	mirrorWorkers        = 4
)

// slot is one key's place in the new manifest, filled when its copy or
// delete finishes, so the manifest is written in key order however the
// work finishes.
type slot chan *mEntry

func done(e *mEntry) slot {
	s := make(slot, 1)
	s <- e
	return s
}

// runPass copies the source into the bucket once, and reports what it
// did.
func (p *Portal) runPass(ctx context.Context, m *Mirror, kind, by string, prog *passProgress) PassSummary {
	sum := PassSummary{N: m.nextPass(), Kind: kind, By: by, Started: time.Now()}
	report := &PassReport{}
	rl := &reportList{r: report}
	fail := func(err error) PassSummary {
		if ctx.Err() != nil {
			err = errors.New("stopped before it finished")
		}
		sum.Error = err.Error()
		sum.Finished = time.Now()
		report.Summary = sum
		if werr := p.writeReport(m.Bucket, report); werr != nil {
			slog.Error("write mirror report", "bucket", m.Bucket, "err", werr)
		}
		slog.Warn("mirror pass stopped", "bucket", m.Bucket, "pass", sum.N, "err", err)
		return sum
	}
	dir := p.mirrorDir(m.Bucket)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail(err)
	}
	if m.Account.Access == "" {
		return fail(errors.New("the mirror has no gateway account"))
	}
	src := m.sourceClient()
	dst := p.vgw.As(m.Account.Access, m.Account.Secret)
	var limit *rateLimit
	if m.LimitMBps > 0 {
		limit = newRateLimit(float64(m.LimitMBps) * 1e6)
	}

	old, err := openManifest(filepath.Join(dir, manifestName))
	if err != nil {
		return fail(err)
	}
	defer old.Close()
	out, err := newManifestWriter(dir)
	if err != nil {
		return fail(err)
	}
	committed := false
	defer func() {
		if !committed {
			out.discard()
		}
	}()

	sources := listing(ctx, "source", src, m.Source.Bucket, func(o ListedObject) {
		prog.listed.Add(1)
		prog.listedBytes.Add(o.Size)
	})
	targets := targetListing(ctx, dst, m.Bucket)
	manifest := manifestStream(old)

	// The writer puts entries in the new manifest in key order.
	slots := make(chan slot, 256)
	var writeErr error
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for s := range slots {
			if e := <-s; e != nil && writeErr == nil {
				writeErr = out.write(*e)
			}
		}
	}()
	// Workers copy and delete.
	jobs := make(chan func(), mirrorWorkers)
	var wg sync.WaitGroup
	for range mirrorWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				j()
			}
		}()
	}
	var copied, copiedBytes, repaired, deleted, failed, conflicts atomic.Int64
	uncopyHash := sha256.New()

	copyJob := func(o ListedObject, prev *mEntry, repair bool) {
		s := make(slot, 1)
		slots <- s
		jobs <- func() {
			e, err := p.copyObject(ctx, src, dst, m.Source.Bucket, m.Bucket, o.Key, limit, prog)
			switch {
			case err == nil:
				if repair {
					repaired.Add(1)
					rl.add(&report.Repaired, o.Key)
				} else {
					copied.Add(1)
					rl.add(&report.Copied, o.Key)
				}
				copiedBytes.Add(e.Size)
				prog.copied.Add(1)
				prog.copiedBytes.Add(e.Size)
				s <- e
			case ctx.Err() != nil:
				s <- prev
			case isPathConflict(err):
				// Counted with the other keys that can't be copied, but
				// only known once tried, so not part of their sum.
				conflicts.Add(1)
				rl.problem(&report.Uncopyable, o.Key, "a file and a folder would have the same name")
				s <- nil
			default:
				failed.Add(1)
				prog.failed.Add(1)
				rl.problem(&report.Failures, o.Key, err.Error())
				s <- prev
			}
		}
	}
	deleteJob := func(e mEntry) {
		s := make(slot, 1)
		slots <- s
		jobs <- func() {
			err := dst.Delete(ctx, m.Bucket, e.Key)
			if err != nil && !IsCode(err, "NoSuchKey") {
				if ctx.Err() == nil {
					failed.Add(1)
					prog.failed.Add(1)
					rl.problem(&report.Failures, e.Key, "delete: "+err.Error())
				}
				s <- &e
				return
			}
			deleted.Add(1)
			prog.deleted.Add(1)
			rl.add(&report.Deleted, e.Key)
			s <- nil
		}
	}

	var loopErr error
	var uncopyableListed int64
	for ctx.Err() == nil {
		so, hasS := sources.peek()
		me, hasM := manifest.peek()
		to, hasT := targets.peek()
		var ks, km, kt *string
		if hasS {
			ks = &so.Key
		}
		if hasM {
			km = &me.Key
		}
		if hasT {
			kt = &to.Key
		}
		key, any := smallest(ks, km, kt)
		if !any {
			break
		}
		inS, inM, inT := hasS && so.Key == key, hasM && me.Key == key, hasT && to.Key == key
		if inS {
			sources.pop()
			sum.SourceObjects++
			sum.SourceBytes += so.Size
		}
		if inM {
			manifest.pop()
		}
		if inT {
			targets.pop()
		}
		var prev *mEntry
		if inM {
			e := me
			prev = &e
		}
		switch {
		case inS:
			if reason := uncopyable(key); reason != "" {
				uncopyableListed++
				uncopyHash.Write([]byte(key + "\x00"))
				rl.problem(&report.Uncopyable, key, reason)
				break
			}
			switch {
			case !inM || !sameSource(me, so):
				copyJob(so, prev, false)
			case !inT || to.Size != me.Size || (me.TargetETag != "" && to.ETag != me.TargetETag):
				copyJob(so, prev, true)
			default:
				slots <- done(prev)
			}
		case inM && inT:
			deleteJob(me)
		case inT:
			sum.Unexpected++
			rl.add(&report.Unexpected, key)
		}
		// inM alone: gone from both sides; it drops out of the manifest.
	}
	close(jobs)
	wg.Wait()
	close(slots)
	<-writerDone
	for _, err := range []error{sources.err, manifest.err, targets.err, ctx.Err(), writeErr} {
		if err != nil {
			loopErr = err
			break
		}
	}

	sum.Copied, sum.CopiedBytes, sum.Repaired = copied.Load(), copiedBytes.Load(), repaired.Load()
	sum.Deleted, sum.Failed = deleted.Load(), failed.Load()
	sum.Uncopyable = uncopyableListed + conflicts.Load()
	if sum.Uncopyable > 0 {
		sort.Slice(report.Uncopyable, func(i, j int) bool { return report.Uncopyable[i].Key < report.Uncopyable[j].Key })
		h := sha256.New()
		for _, u := range report.Uncopyable {
			h.Write([]byte(u.Key + "\x00"))
		}
		sum.UncopyableSum = hex.EncodeToString(h.Sum(nil))
		if report.Truncated {
			// Too many to list; the sum covers the ones found by name.
			sum.UncopyableSum = hex.EncodeToString(uncopyHash.Sum(nil))
		}
	}
	if loopErr != nil {
		return fail(loopErr)
	}
	if err := out.commit(filepath.Join(dir, manifestName)); err != nil {
		return fail(err)
	}
	committed = true
	sum.MirroredObjects, sum.MirroredBytes = out.objects, out.bytes

	if p.zfs != nil {
		snap, err := p.zfs.CreateSnapshot(ctx, m.Bucket, fmt.Sprintf("mirror-%d", sum.N))
		if err != nil {
			sum.SnapshotError = err.Error()
		} else {
			sum.Snapshot = snap.Name
			p.pruneMirrorSnapshots(ctx, m.Bucket)
		}
	}
	sum.Finished = time.Now()
	report.Summary = sum
	if err := p.writeReport(m.Bucket, report); err != nil {
		slog.Error("write mirror report", "bucket", m.Bucket, "err", err)
	}
	slog.Info("mirror pass", "bucket", m.Bucket, "pass", sum.N, "kind", kind, "copied", sum.Copied,
		"repaired", sum.Repaired, "deleted", sum.Deleted, "failed", sum.Failed, "uncopyable", sum.Uncopyable)
	return sum
}

var mirrorSnapRe = regexp.MustCompile(`-mirror-(\d+)$`)

// keptMirrorSnapshots is how many of the latest pass snapshots are kept,
// besides the first pass's and the final one.
const keptMirrorSnapshots = 3

func (p *Portal) pruneMirrorSnapshots(ctx context.Context, bucket string) {
	snaps, err := p.zfs.Snapshots(ctx, bucket)
	if err != nil {
		slog.Warn("list mirror snapshots", "bucket", bucket, "err", err)
		return
	}
	type numbered struct {
		name string
		n    int
	}
	var passes []numbered
	for _, s := range snaps {
		if m := mirrorSnapRe.FindStringSubmatch(s.Name); m != nil {
			n, _ := strconv.Atoi(m[1])
			passes = append(passes, numbered{s.Name, n})
		}
	}
	sort.Slice(passes, func(i, j int) bool { return passes[i].n < passes[j].n })
	for i, s := range passes {
		if i == 0 || i >= len(passes)-keptMirrorSnapshots {
			continue
		}
		if err := p.zfs.DeleteSnapshot(ctx, bucket, s.name); err != nil && !errors.Is(err, ErrZFSNotFound) {
			slog.Warn("prune mirror snapshot", "bucket", bucket, "snapshot", s.name, "err", err)
		}
	}
}

// copiedHeaders are the source headers a copy keeps.
var copiedHeaders = []string{"Content-Type", "Content-Encoding", "Content-Disposition", "Content-Language", "Cache-Control", "Expires"}

// countingReader counts and hashes what passes through it, and waits on a
// rate limit.
type countingReader struct {
	r     io.Reader
	h     hash.Hash
	n     int64
	limit *rateLimit
	ctx   context.Context
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.limit != nil && len(p) > 256<<10 {
		p = p[:256<<10]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	c.h.Write(p[:n])
	if c.limit != nil && n > 0 {
		if werr := c.limit.wait(c.ctx, n); werr != nil {
			return n, werr
		}
	}
	return n, err
}

// copyObject copies one object from the source into the bucket.
func (p *Portal) copyObject(ctx context.Context, src, dst *VGW, srcBucket, bucket, key string, limit *rateLimit, prog *passProgress) (*mEntry, error) {
	resp, err := src.Get(ctx, srcBucket, key, nil)
	if err != nil {
		return nil, fmt.Errorf("read source: %w", err)
	}
	defer resp.Body.Close()
	size := resp.ContentLength
	if size < 0 {
		return nil, errors.New("the source didn't say how big the object is")
	}
	modified, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
	headers := map[string]string{}
	for _, h := range copiedHeaders {
		if v := resp.Header.Get(h); v != "" {
			headers[h] = v
		}
	}
	for h, vs := range resp.Header {
		if strings.HasPrefix(strings.ToLower(h), "x-amz-meta-") && len(vs) > 0 {
			headers[h] = vs[0]
		}
	}
	if !modified.IsZero() {
		headers["X-Amz-Meta-Mirror-Mtime"] = modified.UTC().Format(time.RFC3339)
	}
	body := &countingReader{r: resp.Body, h: md5.New(), limit: limit, ctx: ctx}
	var te string
	if size <= mirrorPartThreshold {
		te, err = dst.Put(ctx, bucket, key, body, size, headers)
	} else {
		te, err = multipartCopy(ctx, dst, bucket, key, body, size, headers)
	}
	if err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	if body.n != size {
		return nil, fmt.Errorf("the source sent %d of %d bytes", body.n, size)
	}
	return &mEntry{
		Key: key, SourceETag: cleanETag(resp.Header.Get("ETag")), Size: size, Modified: modified,
		MD5: hex.EncodeToString(body.h.Sum(nil)), TargetETag: te,
	}, nil
}

// multipartCopy writes size bytes of body as a multipart upload.
func multipartCopy(ctx context.Context, dst *VGW, bucket, key string, body io.Reader, size int64, headers map[string]string) (string, error) {
	part := max(mirrorPartSize, (size+9999)/10000)
	upload, err := dst.CreateMultipart(ctx, bucket, key, headers)
	if err != nil {
		return "", err
	}
	var parts []completedPart
	for n, off := 1, int64(0); off < size; n++ {
		length := min(part, size-off)
		etag, err := dst.UploadPart(ctx, bucket, key, upload, n, io.LimitReader(body, length), length)
		if err != nil {
			dst.AbortMultipart(context.Background(), bucket, key, upload)
			return "", fmt.Errorf("part %d: %w", n, err)
		}
		parts = append(parts, completedPart{n, etag})
		off += length
	}
	etag, err := dst.CompleteMultipart(ctx, bucket, key, upload, parts)
	if err != nil {
		dst.AbortMultipart(context.Background(), bucket, key, upload)
		return "", err
	}
	return etag, nil
}

// ------------------------------------------------------------ verifying

// maxProblems is how many differences a verification keeps to show.
const maxProblems = 50

// verifyMirror checks, after a final pass, that the source hasn't changed
// since and that the bucket holds what the manifest says, byte for byte
// where there's a hash to compare.
func (p *Portal) verifyMirror(ctx context.Context, m *Mirror, final PassSummary, deep bool, prog *passProgress) *Verification {
	cur, _ := p.store.Mirror(m.Bucket)
	if cur == nil {
		cur = m
	}
	v := &Verification{At: time.Now(), Pass: final.N, Deep: deep, FinalClean: final.Clean(cur.Accepted)}
	problem := func(format string, args ...any) {
		if len(v.Problems) < maxProblems {
			v.Problems = append(v.Problems, fmt.Sprintf(format, args...))
		}
	}
	report, _ := p.readReport(m.Bucket, final.N)
	skip := map[string]bool{}
	if report != nil {
		for _, u := range report.Uncopyable {
			skip[u.Key] = true
		}
	}
	src := m.sourceClient()
	dst := p.vgw.As(m.Account.Access, m.Account.Secret)
	path := filepath.Join(p.mirrorDir(m.Bucket), manifestName)

	// The quiet check: the source again, against the manifest.
	r, err := openManifest(path)
	if err != nil {
		v.Error = err.Error()
		return v
	}
	man := manifestStream(r)
	sources := listing(ctx, "source", src, m.Source.Bucket, nil)
	for ctx.Err() == nil {
		so, hasS := sources.peek()
		me, hasM := man.peek()
		switch {
		case hasS && (!hasM || so.Key < me.Key):
			sources.pop()
			if !skip[so.Key] && uncopyable(so.Key) == "" {
				v.QuietChanges++
				problem("Changed at the source after the final pass: %s is new.", so.Key)
			}
			continue
		case hasM && (!hasS || me.Key < so.Key):
			man.pop()
			v.QuietChanges++
			problem("Changed at the source after the final pass: %s was deleted.", me.Key)
			continue
		case hasS && hasM:
			sources.pop()
			man.pop()
			if !sameSource(me, so) {
				v.QuietChanges++
				problem("Changed at the source after the final pass: %s was rewritten.", so.Key)
			}
			continue
		}
		break
	}
	r.Close()
	if err := errors.Join(sources.err, man.err, ctx.Err()); err != nil {
		v.Error = err.Error()
		return v
	}

	// The content check: the bucket against the manifest.
	r, err = openManifest(path)
	if err != nil {
		v.Error = err.Error()
		return v
	}
	defer r.Close()
	man = manifestStream(r)
	targets := targetListing(ctx, dst, m.Bucket)
	for ctx.Err() == nil {
		to, hasT := targets.peek()
		me, hasM := man.peek()
		switch {
		case hasT && (!hasM || to.Key < me.Key):
			targets.pop()
			v.Unexpected++
			problem("%s is in the bucket but didn't come from the source.", to.Key)
			continue
		case hasM && (!hasT || me.Key < to.Key):
			man.pop()
			v.Missing++
			problem("%s was copied but isn't in the bucket.", me.Key)
			continue
		case !hasT || !hasM:
		default:
			targets.pop()
			man.pop()
			v.Checked++
			prog.checked.Add(1)
			switch {
			case to.Size != me.Size:
				v.Mismatched++
				problem("%s is %d bytes here, %d at the source.", me.Key, to.Size, me.Size)
			case me.TargetETag != "" && to.ETag != me.TargetETag:
				v.Mismatched++
				problem("%s changed here after it was copied.", me.Key)
			case me.SourceETag == me.MD5 && me.TargetETag == me.MD5:
				v.EndToEnd++
			default:
				v.SizeOnly++
				if deep {
					sum, err := hashObject(ctx, dst, m.Bucket, me.Key)
					switch {
					case err != nil:
						v.Mismatched++
						problem("Couldn't read %s back: %v", me.Key, err)
					case sum != me.MD5:
						v.Mismatched++
						problem("%s reads back differently from what was copied.", me.Key)
					default:
						v.DeepChecked++
					}
				}
			}
			continue
		}
		break
	}
	if err := errors.Join(targets.err, man.err, ctx.Err()); err != nil {
		v.Error = err.Error()
		return v
	}
	v.Passed = v.FinalClean && v.QuietChanges == 0 && v.Mismatched == 0 && v.Missing == 0 && v.Unexpected == 0
	if !v.FinalClean {
		problem("The final pass didn't finish cleanly: see its failures, and any keys that can't be copied that need accepting.")
	}
	if report != nil {
		report.Verification = v
		if err := p.writeReport(m.Bucket, report); err != nil {
			slog.Error("write mirror report", "bucket", m.Bucket, "err", err)
		}
	}
	slog.Info("mirror verification", "bucket", m.Bucket, "pass", final.N, "passed", v.Passed, "checked", v.Checked,
		"quietChanges", v.QuietChanges, "mismatched", v.Mismatched, "missing", v.Missing, "unexpected", v.Unexpected)
	return v
}

func hashObject(ctx context.Context, v *VGW, bucket, key string) (string, error) {
	resp, err := v.Get(ctx, bucket, key, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	h := md5.New()
	if _, err := io.Copy(h, resp.Body); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ------------------------------------------------------------ rate limit

// rateLimit spreads reads out to bytesPerSec, shared by a pass's workers.
type rateLimit struct {
	mu   sync.Mutex
	bps  float64
	next time.Time
}

func newRateLimit(bps float64) *rateLimit { return &rateLimit{bps: bps} }

func (l *rateLimit) wait(ctx context.Context, n int) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(time.Duration(float64(n) / l.bps * float64(time.Second)))
	l.mu.Unlock()
	d := time.Until(at)
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
