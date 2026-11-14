package main

import (
	"archive/tar"
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"
)

// Selection is what someone picked in the file browser: files and folders
// in the folder Prefix of Bucket, as it is now or (with Snap) in a
// snapshot.
type Selection struct {
	Bucket, Snap, Prefix string
	Keys                 []string
	Folders              []string
}

// maxSelection bounds one request's picks; folders can hold any number.
const maxSelection = 1000

func (s Selection) check() error {
	if err := checkPrefix(s.Prefix); err != nil {
		return err
	}
	if len(s.Keys)+len(s.Folders) == 0 {
		return userErr("Select some files or folders first.")
	}
	if len(s.Keys)+len(s.Folders) > maxSelection {
		return userErr("Select at most %d things at a time.", maxSelection)
	}
	for _, k := range s.Keys {
		if err := checkKey(k); err != nil {
			return err
		}
		if !strings.HasPrefix(k, s.Prefix) {
			return userErr("That isn't in this folder.")
		}
	}
	for _, f := range s.Folders {
		if err := checkPrefix(f); err != nil || f == "" {
			return userErr("That isn't a folder.")
		}
		if !strings.HasPrefix(f, s.Prefix) {
			return userErr("That isn't in this folder.")
		}
	}
	return nil
}

// WalkSelection calls fn for every file the selection covers, folders'
// contents included, in order: a folder's marker object (key ending in /)
// stands for the folder itself. It needs read access.
func (p *Portal) WalkSelection(ctx context.Context, u User, sel Selection, fn func(Object) error) error {
	if err := sel.check(); err != nil {
		return err
	}
	list := func(prefix, after string) (*ObjectList, error) {
		if sel.Snap != "" {
			if err := p.snapshotReader(ctx, u, sel.Bucket); err != nil {
				return nil, err
			}
			l, err := p.zfs.ListSnapshot(ctx, sel.Bucket, sel.Snap, prefix, "", after, 1000)
			if errors.Is(err, ErrZFSNotFound) {
				return nil, userErr("That snapshot or folder is gone.")
			}
			if err != nil {
				return nil, err
			}
			out := &ObjectList{NextToken: l.NextStartAfter}
			for _, o := range l.Objects {
				out.Objects = append(out.Objects, Object{Key: o.Key, Size: o.Size, LastModified: o.Modified})
			}
			return out, nil
		}
		v, caps, err := p.browser(ctx, u, sel.Bucket)
		if err != nil {
			return nil, err
		}
		if !caps.Read {
			return nil, errNoList
		}
		return v.ListObjects(ctx, sel.Bucket, prefix, "", after, 1000)
	}
	for _, f := range sel.Folders {
		token := ""
		for {
			l, err := list(f, token)
			if err != nil {
				return err
			}
			for _, o := range l.Objects {
				if err := fn(o); err != nil {
					return err
				}
			}
			if l.NextToken == "" {
				break
			}
			token = l.NextToken
		}
	}
	for _, k := range sel.Keys {
		// The size and time come from the object itself when it's read.
		if err := fn(Object{Key: k, Size: -1}); err != nil {
			return err
		}
	}
	return nil
}

// openSelected opens one file of a selection for reading.
func (p *Portal) openSelected(ctx context.Context, u User, sel Selection, key string) (io.ReadCloser, int64, time.Time, error) {
	var r *http.Response
	var err error
	if sel.Snap != "" {
		r, err = p.GetSnapshotObject(ctx, u, sel.Bucket, sel.Snap, key)
	} else {
		r, err = p.GetObject(ctx, u, sel.Bucket, key)
	}
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	mod, _ := http.ParseTime(r.Header.Get("Last-Modified"))
	return r.Body, r.ContentLength, mod, nil
}

// ArchiveName is the file name to offer for an archive of sel.
func (sel Selection) ArchiveName(format string) string {
	base := sel.Bucket
	switch {
	case len(sel.Keys) == 0 && len(sel.Folders) == 1:
		base = path.Base(sel.Folders[0])
	case sel.Prefix != "":
		base = path.Base(sel.Prefix)
	}
	if sel.Snap != "" {
		base += "-" + sel.Snap
	}
	return base + "." + format
}

// WriteArchive streams sel to w as a tar or zip file, with paths relative
// to the folder the selection was made in. Nothing is gathered first: each
// file is read from the gateway as it's written, so an error part way
// leaves a truncated archive and is returned.
func (p *Portal) WriteArchive(ctx context.Context, u User, sel Selection, format string, w io.Writer) (files int, bytes int64, err error) {
	var add func(name string, o Object, body io.Reader) error
	var finish func() error
	switch format {
	case "tar":
		tw := tar.NewWriter(w)
		add = func(name string, o Object, body io.Reader) error {
			h := &tar.Header{Name: name, Size: o.Size, Mode: 0o644, ModTime: o.LastModified, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
			if body == nil {
				h.Typeflag, h.Mode, h.Size = tar.TypeDir, 0o755, 0
			}
			if err := tw.WriteHeader(h); err != nil {
				return err
			}
			if body == nil {
				return nil
			}
			n, err := io.Copy(tw, body)
			if err == nil && n != o.Size {
				err = fmt.Errorf("%s changed while being read", o.Key)
			}
			return err
		}
		finish = tw.Close
	case "zip":
		zw := zip.NewWriter(w)
		add = func(name string, o Object, body io.Reader) error {
			// Stored, not deflated: most big files are compressed already,
			// and it keeps the server's work to copying.
			h := &zip.FileHeader{Name: name, Method: zip.Store, Modified: o.LastModified}
			if body == nil {
				h.Name += "/"
			}
			fw, err := zw.CreateHeader(h)
			if err != nil || body == nil {
				return err
			}
			_, err = io.Copy(fw, body)
			return err
		}
		finish = zw.Close
	default:
		return 0, 0, userErr("Archives can be .tar or .zip.")
	}
	err = p.WalkSelection(ctx, u, sel, func(o Object) error {
		name := strings.TrimPrefix(o.Key, sel.Prefix)
		if strings.HasSuffix(o.Key, "/") {
			return add(strings.TrimSuffix(name, "/"), o, nil)
		}
		body, size, mod, err := p.openSelected(ctx, u, sel, o.Key)
		if err != nil {
			return err
		}
		defer body.Close()
		if size >= 0 {
			o.Size = size
		}
		if o.Size < 0 {
			return fmt.Errorf("%s has no length", o.Key)
		}
		if !mod.IsZero() {
			o.LastModified = mod
		}
		if err := add(name, o, body); err != nil {
			return err
		}
		files++
		bytes += o.Size
		return nil
	})
	if err != nil {
		return files, bytes, err
	}
	if err := finish(); err != nil {
		return files, bytes, err
	}
	slog.Info("downloaded archive", "user", u.Name, "bucket", sel.Bucket, "snap", sel.Snap, "prefix", sel.Prefix, "format", format, "files", files, "bytes", bytes)
	return files, bytes, nil
}

// DeleteSelection deletes the selected files and folders. It stops at the
// first failure, and says how many files went.
func (p *Portal) DeleteSelection(ctx context.Context, u User, sel Selection) (int, error) {
	if sel.Snap != "" {
		return 0, userErr("Snapshots are read only.")
	}
	if err := sel.check(); err != nil {
		return 0, err
	}
	deleted := 0
	for _, k := range sel.Keys {
		if err := p.DeleteObject(ctx, u, sel.Bucket, k); err != nil {
			return deleted, err
		}
		deleted++
	}
	for _, f := range sel.Folders {
		n, err := p.DeleteFolder(ctx, u, sel.Bucket, f)
		deleted += n
		if err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

// BucketKey is a key that asks for access to one bucket: what it asked
// for, and what it can do there now, which is less when its owner has
// lost access.
type BucketKey struct {
	KeyEntry
	Asked Perm
	Now   Caps
}

// BucketKeys lists everyone's keys that ask for access to bucket, for
// people who manage it.
func (p *Portal) BucketKeys(ctx context.Context, u User, bucket string) ([]BucketKey, error) {
	v, err := p.Bucket(ctx, u, bucket, false)
	if err != nil {
		return nil, err
	}
	if !v.Manage {
		return nil, userErr("Only %s's owner can see its keys.", bucket)
	}
	var ownerAcct string
	all, err := p.listBuckets(ctx)
	if err != nil {
		return nil, err
	}
	for _, b := range all {
		if b.Name == bucket {
			ownerAcct = b.Owner
		}
	}
	meta := p.store.BucketMeta(bucket)
	var out []BucketKey
	for _, e := range p.store.Entries() {
		perm, ok := e.Buckets[bucket]
		if !ok {
			continue
		}
		person, _ := p.store.Person(e.Owner)
		c, _ := access(e.Owner, person, ownerAcct, meta)
		out = append(out, BucketKey{KeyEntry: e, Asked: perm, Now: perm.Caps().Intersect(c)})
	}
	return out, nil
}

// RemoveKeyFromBucket takes one bucket out of a key's grants, leaving
// the key and its other buckets alone. The bucket's owner may do it to
// anyone's key, so that sharing can be undone key by key.
func (p *Portal) RemoveKeyFromBucket(ctx context.Context, u User, access, bucket string) error {
	v, err := p.Bucket(ctx, u, bucket, true)
	if err != nil {
		return err
	}
	if !v.Manage {
		return userErr("Only %s's owner can change which keys reach it.", bucket)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k, ok := p.store.Get(access)
	if !ok {
		return userErr("No such key.")
	}
	if _, ok := k.Buckets[bucket]; !ok {
		return nil
	}
	grants := map[string]Perm{}
	for b, perm := range k.Buckets {
		if b != bucket {
			grants[b] = perm
		}
	}
	if err := p.store.Put(access, &Key{Owner: k.Owner, Label: k.Label, Created: k.Created, Buckets: grants}); err != nil {
		return err
	}
	if err := p.syncBuckets(ctx, []string{bucket}); err != nil {
		return err
	}
	slog.Info("removed key from bucket", "user", u.Name, "access", access, "owner", k.Owner, "bucket", bucket)
	return nil
}
