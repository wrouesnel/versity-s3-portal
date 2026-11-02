package zfshelper

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wrouesnel/versity-s3-portal/internal/zfsapi"
)

// Deleting a bucket moves its dataset into the trash instead of
// destroying it, since every dataset collects the host's weekly snapshots,
// which a destroy would take with it. In the trash a bucket is
// <trash>/<bucket>-<UTC timestamp>, unmounted (canmount=off) and
// read-only, with all its snapshots. An admin can restore it or purge it
// for good.

func pool(ds string) string {
	p, _, _ := strings.Cut(ds, "/")
	return p
}

// checkTrash makes sure the trash dataset exists, is in the buckets'
// pool (renames can't cross pools), and is neither inside the buckets'
// parent nor its parent.
func (s *Server) checkTrash(ctx context.Context) error {
	switch {
	case s.Trash == s.Parent || strings.HasPrefix(s.Trash, s.Parent+"/"):
		return fmt.Errorf("the trash dataset %s must not be inside %s", s.Trash, s.Parent)
	case strings.HasPrefix(s.Parent, s.Trash+"/"):
		return fmt.Errorf("the trash dataset %s must not contain %s", s.Trash, s.Parent)
	case pool(s.Trash) != pool(s.Parent):
		return fmt.Errorf("the trash dataset %s must be in the same pool as %s", s.Trash, s.Parent)
	}
	st, err := s.state(ctx, s.Trash)
	if err != nil {
		return err
	}
	if !st.exists {
		return fmt.Errorf("the trash dataset %s doesn't exist", s.Trash)
	}
	if st.mounted || st.mountpoint != "none" {
		s.Log.Warn("the trash dataset should have canmount=off and mountpoint=none", "dataset", s.Trash, "mountpoint", st.mountpoint, "mounted", st.mounted)
	}
	return nil
}

// destroy moves an empty bucket's dataset to the trash. Empty means what
// the gateway means: nothing at the root but its temporary directory. An
// empty folder is a folder object, so it counts. The dataset is made
// read-only before the final emptiness check, so nothing can be written
// between the check and the move, and stays read-only in the trash. It's
// unmounted and its mountpoint directory removed, so the gateway no
// longer sees the bucket.
func (s *Server) destroy(w http.ResponseWriter, r *http.Request) error {
	name, _, _, err := s.bucketName(r)
	if err != nil {
		return err
	}
	defer s.lock(name)()
	b, err := s.dataset(r)
	if err != nil {
		return err
	}
	// Past the checks, don't stop part way for a cancelled request.
	ctx := context.WithoutCancel(r.Context())
	notEmpty := &apiError{http.StatusConflict, zfsapi.CodeNotEmpty, fmt.Sprintf("bucket %s isn't empty", name)}
	empty, err := isEmpty(b.fd)
	if err != nil || !empty {
		b.close()
		if err != nil {
			return err
		}
		return notEmpty
	}
	if err := s.setReadonly(ctx, b.ds, true); err != nil {
		b.close()
		return err
	}
	writable := func() {
		if err := s.setReadonly(ctx, b.ds, false); err != nil {
			s.Log.Error("couldn't make the bucket writable again", "bucket", name, "err", err)
		}
	}
	empty, err = isEmpty(b.fd)
	// Close the root before unmounting, or it's busy.
	b.close()
	if err != nil || !empty {
		writable()
		if err != nil {
			return err
		}
		return notEmpty
	}

	entry := name + "-" + s.Now().UTC().Format(zfsapi.SnapshotTimeFormat)
	target := s.Trash + "/" + entry
	if _, err := s.run(ctx, "unmount", b.ds); err != nil {
		writable()
		return fmt.Errorf("unmount %s (is something using it?): %w", name, err)
	}
	remount := func() {
		if _, err := s.run(ctx, "mount", b.ds); err != nil {
			s.Log.Error("couldn't mount the bucket again", "bucket", name, "err", err)
		}
		writable()
	}
	if _, err := s.run(ctx, "set", "canmount=off", b.ds); err != nil {
		remount()
		return err
	}
	if _, err := s.run(ctx, "rename", b.ds, target); err != nil {
		if _, err := s.run(ctx, "inherit", "canmount", b.ds); err != nil {
			s.Log.Error("couldn't reset canmount", "bucket", name, "err", err)
		}
		remount()
		if strings.Contains(err.Error(), "exists") {
			return &apiError{http.StatusConflict, zfsapi.CodeConflict, "that bucket was deleted moments ago already; try again in a second"}
		}
		return err
	}
	// In the trash it inherits mountpoint=none; it can't be mounted anyway.
	if _, err := s.run(ctx, "inherit", "mountpoint", target); err != nil {
		s.Log.Warn("couldn't clear the trashed bucket's mountpoint", "entry", entry, "err", err)
	}
	// The empty directory it was mounted on would look like a bucket to the
	// gateway.
	if err := syscall.Rmdir(b.dir); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("moved %s to the trash as %s, but couldn't remove its directory: %w", name, entry, err)
	}
	if st, err := s.state(ctx, target); err != nil || st.mounted {
		return fmt.Errorf("moved %s to the trash as %s, but it's still mounted (%v)", name, entry, err)
	}
	s.Log.Info("moved bucket to the trash", "bucket", name, "entry", entry)
	writeJSON(w, http.StatusOK, map[string]string{"entry": entry})
	return nil
}

// trashEntry validates the request's trash entry name.
func (s *Server) trashEntry(r *http.Request) (entry, bucket string, err error) {
	entry = r.PathValue("e")
	m := zfsapi.TrashEntryName.FindStringSubmatch(entry)
	if m == nil {
		return "", "", badRequest("bad trash entry %q", entry)
	}
	if _, err := time.Parse(zfsapi.SnapshotTimeFormat, m[2]); err != nil {
		return "", "", badRequest("bad trash entry %q", entry)
	}
	return entry, m[1], nil
}

func (s *Server) listTrash(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	out, err := s.run(ctx, "list", "-H", "-p", "-d", "1", "-t", "filesystem", "-o", "name,used", s.Trash)
	if err != nil {
		return err
	}
	entries := []zfsapi.TrashEntry{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 2 {
			continue
		}
		entry, ok := strings.CutPrefix(f[0], s.Trash+"/")
		if !ok {
			continue
		}
		m := zfsapi.TrashEntryName.FindStringSubmatch(entry)
		if m == nil {
			continue
		}
		trashed, err := time.Parse(zfsapi.SnapshotTimeFormat, m[2])
		if err != nil {
			continue
		}
		used, _ := strconv.ParseInt(f[1], 10, 64)
		e := zfsapi.TrashEntry{Entry: entry, Bucket: m[1], Trashed: trashed.UTC(), Used: used}
		snaps, err := s.allSnapshots(ctx, f[0])
		if err != nil {
			return err
		}
		for _, sn := range snaps {
			if zfsapi.SnapshotName.MatchString(sn.Name) {
				e.PortalSnapshots++
			} else {
				e.OtherSnapshots++
			}
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].Trashed.Equal(entries[j].Trashed) {
			return entries[i].Trashed.After(entries[j].Trashed)
		}
		return entries[i].Entry < entries[j].Entry
	})
	writeJSON(w, http.StatusOK, entries)
	return nil
}

// purgeTrash destroys a trashed bucket for good, with all its snapshots,
// the host's included: the admin's explicit choice.
func (s *Server) purgeTrash(w http.ResponseWriter, r *http.Request) error {
	entry, bucket, err := s.trashEntry(r)
	if err != nil {
		return err
	}
	defer s.lock(bucket)()
	ctx := r.Context()
	ds := s.Trash + "/" + entry
	st, err := s.state(ctx, ds)
	if err != nil {
		return err
	}
	if !st.exists {
		return notFound("no trash entry %s", entry)
	}
	if st.mounted {
		return &apiError{http.StatusConflict, zfsapi.CodeConflict, fmt.Sprintf("trash entry %s is mounted; unmount it on the host first", entry)}
	}
	if _, err := s.run(ctx, "destroy", "-r", ds); err != nil {
		return err
	}
	s.Log.Warn("purged bucket from the trash", "entry", entry)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// restoreTrash moves a trashed bucket back to its name, mounted at its
// directory and writable. A bucket of that name mustn't exist. The
// dataset's root still carries the gateway's xattrs (owner, ACL, policy),
// so the gateway sees the bucket again as it was.
func (s *Server) restoreTrash(w http.ResponseWriter, r *http.Request) error {
	entry, bucket, err := s.trashEntry(r)
	if err != nil {
		return err
	}
	defer s.lock(bucket)()
	ctx := context.WithoutCancel(r.Context())
	src := s.Trash + "/" + entry
	ds, dir := s.Parent+"/"+bucket, s.Root+"/"+bucket
	st, err := s.state(ctx, src)
	if err != nil {
		return err
	}
	if !st.exists {
		return notFound("no trash entry %s", entry)
	}
	exists := &apiError{http.StatusConflict, zfsapi.CodeExists, fmt.Sprintf("a bucket called %s exists; delete or rename it first", bucket)}
	if st, err := s.state(ctx, ds); err != nil || st.exists {
		if err != nil {
			return err
		}
		return exists
	}
	if _, err := os.Lstat(dir); err == nil {
		return exists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if _, err := s.run(ctx, "rename", src, ds); err != nil {
		return err
	}
	// putBack returns it to the trash, as it was, if it can't be mounted.
	putBack := func(why error) error {
		s.run(ctx, "unmount", ds)
		s.run(ctx, "set", "canmount=off", ds)
		s.run(ctx, "set", "readonly=on", ds)
		if _, err := s.run(ctx, "rename", ds, src); err != nil {
			s.Log.Error("couldn't return a bucket to the trash after a failed restore", "dataset", ds, "err", err)
		} else {
			s.run(ctx, "inherit", "mountpoint", src)
		}
		syscall.Rmdir(dir)
		return why
	}
	for _, args := range [][]string{
		{"set", "mountpoint=" + dir, ds},
		{"inherit", "canmount", ds},
		{"inherit", "readonly", ds},
		{"mount", ds},
	} {
		if _, err := s.run(ctx, args...); err != nil {
			return putBack(err)
		}
	}
	b, err := s.openDataset(ctx, bucket, ds, dir)
	if err != nil {
		return putBack(err)
	}
	b.close()
	s.Log.Info("restored bucket from the trash", "entry", entry, "bucket", bucket)
	writeJSON(w, http.StatusOK, map[string]string{"bucket": bucket, "dataset": ds})
	return nil
}
