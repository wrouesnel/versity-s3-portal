package zfshelper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/wrouesnel/versity-s3-portal/internal/zfsapi"
)

// Adopting turns a bucket the gateway just made, still an empty
// directory, into a dataset mounted in its place, carrying over the
// directory's owner, mode and xattrs (where the gateway keeps the bucket's
// owner, ACL and policy):
//
//  1. check the directory holds nothing but the gateway's empty temporary
//     directories, and save its metadata to StateDir, synced to disk;
//  2. create the dataset unmounted, with canmount=noauto so nothing mounts
//     it behind our back, have the mounter mount it in Staging, a root-only
//     directory outside the buckets tree, set it up there, and have the
//     mounter unmount it, so it's never visible half done;
//  3. remove the directory and have the mounter mount the dataset in its
//     place, then set canmount=on so the host mounts it at boot (at its
//     inherited mountpoint, which is the same place);
//  4. delete the saved metadata.
//
// The helper never sets a mountpoint: its user isn't allowed to, so a
// bucket can't be made to mount over anything else at boot. If a step
// fails, what was done is undone. If the helper dies part way, Recover
// (run at startup) finishes or undoes it from the saved metadata.

// adoptState is what's saved in StateDir while a bucket is being adopted.
type adoptState struct {
	Bucket string `json:"bucket"`
	Meta   *meta  `json:"meta"`
}

func (s *Server) statePath(bucket string) string {
	return filepath.Join(s.StateDir, bucket+".json")
}

func (s *Server) saveState(bucket string, m *meta) error {
	data, err := json.Marshal(adoptState{Bucket: bucket, Meta: m})
	if err != nil {
		return err
	}
	tmp := s.statePath(bucket) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.statePath(bucket)); err != nil {
		return err
	}
	return syncDir(s.StateDir)
}

func (s *Server) dropState(bucket string) {
	if err := os.Remove(s.statePath(bucket)); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.Log.Error("couldn't remove saved adoption state", "bucket", bucket, "err", err)
		return
	}
	syncDir(s.StateDir)
}

func syncDir(dir string) error {
	fd, err := openRoot(dir)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return syscall.Fsync(fd)
}

func (s *Server) adopt(w http.ResponseWriter, r *http.Request) error {
	name, ds, dir, err := s.bucketName(r)
	if err != nil {
		return err
	}
	defer s.lock(name)()
	ctx := r.Context()
	st, err := s.state(ctx, ds)
	if err != nil {
		return err
	}
	if st.exists {
		b, err := s.openDataset(ctx, name, ds, dir)
		if err != nil {
			return &apiError{http.StatusConflict, zfsapi.CodeConflict,
				fmt.Sprintf("dataset %s exists but isn't ready (%v); restart the helper to recover it", ds, err)}
		}
		b.close()
		writeJSON(w, http.StatusOK, map[string]string{"dataset": ds})
		return nil
	}
	created, err := s.adoptNew(context.WithoutCancel(ctx), name, ds, dir)
	if err != nil {
		return err
	}
	if !created {
		writeJSON(w, http.StatusOK, map[string]string{"dataset": ds})
		return nil
	}
	writeJSON(w, http.StatusCreated, map[string]string{"dataset": ds})
	return nil
}

// adoptNew adopts a bucket directory with no dataset yet. It isn't
// cancelled with the request: stopping part way would leave more to undo.
func (s *Server) adoptNew(ctx context.Context, name, ds, dir string) (bool, error) {
	fd, err := openRoot(dir)
	if errors.Is(err, syscall.ENOENT) {
		return false, notFound("no bucket directory %s", dir)
	}
	if err != nil {
		return false, err
	}
	err = checkEmptyInternals(fd)
	var m *meta
	if err == nil {
		m, err = readMeta(fd)
	}
	syscall.Close(fd)
	if err != nil {
		return false, err
	}
	if err := s.saveState(name, m); err != nil {
		return false, fmt.Errorf("save the bucket directory's metadata: %w", err)
	}

	// undo destroys the new dataset; the directory is still in place.
	undo := func(why error) (bool, error) {
		if err := s.Mount.Unmount(ctx, zfsapi.PlaceStaging, name); err != nil {
			s.Log.Error("couldn't unmount a half-adopted dataset from staging; Recover will retry at startup", "dataset", ds, "err", err)
			return false, why
		}
		if st, err := s.state(ctx, ds); err == nil && st.exists {
			if _, err := s.run(ctx, "destroy", ds); err != nil {
				s.Log.Error("couldn't destroy half-adopted dataset; Recover will retry at startup", "dataset", ds, "err", err)
				return false, why
			}
		}
		s.dropState(name)
		return false, why
	}
	if _, err := s.run(ctx, "create", "-u", "-o", "canmount=noauto", ds); err != nil {
		return undo(err)
	}
	if err := s.Mount.Mount(ctx, zfsapi.PlaceStaging, name); err != nil {
		return undo(err)
	}
	stage := filepath.Join(s.Staging, name)
	sfd, err := s.openMounted(stage, s.Staging)
	if err == nil {
		err = m.apply(sfd, true)
		syscall.Close(sfd)
	}
	if err != nil {
		return undo(fmt.Errorf("set up the new dataset: %w", err))
	}
	if err := s.Mount.Unmount(ctx, zfsapi.PlaceStaging, name); err != nil {
		return undo(err)
	}

	// Check again (the gateway may have written meanwhile), and clear the
	// gateway's temporary directories.
	fd, err = openRoot(dir)
	if err == nil {
		err = removeEmptyInternals(fd)
		syscall.Close(fd)
	}
	if err == nil {
		err = syscall.Rmdir(dir)
	}
	if err != nil {
		return undo(err)
	}
	if err := s.Mount.Mount(ctx, zfsapi.PlaceBucket, name); err != nil {
		s.Mount.Unmount(ctx, zfsapi.PlaceBucket, name)
		if perr := s.putBack(dir, m); perr != nil {
			s.Log.Error("couldn't put the bucket directory back; Recover will retry at startup", "bucket", name, "err", perr)
			return false, err
		}
		return undo(err)
	}
	b, err := s.openDataset(ctx, name, ds, dir)
	if err != nil {
		s.Log.Error("adopted dataset isn't mounted at its bucket; Recover will sort it out at startup", "bucket", name, "err", err)
		return false, err
	}
	b.close()
	s.mountAtBoot(ctx, name, ds)
	s.dropState(name)
	s.Log.Info("adopted bucket", "bucket", name, "dataset", ds)
	return true, nil
}

// mountAtBoot sets canmount=on on a bucket mounted in its place, so the
// host mounts it at boot. If that fails the bucket still works until the
// host restarts, so it's logged rather than undone; Check tries again at
// startup.
func (s *Server) mountAtBoot(ctx context.Context, name, ds string) {
	if err := s.setProp(ctx, ds, "canmount", "on"); err != nil {
		s.Log.Error("couldn't set canmount=on; the bucket won't be mounted after a reboot until the helper restarts", "bucket", name, "err", err)
	}
}

// putBack recreates a bucket directory with its saved metadata.
func (s *Server) putBack(dir string, m *meta) error {
	if err := syscall.Mkdir(dir, 0o700); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	fd, err := openRoot(dir)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return m.apply(fd, true)
}

// Recover finishes or undoes adoptions a crash interrupted. A dataset
// mounted at its bucket is done; anything else is destroyed (it was
// created moments before and is empty) and the bucket directory put back.
func (s *Server) Recover(ctx context.Context) error {
	ents, err := os.ReadDir(s.StateDir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		bucket, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !zfsapi.BucketName.MatchString(bucket) {
			continue
		}
		if err := s.recoverOne(ctx, bucket); err != nil {
			s.Log.Error("couldn't recover an interrupted adoption", "bucket", bucket, "err", err)
		}
	}
	return nil
}

func (s *Server) recoverOne(ctx context.Context, bucket string) error {
	data, err := os.ReadFile(s.statePath(bucket))
	if err != nil {
		return err
	}
	var st adoptState
	if err := json.Unmarshal(data, &st); err != nil || st.Meta == nil || st.Bucket != bucket {
		return fmt.Errorf("unreadable state file %s", s.statePath(bucket))
	}
	ds, dir := s.Parent+"/"+bucket, s.Root+"/"+bucket
	if err := s.Mount.Unmount(ctx, zfsapi.PlaceStaging, bucket); err != nil {
		return err
	}
	if b, err := s.openDataset(ctx, bucket, ds, dir); err == nil {
		b.close()
		s.mountAtBoot(ctx, bucket, ds)
		s.Log.Info("finished an interrupted adoption", "bucket", bucket)
		s.dropState(bucket)
		return nil
	}
	dsState, err := s.state(ctx, ds)
	if err != nil {
		return err
	}
	if dsState.exists {
		// It may be mounted at the bucket's directory but not usable;
		// the mounter only unmounts it if it's that dataset.
		if err := s.Mount.Unmount(ctx, zfsapi.PlaceBucket, bucket); err != nil {
			return err
		}
		if _, err := s.run(ctx, "destroy", ds); err != nil {
			return fmt.Errorf("destroy %s: %w", ds, err)
		}
	}
	if err := s.putBack(dir, st.Meta); err != nil {
		return fmt.Errorf("put back %s: %w", dir, err)
	}
	s.Log.Warn("undid an interrupted adoption", "bucket", bucket)
	s.dropState(bucket)
	return nil
}

// checkEmptyInternals checks the bucket directory fd holds nothing but
// the gateway's temporary directory, itself holding only directories.
func checkEmptyInternals(fd int) error {
	ents, err := readDirAt(fd)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.name != ".sgwtmp" || !e.isDir() {
			return &apiError{http.StatusConflict, zfsapi.CodeNotEmpty, "the bucket directory isn't empty"}
		}
		if err := dirsOnly(fd, e.name, false); err != nil {
			return err
		}
	}
	return nil
}

// removeEmptyInternals checks as checkEmptyInternals does, and removes
// the temporary directories.
func removeEmptyInternals(fd int) error {
	if err := checkEmptyInternals(fd); err != nil {
		return err
	}
	ents, err := readDirAt(fd)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if err := dirsOnly(fd, e.name, true); err != nil {
			return err
		}
	}
	return nil
}

// dirsOnly checks the directory name below dirfd holds only directories,
// and with remove, removes them all.
func dirsOnly(dirfd int, name string, remove bool) error {
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
			if err = dirsOnly(fd, e.name, remove); err != nil {
				break
			}
		}
	}
	syscall.Close(fd)
	if err != nil || !remove {
		return err
	}
	return unlinkatDir(dirfd, name)
}
