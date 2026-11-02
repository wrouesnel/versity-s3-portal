// Package zfstest is a fake zfs command for testing s3-zfs-helper and its
// client without ZFS. Datasets are plain directories, and a snapshot is a
// copy of its dataset's files under <mountpoint>/.zfs/snapshot/<name>.
package zfstest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type snap struct {
	name    string
	created time.Time
}

// Fake answers the zfs commands the helper runs.
type Fake struct {
	mu        sync.Mutex
	mounts    map[string]string // dataset -> mountpoint
	props     map[string]map[string]string
	snaps     map[string][]snap
	calls     [][]string
	unmounted map[string]bool
	Now       func() time.Time
	FailNext  map[string]error // first argument -> error for its next call
	// CreateButNoMount makes the next create make the dataset but fail
	// to mount it, as a real mount failure would.
	CreateButNoMount bool
	// Hook, if set, sees each command before it runs.
	Hook func(args []string)
}

// Unmount marks ds as not mounted, as zfs list would report it.
func (f *Fake) Unmount(ds string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unmounted[ds] = true
}

// New makes a fake with parent mounted at root, creating root.
func New(parent, root string) (*Fake, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &Fake{
		mounts:    map[string]string{parent: root},
		props:     map[string]map[string]string{},
		snaps:     map[string][]snap{},
		unmounted: map[string]bool{},
		Now:       time.Now,
	}, nil
}

// Calls returns every command run so far.
func (f *Fake) Calls() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.calls...)
}

// Prop returns a dataset property set with zfs set, or "".
func (f *Fake) Prop(ds, prop string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.props[ds][prop]
}

// IsDataset reports whether ds exists.
func (f *Fake) IsDataset(ds string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.mounts[ds]
	return ok
}

// Snapshot takes a snapshot outside the helper, such as the host's
// weekly ones.
func (f *Fake) Snapshot(ds, name string, created time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot(ds, name, created)
}

func noDataset(name string) error {
	return fmt.Errorf("cannot open '%s': dataset does not exist", name)
}

// Run is a zfshelper.Runner.
func (f *Fake) Run(ctx context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string(nil), args...))
	if len(args) == 0 {
		return nil, errors.New("no command")
	}
	if f.Hook != nil {
		f.Hook(args)
	}
	if err := f.FailNext[args[0]]; err != nil {
		delete(f.FailNext, args[0])
		return nil, err
	}
	last := args[len(args)-1]
	switch args[0] {
	case "list":
		snapshots := contains(args, "snapshot")
		mp, ok := f.mounts[last]
		if !ok {
			return nil, noDataset(last)
		}
		if snapshots {
			var b strings.Builder
			for _, s := range f.snaps[last] {
				fmt.Fprintf(&b, "%s@%s\t%d\t%d\n", last, s.name, s.created.Unix(), 4096)
			}
			return []byte(b.String()), nil
		}
		mounted := "yes"
		if f.unmounted[last] {
			mounted = "no"
		}
		return []byte(last + "\t" + mp + "\t" + mounted + "\n"), nil

	case "get":
		mp, ok := f.mounts[last]
		if !ok {
			return nil, noDataset(last)
		}
		used := duBytes(mp)
		var b strings.Builder
		for _, p := range strings.Split(args[len(args)-2], ",") {
			v := "-"
			switch p {
			case "used", "referenced":
				v = fmt.Sprint(used)
			case "refquota":
				v = "0"
				if q := f.props[last]["refquota"]; q != "" && q != "none" {
					v = q
				}
			case "available":
				v = fmt.Sprint(int64(1) << 40)
			case "usedbysnapshots":
				v = fmt.Sprint(int64(len(f.snaps[last])) * 4096)
			default:
				if q := f.props[last][p]; q != "" {
					v = q
				}
			}
			fmt.Fprintf(&b, "%s\t%s\n", p, v)
		}
		return []byte(b.String()), nil

	case "create":
		var mp string
		for _, a := range args {
			if v, ok := strings.CutPrefix(a, "mountpoint="); ok {
				mp = v
			}
		}
		if _, ok := f.mounts[last]; ok {
			return nil, fmt.Errorf("cannot create '%s': dataset already exists", last)
		}
		if _, ok := f.mounts[last[:strings.LastIndex(last, "/")]]; !ok {
			return nil, fmt.Errorf("cannot create '%s': parent does not exist", last)
		}
		f.mounts[last] = mp
		if f.CreateButNoMount {
			f.CreateButNoMount = false
			f.unmounted[last] = true
			return nil, fmt.Errorf("filesystem successfully created, but not mounted")
		}
		if err := os.Mkdir(mp, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		return nil, nil

	case "destroy":
		if ds, name, ok := strings.Cut(last, "@"); ok {
			mp, okds := f.mounts[ds]
			idx := -1
			for i, s := range f.snaps[ds] {
				if s.name == name {
					idx = i
				}
			}
			if !okds || idx < 0 {
				return nil, noDataset(last)
			}
			f.snaps[ds] = append(f.snaps[ds][:idx], f.snaps[ds][idx+1:]...)
			return nil, removeAll(filepath.Join(mp, ".zfs", "snapshot", name))
		}
		mp, ok := f.mounts[last]
		if !ok {
			return nil, noDataset(last)
		}
		if len(f.snaps[last]) > 0 && !contains(args, "-r") {
			return nil, fmt.Errorf("cannot destroy '%s': filesystem has children", last)
		}
		delete(f.mounts, last)
		delete(f.snaps, last)
		delete(f.props, last)
		if f.unmounted[last] {
			delete(f.unmounted, last)
			return nil, nil
		}
		return nil, removeAll(mp)

	case "set":
		prop, val, _ := strings.Cut(args[1], "=")
		old, ok := f.mounts[last]
		if !ok {
			return nil, noDataset(last)
		}
		if prop == "mountpoint" {
			// Remount: the dataset's files move with it.
			if err := os.Rename(old, val); err != nil {
				return nil, fmt.Errorf("cannot mount '%s': %v", last, err)
			}
			f.mounts[last] = val
			return nil, nil
		}
		if f.props[last] == nil {
			f.props[last] = map[string]string{}
		}
		f.props[last][prop] = val
		return nil, nil

	case "inherit":
		if _, ok := f.mounts[last]; !ok {
			return nil, noDataset(last)
		}
		delete(f.props[last], args[1])
		return nil, nil

	case "snapshot":
		ds, name, _ := strings.Cut(last, "@")
		return nil, f.snapshot(ds, name, f.Now())
	}
	return nil, fmt.Errorf("fake zfs: unsupported command %v", args)
}

func (f *Fake) snapshot(ds, name string, created time.Time) error {
	mp, ok := f.mounts[ds]
	if !ok {
		return noDataset(ds)
	}
	for _, s := range f.snaps[ds] {
		if s.name == name {
			return fmt.Errorf("cannot create snapshot '%s@%s': dataset already exists", ds, name)
		}
	}
	dst := filepath.Join(mp, ".zfs", "snapshot", name)
	if err := copyTree(mp, dst); err != nil {
		return err
	}
	f.snaps[ds] = append(f.snaps[ds], snap{name, created})
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// removeAll removes a tree even where the test made it read-only.
func removeAll(dir string) error {
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			os.Chmod(p, 0o700)
		}
		return nil
	})
	return os.RemoveAll(dir)
}

func duBytes(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && d.Name() == ".zfs" {
			return filepath.SkipDir
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			n += info.Size()
		}
		return nil
	})
	return n
}

// copyTree copies src to dst, skipping .zfs, keeping modes, times, user
// xattrs and symlinks as they are.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if rel == ".zfs" {
			return filepath.SkipDir
		}
		target := filepath.Join(dst, rel)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case info.IsDir():
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			in, err := os.Open(p)
			if err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				in.Close()
				return err
			}
			_, err = io.Copy(out, in)
			in.Close()
			out.Close()
			if err != nil {
				return err
			}
		default:
			return nil
		}
		copyXattrs(p, target)
		os.Chmod(target, info.Mode().Perm())
		return os.Chtimes(target, info.ModTime(), info.ModTime())
	})
}

func copyXattrs(src, dst string) {
	buf := make([]byte, 64<<10)
	n, err := syscall.Listxattr(src, buf)
	if err != nil {
		return
	}
	for _, name := range strings.Split(string(buf[:n]), "\x00") {
		if !strings.HasPrefix(name, "user.") {
			continue
		}
		val := make([]byte, 64<<10)
		m, err := syscall.Getxattr(src, name, val)
		if err == nil {
			syscall.Setxattr(dst, name, val[:m], 0)
		}
	}
}
