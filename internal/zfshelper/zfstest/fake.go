// Package zfstest is a fake zfs command for testing s3-zfs-helper and its
// client without ZFS. A mounted dataset's files are a plain directory at
// its mountpoint; an unmounted one's are kept aside in a hidden directory
// and move back when it's mounted. A snapshot is a copy of the dataset's
// files under .zfs/snapshot/<name>.
package zfstest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type snap struct {
	name    string
	created time.Time
}

type dataset struct {
	mountpoint string // "none" for none
	mounted    bool
	canmount   string
	props      map[string]string
	snaps      []snap
}

// Fake answers the zfs commands the helper runs.
type Fake struct {
	mu    sync.Mutex
	aside string // where unmounted datasets' files are kept
	ds    map[string]*dataset
	calls [][]string
	Now   func() time.Time
	// FailNext maps a command (its first argument) to an error for its
	// next call.
	FailNext map[string]error
	// CreateButNoMount makes the next create make the dataset but fail
	// to mount it, as a real mount failure would.
	CreateButNoMount bool
	// Hook, if set, sees each command before it runs.
	Hook func(args []string)
}

// New makes a fake with parent mounted at root, creating root.
func New(parent, root string) (*Fake, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	aside := filepath.Join(filepath.Dir(root), ".fakezfs")
	if err := os.MkdirAll(aside, 0o700); err != nil {
		return nil, err
	}
	f := &Fake{aside: aside, ds: map[string]*dataset{}, Now: time.Now}
	f.ds[parent] = &dataset{mountpoint: root, mounted: true, canmount: "on", props: map[string]string{}}
	return f, nil
}

// AddUnmounted adds a dataset with no mountpoint, such as the trash
// parent.
func (f *Fake) AddUnmounted(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ds[name] = &dataset{mountpoint: "none", canmount: "off", props: map[string]string{}}
	os.MkdirAll(f.asideDir(name), 0o755)
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
	if d, ok := f.ds[ds]; ok {
		return d.props[prop]
	}
	return ""
}

// IsDataset reports whether ds exists.
func (f *Fake) IsDataset(ds string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.ds[ds]
	return ok
}

// Mounted reports whether ds exists and is mounted, and where.
func (f *Fake) Mounted(ds string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.ds[ds]
	if !ok || !d.mounted {
		return "", false
	}
	return d.mountpoint, true
}

// Unmount unmounts ds, as if something on the host had.
func (f *Fake) Unmount(ds string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unmount(ds)
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

func (f *Fake) asideDir(name string) string {
	return filepath.Join(f.aside, strings.ReplaceAll(name, "/", "%"))
}

// data is where ds's files are now.
func (f *Fake) data(name string) string {
	if d := f.ds[name]; d.mounted {
		return d.mountpoint
	}
	return f.asideDir(name)
}

func (f *Fake) unmount(name string) error {
	d := f.ds[name]
	if !d.mounted {
		return nil
	}
	if err := os.Rename(d.mountpoint, f.asideDir(name)); err != nil {
		return err
	}
	d.mounted = false
	return nil
}

func (f *Fake) mount(name string) error {
	d := f.ds[name]
	if d.mounted {
		return nil
	}
	if d.mountpoint == "none" || d.canmount == "off" {
		return fmt.Errorf("cannot mount '%s': not mountable", name)
	}
	// zfs mounts over an empty directory, or makes one.
	if err := syscall.Rmdir(d.mountpoint); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("cannot mount '%s': directory is not empty", name)
	}
	if err := os.Rename(f.asideDir(name), d.mountpoint); err != nil {
		return err
	}
	d.mounted = true
	return nil
}

func (f *Fake) parentOf(name string) *dataset {
	i := strings.LastIndex(name, "/")
	if i < 0 {
		return nil
	}
	return f.ds[name[:i]]
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
		return f.list(args)

	case "get":
		d, ok := f.ds[last]
		if !ok {
			return nil, noDataset(last)
		}
		used := duBytes(f.data(last))
		var b strings.Builder
		for _, p := range strings.Split(args[len(args)-2], ",") {
			v := "-"
			switch p {
			case "used", "referenced":
				v = fmt.Sprint(used)
			case "refquota":
				v = "0"
				if q := d.props["refquota"]; q != "" && q != "none" {
					v = q
				}
			case "available":
				v = fmt.Sprint(int64(1) << 40)
			case "usedbysnapshots":
				v = fmt.Sprint(int64(len(d.snaps)) * 4096)
			default:
				if q := d.props[p]; q != "" {
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
		if _, ok := f.ds[last]; ok {
			return nil, fmt.Errorf("cannot create '%s': dataset already exists", last)
		}
		if f.parentOf(last) == nil {
			return nil, fmt.Errorf("cannot create '%s': parent does not exist", last)
		}
		d := &dataset{mountpoint: mp, canmount: "on", props: map[string]string{}}
		f.ds[last] = d
		if err := os.Mkdir(f.asideDir(last), 0o755); err != nil {
			return nil, err
		}
		if f.CreateButNoMount {
			f.CreateButNoMount = false
			return nil, fmt.Errorf("filesystem successfully created, but not mounted")
		}
		return nil, f.mount(last)

	case "destroy":
		if name, snapName, ok := strings.Cut(last, "@"); ok {
			d, okds := f.ds[name]
			idx := -1
			if okds {
				for i, s := range d.snaps {
					if s.name == snapName {
						idx = i
					}
				}
			}
			if idx < 0 {
				return nil, noDataset(last)
			}
			d.snaps = append(d.snaps[:idx], d.snaps[idx+1:]...)
			return nil, removeAll(filepath.Join(f.data(name), ".zfs", "snapshot", snapName))
		}
		d, ok := f.ds[last]
		if !ok {
			return nil, noDataset(last)
		}
		if len(d.snaps) > 0 && !contains(args, "-r") {
			return nil, fmt.Errorf("cannot destroy '%s': filesystem has children", last)
		}
		dir := f.data(last)
		delete(f.ds, last)
		return nil, removeAll(dir)

	case "unmount":
		if _, ok := f.ds[last]; !ok {
			return nil, noDataset(last)
		}
		return nil, f.unmount(last)

	case "mount":
		if _, ok := f.ds[last]; !ok {
			return nil, noDataset(last)
		}
		return nil, f.mount(last)

	case "rename":
		from, to := args[len(args)-2], last
		d, ok := f.ds[from]
		if !ok {
			return nil, noDataset(from)
		}
		if _, ok := f.ds[to]; ok {
			return nil, fmt.Errorf("cannot rename to '%s': dataset already exists", to)
		}
		if f.parentOf(to) == nil {
			return nil, fmt.Errorf("cannot rename to '%s': parent does not exist", to)
		}
		if strings.SplitN(from, "/", 2)[0] != strings.SplitN(to, "/", 2)[0] {
			return nil, fmt.Errorf("cannot rename to '%s': datasets must be within same pool", to)
		}
		if !d.mounted {
			if err := os.Rename(f.asideDir(from), f.asideDir(to)); err != nil {
				return nil, err
			}
		}
		delete(f.ds, from)
		f.ds[to] = d
		return nil, nil

	case "set":
		prop, val, _ := strings.Cut(args[1], "=")
		d, ok := f.ds[last]
		if !ok {
			return nil, noDataset(last)
		}
		switch prop {
		case "mountpoint":
			if d.mounted {
				// Remount: the files move with it.
				if err := os.Rename(d.mountpoint, val); err != nil {
					return nil, fmt.Errorf("cannot mount '%s': %v", last, err)
				}
			}
			d.mountpoint = val
		case "canmount":
			d.canmount = val
			if val == "off" {
				if err := f.unmount(last); err != nil {
					return nil, err
				}
			}
		default:
			d.props[prop] = val
		}
		return nil, nil

	case "inherit":
		prop := args[1]
		d, ok := f.ds[last]
		if !ok {
			return nil, noDataset(last)
		}
		switch prop {
		case "mountpoint":
			p := f.parentOf(last)
			mp := "none"
			if p != nil && p.mountpoint != "none" {
				mp = filepath.Join(p.mountpoint, last[strings.LastIndex(last, "/")+1:])
			}
			if d.mounted {
				if err := f.unmount(last); err != nil {
					return nil, err
				}
			}
			d.mountpoint = mp
		case "canmount":
			d.canmount = "on"
		default:
			delete(d.props, prop)
		}
		return nil, nil

	case "snapshot":
		name, snapName, _ := strings.Cut(last, "@")
		return nil, f.snapshot(name, snapName, f.Now())
	}
	return nil, fmt.Errorf("fake zfs: unsupported command %v", args)
}

// list answers zfs list -H [-p] [-t snapshot] [-d 1] -o fields name.
func (f *Fake) list(args []string) ([]byte, error) {
	last := args[len(args)-1]
	d, ok := f.ds[last]
	if !ok {
		return nil, noDataset(last)
	}
	var fields []string
	for i, a := range args {
		if a == "-o" {
			fields = strings.Split(args[i+1], ",")
		}
	}
	var b strings.Builder
	row := func(vals map[string]string) {
		out := make([]string, len(fields))
		for i, fl := range fields {
			out[i] = vals[fl]
		}
		b.WriteString(strings.Join(out, "\t") + "\n")
	}
	if contains(args, "snapshot") {
		for _, s := range d.snaps {
			row(map[string]string{"name": last + "@" + s.name, "creation": fmt.Sprint(s.created.Unix()), "used": "4096"})
		}
		return []byte(b.String()), nil
	}
	names := []string{last}
	if contains(args, "-d") {
		for n := range f.ds {
			if strings.HasPrefix(n, last+"/") && !strings.Contains(n[len(last)+1:], "/") {
				names = append(names, n)
			}
		}
		sort.Strings(names[1:])
	}
	for _, n := range names {
		x := f.ds[n]
		mounted := "no"
		if x.mounted {
			mounted = "yes"
		}
		row(map[string]string{"name": n, "mountpoint": x.mountpoint, "mounted": mounted, "used": fmt.Sprint(duBytes(f.data(n)))})
	}
	return []byte(b.String()), nil
}

func (f *Fake) snapshot(name, snapName string, created time.Time) error {
	d, ok := f.ds[name]
	if !ok {
		return noDataset(name)
	}
	for _, s := range d.snaps {
		if s.name == snapName {
			return fmt.Errorf("cannot create snapshot '%s@%s': dataset already exists", name, snapName)
		}
	}
	src := f.data(name)
	if err := copyTree(src, filepath.Join(src, ".zfs", "snapshot", snapName)); err != nil {
		return err
	}
	d.snaps = append(d.snaps, snap{snapName, created})
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
