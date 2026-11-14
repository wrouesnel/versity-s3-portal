// Package zfstest is a fake zfs command, and a fake s3-zfs-mounter, for
// testing s3-zfs-helper and its client without ZFS. A mounted dataset's
// files are a plain directory where it's mounted; an unmounted one's are
// kept aside in a hidden directory and move back when it's mounted. A
// snapshot is a copy of the dataset's files under .zfs/snapshot/<name>.
//
// It answers as zfs does for the helper's unprivileged user with the
// delegated grants in docs/zfs-helper.md: it can't mount or unmount,
// can't set mountpoint, exec, setuid or devices, and a change to readonly
// or canmount on a mounted dataset is made but reported as a failure,
// since libzfs then can't remount it.
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
	mountpoint string // set locally; "" inherits
	at         string // where it's mounted; "" when it isn't
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
	// FailNext maps a command (its first argument, or "mounter mount"
	// and "mounter unmount") to an error for its next call.
	FailNext map[string]error
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
	f.ds[parent] = &dataset{mountpoint: root, at: root, props: map[string]string{}}
	return f, nil
}

// AddUnmounted adds a dataset with no mountpoint, such as the trash
// parent.
func (f *Fake) AddUnmounted(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ds[name] = &dataset{mountpoint: "none", props: map[string]string{"canmount": "off"}}
	os.MkdirAll(f.asideDir(name), 0o755)
}

// AddMounted adds a dataset already mounted at dir, such as a bucket
// left from an earlier run.
func (f *Fake) AddMounted(name, dir string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ds[name] = &dataset{at: dir, props: map[string]string{}}
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
		if prop == "mountpoint" {
			return d.mountpoint
		}
		return d.props[prop]
	}
	return ""
}

// SetProp sets a property as root on the host would, such as a local
// mountpoint left by an older helper.
func (f *Fake) SetProp(ds, prop, val string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d, ok := f.ds[ds]; ok {
		if prop == "mountpoint" {
			d.mountpoint = val
		} else {
			d.props[prop] = val
		}
	}
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
	if !ok || d.at == "" {
		return "", false
	}
	return d.at, true
}

// Unmount unmounts ds, as if something on the host had.
func (f *Fake) Unmount(ds string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unmount(ds)
}

// MountAt mounts ds at dir, as root on the host could.
func (f *Fake) MountAt(ds, dir string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mountAt(ds, dir)
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

func denied(what, name string) error {
	return fmt.Errorf("cannot %s '%s': permission denied", what, name)
}

func (f *Fake) asideDir(name string) string {
	return filepath.Join(f.aside, strings.ReplaceAll(name, "/", "%"))
}

// data is where ds's files are now.
func (f *Fake) data(name string) string {
	if d := f.ds[name]; d.at != "" {
		return d.at
	}
	return f.asideDir(name)
}

// mountpoint is ds's mountpoint property, set or inherited.
func (f *Fake) mountpoint(name string) string {
	d := f.ds[name]
	if d.mountpoint != "" {
		return d.mountpoint
	}
	i := strings.LastIndex(name, "/")
	if i < 0 {
		return "/" + name
	}
	if p := f.mountpoint(name[:i]); p != "none" {
		return p + "/" + name[i+1:]
	}
	return "none"
}

func (f *Fake) canmount(name string) string {
	if v := f.ds[name].props["canmount"]; v != "" {
		return v
	}
	return "on"
}

func (f *Fake) unmount(name string) error {
	d := f.ds[name]
	if d.at == "" {
		return nil
	}
	if err := os.Rename(d.at, f.asideDir(name)); err != nil {
		return err
	}
	d.at = ""
	return nil
}

// mountAt mounts ds over dir, an empty directory, as a raw mount(2)
// would: the mountpoint property doesn't matter, canmount=off does.
func (f *Fake) mountAt(name, dir string) error {
	d, ok := f.ds[name]
	if !ok {
		return noDataset(name)
	}
	if d.at != "" {
		return fmt.Errorf("%s is already mounted at %s", name, d.at)
	}
	if f.canmount(name) == "off" {
		return fmt.Errorf("cannot mount '%s': canmount=off", name)
	}
	if err := syscall.Rmdir(dir); err != nil {
		return fmt.Errorf("mount %s on %s: %w", name, dir, err)
	}
	if err := os.Rename(f.asideDir(name), dir); err != nil {
		return err
	}
	d.at = dir
	return nil
}

func (f *Fake) parentOf(name string) *dataset {
	i := strings.LastIndex(name, "/")
	if i < 0 {
		return nil
	}
	return f.ds[name[:i]]
}

// remountProps are the properties libzfs remounts for, which an
// unprivileged user then can't do.
var remountProps = map[string]bool{"readonly": true, "canmount": true}

// forbiddenProps aren't delegated.
var forbiddenProps = map[string]bool{"mountpoint": true, "exec": true, "setuid": true, "devices": true, "zoned": true}

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
		var fields []string
		for i, a := range args {
			if a == "-o" {
				fields = strings.Split(args[i+1], ",")
			}
		}
		used := duBytes(f.data(last))
		var b strings.Builder
		for _, p := range strings.Split(args[len(args)-2], ",") {
			v, source := "-", "default"
			if q, ok := d.props[p]; ok {
				v, source = q, "local"
			}
			switch p {
			case "used", "referenced":
				v = fmt.Sprint(used)
			case "refquota":
				if v == "-" || v == "none" {
					v = "0"
				}
			case "available":
				v = fmt.Sprint(int64(1) << 40)
			case "usedbysnapshots":
				v = fmt.Sprint(int64(len(d.snaps)) * 4096)
			case "readonly":
				if v == "-" {
					v = "off"
				}
			case "canmount":
				v = f.canmount(last)
			case "mountpoint":
				v = f.mountpoint(last)
				if d.mountpoint != "" {
					source = "local"
				} else {
					source = "inherited"
				}
			}
			vals := map[string]string{"property": p, "value": v, "source": source}
			out := make([]string, len(fields))
			for i, fl := range fields {
				out[i] = vals[fl]
			}
			b.WriteString(strings.Join(out, "\t") + "\n")
		}
		return []byte(b.String()), nil

	case "create":
		props := map[string]string{}
		for i, a := range args {
			if a == "-o" {
				k, v, _ := strings.Cut(args[i+1], "=")
				props[k] = v
			}
		}
		for k := range props {
			if forbiddenProps[k] {
				return nil, denied("create", last)
			}
		}
		if _, ok := f.ds[last]; ok {
			return nil, fmt.Errorf("cannot create '%s': dataset already exists", last)
		}
		if f.parentOf(last) == nil {
			return nil, fmt.Errorf("cannot create '%s': parent does not exist", last)
		}
		f.ds[last] = &dataset{props: props}
		if err := os.Mkdir(f.asideDir(last), 0o755); err != nil {
			return nil, err
		}
		if !contains(args, "-u") {
			return nil, errors.New("filesystem successfully created, but it may only be mounted by root")
		}
		return nil, nil

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
		if d.at != "" {
			return nil, fmt.Errorf("cannot unmount '%s': permission denied", d.at)
		}
		if len(d.snaps) > 0 && !contains(args, "-r") {
			return nil, fmt.Errorf("cannot destroy '%s': filesystem has children", last)
		}
		dir := f.data(last)
		delete(f.ds, last)
		return nil, removeAll(dir)

	case "mount", "unmount":
		return nil, errors.New("only root can mount or unmount filesystems")

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
		if d.at != "" {
			// It would be remounted, or left mounted at the old place.
			return nil, fmt.Errorf("cannot rename '%s': it's mounted (the helper renames only unmounted datasets)", from)
		}
		if !contains(args, "-u") {
			return nil, fmt.Errorf("cannot rename '%s': without -u zfs would mount it", from)
		}
		if err := os.Rename(f.asideDir(from), f.asideDir(to)); err != nil {
			return nil, err
		}
		delete(f.ds, from)
		f.ds[to] = d
		return nil, nil

	case "set", "inherit":
		var prop, val string
		if args[0] == "set" {
			prop, val, _ = strings.Cut(args[1], "=")
		} else {
			prop = args[1]
		}
		d, ok := f.ds[last]
		if !ok {
			return nil, noDataset(last)
		}
		if forbiddenProps[prop] {
			return nil, denied("set property for", last)
		}
		if args[0] == "set" {
			d.props[prop] = val
		} else {
			delete(d.props, prop)
		}
		if remountProps[prop] && d.at != "" {
			return nil, fmt.Errorf("cannot remount '%s': permission denied (exit status 255)", last)
		}
		return nil, nil

	case "snapshot":
		name, snapName, _ := strings.Cut(last, "@")
		return nil, f.snapshot(name, snapName, f.Now())
	}
	return nil, fmt.Errorf("fake zfs: unsupported command %v", args)
}

// Mounter is a fake s3-zfs-mounter, mounting the buckets of parent at
// root or in staging.
type Mounter struct {
	f                     *Fake
	parent, root, staging string
	// Dev, when set, is what RootDev reports instead of root's device,
	// as if the host had remounted the parent.
	Dev uint64
}

// RootDev is the device number of root.
func (m *Mounter) RootDev(ctx context.Context) (uint64, error) {
	if m.Dev != 0 {
		return m.Dev, nil
	}
	var st syscall.Stat_t
	if err := syscall.Stat(m.root, &st); err != nil {
		return 0, err
	}
	return st.Dev, nil
}

// Mounter makes a fake mounter for this fake's datasets.
func (f *Fake) Mounter(parent, root, staging string) *Mounter {
	return &Mounter{f: f, parent: parent, root: root, staging: staging}
}

func (m *Mounter) dir(place, bucket string) (string, error) {
	switch place {
	case "bucket":
		return filepath.Join(m.root, bucket), nil
	case "staging":
		return filepath.Join(m.staging, bucket), nil
	}
	return "", fmt.Errorf("bad place %q", place)
}

func (m *Mounter) call(op, place, bucket string) error {
	f := m.f
	f.calls = append(f.calls, []string{"mounter", op, place, bucket})
	if f.Hook != nil {
		f.Hook([]string{"mounter", op, place, bucket})
	}
	if err := f.FailNext["mounter "+op]; err != nil {
		delete(f.FailNext, "mounter "+op)
		return err
	}
	return nil
}

// Mount mounts the bucket's dataset at its place, making the directory
// if it's missing and refusing one that isn't empty.
func (m *Mounter) Mount(ctx context.Context, place, bucket string) error {
	f := m.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := m.call("mount", place, bucket); err != nil {
		return err
	}
	dir, err := m.dir(place, bucket)
	if err != nil {
		return err
	}
	ds := m.parent + "/" + bucket
	d, ok := f.ds[ds]
	if !ok {
		return noDataset(ds)
	}
	if d.at == dir {
		return nil
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if ents, err := os.ReadDir(dir); err != nil || len(ents) > 0 {
		return fmt.Errorf("%s isn't an empty directory (%v)", dir, err)
	}
	return f.mountAt(ds, dir)
}

// Unmount unmounts the bucket's dataset from its place, if it's there,
// and removes the directory if it's empty.
func (m *Mounter) Unmount(ctx context.Context, place, bucket string) error {
	f := m.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := m.call("unmount", place, bucket); err != nil {
		return err
	}
	dir, err := m.dir(place, bucket)
	if err != nil {
		return err
	}
	ds := m.parent + "/" + bucket
	if d, ok := f.ds[ds]; ok && d.at == dir {
		if err := f.unmount(ds); err != nil {
			return err
		}
	}
	syscall.Rmdir(dir)
	return nil
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
		mounted := "no"
		if f.ds[n].at != "" {
			mounted = "yes"
		}
		du := fmt.Sprint(duBytes(f.data(n)))
		quota := f.ds[n].props["refquota"]
		if quota == "" || quota == "none" {
			quota = "0"
		}
		row(map[string]string{"name": n, "mountpoint": f.mountpoint(n), "mounted": mounted, "used": du, "referenced": du, "refquota": quota})
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
