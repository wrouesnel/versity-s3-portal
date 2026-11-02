package zfshelper

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wrouesnel/versity-s3-portal/internal/zfsapi"
)

// Runner runs the zfs command with args and returns its standard output.
// Its error includes what the command printed to standard error.
type Runner func(ctx context.Context, args ...string) ([]byte, error)

// ExecRunner runs the zfs binary at path.
func ExecRunner(path string) Runner {
	return func(ctx context.Context, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, path, args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("zfs %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
		}
		return stdout.Bytes(), nil
	}
}

// backupProp is the user property backupctl reads to include a dataset.
const backupProp = "backupctl:include"

func isNoDataset(err error) bool {
	return err != nil && strings.Contains(err.Error(), "does not exist")
}

// dsState is what zfs says about a dataset.
type dsState struct {
	exists     bool
	mountpoint string
	mounted    bool
}

func (s *Server) state(ctx context.Context, ds string) (dsState, error) {
	out, err := s.run(ctx, "list", "-H", "-o", "name,mountpoint,mounted", ds)
	if isNoDataset(err) {
		return dsState{}, nil
	}
	if err != nil {
		return dsState{}, err
	}
	f := strings.Split(strings.TrimSpace(string(out)), "\t")
	if len(f) != 3 || f[0] != ds {
		return dsState{}, fmt.Errorf("unexpected zfs list output %q", out)
	}
	return dsState{exists: true, mountpoint: f[1], mounted: f[2] == "yes"}, nil
}

func (s *Server) info(ctx context.Context, ds string) (*zfsapi.BucketInfo, error) {
	out, err := s.run(ctx, "get", "-H", "-p", "-o", "property,value",
		"used,referenced,refquota,available,usedbysnapshots,"+backupProp, ds)
	if err != nil {
		return nil, err
	}
	info := &zfsapi.BucketInfo{Dataset: ds}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		prop, val, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		num := func() int64 {
			n, _ := strconv.ParseInt(val, 10, 64)
			return n
		}
		switch prop {
		case "used":
			info.Used = num()
		case "referenced":
			info.Referenced = num()
		case "refquota":
			info.RefQuota = num()
		case "available":
			info.Available = num()
		case "usedbysnapshots":
			info.UsedBySnapshots = num()
		case backupProp:
			info.Backup = val == "on"
		}
	}
	return info, nil
}

func (s *Server) setRefquota(ctx context.Context, ds string, bytes int64) error {
	val := "none"
	if bytes > 0 {
		val = strconv.FormatInt(bytes, 10)
	}
	_, err := s.run(ctx, "set", "refquota="+val, ds)
	return err
}

func (s *Server) setBackup(ctx context.Context, ds string, include bool) error {
	var err error
	if include {
		_, err = s.run(ctx, "set", backupProp+"=on", ds)
	} else {
		_, err = s.run(ctx, "inherit", backupProp, ds)
	}
	return err
}

func (s *Server) setReadonly(ctx context.Context, ds string, on bool) error {
	if on {
		return s.setProp(ctx, ds, "readonly", "on")
	}
	return s.inheritProp(ctx, ds, "readonly")
}

// getProp returns a property's value and its source (local, default,
// inherited from ...).
func (s *Server) getProp(ctx context.Context, ds, prop string) (value, source string, err error) {
	out, err := s.run(ctx, "get", "-H", "-o", "value,source", prop, ds)
	if err != nil {
		return "", "", err
	}
	value, source, ok := strings.Cut(strings.TrimRight(string(out), "\n"), "\t")
	if !ok {
		return "", "", fmt.Errorf("unexpected zfs get output %q", out)
	}
	return value, source, nil
}

// setProp sets a property. The helper's user can change readonly and
// canmount, but zfs then tries to remount the dataset, can't, and exits
// with an error though the change was made (and the kernel applies
// readonly to the live mount at once). So when zfs fails, the property
// is read back, and if it's as asked that's success.
func (s *Server) setProp(ctx context.Context, ds, prop, val string) error {
	_, err := s.run(ctx, "set", prop+"="+val, ds)
	if err == nil {
		return nil
	}
	if v, src, gerr := s.getProp(ctx, ds, prop); gerr == nil && v == val && src == "local" {
		return nil
	}
	return err
}

// inheritProp clears a property, as setProp sets one.
func (s *Server) inheritProp(ctx context.Context, ds, prop string) error {
	_, err := s.run(ctx, "inherit", prop, ds)
	if err == nil {
		return nil
	}
	if _, src, gerr := s.getProp(ctx, ds, prop); gerr == nil && src != "local" {
		return nil
	}
	return err
}

// allSnapshots lists every snapshot of ds, ours or not.
func (s *Server) allSnapshots(ctx context.Context, ds string) ([]zfsapi.Snapshot, error) {
	out, err := s.run(ctx, "list", "-H", "-p", "-t", "snapshot", "-d", "1", "-o", "name,creation,used", ds)
	if err != nil {
		return nil, err
	}
	snaps := []zfsapi.Snapshot{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			continue
		}
		owner, name, ok := strings.Cut(f[0], "@")
		if !ok || owner != ds {
			continue
		}
		created, _ := strconv.ParseInt(f[1], 10, 64)
		used, _ := strconv.ParseInt(f[2], 10, 64)
		snaps = append(snaps, zfsapi.Snapshot{Name: name, Created: time.Unix(created, 0).UTC(), Used: used})
	}
	return snaps, nil
}

// snapshots lists ds's portal snapshots, newest first.
func (s *Server) snapshots(ctx context.Context, ds string) ([]zfsapi.Snapshot, error) {
	all, err := s.allSnapshots(ctx, ds)
	if err != nil {
		return nil, err
	}
	snaps := []zfsapi.Snapshot{}
	for _, sn := range all {
		if zfsapi.SnapshotName.MatchString(sn.Name) {
			snaps = append(snaps, sn)
		}
	}
	sort.Slice(snaps, func(i, j int) bool {
		if !snaps[i].Created.Equal(snaps[j].Created) {
			return snaps[i].Created.After(snaps[j].Created)
		}
		return snaps[i].Name > snaps[j].Name
	})
	return snaps, nil
}

func (s *Server) hasSnapshot(ctx context.Context, ds, name string) (bool, error) {
	snaps, err := s.snapshots(ctx, ds)
	if err != nil {
		return false, err
	}
	for _, sn := range snaps {
		if sn.Name == name {
			return true, nil
		}
	}
	return false, nil
}
