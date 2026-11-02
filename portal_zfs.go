package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ZFSDefaults are applied to each new bucket's dataset.
type ZFSDefaults struct {
	// Quota in bytes, or 0 for none.
	Quota     int64
	Snapshots SnapshotSchedule
}

// snapshotEvery is how long each schedule waits between snapshots.
var snapshotEvery = map[string]time.Duration{
	"hourly": time.Hour,
	"daily":  24 * time.Hour,
	"weekly": 7 * 24 * time.Hour,
}

// ParseSchedule reads "daily:14" (every, keep), or "" / "off" for none.
func ParseSchedule(s string) (SnapshotSchedule, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "off" {
		return SnapshotSchedule{}, nil
	}
	every, keep, _ := strings.Cut(s, ":")
	n, err := strconv.Atoi(keep)
	if _, ok := snapshotEvery[every]; !ok || err != nil || n < 1 || n > 1000 {
		return SnapshotSchedule{}, fmt.Errorf("snapshot schedule %q: want hourly, daily or weekly, a colon, and how many to keep (1-1000), e.g. daily:14", s)
	}
	return SnapshotSchedule{Every: every, Keep: n}, nil
}

// ParseSize reads a size like 500G, 2T or 1048576, in binary units.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.TrimSuffix(strings.TrimSuffix(s, "B"), "I")
	if s == "" || s == "0" {
		return 0, nil
	}
	mult := int64(1)
	if i := strings.IndexAny(s, "KMGTP"); i == len(s)-1 {
		mult = int64(1) << (10 * (strings.IndexByte("KMGTP", s[i]) + 1))
		s = s[:i]
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("size %q: want a number with an optional K, M, G, T or P", s)
	}
	return int64(f * float64(mult)), nil
}

func (p *Portal) newBucketMeta() *BucketMeta {
	return &BucketMeta{Snapshots: p.zfsDefaults.Snapshots}
}

// adoptBucket moves a just-created bucket into its own dataset. If that
// fails, the bucket is deleted again so nothing is left half made. Callers
// hold p.mu.
func (p *Portal) adoptBucket(ctx context.Context, name string) error {
	err := p.zfs.Adopt(ctx, name)
	if err == nil && p.zfsDefaults.Quota > 0 {
		err = p.zfs.SetQuota(ctx, name, p.zfsDefaults.Quota)
	}
	if err != nil {
		slog.Error("give bucket its own dataset", "bucket", name, "err", err)
		// A dataset that got made (mounted or not) goes through the helper,
		// and the plain directory, if it's still there, through the gateway.
		p.zfs.Destroy(ctx, name)
		p.vgw.DeleteBucket(ctx, name)
		p.forgetBuckets()
		return fmt.Errorf("adopt bucket %s: %w", name, err)
	}
	return nil
}

// destroyBucket deletes an empty bucket and its dataset. Callers hold p.mu.
func (p *Portal) destroyBucket(ctx context.Context, name string) error {
	// Same rule as the gateway's: no objects, not even empty folders.
	list, err := p.vgw.ListObjects(ctx, name, "", "/", "", 3)
	if err != nil {
		return err
	}
	for _, pre := range list.Prefixes {
		// ZFS's snapshot directory and the gateway's temporary files aren't
		// objects. (ZFS hides .zfs from listings, but not every setup does.)
		if pre != ".zfs/" && pre != ".sgwtmp/" {
			return &APIError{Status: http.StatusConflict, Code: "BucketNotEmpty"}
		}
	}
	if len(list.Objects) > 0 {
		return &APIError{Status: http.StatusConflict, Code: "BucketNotEmpty"}
	}
	err = p.zfs.Destroy(ctx, name)
	if errors.Is(err, ErrZFSNotEmpty) {
		return &APIError{Status: http.StatusConflict, Code: "BucketNotEmpty"}
	}
	return err
}

// Storage is a bucket's dataset as its settings page shows it.
type Storage struct {
	Info      *ZFSBucketInfo
	Snapshots []ZFSSnapshot
	Schedule  SnapshotSchedule
}

// Storage returns bucket's dataset details, for people who may manage it.
func (p *Portal) Storage(ctx context.Context, u User, bucket string) (*Storage, error) {
	if p.zfs == nil {
		return nil, nil
	}
	v, err := p.Bucket(ctx, u, bucket, false)
	if err != nil {
		return nil, err
	}
	if !v.Manage && !v.Caps.Read {
		return nil, userErr("No such bucket.")
	}
	info, err := p.zfs.Info(ctx, bucket)
	if err != nil {
		return nil, err
	}
	snaps, err := p.zfs.Snapshots(ctx, bucket)
	if err != nil {
		return nil, err
	}
	return &Storage{Info: info, Snapshots: snaps, Schedule: p.store.BucketMeta(bucket).Snapshots}, nil
}

var errNoZFS = userErr("Buckets here aren't ZFS datasets, so there are no quotas or snapshots.")

func (p *Portal) manageZFS(ctx context.Context, u User, bucket string, adminOnly bool) error {
	if p.zfs == nil {
		return errNoZFS
	}
	v, err := p.Bucket(ctx, u, bucket, true)
	if err != nil {
		return err
	}
	if adminOnly && !u.Admin {
		return userErr("Only admins can change that.")
	}
	if !v.Manage {
		return userErr("Only the bucket's owner or an admin can change that.")
	}
	return nil
}

// SetQuota limits a bucket's size, for admins. 0 removes the limit.
func (p *Portal) SetQuota(ctx context.Context, u User, bucket string, bytes int64) error {
	if err := p.manageZFS(ctx, u, bucket, true); err != nil {
		return err
	}
	if err := p.zfs.SetQuota(ctx, bucket, bytes); err != nil {
		return err
	}
	slog.Info("set bucket quota", "admin", u.Name, "bucket", bucket, "bytes", bytes)
	return nil
}

// SetBackup marks a bucket for the host's backups, or not, for admins.
func (p *Portal) SetBackup(ctx context.Context, u User, bucket string, include bool) error {
	if err := p.manageZFS(ctx, u, bucket, true); err != nil {
		return err
	}
	if err := p.zfs.SetBackup(ctx, bucket, include); err != nil {
		return err
	}
	slog.Info("set bucket backup", "admin", u.Name, "bucket", bucket, "include", include)
	return nil
}

// SetSchedule sets how often a bucket is snapshotted, for its owner and
// admins.
func (p *Portal) SetSchedule(ctx context.Context, u User, bucket string, sched SnapshotSchedule) error {
	if err := p.manageZFS(ctx, u, bucket, false); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	meta := p.store.BucketMeta(bucket)
	meta.Snapshots = sched
	if err := p.store.PutBucketMeta(bucket, meta); err != nil {
		return err
	}
	slog.Info("set snapshot schedule", "user", u.Name, "bucket", bucket, "every", sched.Every, "keep", sched.Keep)
	return nil
}

// Snapshot labels: scheduled ones are pruned, manual ones are kept until
// someone deletes them.
const (
	autoLabel   = "auto"
	manualLabel = "manual"
)

var snapshotLabelRe = regexp.MustCompile(`-(auto|manual)$`)

func snapshotKind(name string) string {
	if m := snapshotLabelRe.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return ""
}

// TakeSnapshot snapshots a bucket now, for its owner and admins.
func (p *Portal) TakeSnapshot(ctx context.Context, u User, bucket string) (ZFSSnapshot, error) {
	if err := p.manageZFS(ctx, u, bucket, false); err != nil {
		return ZFSSnapshot{}, err
	}
	snap, err := p.zfs.CreateSnapshot(ctx, bucket, manualLabel)
	if err == nil {
		slog.Info("took snapshot", "user", u.Name, "bucket", bucket, "snapshot", snap.Name)
	}
	return snap, err
}

// DeleteSnapshot deletes one of a bucket's snapshots, for its owner and
// admins.
func (p *Portal) DeleteSnapshot(ctx context.Context, u User, bucket, snap string) error {
	if err := p.manageZFS(ctx, u, bucket, false); err != nil {
		return err
	}
	if err := p.zfs.DeleteSnapshot(ctx, bucket, snap); err != nil {
		if errors.Is(err, ErrZFSNotFound) {
			return userErr("That snapshot is gone.")
		}
		return err
	}
	slog.Info("deleted snapshot", "user", u.Name, "bucket", bucket, "snapshot", snap)
	return nil
}

// snapshotReader checks u may read bucket, which lets them read its
// snapshots too.
func (p *Portal) snapshotReader(ctx context.Context, u User, bucket string) error {
	if p.zfs == nil {
		return errNoZFS
	}
	v, err := p.Bucket(ctx, u, bucket, false)
	if err != nil {
		return err
	}
	if !v.Caps.Read {
		return userErr("You can't see what's in %s, so you can't see its snapshots either.", bucket)
	}
	return nil
}

// ListSnapshot lists a folder of a bucket as it was in a snapshot.
func (p *Portal) ListSnapshot(ctx context.Context, u User, bucket, snap, prefix, after string) (*ObjectList, error) {
	if err := checkPrefix(prefix); err != nil {
		return nil, err
	}
	if err := p.snapshotReader(ctx, u, bucket); err != nil {
		return nil, err
	}
	l, err := p.zfs.ListSnapshot(ctx, bucket, snap, prefix, "/", after, pageSize)
	if errors.Is(err, ErrZFSNotFound) {
		return nil, userErr("That snapshot or folder is gone.")
	}
	if err != nil {
		return nil, err
	}
	out := &ObjectList{Prefixes: l.Prefixes, NextToken: l.NextStartAfter}
	for _, o := range l.Objects {
		if o.Key != prefix {
			out.Objects = append(out.Objects, Object{Key: o.Key, Size: o.Size, LastModified: o.Modified})
		}
	}
	return out, nil
}

// GetSnapshotObject returns a file as it was in a snapshot, for the
// caller to stream and close.
func (p *Portal) GetSnapshotObject(ctx context.Context, u User, bucket, snap, key string) (*http.Response, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	if err := p.snapshotReader(ctx, u, bucket); err != nil {
		return nil, err
	}
	resp, err := p.zfs.GetSnapshotObject(ctx, bucket, snap, key)
	if errors.Is(err, ErrZFSNotFound) {
		return nil, userErr("That file isn't in the snapshot.")
	}
	return resp, err
}

// Restore copies a file, a folder, or (with both empty) everything back
// from a snapshot, replacing what's there now. It needs read & write.
func (p *Portal) Restore(ctx context.Context, u User, bucket, snap, key, prefix string) (int, error) {
	if p.zfs == nil {
		return 0, errNoZFS
	}
	v, err := p.Bucket(ctx, u, bucket, true)
	if err != nil {
		return 0, err
	}
	if !v.Caps.Covers(PermReadWrite.Caps()) {
		return 0, userErr("Restoring replaces files, so it needs read & write access to %s.", bucket)
	}
	var n int
	switch {
	case key != "":
		if err := checkKey(key); err != nil {
			return 0, err
		}
		n, err = 1, p.zfs.RestoreObject(ctx, bucket, snap, key)
	case prefix != "":
		if err := checkPrefix(prefix); err != nil {
			return 0, err
		}
		n, err = p.zfs.RestorePrefix(ctx, bucket, snap, prefix)
	default:
		n, err = p.zfs.RestoreAll(ctx, bucket, snap)
	}
	if errors.Is(err, ErrZFSNotFound) {
		return 0, userErr("That isn't in the snapshot.")
	}
	if err != nil {
		return 0, err
	}
	slog.Warn("restored from snapshot", "user", u.Name, "bucket", bucket, "snapshot", snap, "key", key, "prefix", prefix, "objects", n)
	return n, nil
}

// RunSnapshots takes scheduled snapshots and prunes old ones, checking
// every interval until ctx ends.
func (p *Portal) RunSnapshots(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		p.snapshotRound(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// snapshotRound snapshots every scheduled bucket that's due, and prunes its
// scheduled snapshots beyond what it keeps.
func (p *Portal) snapshotRound(ctx context.Context, now time.Time) {
	buckets, err := p.vgw.ListBuckets(ctx)
	if err != nil {
		slog.Error("snapshot schedule: list buckets", "err", err)
		return
	}
	for _, b := range buckets {
		sched := p.store.BucketMeta(b.Name).Snapshots
		every, ok := snapshotEvery[sched.Every]
		if !ok {
			continue
		}
		snaps, err := p.zfs.Snapshots(ctx, b.Name)
		if err != nil {
			slog.Error("snapshot schedule: list snapshots", "bucket", b.Name, "err", err)
			continue
		}
		var auto []ZFSSnapshot
		for _, s := range snaps {
			if snapshotKind(s.Name) == autoLabel {
				auto = append(auto, s)
			}
		}
		sort.Slice(auto, func(i, j int) bool { return auto[i].Created.After(auto[j].Created) })
		// A little slack, so a snapshot taken a few seconds late doesn't
		// push every later one back by a round.
		if len(auto) == 0 || now.Sub(auto[0].Created) >= every-time.Minute {
			s, err := p.zfs.CreateSnapshot(ctx, b.Name, autoLabel)
			if err != nil {
				slog.Error("scheduled snapshot", "bucket", b.Name, "err", err)
				continue
			}
			auto = append([]ZFSSnapshot{s}, auto...)
		}
		for _, old := range auto[min(len(auto), sched.Keep):] {
			if err := p.zfs.DeleteSnapshot(ctx, b.Name, old.Name); err != nil && !errors.Is(err, ErrZFSNotFound) {
				slog.Error("prune snapshot", "bucket", b.Name, "snapshot", old.Name, "err", err)
			}
		}
	}
}
