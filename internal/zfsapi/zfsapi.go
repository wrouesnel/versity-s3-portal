// Package zfsapi holds what the portal and s3-zfs-helper share: the JSON
// shapes of the helper's API and the names it accepts.
package zfsapi

import (
	"regexp"
	"time"
)

// SnapshotPrefix starts the name of every snapshot the portal makes. The
// helper only lists, restores or destroys snapshots with it, so other
// snapshots of the same datasets (the host's weekly ones) are left alone.
const SnapshotPrefix = "s3portal-"

var (
	// BucketName is what a bucket, and so its dataset's last component,
	// may be called.
	BucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	// SnapshotName matches s3portal-<UTC timestamp>[-<label>].
	SnapshotName = regexp.MustCompile(`^s3portal-[0-9]{8}T[0-9]{6}Z(-[a-z0-9][a-z0-9-]{0,31})?$`)
	// SnapshotLabel is the optional label at the end of a snapshot's name.
	SnapshotLabel = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	// TrashEntryName matches a deleted bucket's dataset in the trash:
	// <bucket>-<UTC timestamp of the deletion>.
	TrashEntryName = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{1,61}[a-z0-9])-([0-9]{8}T[0-9]{6}Z)$`)
)

// TrashEntry is a deleted bucket kept in the trash, GET /trash.
type TrashEntry struct {
	Entry   string    `json:"entry"`
	Bucket  string    `json:"bucket"`
	Trashed time.Time `json:"trashed"`
	// Used counts the bucket's data and all its snapshots.
	Used int64 `json:"used"`
	// PortalSnapshots and OtherSnapshots count the portal's snapshots
	// and others (the host's), which purging destroys too.
	PortalSnapshots int `json:"portalSnapshots"`
	OtherSnapshots  int `json:"otherSnapshots"`
}

// SnapshotTimeFormat is the timestamp in a snapshot's name.
const SnapshotTimeFormat = "20060102T150405Z"

// Error is the body of every error response.
type Error struct {
	Error string `json:"error"`
	// Code is one of the Code* constants.
	Code string `json:"code"`
}

const (
	CodeBadRequest = "BadRequest"
	CodeNotFound   = "NotFound"
	CodeNotEmpty   = "NotEmpty"
	CodeNotDataset = "NotDataset"
	CodeConflict   = "Conflict"
	CodeInternal   = "Internal"
	// CodeHasHostSnapshots: the bucket can't be destroyed, since that would
	// also destroy snapshots that aren't the portal's (the host's). Not
	// sent since deleting moved to the trash; kept for older clients.
	CodeHasHostSnapshots = "HasHostSnapshots"
	// CodeExists: a bucket of that name already exists, e.g. when
	// restoring from the trash.
	CodeExists = "Exists"
	// CodeBusy: too many requests are already being served.
	CodeBusy = "Busy"
)

// BucketInfo is GET /buckets/{b}.
type BucketInfo struct {
	Dataset string `json:"dataset"`
	// Used counts the live data and its snapshots.
	Used int64 `json:"used"`
	// Referenced is the live data alone, which the quota limits.
	Referenced int64 `json:"referenced"`
	// RefQuota is 0 when there's no quota.
	RefQuota  int64 `json:"refquota"`
	Available int64 `json:"available"`
	// UsedBySnapshots is what deleting every snapshot would free.
	UsedBySnapshots int64 `json:"usedbysnapshots"`
	Backup          bool  `json:"backup"`
}

// Quota is PUT /buckets/{b}/quota. 0 removes the quota.
type Quota struct {
	Bytes int64 `json:"bytes"`
}

// Backup is PUT /buckets/{b}/backup.
type Backup struct {
	Include bool `json:"include"`
}

// Snapshot is one of a bucket's portal snapshots.
type Snapshot struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	// Used is the space only this snapshot holds.
	Used int64 `json:"used"`
}

// NewSnapshot is POST /buckets/{b}/snapshots.
type NewSnapshot struct {
	Label string `json:"label,omitempty"`
}

// Object is a file in a snapshot. Directory objects ("folder/") have keys
// ending in "/".
type Object struct {
	Key      string    `json:"key"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

// ObjectList is GET /buckets/{b}/snapshots/{s}/list.
type ObjectList struct {
	Objects  []Object `json:"objects"`
	Prefixes []string `json:"prefixes"`
	// NextStartAfter is set when there's more; pass it as start-after.
	NextStartAfter string `json:"nextStartAfter,omitempty"`
}

// Restore is POST /buckets/{b}/snapshots/{s}/restore: one object (Key),
// or everything under a prefix (Prefix; "" with All for the whole bucket).
type Restore struct {
	Key    string `json:"key,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	// All must be set to restore the whole bucket, so an empty request
	// can't do it by accident.
	All bool `json:"all,omitempty"`
}

// Restored is the reply to a restore.
type Restored struct {
	Objects int `json:"objects"`
	// Skipped counts files a prefix or whole-bucket restore left out
	// because their keys are too long to be objects.
	Skipped int `json:"skipped,omitempty"`
}

// The mounter's places: where s3-zfs-mounter mounts a bucket's dataset.
// It computes the directory itself, from its own configuration.
const (
	// PlaceBucket is the bucket's directory, where the gateway sees it.
	PlaceBucket = "bucket"
	// PlaceStaging is a directory in the staging area, where a new
	// dataset is set up before it takes the bucket's place.
	PlaceStaging = "staging"
)

// ValidPlace says whether p is one of the Place* constants.
func ValidPlace(p string) bool { return p == PlaceBucket || p == PlaceStaging }

// MountRoot is the mounter's GET /root: the device number of the
// buckets' parent filesystem as the host sees it.
type MountRoot struct {
	Dev uint64 `json:"dev"`
}
