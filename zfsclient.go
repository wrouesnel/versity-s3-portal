package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/wrouesnel/versity-s3-portal/internal/zfsapi"
)

// The helper's types, under the portal's names.
type (
	ZFSBucketInfo     = zfsapi.BucketInfo
	ZFSSnapshot       = zfsapi.Snapshot
	ZFSObject         = zfsapi.Object
	ZFSSnapshotObject = zfsapi.ObjectList
)

// ZFSHelper talks to s3-zfs-helper, which keeps each bucket in its own ZFS
// dataset, over its unix socket.
type ZFSHelper struct {
	http *http.Client
	// Streams has no timeout, for snapshot downloads of any size.
	streams *http.Client
}

// ZFSError is an error the helper reported.
type ZFSError struct {
	Status int
	Code   string
	Msg    string
}

func (e *ZFSError) Error() string { return fmt.Sprintf("zfs helper: %s (%s)", e.Msg, e.Code) }

// Errors to test for with errors.Is.
var (
	// ErrZFSNotEmpty: the bucket (or the directory being adopted) has
	// objects in it.
	ErrZFSNotEmpty = errors.New("bucket isn't empty")
	// ErrZFSNotDataset: the bucket isn't one of the helper's datasets
	// (yet), e.g. one made before ZFS was set up.
	ErrZFSNotDataset = errors.New("bucket isn't a dataset")
	// ErrZFSNotFound: no such bucket, snapshot or object.
	ErrZFSNotFound = errors.New("not found")
)

func (e *ZFSError) Is(target error) bool {
	switch target {
	case ErrZFSNotEmpty:
		return e.Code == zfsapi.CodeNotEmpty
	case ErrZFSNotDataset:
		return e.Code == zfsapi.CodeNotDataset
	case ErrZFSNotFound:
		return e.Code == zfsapi.CodeNotFound
	}
	return false
}

// NewZFSHelper talks to the helper listening on socket.
func NewZFSHelper(socket string) *ZFSHelper {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns: 4,
	}
	return &ZFSHelper{
		// Destroying a dataset with many snapshots, or restoring a big
		// folder, can take a while.
		http:    &http.Client{Transport: transport, Timeout: 10 * time.Minute},
		streams: &http.Client{Transport: transport},
	}
}

func zfsPath(bucket string, rest ...string) string {
	p := "/buckets/" + url.PathEscape(bucket)
	for _, r := range rest {
		p += "/" + url.PathEscape(r)
	}
	return p
}

func (z *ZFSHelper) request(ctx context.Context, client *http.Client, method, path string, query url.Values, in any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	u := "http://zfs-helper" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zfs helper: %w", err)
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		var e zfsapi.Error
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if json.Unmarshal(data, &e) != nil || e.Error == "" {
			e.Error = resp.Status
		}
		return nil, &ZFSError{Status: resp.StatusCode, Code: e.Code, Msg: e.Error}
	}
	return resp, nil
}

func (z *ZFSHelper) call(ctx context.Context, method, path string, query url.Values, in, out any) error {
	resp, err := z.request(ctx, z.http, method, path, query, in)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Adopt turns a newly created, still empty bucket into its own dataset.
// It's safe to repeat.
func (z *ZFSHelper) Adopt(ctx context.Context, bucket string) error {
	return z.call(ctx, http.MethodPost, zfsPath(bucket, "adopt"), nil, nil, nil)
}

// Destroy destroys an empty bucket's dataset and its snapshots, which
// deletes the bucket. It fails with ErrZFSNotEmpty if it has objects.
func (z *ZFSHelper) Destroy(ctx context.Context, bucket string) error {
	return z.call(ctx, http.MethodDelete, zfsPath(bucket), nil, nil, nil)
}

// Info returns the bucket's space use, quota and backup flag.
func (z *ZFSHelper) Info(ctx context.Context, bucket string) (*ZFSBucketInfo, error) {
	var info ZFSBucketInfo
	if err := z.call(ctx, http.MethodGet, zfsPath(bucket), nil, nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// SetQuota limits the bucket's live data to bytes; 0 removes the limit.
func (z *ZFSHelper) SetQuota(ctx context.Context, bucket string, bytes int64) error {
	return z.call(ctx, http.MethodPut, zfsPath(bucket, "quota"), nil, zfsapi.Quota{Bytes: bytes}, nil)
}

// SetBackup marks the bucket for backup, or not.
func (z *ZFSHelper) SetBackup(ctx context.Context, bucket string, include bool) error {
	return z.call(ctx, http.MethodPut, zfsPath(bucket, "backup"), nil, zfsapi.Backup{Include: include}, nil)
}

// Snapshots lists the portal's snapshots of the bucket, newest first.
func (z *ZFSHelper) Snapshots(ctx context.Context, bucket string) ([]ZFSSnapshot, error) {
	var out []ZFSSnapshot
	err := z.call(ctx, http.MethodGet, zfsPath(bucket, "snapshots"), nil, nil, &out)
	return out, err
}

// CreateSnapshot snapshots the bucket now. label, if given, is up to 32
// lowercase letters, digits and hyphens, and ends the snapshot's name.
func (z *ZFSHelper) CreateSnapshot(ctx context.Context, bucket, label string) (ZFSSnapshot, error) {
	var out ZFSSnapshot
	err := z.call(ctx, http.MethodPost, zfsPath(bucket, "snapshots"), nil, zfsapi.NewSnapshot{Label: label}, &out)
	return out, err
}

// DeleteSnapshot destroys one of the portal's snapshots.
func (z *ZFSHelper) DeleteSnapshot(ctx context.Context, bucket, snapshot string) error {
	return z.call(ctx, http.MethodDelete, zfsPath(bucket, "snapshots", snapshot), nil, nil, nil)
}

// ListSnapshot lists objects in a snapshot as S3 would: under prefix,
// rolled up into folders at delimiter ("/" or ""), after startAfter, at
// most max (0 for the helper's limit of 1000).
func (z *ZFSHelper) ListSnapshot(ctx context.Context, bucket, snapshot, prefix, delimiter, startAfter string, max int) (*ZFSSnapshotObject, error) {
	q := url.Values{}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	if delimiter != "" {
		q.Set("delimiter", delimiter)
	}
	if startAfter != "" {
		q.Set("start-after", startAfter)
	}
	if max > 0 {
		q.Set("max-keys", strconv.Itoa(max))
	}
	var out ZFSSnapshotObject
	if err := z.call(ctx, http.MethodGet, zfsPath(bucket, "snapshots", snapshot, "list"), q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetSnapshotObject returns the response carrying a file from a snapshot,
// for the caller to stream and close. Content-Length and Last-Modified are
// set.
func (z *ZFSHelper) GetSnapshotObject(ctx context.Context, bucket, snapshot, key string) (*http.Response, error) {
	return z.request(ctx, z.streams, http.MethodGet, zfsPath(bucket, "snapshots", snapshot, "object"), url.Values{"key": {key}}, nil)
}

// RestoreObject copies one object from a snapshot over the live one.
func (z *ZFSHelper) RestoreObject(ctx context.Context, bucket, snapshot, key string) error {
	_, err := z.restore(ctx, bucket, snapshot, zfsapi.Restore{Key: key})
	return err
}

// RestorePrefix copies everything under prefix (a folder, ending in "/")
// from a snapshot over the live bucket, and returns how many objects.
// Objects only in the live bucket stay.
func (z *ZFSHelper) RestorePrefix(ctx context.Context, bucket, snapshot, prefix string) (int, error) {
	return z.restore(ctx, bucket, snapshot, zfsapi.Restore{Prefix: prefix})
}

// RestoreAll copies the whole snapshot over the live bucket.
func (z *ZFSHelper) RestoreAll(ctx context.Context, bucket, snapshot string) (int, error) {
	return z.restore(ctx, bucket, snapshot, zfsapi.Restore{All: true})
}

func (z *ZFSHelper) restore(ctx context.Context, bucket, snapshot string, req zfsapi.Restore) (int, error) {
	var out zfsapi.Restored
	err := z.call(ctx, http.MethodPost, zfsPath(bucket, "snapshots", snapshot, "restore"), nil, req, &out)
	return out.Objects, err
}
