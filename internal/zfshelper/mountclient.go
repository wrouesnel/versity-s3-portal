package zfshelper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/wrouesnel/versity-s3-portal/internal/zfsapi"
)

// Mounter mounts and unmounts buckets' datasets, which the helper's own
// user can't: zfs mount needs CAP_SYS_ADMIN, and that bypasses every
// delegation check ZFS has. s3-zfs-mounter does it, as root, without
// /dev/zfs. place is zfsapi.PlaceBucket or zfsapi.PlaceStaging.
type Mounter interface {
	// Mount mounts the bucket's dataset at its place. The directory is
	// made if it's missing and must be empty if it isn't. Mounting where
	// it's already mounted is fine.
	Mount(ctx context.Context, place, bucket string) error
	// Unmount unmounts the bucket's dataset from its place, if it's
	// mounted there, and removes the directory if it's empty.
	Unmount(ctx context.Context, place, bucket string) error
}

// MountClient talks to s3-zfs-mounter over its unix socket.
type MountClient struct {
	http *http.Client
}

func NewMountClient(socket string) *MountClient {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns: 2,
	}
	return &MountClient{http: &http.Client{Transport: tr, Timeout: 2 * time.Minute}}
}

func (c *MountClient) Mount(ctx context.Context, place, bucket string) error {
	return c.do(ctx, "mount", place, bucket)
}

func (c *MountClient) Unmount(ctx context.Context, place, bucket string) error {
	return c.do(ctx, "unmount", place, bucket)
}

func (c *MountClient) do(ctx context.Context, op, place, bucket string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://mounter/"+op+"/"+place+"/"+bucket, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("s3-zfs-mounter: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var e zfsapi.Error
	if json.Unmarshal(body, &e) != nil || e.Error == "" {
		e = zfsapi.Error{Error: strings.TrimSpace(string(body)), Code: zfsapi.CodeInternal}
	}
	status := resp.StatusCode
	if status >= 500 {
		status = http.StatusInternalServerError
	}
	return &apiError{status, e.Code, fmt.Sprintf("%s %s at %s: %s", op, bucket, place, e.Error)}
}
