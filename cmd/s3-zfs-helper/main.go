// s3-zfs-helper keeps each of the S3 gateway's buckets in its own ZFS
// dataset, for s3-key-portal: it adopts new buckets as datasets, sets
// quotas and the backup flag, and takes, lists, browses and restores from
// snapshots. It runs as root on the host and serves a small JSON API on a
// unix socket, either passed in by systemd socket activation or made with
// -socket. See docs/zfs-helper.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/wrouesnel/versity-s3-portal/internal/zfshelper"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	parent := flag.String("parent", "storage/s3/buckets", "dataset whose children are buckets")
	root := flag.String("root", "/storage/s3/buckets", "where the parent dataset is mounted")
	trash := flag.String("trash", "storage/s3/trash", "dataset deleted buckets are moved under, in the same pool and outside -parent (canmount=off, mountpoint=none)")
	staging := flag.String("staging", "", "root-only directory outside -root where new datasets are set up (default: .s3-zfs-staging beside -root)")
	stateDir := flag.String("state-dir", "/var/lib/s3-zfs-helper", "root-only directory for metadata saved while adopting a bucket")
	zfsPath := flag.String("zfs", "/usr/sbin/zfs", "the zfs command")
	socket := flag.String("socket", "", "unix socket to listen on, when not socket-activated")
	group := flag.Int("socket-group", -1, "gid to own -socket, which is made mode 0660")
	flag.Parse()

	srv := zfshelper.New(zfshelper.Config{
		Parent: *parent, Root: *root, Trash: *trash, Staging: *staging, StateDir: *stateDir,
		Run: zfshelper.ExecRunner(*zfsPath),
	})
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := srv.Check(ctx); err != nil {
		return err
	}

	ln, err := listener(*socket, *group)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdown)
	}()
	slog.Info("serving", "addr", ln.Addr().String(), "parent", *parent, "root", *root)
	if err := httpServer.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// listener takes the socket systemd passed (LISTEN_FDS), or makes one.
func listener(path string, gid int) (net.Listener, error) {
	if pid, _ := strconv.Atoi(os.Getenv("LISTEN_PID")); pid == os.Getpid() {
		if n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS")); n >= 1 {
			os.Unsetenv("LISTEN_PID")
			os.Unsetenv("LISTEN_FDS")
			os.Unsetenv("LISTEN_FDNAMES")
			syscall.CloseOnExec(3)
			return net.FileListener(os.NewFile(3, "systemd-socket"))
		}
	}
	if path == "" {
		return nil, fmt.Errorf("not socket-activated, and no -socket given")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if gid >= 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			ln.Close()
			return nil, err
		}
		if err := os.Chmod(path, 0o660); err != nil {
			ln.Close()
			return nil, err
		}
	}
	return ln, nil
}
