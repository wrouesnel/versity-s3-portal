// s3-zfs-mounter mounts and unmounts S3 buckets' ZFS datasets for
// s3-zfs-helper, which runs unprivileged and so can't. It runs as root
// with CAP_SYS_ADMIN only and no access to /dev/zfs, so it can't run a
// single ZFS command: all it can do is mount a bucket's dataset in the
// bucket's directory or in staging, and unmount it. It serves a tiny API
// on a unix socket, passed in by systemd socket activation or made with
// -socket, and answers only the helper's user (and root). See
// docs/zfs-helper.md.
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
	"os/user"
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
	staging := flag.String("staging", "/storage/s3/.s3-zfs-staging", "root-owned 0700 directory outside -root where new datasets are mounted to be set up")
	socket := flag.String("socket", "", "unix socket to listen on, when not socket-activated")
	allow := flag.String("allow-user", "s3zfs", "the only user (besides root) whose connections are answered: s3-zfs-helper's")
	flag.Parse()

	u, err := user.Lookup(*allow)
	if err != nil {
		return fmt.Errorf("-allow-user: %w", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	srv := zfshelper.NewMountServer(zfshelper.MountConfig{Parent: *parent, Root: *root, Staging: *staging})
	if err := srv.Check(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ln, err := listener(*socket)
	if err != nil {
		return err
	}
	ln = &peerListener{Listener: ln, uid: uint32(uid)}
	httpServer := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdown)
	}()
	slog.Info("serving", "addr", ln.Addr().String(), "parent", *parent, "root", *root, "staging", *staging, "allow", *allow)
	if err := httpServer.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// peerListener drops connections from anyone but uid and root, checked
// with SO_PEERCRED.
type peerListener struct {
	net.Listener
	uid uint32
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			continue
		}
		raw, err := uc.SyscallConn()
		if err != nil {
			c.Close()
			continue
		}
		var cred *syscall.Ucred
		var cerr error
		raw.Control(func(fd uintptr) {
			cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		})
		if cerr != nil || (cred.Uid != l.uid && cred.Uid != 0) {
			if cred != nil {
				slog.Warn("refused a connection", "uid", cred.Uid, "pid", cred.Pid)
			}
			c.Close()
			continue
		}
		return c, nil
	}
}

// listener takes the socket systemd passed (LISTEN_FDS), or makes one
// only root can use.
func listener(path string) (net.Listener, error) {
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
	defer syscall.Umask(old)
	return net.Listen("unix", path)
}
