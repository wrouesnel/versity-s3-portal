// s3-key-portal lets people log in with their LDAP password and issue
// versitygw access keys limited to buckets they own.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func mustEnv(name string) (string, error) {
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("%s is required", name)
}

// readSecret reads a secret from the file named by name+"_FILE", or failing
// that from name itself.
func readSecret(name string) (string, error) {
	if path := os.Getenv(name + "_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	return mustEnv(name)
}

func run() error {
	var missing []error
	need := func(name string) string {
		v, err := mustEnv(name)
		missing = append(missing, err)
		return v
	}
	secret := func(name string) string {
		v, err := readSecret(name)
		missing = append(missing, err)
		return v
	}

	vgw := NewVGW(
		need("VGW_S3_ENDPOINT"), need("VGW_ADMIN_ENDPOINT"), env("VGW_REGION", "us-east-1"),
		secret("VGW_ROOT_ACCESS"), secret("VGW_ROOT_SECRET"),
	)
	auth := &LDAPAuth{
		URL:          need("LDAP_URL"),
		ServerName:   os.Getenv("LDAP_SERVER_NAME"),
		CAFile:       os.Getenv("LDAP_CA_FILE"),
		BaseDN:       need("LDAP_BASE_DN"),
		BindDN:       need("LDAP_BIND_DN"),
		BindPassword: secret("LDAP_BIND_PASSWORD"),
		AllowedGroup: os.Getenv("ALLOWED_GROUP_DN"),
	}
	sessionKey := secret("SESSION_KEY")
	statePath := need("STATE_FILE")
	publicURL := need("PUBLIC_S3_URL")
	if err := errors.Join(missing...); err != nil {
		return err
	}
	if len(sessionKey) < 32 {
		return errors.New("SESSION_KEY must be at least 32 characters")
	}

	store, err := OpenStore(statePath)
	if err != nil {
		return err
	}
	portal := NewPortal(vgw, store)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The gateway may still be starting.
	for attempt := 1; ; attempt++ {
		err := portal.Reconcile(ctx)
		if err == nil {
			break
		}
		if attempt == 30 || ctx.Err() != nil {
			return fmt.Errorf("reconcile with gateway: %w", err)
		}
		slog.Warn("reconcile with gateway failed, retrying", "err", err)
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
		}
	}

	sessions := &Sessions{Key: []byte(sessionKey), TTL: 12 * time.Hour, Secure: env("INSECURE_COOKIES", "") == ""}
	server := NewServer(portal, auth, sessions, env("TITLE", "S3 access keys"), publicURL, vgw.Region)
	httpServer := &http.Server{
		Addr:              env("LISTEN", ":8080"),
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdownCtx)
	}()
	slog.Info("listening", "addr", httpServer.Addr)
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}
