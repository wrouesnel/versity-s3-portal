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
	"strconv"
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

// optInt reads an optional integer setting, 0 when unset.
func optInt(name string) (int, error) {
	v := os.Getenv(name)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return n, nil
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
	// LDAP password login and OIDC are each optional, but one is needed.
	var auth Authenticator
	var ldapAuth *LDAPAuth
	if os.Getenv("LDAP_URL") != "" {
		ldapAuth = &LDAPAuth{
			URL:          need("LDAP_URL"),
			ServerName:   os.Getenv("LDAP_SERVER_NAME"),
			CAFile:       os.Getenv("LDAP_CA_FILE"),
			BaseDN:       need("LDAP_BASE_DN"),
			BindDN:       need("LDAP_BIND_DN"),
			BindPassword: secret("LDAP_BIND_PASSWORD"),
			AllowedGroup: os.Getenv("ALLOWED_GROUP_DN"),
			AdminGroup:   os.Getenv("ADMIN_GROUP_DN"),
			GroupFilter:  os.Getenv("LDAP_GROUP_FILTER"),
		}
		auth = ldapAuth
	}
	pollInterval, err := time.ParseDuration(env("DIRECTORY_POLL_INTERVAL", "5m"))
	if err != nil || pollInterval < 10*time.Second {
		missing = append(missing, errors.New("DIRECTORY_POLL_INTERVAL must be a duration of at least 10s, e.g. 5m"))
	}
	var zfsDefaults ZFSDefaults
	zfsSocket := os.Getenv("ZFS_HELPER_SOCKET")
	if zfsSocket != "" {
		var err1, err2 error
		zfsDefaults.Quota, err1 = ParseSize(os.Getenv("ZFS_DEFAULT_QUOTA"))
		zfsDefaults.Snapshots, err2 = ParseSchedule(os.Getenv("ZFS_DEFAULT_SNAPSHOTS"))
		missing = append(missing, err1, err2)
	}
	var apiToken string
	if os.Getenv("API_TOKEN") != "" || os.Getenv("API_TOKEN_FILE") != "" {
		apiToken = secret("API_TOKEN")
	}
	var oidcConfig *OIDCConfig
	if os.Getenv("OIDC_ISSUER") != "" {
		oidcConfig = &OIDCConfig{
			Name:          env("OIDC_NAME", "single sign-on"),
			Issuer:        need("OIDC_ISSUER"),
			ClientID:      need("OIDC_CLIENT_ID"),
			ClientSecret:  secret("OIDC_CLIENT_SECRET"),
			RedirectURL:   need("OIDC_REDIRECT_URL"),
			Scopes:        strings.Fields(os.Getenv("OIDC_SCOPES")),
			UsernameClaim: env("OIDC_USERNAME_CLAIM", "preferred_username"),
			GroupsClaim:   env("OIDC_GROUPS_CLAIM", "groups"),
			UIDClaim:      os.Getenv("OIDC_UID_CLAIM"),
			GIDClaim:      os.Getenv("OIDC_GID_CLAIM"),
			AllowedGroup:  os.Getenv("OIDC_ALLOWED_GROUP"),
			AdminGroup:    os.Getenv("OIDC_ADMIN_GROUP"),
		}
		var err1, err2 error
		oidcConfig.DefaultUID, err1 = optInt("OIDC_DEFAULT_UID")
		oidcConfig.DefaultGID, err2 = optInt("OIDC_DEFAULT_GID")
		missing = append(missing, err1, err2)
	}
	if auth == nil && oidcConfig == nil {
		missing = append(missing, errors.New("set LDAP_URL, OIDC_ISSUER or both"))
	}
	trustedProxies, err := ParseTrustedProxies(os.Getenv("TRUSTED_PROXIES"))
	missing = append(missing, err)
	sessionKey := secret("SESSION_KEY")
	statePath := need("STATE_FILE")
	publicURL := need("PUBLIC_S3_URL")
	if err := errors.Join(missing...); err != nil {
		return err
	}
	if len(sessionKey) < 32 {
		return errors.New("SESSION_KEY must be at least 32 characters")
	}

	var oidcAuth *OIDCAuth
	if oidcConfig != nil {
		var err error
		discoverCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		oidcAuth, err = NewOIDCAuth(discoverCtx, *oidcConfig)
		cancel()
		if err != nil {
			return err
		}
	}

	store, err := OpenStore(statePath)
	if err != nil {
		return err
	}
	portal := NewPortal(vgw, store)
	if ldapAuth != nil {
		portal.dir = ldapAuth
	}
	if zfsSocket != "" {
		portal.zfs, portal.zfsDefaults = NewZFSHelper(zfsSocket), zfsDefaults
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Before any policy is written, so people from before the portal kept
	// records keep their access.
	if err := portal.LearnPeople(); err != nil {
		slog.Error("learn people from the directory", "err", err)
	}

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

	if apiToken != "" && len(apiToken) < 32 {
		return errors.New("API_TOKEN must be at least 32 characters")
	}
	if portal.dir != nil {
		// Catch up on anything that changed while the portal was down, then
		// keep checking.
		if report, err := portal.SyncDirectory(ctx); err != nil {
			slog.Error("directory sync at startup", "err", err)
		} else {
			slog.Info("directory sync at startup", "checked", report.Checked, "changed", len(report.Changed), "disabled", report.Disabled)
		}
		go portal.PollDirectory(ctx, pollInterval)
	}

	if portal.zfs != nil {
		go portal.RunSnapshots(ctx, 5*time.Minute)
	}

	sessions := &Sessions{Key: []byte(sessionKey), TTL: 12 * time.Hour, Secure: env("INSECURE_COOKIES", "") == "", Store: store}
	server := NewServer(portal, auth, oidcAuth, sessions, env("TITLE", "S3 access keys"), publicURL, vgw.Region)
	server.APIToken = apiToken
	server.TrustedProxies = trustedProxies
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
