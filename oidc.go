package main

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCAuth logs people in with an OpenID Connect provider, using the
// authorization code flow with PKCE.
//
// Gateway accounts are named after people, so each person needs a username
// that fits usernameRe; it comes from UsernameClaim. Their uid and gid come
// from UIDClaim and GIDClaim when the provider has them, or else from
// DefaultUID and DefaultGID, so that files written by everyone without
// their own ids are owned by one service user.
type OIDCAuth struct {
	// Name is shown on the login button, e.g. "Sign in with Okta".
	Name string

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
	issuer   string

	UsernameClaim string
	GroupsClaim   string
	UIDClaim      string
	GIDClaim      string
	DefaultUID    int
	DefaultGID    int
	// AllowedGroup, when set, must be in the groups claim to log in, unless
	// AdminGroup is, which lets its members in too.
	AllowedGroup string
	// AdminGroup, when set, makes members admins.
	AdminGroup string
}

// OIDCConfig is what NewOIDCAuth needs.
type OIDCConfig struct {
	Name, Issuer, ClientID, ClientSecret, RedirectURL string
	Scopes                                            []string
	UsernameClaim, GroupsClaim, UIDClaim, GIDClaim    string
	DefaultUID, DefaultGID                            int
	AllowedGroup, AdminGroup                          string
}

// NewOIDCAuth fetches the provider's discovery document.
func NewOIDCAuth(ctx context.Context, c OIDCConfig) (*OIDCAuth, error) {
	if (c.UIDClaim == "") != (c.GIDClaim == "") {
		return nil, errors.New("set both OIDC_UID_CLAIM and OIDC_GID_CLAIM, or neither")
	}
	if c.DefaultUID == 0 || c.DefaultGID == 0 {
		if c.UIDClaim == "" {
			return nil, errors.New("OIDC needs OIDC_UID_CLAIM and OIDC_GID_CLAIM, or OIDC_DEFAULT_UID and OIDC_DEFAULT_GID (not 0)")
		}
	}
	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery for %s: %w", c.Issuer, err)
	}
	scopes := c.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
		if c.GroupsClaim != "" && (c.AllowedGroup != "" || c.AdminGroup != "") {
			scopes = append(scopes, "groups")
		}
	}
	return &OIDCAuth{
		Name:     c.Name,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: c.ClientID}),
		oauth: oauth2.Config{
			ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: c.RedirectURL,
			Endpoint: provider.Endpoint(), Scopes: scopes,
		},
		issuer:        c.Issuer,
		UsernameClaim: c.UsernameClaim, GroupsClaim: c.GroupsClaim,
		UIDClaim: c.UIDClaim, GIDClaim: c.GIDClaim,
		DefaultUID: c.DefaultUID, DefaultGID: c.DefaultGID,
		AllowedGroup: c.AllowedGroup, AdminGroup: c.AdminGroup,
	}, nil
}

// oidcFlow is kept in a short-lived signed cookie between the redirect to
// the provider and the callback.
type oidcFlow struct {
	State    string    `json:"state"`
	Nonce    string    `json:"nonce"`
	Verifier string    `json:"verifier"`
	Expires  time.Time `json:"exp"`
}

const oidcFlowCookie = "s3portal_oidc"

// errOIDCDenied is a login the provider accepted but the portal refuses.
type errOIDCDenied struct{ reason string }

func (e *errOIDCDenied) Error() string { return e.reason }

// AuthURL starts a login, setting the flow cookie.
func (o *OIDCAuth) AuthURL(w http.ResponseWriter, s *Sessions) (string, error) {
	flow := oidcFlow{
		State: randomToken(24), Nonce: randomToken(24), Verifier: oauth2.GenerateVerifier(),
		Expires: time.Now().Add(10 * time.Minute),
	}
	data, err := json.Marshal(flow)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(data)
	http.SetCookie(w, &http.Cookie{
		Name: oidcFlowCookie, Value: payload + "." + s.sign("oidc:"+payload),
		Path: "/auth/", MaxAge: 600, HttpOnly: true, Secure: s.Secure,
		// The callback is a cross-site navigation from the provider.
		SameSite: http.SameSiteLaxMode,
	})
	return o.oauth.AuthCodeURL(flow.State, oidc.Nonce(flow.Nonce), oauth2.S256ChallengeOption(flow.Verifier)), nil
}

func (o *OIDCAuth) takeFlow(w http.ResponseWriter, r *http.Request, s *Sessions) (*oidcFlow, error) {
	c, err := r.Cookie(oidcFlowCookie)
	http.SetCookie(w, &http.Cookie{Name: oidcFlowCookie, Value: "", Path: "/auth/", MaxAge: -1, HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteLaxMode})
	if err != nil {
		return nil, errors.New("no login in progress")
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.sign("oidc:"+payload))) {
		return nil, errors.New("bad login cookie")
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, errors.New("bad login cookie")
	}
	var flow oidcFlow
	if err := json.Unmarshal(data, &flow); err != nil || time.Now().After(flow.Expires) {
		return nil, errors.New("login took too long")
	}
	return &flow, nil
}

// Callback finishes a login and returns the user and their subject
// (issuer and sub), which stays the same if their username changes.
func (o *OIDCAuth) Callback(w http.ResponseWriter, r *http.Request, s *Sessions) (Identity, string, error) {
	flow, err := o.takeFlow(w, r, s)
	if err != nil {
		return Identity{}, "", err
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		return Identity{}, "", &errOIDCDenied{"The sign-in provider said: " + e}
	}
	if !hmac.Equal([]byte(q.Get("state")), []byte(flow.State)) {
		return Identity{}, "", errors.New("state mismatch")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	token, err := o.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		return Identity{}, "", fmt.Errorf("exchange code: %w", err)
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return Identity{}, "", errors.New("no id_token in token response")
	}
	idToken, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, "", fmt.Errorf("verify id_token: %w", err)
	}
	if !hmac.Equal([]byte(idToken.Nonce), []byte(flow.Nonce)) {
		return Identity{}, "", errors.New("nonce mismatch")
	}
	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, "", err
	}
	// Providers often leave groups and custom claims out of the ID token;
	// the userinfo endpoint has them.
	if o.needsUserinfo(claims) {
		info, err := o.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return Identity{}, "", fmt.Errorf("userinfo: %w", err)
		}
		if info.Subject != idToken.Subject {
			return Identity{}, "", errors.New("userinfo subject doesn't match the id_token")
		}
		extra := map[string]any{}
		if err := info.Claims(&extra); err != nil {
			return Identity{}, "", err
		}
		for k, v := range extra {
			if _, ok := claims[k]; !ok {
				claims[k] = v
			}
		}
	}
	user, err := o.userFromClaims(claims)
	if err != nil {
		return Identity{}, "", err
	}
	return user, o.issuer + " " + idToken.Subject, nil
}

func (o *OIDCAuth) needsUserinfo(claims map[string]any) bool {
	for _, c := range []string{o.UsernameClaim, o.UIDClaim, o.GIDClaim} {
		if c != "" && claims[c] == nil {
			return true
		}
	}
	return o.GroupsClaim != "" && (o.AllowedGroup != "" || o.AdminGroup != "") && claims[o.GroupsClaim] == nil
}

// usernameFromClaim turns a claim value into a username: lowercased, and
// for an email address the part before the @.
func usernameFromClaim(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if i := strings.LastIndex(v, "@"); i > 0 {
		v = v[:i]
	}
	return v
}

func (o *OIDCAuth) userFromClaims(claims map[string]any) (Identity, error) {
	rawName, _ := claims[o.UsernameClaim].(string)
	name := usernameFromClaim(rawName)
	if !usernameRe.MatchString(name) {
		return Identity{}, &errOIDCDenied{fmt.Sprintf("Your account's %s (%q) can't be used as a username here.", o.UsernameClaim, rawName)}
	}
	groups := claimStrings(claims[o.GroupsClaim])
	admin := o.AdminGroup != "" && containsFold(groups, o.AdminGroup)
	// The admins' group lets its members in too: an admin needn't be in
	// the allowed group as well.
	if o.AllowedGroup != "" && !containsFold(groups, o.AllowedGroup) && !admin {
		return Identity{}, &errOIDCDenied{"Your account isn't allowed to use this service."}
	}
	user := User{Name: name, UID: o.DefaultUID, GID: o.DefaultGID}
	if o.UIDClaim != "" {
		uid, err1 := claimInt(claims[o.UIDClaim])
		gid, err2 := claimInt(claims[o.GIDClaim])
		if err1 != nil || err2 != nil {
			return Identity{}, &errOIDCDenied{"Your account has no usable uid and gid."}
		}
		user.UID, user.GID = uid, gid
	}
	if user.UID <= 0 || user.GID <= 0 {
		return Identity{}, &errOIDCDenied{"Your account has no usable uid and gid."}
	}
	user.Admin = admin
	return Identity{User: user, Groups: groups}, nil
}

func claimStrings(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func claimInt(v any) (int, error) {
	switch v := v.(type) {
	case float64:
		if v != float64(int(v)) {
			return 0, errors.New("not an integer")
		}
		return int(v), nil
	case string:
		return strconv.Atoi(strings.TrimSpace(v))
	}
	return 0, errors.New("missing")
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// oidcLogin redirects to the provider.
func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	u, err := s.OIDC.AuthURL(w, s.Sessions)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

// oidcCallback finishes a login with the provider.
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	id, subject, err := s.OIDC.Callback(w, r, s.Sessions)
	if err == nil {
		err = s.Portal.BindSubject(id.Name, subject)
	}
	if err != nil {
		msg := "Signing in didn't work. Try again."
		status := http.StatusUnauthorized
		var denied *errOIDCDenied
		var ue *UserError
		switch {
		case errors.As(err, &denied):
			msg = denied.reason
			slog.Info("oidc login refused", "user", id.Name, "reason", denied.reason, "remote", s.clientIP(r))
		case errors.As(err, &ue):
			msg = ue.Msg
			slog.Warn("oidc login refused", "user", id.Name, "reason", ue.Msg, "remote", s.clientIP(r))
		default:
			slog.Error("oidc login", "err", err, "remote", s.clientIP(r))
		}
		s.render(w, status, "login.html", page{Error: msg})
		return
	}
	if !s.startSession(w, r, id, "oidc") {
		return
	}
	// The session cookie is SameSite=Strict, and browsers don't send it on a
	// redirect that started on the provider's site, so step through a page
	// of our own first.
	s.render(w, http.StatusOK, "continue.html", page{Refresh: "/"})
}
