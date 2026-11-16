package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeProvider is a minimal OpenID provider: it issues a code for whoever
// the test says is logging in, and checks PKCE when the code is exchanged.
type fakeProvider struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	mu   sync.Mutex
	next map[string]any // claims for the next login
	// by code: the challenge, nonce and claims it was issued for
	codes    map[string][3]any
	userinfo map[string]any
}

func newFakeProvider(t *testing.T) *fakeProvider {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeProvider{key: key, codes: map[string][3]any{}}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	iss := f.srv.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": iss, "authorization_endpoint": iss + "/authorize", "token_endpoint": iss + "/token",
			"jwks_uri": iss + "/jwks", "userinfo_endpoint": iss + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
	})
	// The browser would land here; the test reads the redirect instead.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" {
			http.Error(w, "PKCE required", 400)
			return
		}
		f.mu.Lock()
		code := randomToken(8)
		f.codes[code] = [3]any{q.Get("code_challenge"), q.Get("nonce"), f.next}
		f.mu.Unlock()
		back, _ := url.Parse(q.Get("redirect_uri"))
		back.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		issued, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != issued[0] {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		claims := map[string]any{"iss": iss, "aud": "portal", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": issued[1]}
		for k, v := range issued[2].(map[string]any) {
			claims[k] = v
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k"))
		raw, _ := jwt.Signed(signer).Claims(claims).Serialize()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at-" + claims["sub"].(string), "token_type": "Bearer", "id_token": raw})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		sub := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer at-")
		info := map[string]any{"sub": sub}
		for k, v := range f.userinfo {
			info[k] = v
		}
		json.NewEncoder(w).Encode(info)
	})
	return f
}

// login runs a whole login as claims, and returns the callback's response.
func (f *fakeProvider) login(t *testing.T, h http.Handler, claims map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	f.mu.Lock()
	f.next = claims
	f.mu.Unlock()
	start := httptest.NewRecorder()
	h.ServeHTTP(start, httptest.NewRequest("GET", "/auth/login", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("/auth/login: %d", start.Code)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cb := httptest.NewRequest("GET", resp.Header.Get("Location"), nil)
	for _, c := range start.Result().Cookies() {
		cb.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, cb)
	return rec
}

func sessionFrom(t *testing.T, s *Sessions, rec *httptest.ResponseRecorder) *Session {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			r := httptest.NewRequest("GET", "/", nil)
			r.AddCookie(c)
			sess, err := s.Get(r)
			if err != nil {
				t.Fatal(err)
			}
			return sess
		}
	}
	return nil
}

func TestOIDCLogin(t *testing.T) {
	f := newFakeProvider(t)
	f.userinfo = map[string]any{"groups": []any{"s3-users", "s3-admin"}}
	auth, err := NewOIDCAuth(context.Background(), OIDCConfig{
		Name: "Test", Issuer: f.srv.URL, ClientID: "portal", ClientSecret: "s",
		RedirectURL:   "https://portal.example/auth/callback",
		UsernameClaim: "email", GroupsClaim: "groups",
		DefaultUID: 5000, DefaultGID: 5000,
		AllowedGroup: "s3-users", AdminGroup: "s3-admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	sessions := &Sessions{Key: []byte("0123456789abcdef0123456789abcdef"), TTL: time.Hour, Store: store}
	h := NewServer(NewPortal(nil, store), nil, auth, sessions, "t", "https://s3", "us-east-1").Handler()

	// Groups come from userinfo, since the ID token leaves them out.
	rec := f.login(t, h, map[string]any{"sub": "u1", "email": "Alice@Example.com"})
	sess := sessionFrom(t, sessions, rec)
	if rec.Code != 200 || sess == nil {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	if sess.User != (User{Name: "alice", UID: 5000, GID: 5000, Admin: true}) {
		t.Fatalf("user: %+v", sess.User)
	}
	if !strings.Contains(rec.Body.String(), `http-equiv="refresh"`) {
		t.Error("callback should step through a same-site page")
	}

	// Someone else whose email has the same local part can't become alice.
	rec = f.login(t, h, map[string]any{"sub": "u2", "email": "alice@elsewhere.example"})
	if sessionFrom(t, sessions, rec) != nil || !strings.Contains(rec.Body.String(), "already belongs") {
		t.Fatalf("second identity for alice: %d %s", rec.Code, rec.Body)
	}

	// Outside the allowed group.
	f.userinfo = map[string]any{"groups": []any{"other"}}
	rec = f.login(t, h, map[string]any{"sub": "u3", "email": "bob@example.com"})
	if sessionFrom(t, sessions, rec) != nil || rec.Code != http.StatusUnauthorized {
		t.Fatalf("bob outside the group: %d", rec.Code)
	}

	// In the admins' group alone: admins needn't be in the allowed group.
	f.userinfo = map[string]any{"groups": []any{"s3-admin"}}
	rec = f.login(t, h, map[string]any{"sub": "u6", "email": "erin@example.com"})
	if sess := sessionFrom(t, sessions, rec); sess == nil || !sess.User.Admin {
		t.Fatalf("erin, an admin outside the allowed group: %d %+v", rec.Code, sess)
	}

	// Not an admin.
	f.userinfo = map[string]any{"groups": []any{"s3-users"}}
	rec = f.login(t, h, map[string]any{"sub": "u4", "email": "carol@example.com"})
	if sess := sessionFrom(t, sessions, rec); sess == nil || sess.User.Admin {
		t.Fatalf("carol: %+v", sess)
	}

	// A username that can't be an account name.
	rec = f.login(t, h, map[string]any{"sub": "u5", "email": "Dave Smith@example.com"})
	if sessionFrom(t, sessions, rec) != nil {
		t.Fatal("bad username accepted")
	}

	// A callback without the flow cookie, or with someone else's state.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/callback?code=x&state=y", nil))
	if sessionFrom(t, sessions, rec) != nil || rec.Code != http.StatusUnauthorized {
		t.Fatalf("callback without flow: %d", rec.Code)
	}
	start := httptest.NewRecorder()
	h.ServeHTTP(start, httptest.NewRequest("GET", "/auth/login", nil))
	cb := httptest.NewRequest("GET", "/auth/callback?code=x&state=forged", nil)
	for _, c := range start.Result().Cookies() {
		cb.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, cb)
	if sessionFrom(t, sessions, rec) != nil {
		t.Fatal("forged state accepted")
	}

	// Password login isn't offered when only OIDC is configured.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/login", strings.NewReader("username=alice&password=x")))
	if rec.Code == http.StatusSeeOther || rec.Code == http.StatusOK {
		t.Fatalf("POST /login without LDAP: %d", rec.Code)
	}
}

func TestOIDCClaimsFromProvider(t *testing.T) {
	a := &OIDCAuth{UsernameClaim: "preferred_username", GroupsClaim: "groups", UIDClaim: "uidNumber", GIDClaim: "gidNumber"}
	u, err := a.userFromClaims(map[string]any{"preferred_username": "will", "uidNumber": float64(1000), "gidNumber": "1000"})
	if err != nil || u.User != (User{Name: "will", UID: 1000, GID: 1000}) {
		t.Fatalf("%+v %v", u, err)
	}
	if _, err := a.userFromClaims(map[string]any{"preferred_username": "root", "uidNumber": float64(0), "gidNumber": float64(0)}); err == nil {
		t.Fatal("uid 0 accepted")
	}
	if _, err := a.userFromClaims(map[string]any{"preferred_username": "x"}); err == nil {
		t.Fatal("missing uid accepted")
	}
}
