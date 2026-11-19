package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
)

// s3-portal login: a device code, approved in the browser by someone signed in to the
// portal (docs/design-expiring-keys.md). The command starts a request, which has a code
// people see and a poll token only the command has; the person approves the code here,
// which makes their login key; the command polls, and gets the key once.

const (
	cliCodeTTL     = 10 * time.Minute
	cliPollEvery   = 2 * time.Second
	cliMaxPending  = 500
	cliMaxPerIP    = 5
	cliCodeLetters = "BCDFGHJKLMNPQRSTVWXZ23456789" // no vowels (no words), no 0/O, 1/I
	nextCookie     = "s3p_next"
)

// CLILoginView is the page approving an s3-portal login: State is "enter" (the code to
// type), "confirm" (what's asked, to approve or deny), "approved", "denied" or "expired".
type CLILoginView struct {
	State    string
	Code     string
	Computer string
	From     string
	Asked    time.Time
	Lifetime time.Duration
	// Buckets are those the key would be limited to, if it asked for some; else it reaches
	// everything the person can (Reach, by bucket).
	Buckets map[string]Perm
	Reach   map[string]Perm
}

// cliRequest is one s3-portal login's request.
type cliRequest struct {
	code     string // as shown, XXXX-XXXX
	poll     string // the poll token's hash
	computer string
	from     string
	asked    time.Time
	lifetime string // as the command asked; "" the login default
	buckets  map[string]Perm
	state    string // pending, approved, denied
	// Once approved: the key, given to the command once.
	user, access, secret, logout string
	expires                      time.Time
	delivered                    bool
}

func (c *cliRequest) expired(now time.Time) bool { return now.Sub(c.asked) > cliCodeTTL }

type cliLogins struct {
	mu   sync.Mutex
	reqs map[string]*cliRequest // by code
}

func (l *cliLogins) sweep(now time.Time) {
	for code, c := range l.reqs {
		// Kept a little past expiry, so a late poll or page says it expired.
		if now.Sub(c.asked) > cliCodeTTL+5*time.Minute {
			delete(l.reqs, code)
		}
	}
}

func randomString(n int, alphabet string) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func hashToken(t string) string { s := sha256.Sum256([]byte(t)); return hex.EncodeToString(s[:]) }

// normalizeCode is a code as typed (any case, with or without the dash or spaces) as shown.
func normalizeCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		if strings.ContainsRune(cliCodeLetters, r) {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) != 8 {
		return ""
	}
	return s[:4] + "-" + s[4:]
}

// cleanComputer is the computer's name as the command gave it, made safe to show.
func cleanComputer(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) && r != '<' && r != '>' {
			return r
		}
		return -1
	}, strings.TrimSpace(s))
	if len(s) > 64 {
		s = s[:64]
	}
	if s == "" {
		s = "a computer"
	}
	return s
}

// CLIStartRequest starts an s3-portal login.
type CLIStartRequest struct {
	Computer string          `json:"computer"`
	Lifetime string          `json:"lifetime,omitempty"`
	Buckets  map[string]Perm `json:"buckets,omitempty"`
}

// CLIStartResult is the code to approve, where, and the token to poll with.
type CLIStartResult struct {
	Code            string `json:"code"`
	VerifyURL       string `json:"verify_url"`
	VerifyURLWith   string `json:"verify_url_complete"`
	PollToken       string `json:"poll_token"`
	IntervalSeconds int    `json:"interval"`
	ExpiresIn       int    `json:"expires_in"`
}

// CLIPollResult is a login's state, and its key once approved.
type CLIPollResult struct {
	State       string     `json:"state"` // pending, approved, denied, expired
	User        string     `json:"user,omitempty"`
	AccessKey   string     `json:"access_key,omitempty"`
	SecretKey   string     `json:"secret_key,omitempty"`
	Expires     *time.Time `json:"expires,omitempty"`
	Endpoint    string     `json:"endpoint,omitempty"`
	Region      string     `json:"region,omitempty"`
	LogoutToken string     `json:"logout_token,omitempty"`
}

// publicJSON serves an API call which needs no login: the command's own.
func (s *Server) publicJSON(h func(w http.ResponseWriter, r *http.Request) (int, any)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		status, out := h(w, r)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(out)
	}
}

func jsonErr(msg string) map[string]string { return map[string]string{"error": msg} }

func (s *Server) cliStart(_ http.ResponseWriter, r *http.Request) (int, any) {
	var req CLIStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		return http.StatusBadRequest, jsonErr("The request isn't valid JSON.")
	}
	if req.Lifetime != "" {
		if _, never, err := parseLifetime(req.Lifetime); err != nil || never {
			return http.StatusBadRequest, jsonErr("A login key's lifetime is hours, days or weeks (12h, 30d, 2w), up to the portal's most.")
		}
	}
	for b, p := range req.Buckets {
		if !p.Valid() {
			return http.StatusBadRequest, jsonErr(string(p) + " isn't a level of access (for " + b + "): read, readwrite, createonly or writeonly.")
		}
	}
	from := s.clientIP(r)
	now := time.Now()
	l := s.cli
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(now)
	mine := 0
	for _, c := range l.reqs {
		if c.from == from && c.state == "pending" && !c.expired(now) {
			mine++
		}
	}
	if len(l.reqs) >= cliMaxPending || mine >= cliMaxPerIP {
		return http.StatusTooManyRequests, jsonErr("Too many logins waiting to be approved: try again in a few minutes.")
	}
	var code string
	for code == "" || l.reqs[code] != nil {
		raw := randomString(8, cliCodeLetters)
		code = raw[:4] + "-" + raw[4:]
	}
	poll := base64.RawURLEncoding.EncodeToString([]byte(randomString(32, cliCodeLetters+"abcdefghijklmnopqrstuvwxyz")))
	l.reqs[code] = &cliRequest{code: code, poll: hashToken(poll), computer: cleanComputer(req.Computer), from: from, asked: now,
		lifetime: req.Lifetime, buckets: req.Buckets, state: "pending"}
	slog.Info("s3-portal login started", "computer", cleanComputer(req.Computer), "remote", from)
	verify := strings.TrimRight(s.S3URL, "/") + "/login/cli"
	return http.StatusOK, CLIStartResult{Code: code, VerifyURL: verify, VerifyURLWith: verify + "?code=" + url.QueryEscape(code),
		PollToken: poll, IntervalSeconds: int(cliPollEvery / time.Second), ExpiresIn: int(cliCodeTTL / time.Second)}
}

func (s *Server) cliPoll(_ http.ResponseWriter, r *http.Request) (int, any) {
	var req struct {
		PollToken string `json:"poll_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PollToken == "" {
		return http.StatusBadRequest, jsonErr("Give the poll_token the login started with.")
	}
	h := hashToken(req.PollToken)
	now := time.Now()
	l := s.cli
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.reqs {
		if subtle.ConstantTimeCompare([]byte(c.poll), []byte(h)) != 1 {
			continue
		}
		switch {
		case c.state == "denied":
			return http.StatusForbidden, CLIPollResult{State: "denied"}
		case c.state == "approved" && !c.delivered:
			c.delivered = true
			res := CLIPollResult{State: "approved", User: c.user, AccessKey: c.access, SecretKey: c.secret, Expires: &c.expires,
				Endpoint: s.S3URL, Region: s.Region, LogoutToken: c.logout}
			c.secret, c.logout = "", ""
			return http.StatusOK, res
		case c.state == "approved" || c.expired(now):
			return http.StatusGone, CLIPollResult{State: "expired"}
		}
		return http.StatusOK, CLIPollResult{State: "pending"}
	}
	return http.StatusGone, CLIPollResult{State: "expired"}
}

// cliLogout revokes a login key, with the token its login was given.
func (s *Server) cliLogout(_ http.ResponseWriter, r *http.Request) (int, any) {
	var req struct {
		AccessKey   string `json:"access_key"`
		LogoutToken string `json:"logout_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AccessKey == "" || req.LogoutToken == "" {
		return http.StatusBadRequest, jsonErr("Give the access_key and logout_token its login was given.")
	}
	if err := s.Portal.LogoutKey(r.Context(), req.AccessKey, req.LogoutToken); err != nil {
		var ue *UserError
		if errors.As(err, &ue) {
			return http.StatusBadRequest, jsonErr(ue.Msg)
		}
		slog.Error("s3-portal logout", "access", req.AccessKey, "err", err)
		return http.StatusBadGateway, jsonErr(genericError)
	}
	return http.StatusOK, map[string]string{"revoked": req.AccessKey}
}

// cliPage is the approval page. Someone not signed in is sent to sign in, and back.
func (s *Server) cliPage(w http.ResponseWriter, r *http.Request) {
	code := normalizeCode(r.URL.Query().Get("code"))
	sess, err := s.Sessions.Get(r)
	if err != nil {
		if code != "" {
			http.SetCookie(w, &http.Cookie{Name: nextCookie, Value: code, Path: "/", MaxAge: int(cliCodeTTL / time.Second),
				HttpOnly: true, Secure: strings.HasPrefix(s.S3URL, "https:"), SameSite: http.SameSiteLaxMode})
		}
		s.render(w, http.StatusOK, "login.html", page{Notice: "Sign in to approve s3-portal login on your computer."})
		return
	}
	p := s.base(w, r, sess, "keys")
	if code == "" {
		p.CLILogin = &CLILoginView{State: "enter", Code: r.URL.Query().Get("code")}
		if r.URL.Query().Get("code") != "" {
			p.Error = "That isn't a code s3-portal shows: 8 letters and digits, as HXQM-4TRW."
		}
		s.render(w, http.StatusOK, "login_cli.html", p)
		return
	}
	l := s.cli
	l.mu.Lock()
	c := l.reqs[code]
	var v *CLILoginView
	if c != nil {
		v = &CLILoginView{State: c.state, Code: c.code, Computer: c.computer, From: c.from, Asked: c.asked, Buckets: c.buckets}
		if c.state == "approving" {
			v.State = "pending"
		}
		if v.State == "pending" && c.expired(time.Now()) || c.state == "approved" && c.user != sess.User.Name {
			v.State = "expired"
		}
	}
	lifetime := ""
	if c != nil {
		lifetime = c.lifetime
	}
	l.mu.Unlock()
	if v == nil {
		v = &CLILoginView{State: "expired", Code: code}
	}
	if v.State == "pending" {
		v.State = "confirm"
		v.Lifetime = s.Portal.loginLifetime(lifetime)
		if len(v.Buckets) == 0 {
			v.Reach = map[string]Perm{}
			if buckets, err := s.Portal.Buckets(r.Context(), sess.User); err == nil {
				for _, b := range buckets {
					if perm := bestPerm(b.Caps); perm != "" {
						v.Reach[b.Name] = perm
					}
				}
			}
		}
	}
	if v.State == "approved" || v.State == "denied" {
		v.Lifetime = s.Portal.loginLifetime(lifetime)
	}
	p.CLILogin = v
	s.render(w, http.StatusOK, "login_cli.html", p)
}

// bestPerm is the most a level of access c covers, for showing what a login key reaches.
func bestPerm(c Caps) Perm {
	for _, p := range Perms {
		if c.Covers(p.Caps()) {
			return p
		}
	}
	return ""
}

// cliDecide approves or denies a login.
func (s *Server) cliDecide(w http.ResponseWriter, r *http.Request, sess *Session) {
	code := normalizeCode(r.PostFormValue("code"))
	back := "/login/cli?code=" + url.QueryEscape(code)
	approve := r.PostFormValue("decision") == "approve"
	if approve && r.PostFormValue("matches") != "yes" {
		redirectFlash(w, r, back, "", "Check the code matches the one in your terminal first.")
		return
	}
	l := s.cli
	l.mu.Lock()
	c := l.reqs[code]
	if c == nil || c.state != "pending" || c.expired(time.Now()) {
		l.mu.Unlock()
		redirectFlash(w, r, back, "", "")
		return
	}
	if !approve {
		c.state = "denied"
		l.mu.Unlock()
		slog.Warn("s3-portal login denied", "user", sess.User.Name, "computer", c.computer, "remote", c.from)
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	// Taken while the key is made, so the code is approved only once.
	c.state = "approving"
	computer, lifetime, buckets := c.computer, c.lifetime, c.buckets
	l.mu.Unlock()

	access, secret, expires, logout, err := s.Portal.CreateLoginKey(r.Context(), sess.User, computer, lifetime, buckets)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		c.state = "pending"
		redirectFlash(w, r, back, "", userMessage(r, sess, err))
		return
	}
	c.state, c.user, c.access, c.secret, c.logout, c.expires = "approved", sess.User.Name, access, secret, logout, expires
	slog.Info("s3-portal login approved", "user", sess.User.Name, "computer", computer, "remote", c.from, "access", access)
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// nextAfterLogin is where to go once signed in: the login approval page, if signing in
// was for it.
func nextAfterLogin(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie(nextCookie)
	if err != nil {
		return "/"
	}
	http.SetCookie(w, &http.Cookie{Name: nextCookie, Path: "/", MaxAge: -1})
	if code := normalizeCode(c.Value); code != "" {
		return "/login/cli?code=" + url.QueryEscape(code)
	}
	return "/"
}

// loginLifetime is how long a login key asked to last lifetime ("" the default) would.
func (p *Portal) loginLifetime(lifetime string) time.Duration {
	pol := p.KeyPolicy()
	d, _, err := parseLifetime(lifetime)
	if lifetime == "" || err != nil {
		return pol.Login
	}
	return d
}

// CreateLoginKey makes u's login key for computer: reaching everything u can, or only
// buckets if given, lasting lifetime ("" the login default, at most the most). It returns
// the key, its expiry, and a token to revoke it with (LogoutKey), whose hash it keeps.
func (p *Portal) CreateLoginKey(ctx context.Context, u User, computer, lifetime string, buckets map[string]Perm) (string, string, time.Time, string, error) {
	pol := p.KeyPolicy()
	d := p.loginLifetime(lifetime)
	if d > pol.Max {
		return "", "", time.Time{}, "", userErr("s3-portal asked for a key lasting %s: the most is %s. Log in again with a shorter --lifetime.", lifetimeLabel(d), lifetimeLabel(pol.Max))
	}
	expires := time.Now().UTC().Add(d).Truncate(time.Second)
	logout := randomString(40, cliCodeLetters+"abcdefghijklmnopqrstuvwxyz")
	if buckets == nil {
		buckets = map[string]Perm{}
	}
	access, secret, err := p.createKey(ctx, u, computer, buckets, keyOpts{Expires: &expires, Login: true, Computer: computer, LogoutHash: hashToken(logout)})
	if err != nil {
		return "", "", time.Time{}, "", err
	}
	return access, secret, expires, logout, nil
}

// LogoutKey revokes a login key, given the token its login was.
func (p *Portal) LogoutKey(ctx context.Context, access, token string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	k, ok := p.store.Get(access)
	if !ok {
		return nil // gone already: logged out
	}
	if !k.Login || k.LogoutHash == "" || subtle.ConstantTimeCompare([]byte(k.LogoutHash), []byte(hashToken(token))) != 1 {
		return userErr("That isn't this key's logout token.")
	}
	if err := p.revoke(ctx, []string{access}); err != nil {
		return err
	}
	slog.Info("s3-portal logout", "user", k.Owner, "access", access, "computer", k.Computer)
	return nil
}
