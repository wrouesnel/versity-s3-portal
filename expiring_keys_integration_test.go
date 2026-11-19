package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Keys with lifetimes on the scratch gateway: the default, the most, never for admins
// alone, renewing, and an expired key revoked.
func TestExpiringKeysAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	admin := User{Name: "exadmin" + suffix, UID: 1030, GID: 1030, Admin: true}
	alice := User{Name: "exalice" + suffix, UID: 1031, GID: 1031}
	enroll(t, p, admin)
	enroll(t, p, alice)
	bucket := "exp-" + suffix
	ok(t, "bucket", p.CreateBucket(ctx, alice, bucket))
	grants := map[string]Perm{bucket: PermReadWrite}

	access, secret, err := p.CreateKey(ctx, alice, "default", grants)
	ok(t, "a key lasting the default", err)
	k, _ := store.Get(access)
	if k.Expires == nil || k.Expires.Sub(time.Now()) < 89*day || k.Expires.Sub(time.Now()) > 90*day {
		t.Fatalf("the default lifetime: %v", k.Expires)
	}
	userError(t, "longer than the most", firstErr2(p.CreateKeyLasting(ctx, alice, "long", grants, "400d")))
	userError(t, "never, not as an admin", firstErr2(p.CreateKeyLasting(ctx, alice, "never", grants, "never")))
	never, _, err := p.CreateKeyForLasting(ctx, admin, alice.Name, "an admin's never", grants, "never")
	ok(t, "never, by an admin", err)
	if k, _ := store.Get(never); k.Expires != nil || k.NeverBy != admin.Name || k.IssuedBy != admin.Name {
		t.Fatalf("never: %+v", k)
	}
	userError(t, "alice makes it expire, then never", p.RenewKey(ctx, alice, never, "never"))
	ok(t, "alice renews it, so it expires", p.RenewKey(ctx, alice, never, "7d"))
	if k, _ := store.Get(never); k.Expires == nil || k.NeverBy != "" {
		t.Fatalf("renewed: %+v", k)
	}
	userError(t, "someone else renews alice's key", p.RenewKey(ctx, User{Name: "nobody"}, access, "1d"))

	// The key works, then expires: revoked from the gateway, and gone from the portal.
	ok(t, "write before it expires", putObject(ctx, as(root, access, secret), bucket, "a.txt", "x"))
	k, _ = store.Get(access)
	past := time.Now().Add(-time.Second)
	k.Expires = &past
	ok(t, "expire it", store.Put(access, k))
	if n, err := p.ReapExpired(ctx); err != nil || n != 1 {
		t.Fatalf("reap: %d %v", n, err)
	}
	if _, ok := store.Get(access); ok {
		t.Fatal("the expired key is still there")
	}
	denied(t, "an expired key", putObject(ctx, as(root, access, secret), bucket, "b.txt", "x"))
	if n, _ := p.ReapExpired(ctx); n != 0 {
		t.Errorf("reaped again: %d", n)
	}

	userError(t, "a default longer than the most", p.SetKeyPolicy(admin, KeyPolicy{Default: 30 * day, Login: time.Hour, Max: 7 * day}))
	userError(t, "a policy, not as an admin", p.SetKeyPolicy(alice, DefaultKeyPolicy))
	ok(t, "a policy", p.SetKeyPolicy(admin, KeyPolicy{Default: 7 * day, Login: 2 * time.Hour, Max: 30 * day}))
	if pol := p.KeyPolicy(); pol.Max != 30*day {
		t.Errorf("policy %+v", pol)
	}
	userError(t, "longer than the new most", firstErr2(p.CreateKeyLasting(ctx, alice, "x", grants, "31d")))
}

// s3-portal login, the real binary, against the portal over HTTP and the scratch gateway:
// the command shows a code; bob, signed in in a "browser", approves it; the command gets
// a key reaching what bob can (alice's bucket, shared with his group, read only), and
// sets up aws, rclone and mc. Logging in again replaces the key; a second portal leaves
// the default alone until told; logging out revokes the key.
func TestLoginAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	dir := t.TempDir()
	tool := filepath.Join(dir, "s3-portal")
	if out, err := exec.Command("go", "build", "-o", tool, "./cmd/s3-portal").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	store, _ := OpenStore(filepath.Join(dir, "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	alice := User{Name: "lgalice" + suffix, UID: 1040, GID: 1040}
	bob := User{Name: "lgbob" + suffix, UID: 1041, GID: 1041}
	team := "team" + suffix
	enroll(t, p, alice)
	enroll(t, p, bob, team)
	shared := "lg-" + suffix
	ok(t, "bucket", p.CreateBucket(ctx, alice, shared))
	ok(t, "share it", p.SetGroupGrant(ctx, alice, shared, team, PermRead))
	wa, ws := webAccount(t, p, alice)
	ok(t, "a file", putObject(ctx, as(root, wa, ws), shared, "hello.txt", "hi"))

	sessions := &Sessions{Key: []byte("0123456789abcdef0123456789abcdef"), TTL: 3600e9, Store: store}
	srv := httptest.NewServer(NewServer(p, stubAuth{user: bob, groups: []string{team}}, nil, sessions, "t", root.S3Endpoint, "us-east-1").Handler())
	defer srv.Close()

	home := filepath.Join(dir, "home")
	// A clean environment, as a user's shell might be: not this host's AWS_REGION or profile.
	var base []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "AWS_") && !strings.HasPrefix(kv, "MC_") && !strings.HasPrefix(kv, "RCLONE_") {
			base = append(base, kv)
		}
	}
	env := append(base, "HOME="+home, "S3_PORTAL_CONFIG="+filepath.Join(home, "cfg"), "AWS_CONFIG_FILE="+filepath.Join(home, "aws"),
		"RCLONE_CONFIG="+filepath.Join(home, "rclone.conf"), "MC_CONFIG_DIR="+filepath.Join(home, "mc"), "S3_PORTAL=", "DISPLAY=", "WAYLAND_DISPLAY=")
	run := func(args ...string) (string, string, error) {
		t.Helper()
		cmd := exec.Command(tool, args...)
		cmd.Env = env
		var out, errOut strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		return out.String(), errOut.String(), err
	}

	// The browser: bob signs in, from the link, and approves.
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar}
	get := func(path string) string {
		t.Helper()
		resp, err := browser.Get(srv.URL + path)
		ok(t, "GET "+path, err)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return string(b)
	}
	csrf := func(page string) string {
		m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("no CSRF token in\n%s", page)
		}
		return m[1]
	}
	signedIn := false
	approve := func(code string) {
		t.Helper()
		page := get("/login/cli?code=" + url.QueryEscape(code))
		if !signedIn {
			if !strings.Contains(page, "Sign in to approve") {
				t.Fatalf("not signed in:\n%s", page)
			}
			resp, err := browser.PostForm(srv.URL+"/login", url.Values{"username": {bob.Name}, "password": {"pw"}})
			ok(t, "sign in", err)
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			page, signedIn = string(b), true // back at the approval page, after signing in
		}
		host, _ := os.Hostname()
		if !strings.Contains(page, "Sign in s3-portal on "+cleanComputer(host)) || !strings.Contains(page, shared) || !strings.Contains(page, code) {
			t.Fatalf("the approval page:\n%s", page)
		}
		resp, _ := browser.PostForm(srv.URL+"/login/cli", url.Values{"csrf": {csrf(page)}, "code": {code}, "decision": {"approve"}})
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(b), "Check the code matches") {
			t.Fatalf("approved without checking the code:\n%s", b)
		}
		resp, _ = browser.PostForm(srv.URL+"/login/cli", url.Values{"csrf": {csrf(page)}, "code": {code}, "decision": {"approve"}, "matches": {"yes"}})
		b, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(b), "Signed in on") {
			t.Fatalf("after approving:\n%s", b)
		}
	}
	// login runs the command, approving its code, and returns what it printed.
	login := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(tool, append([]string{"login"}, args...)...)
		cmd.Env = env
		stdout, _ := cmd.StdoutPipe()
		var errOut strings.Builder
		cmd.Stderr = &errOut
		ok(t, "start login", cmd.Start())
		var out strings.Builder
		sc := bufio.NewScanner(stdout)
		code := ""
		for sc.Scan() {
			out.WriteString(sc.Text() + "\n")
			if m := regexp.MustCompile(`Code: (\S+)`).FindStringSubmatch(sc.Text()); m != nil {
				code = m[1]
				break
			}
		}
		if code == "" {
			cmd.Wait()
			t.Fatalf("no code:\n%s%s", out.String(), errOut.String())
		}
		approve(code)
		rest, _ := io.ReadAll(stdout)
		out.Write(rest)
		if err := cmd.Wait(); err != nil {
			t.Fatalf("login: %v\n%s%s", err, out.String(), errOut.String())
		}
		return out.String() + errOut.String()
	}

	out := login(srv.URL, "--name", "lab")
	if !strings.Contains(out, "Logged in to lab as "+bob.Name) || !strings.Contains(out, "lab is the default portal") {
		t.Fatalf("login:\n%s", out)
	}
	creds := func(name string) (string, string) {
		t.Helper()
		stdout, stderr, err := run("credentials", name)
		var c struct{ AccessKeyId, SecretAccessKey, Expiration string }
		if err != nil || json.Unmarshal([]byte(stdout), &c) != nil || c.AccessKeyId == "" {
			t.Fatalf("credentials: %v %s %s", err, stdout, stderr)
		}
		return c.AccessKeyId, c.SecretAccessKey
	}
	access, secret := creds("lab")
	k, _ := store.Get(access)
	if k == nil || !k.Login || k.Owner != bob.Name || k.Expires == nil || time.Until(*k.Expires) > 12*time.Hour || time.Until(*k.Expires) < 11*time.Hour {
		t.Fatalf("the login key: %+v", k)
	}
	key := as(root, access, secret)
	if got, err := getObject(ctx, key, shared, "hello.txt"); err != nil || got != "hi" {
		t.Fatalf("reading alice's bucket, shared with bob: %q %v", got, err)
	}
	denied(t, "writing a bucket bob may only read", putObject(ctx, key, shared, "no.txt", "x"))
	// It follows bob's access: shared read & write, it writes.
	ok(t, "share it read & write", p.SetGroupGrant(ctx, alice, shared, team, PermReadWrite))
	ok(t, "writing once it's shared read & write", putObject(ctx, key, shared, "bob.txt", "x"))

	awsCfg, _ := os.ReadFile(filepath.Join(home, "aws"))
	rclone, _ := os.ReadFile(filepath.Join(home, "rclone.conf"))
	mc, _ := os.ReadFile(filepath.Join(home, "mc", "config.json"))
	if !strings.Contains(string(awsCfg), "[profile lab]") || !strings.Contains(string(awsCfg), "credentials lab") || !strings.Contains(string(awsCfg), "endpoint_url = "+root.S3Endpoint) {
		t.Errorf("aws config:\n%s", awsCfg)
	}
	if !strings.Contains(string(rclone), "[lab]") || !strings.Contains(string(rclone), "profile = lab") {
		t.Errorf("rclone config:\n%s", rclone)
	}
	if !strings.Contains(string(mc), access) {
		t.Errorf("mc config:\n%s", mc)
	}

	// The tools themselves, where they're installed, use what login set up: aws and rclone
	// through credential_process, mc with the key in its alias.
	for _, tc := range []struct {
		tool string
		args []string
	}{
		{"aws", []string{"--profile", "lab", "s3", "ls", "s3://" + shared + "/"}},
		{"rclone", []string{"lsf", "lab:" + shared}},
		{"mc", []string{"ls", "lab/" + shared}},
	} {
		if _, err := exec.LookPath(tc.tool); err != nil {
			t.Logf("%s isn't installed: not tried", tc.tool)
			continue
		}
		cmd := exec.Command(tc.tool, tc.args...)
		cmd.Env = env
		got, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(got), "hello.txt") {
			t.Errorf("%s %s: %v\n%s", tc.tool, strings.Join(tc.args, " "), err, got)
		} else {
			t.Logf("%s lists %s with the login key", tc.tool, shared)
		}
	}

	// Again: a new key, the old one revoked.
	login("lab")
	access2, _ := creds("lab")
	if _, ok := store.Get(access); ok || access2 == access {
		t.Fatalf("the old key is still there (%s, now %s)", access, access2)
	}

	// A second portal (the same server, by another name) doesn't become the default.
	out = login(srv.URL, "--name", "other")
	if !strings.Contains(out, "The default portal is lab") {
		t.Fatalf("a second portal:\n%s", out)
	}
	status, _, _ := run("status")
	if !strings.Contains(status, "* lab") || !strings.Contains(status, "  other") {
		t.Errorf("status:\n%s", status)
	}
	if out, _, err := run("default", "other"); err != nil || !strings.Contains(out, "other") {
		t.Fatalf("default other: %v %s", err, out)
	}
	otherAccess, _ := creds("other")
	// Logging out, without PORTAL: the default, and it says so.
	stdout, stderr, err := run("logout")
	if err != nil || !strings.Contains(stderr, "Using other") || !strings.Contains(stderr, "the default") || !strings.Contains(stdout, "Logged out of other") {
		t.Fatalf("logout: %v\n%s%s", err, stdout, stderr)
	}
	if _, ok := store.Get(otherAccess); ok {
		t.Fatal("logged out, and the key is still there")
	}
	if _, stderr, err := run("credentials", "other"); err == nil || !strings.Contains(stderr, "s3-portal login other") {
		t.Errorf("credentials after logout: %v %s", err, stderr)
	}
	if _, stderr, err := run("logout"); err == nil || !strings.Contains(stderr, "no default portal") {
		t.Errorf("logout with no default: %v %s", err, stderr)
	}

	// Denied in the browser, the command gets nothing.
	var start CLIStartResult
	resp, err := http.Post(srv.URL+"/api/login/start", "application/json", strings.NewReader(`{"computer":"mallory-box"}`))
	ok(t, "start", err)
	json.NewDecoder(resp.Body).Decode(&start)
	resp.Body.Close()
	page := get("/login/cli?code=" + start.Code)
	resp, _ = browser.PostForm(srv.URL+"/login/cli", url.Values{"csrf": {csrf(page)}, "code": {start.Code}, "decision": {"deny"}})
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "Not signed in") {
		t.Fatalf("after denying:\n%s", b)
	}
	resp, _ = http.Post(srv.URL+"/api/login/poll", "application/json", strings.NewReader(`{"poll_token":"`+start.PollToken+`"}`))
	var polled CLIPollResult
	json.NewDecoder(resp.Body).Decode(&polled)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || polled.State != "denied" || polled.AccessKey != "" {
		t.Fatalf("polling a denied login: %d %+v", resp.StatusCode, polled)
	}
}

// The forms, over HTTP: a key made with a lifetime, renewed; the admin's lifetimes, and an
// admin making a key never expire.
func TestExpiringKeysWebAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	admin := User{Name: "exwadmin" + suffix, UID: 1050, GID: 1050, Admin: true}
	enroll(t, p, admin)
	bucket := "exw-" + suffix
	ok(t, "bucket", p.CreateBucket(ctx, admin, bucket))
	sessions := &Sessions{Key: []byte("0123456789abcdef0123456789abcdef"), TTL: 3600e9, Store: store}
	srv := httptest.NewServer(NewServer(p, stubAuth{user: admin}, nil, sessions, "t", root.S3Endpoint, "us-east-1").Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.PostForm(srv.URL+"/login", url.Values{"username": {admin.Name}, "password": {"pw"}})
	ok(t, "login", err)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(string(b))[1]
	post := func(path string, form url.Values) string {
		t.Helper()
		form.Set("csrf", csrf)
		resp, err := c.PostForm(srv.URL+path, form)
		ok(t, "POST "+path, err)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return string(b)
	}
	get := func(path string) string {
		t.Helper()
		resp, err := c.Get(srv.URL + path)
		ok(t, "GET "+path, err)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return string(b)
	}

	if page := get("/keys/new"); !strings.Contains(page, `<option value="90d" selected>90 days</option>`) || !strings.Contains(page, `value="never"`) {
		t.Fatalf("the new key form's lifetimes:\n%s", page)
	}
	page := post("/keys", url.Values{"label": {"week"}, "lifetime": {"7d"}, "perm_" + bucket: {"read"}})
	m := regexp.MustCompile(`<code class="copy">(VGW[A-Z0-9]+)</code>`).FindStringSubmatch(page)
	if m == nil || !strings.Contains(page, "expires in 7 days") {
		t.Fatalf("the key made:\n%s", page)
	}
	access := m[1]
	if page := get("/keys"); !strings.Contains(page, "expires in 7 days") {
		t.Errorf("the keys page:\n%s", page)
	}
	if page := post("/keys/edit", url.Values{"access": {access}, "label": {"week"}, "renew": {"yes"}, "lifetime": {"30d"}, "perm_" + bucket: {"read"}}); !strings.Contains(page, "expires in 30 days") {
		t.Errorf("renewed:\n%s", page)
	}
	if page := post("/admin/lifetimes", url.Values{"default": {"30d"}, "login": {"8h"}, "max": {"60d"}}); !strings.Contains(page, "New keys now last 30 days (8 hours for login keys), at most 60 days") {
		t.Errorf("lifetimes set:\n%s", page)
	}
	if page := post("/admin/lifetimes", url.Values{"default": {"90d"}, "login": {"8h"}, "max": {"60d"}}); !strings.Contains(page, "longer than the most") {
		t.Errorf("a default longer than the most:\n%s", page)
	}
	if page := post("/admin/renew", url.Values{"access": {access}, "lifetime": {"never"}}); !strings.Contains(page, "never expires") || !strings.Contains(page, "1 never expire") {
		t.Errorf("made never to expire:\n%s", page)
	}
	if k, _ := store.Get(access); k.Expires != nil || k.NeverBy != admin.Name {
		t.Errorf("the key: %+v", k)
	}
}
