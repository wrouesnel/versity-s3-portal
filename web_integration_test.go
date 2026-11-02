package main

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type stubAuth struct{ user User }

func (a stubAuth) Authenticate(username, password string) (User, error) {
	if username != a.user.Name || password != "pw" {
		return User{}, ErrBadCredentials
	}
	return a.user, nil
}

// Drives the web UI over HTTP against the scratch gateway: log in, upload,
// browse, download, and open the admin page.
func TestWebAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	bucket := "web-" + suffix
	user := User{Name: "carol" + suffix, UID: 1004, GID: 1004, Admin: true}
	ok(t, "create bucket", p.CreateBucket(ctx, user, bucket))

	sessions := &Sessions{Key: []byte("0123456789abcdef0123456789abcdef"), TTL: 3600e9}
	srv := httptest.NewServer(NewServer(p, stubAuth{user}, nil, sessions, "t", "https://s3", "us-east-1").Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	resp, err := c.PostForm(srv.URL+"/login", url.Values{"username": {user.Name}, "password": {"pw"}})
	ok(t, "login", err)
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(page)
	if m == nil || !strings.Contains(string(page), "/browse?bucket="+bucket) {
		t.Fatalf("dashboard after login lacks the CSRF token or bucket link:\n%s", page)
	}
	csrf := string(m[1])

	key := "docs/report (final) & notes.txt"
	req, _ := http.NewRequest("PUT", srv.URL+"/upload?"+url.Values{"bucket": {bucket}, "key": {key}}.Encode(), strings.NewReader("hello web"))
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = c.Do(req)
	ok(t, "upload", err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("upload: HTTP %d", resp.StatusCode)
	}

	resp, err = c.Get(srv.URL + "/browse?" + url.Values{"bucket": {bucket}, "prefix": {"docs/"}}.Encode())
	ok(t, "browse", err)
	page, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(page), "report (final) &amp; notes.txt") {
		t.Fatalf("browse: HTTP %d\n%s", resp.StatusCode, page)
	}

	resp, err = c.Get(srv.URL + "/download?" + url.Values{"bucket": {bucket}, "key": {key}}.Encode())
	ok(t, "download", err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello web" || resp.Header.Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("download: %q %v", body, resp.Header)
	}

	resp, err = c.Get(srv.URL + "/admin")
	ok(t, "admin page", err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin page: HTTP %d", resp.StatusCode)
	}

	resp, err = c.PostForm(srv.URL+"/folders/delete", url.Values{"csrf": {csrf}, "bucket": {bucket}, "folder": {"docs/"}})
	ok(t, "delete folder", err)
	resp.Body.Close()
	ok(t, "delete bucket", p.DeleteBucket(ctx, user, bucket))
}
