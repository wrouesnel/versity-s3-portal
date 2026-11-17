package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// An admin issues an API token on the admin page, which a tool (a migrator)
// drives the admin API with, recorded by its name, until it's revoked or
// its maker is no longer an admin. Only its hash is kept.
func TestAPITokensAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	store, _ := OpenStore(statePath)
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	admin := User{Name: "fay" + suffix, UID: 1009, GID: 1009, Admin: true}
	alice := User{Name: "alice" + suffix, UID: 1010, GID: 1010}
	enroll(t, p, admin)
	enroll(t, p, alice)
	userError(t, "a token, not as an admin", firstErr2(p.CreateAPIToken(alice, "x")))

	sessions := &Sessions{Key: []byte("0123456789abcdef0123456789abcdef"), TTL: 3600e9, Store: store}
	srv := httptest.NewServer(NewServer(p, stubAuth{user: admin}, nil, sessions, "", "https://s3", "us-east-1").Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.PostForm(srv.URL+"/login", url.Values{"username": {admin.Name}, "password": {"pw"}})
	ok(t, "login", err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf := string(regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(body)[1])
	if strings.Contains(string(body), "S3 access keys") {
		t.Error("the header shows a title, though none is configured")
	}
	resp, err = c.PostForm(srv.URL+"/admin/tokens", url.Values{"csrf": {csrf}, "name": {"migrator"}})
	ok(t, "issue a token", err)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`<code class="copy">(s3p_[A-Za-z0-9]+)</code>`).FindSubmatch(body)
	if m == nil || !strings.Contains(string(body), "/api/keys") {
		t.Fatalf("the token issued:\n%s", body)
	}
	token := string(m[1])
	state, _ := os.ReadFile(statePath)
	if bytes.Contains(state, []byte(token)) {
		t.Fatal("the token itself is in the state")
	}
	resp, _ = c.PostForm(srv.URL+"/admin/tokens", url.Values{"csrf": {csrf}, "name": {"Migrator"}})
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "a token called Migrator already") {
		t.Errorf("a second token of the name:\n%s", body)
	}
	resp, _ = c.Get(srv.URL + "/admin?section=tokens")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "migrator") || strings.Contains(string(body), token) {
		t.Fatalf("the tokens' list shows it, or its secret:\n%s", body)
	}

	api := func(method, path, data string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		ok(t, method+" "+path, err)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	bucket := "tok-" + suffix
	if code, b := api("POST", "/api/buckets", `{"owner": "`+alice.Name+`", "name": "`+bucket+`"}`); code != 200 || !strings.Contains(b, `"created":true`) {
		t.Fatalf("a bucket with the token: %d %s", code, b)
	}
	code, b := api("POST", "/api/keys", `{"owner": "`+alice.Name+`", "label": "migration", "buckets": {"`+bucket+`": "readwrite"}}`)
	access := regexp.MustCompile(`"access_key":"([^"]+)"`).FindStringSubmatch(b)
	if code != 200 || access == nil {
		t.Fatalf("a key with the token: %d %s", code, b)
	}
	if k, _ := store.Get(access[1]); k.IssuedBy != "api:migrator" {
		t.Errorf("the key's issued by %q", k.IssuedBy)
	}
	if list, _ := p.APITokenList(admin); len(list) != 1 || list[0].LastUsed.IsZero() || !list[0].Valid {
		t.Errorf("the token's record: %+v", list)
	}

	// Its maker no longer an admin: it stops working, and says why.
	person, _ := store.Person(admin.Name)
	person.Admin = false
	ok(t, "demote", store.PutPerson(admin.Name, person))
	if code, _ := api("GET", "/api/users/"+alice.Name, ""); code != http.StatusUnauthorized {
		t.Errorf("a token whose maker isn't an admin: %d", code)
	}
	if list, _ := p.APITokenList(admin); len(list) != 1 || list[0].Valid || !strings.Contains(list[0].Reason, "no longer an admin") {
		t.Errorf("the token's record: %+v", list)
	}
	person.Admin = true
	ok(t, "promote", store.PutPerson(admin.Name, person))
	if code, _ := api("GET", "/api/users/"+alice.Name, ""); code != 200 {
		t.Errorf("the token again: %d", code)
	}
	list, _ := p.APITokenList(admin)
	resp, _ = c.PostForm(srv.URL+"/admin/tokens/revoke", url.Values{"csrf": {csrf}, "id": {list[0].ID}})
	resp.Body.Close()
	if code, _ := api("GET", "/api/users/"+alice.Name, ""); code != http.StatusUnauthorized {
		t.Errorf("a revoked token: %d", code)
	}
	if code, _ := api("GET", "/api/users/"+alice.Name, ""); code != http.StatusUnauthorized {
		t.Error("a revoked token works")
	}
}
