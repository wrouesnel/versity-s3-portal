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
	"time"
)

// A server mirror on the scratch gateway: a gateway account owning three
// buckets is "the server". Its buckets are on this gateway too, so every
// row's name is taken here, and each is given another; then they're
// mirrored, queued passes run two at a time, and the whole server is frozen
// and completed.
func TestServerMirrorAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	admin := User{Name: "admin" + suffix, UID: 1000, GID: 1000, Admin: true}
	alice := User{Name: "alice" + suffix, UID: 1001, GID: 1001}
	enroll(t, p, admin)
	enroll(t, p, alice)

	// The server: an account of its own, seeing only its buckets.
	srcAcct := Account{Access: "srv" + suffix, Secret: newSecret(), Role: "user", UserID: 2000, GroupID: 2000}
	ok(t, "source account", root.CreateAccount(ctx, srcAcct))
	t.Cleanup(func() { root.DeleteAccount(ctx, srcAcct.Access) })
	names := []string{"sa-" + suffix, "sb-" + suffix, "sc-" + suffix}
	for i, b := range names {
		ok(t, "source bucket", root.CreateBucket(ctx, b, srcAcct.Access))
		for j := 0; j <= i; j++ {
			_, err := root.Put(ctx, b, "f"+string(rune('0'+j))+".txt", strings.NewReader("x"), 1, nil)
			ok(t, "source put", err)
		}
	}
	src := MirrorSource{Endpoint: root.S3Endpoint, Region: "us-east-1", Access: srcAcct.Access, Secret: srcAcct.Secret}

	userError(t, "register as non-admin", firstErr(p.RegisterServer(ctx, alice, ServerRequest{Name: "x", Source: src, DefaultOwner: alice.Name})))
	bad := src
	bad.Secret = "wrong"
	userError(t, "register with a bad key", firstErr(p.RegisterServer(ctx, admin, ServerRequest{Name: "x", Source: bad, DefaultOwner: alice.Name})))
	userError(t, "register for nobody", firstErr(p.RegisterServer(ctx, admin, ServerRequest{Name: "x", Source: src, DefaultOwner: "nobody"})))
	id, err := p.RegisterServer(ctx, admin, ServerRequest{Name: "Old server " + suffix, Source: src, DefaultOwner: alice.Name, Every: "hourly"})
	ok(t, "register", err)

	v, err := p.ServerDetail(ctx, admin, id)
	ok(t, "detail", err)
	if v.ListError != "" || len(v.Rows) != 3 || v.Source.Secret != "" || !v.HasSecret {
		t.Fatalf("detail: %+v", v)
	}
	for i, r := range v.Rows {
		// Here too, with things in them, and owned by nobody the portal knows.
		if r.Source != names[i] || r.Status != RowClash || r.Include {
			t.Errorf("row %d: %+v", i, r)
		}
	}

	picks := []ServerPick{
		{Source: names[0], Local: "ma-" + suffix},
		{Source: names[1], Local: "mb-" + suffix, Owner: alice.Name},
		{Source: names[2], Local: "mc-" + suffix},
		{Source: "nosuch-" + suffix, Local: "md-" + suffix},
		{Source: names[0], Local: "mb-" + suffix},
	}
	made, err := p.CreateServerMirrors(ctx, admin, id, picks)
	if len(made) != 3 || err == nil || !strings.Contains(err.Error(), "nosuch-"+suffix) || !strings.Contains(err.Error(), "picked for another bucket") {
		t.Fatalf("create: %v %v", made, err)
	}
	for _, b := range made {
		m, _ := p.store.Mirror(b)
		if m.Server != id || m.Owner != alice.Name || m.Every != "hourly" {
			t.Errorf("%s: %+v", b, m)
		}
	}
	if _, err := p.CreateServerMirrors(ctx, admin, id, picks[:1]); err == nil || !strings.Contains(err.Error(), "mirrored from this server already") {
		t.Errorf("mirroring a bucket again: %v", err)
	}
	if v, _ := p.ServerDetail(ctx, admin, id); len(v.Rows) != 0 || len(v.Mirrors) != 3 {
		t.Fatalf("after create: %d rows, %d mirrors", len(v.Rows), len(v.Mirrors))
	}

	// RegisterMirror started nothing (the scheduler isn't running here):
	// queue a pass of each, and see two start, then the third.
	n, err := p.ServerRunPasses(admin, id)
	if err != nil || n != 3 {
		t.Fatalf("run passes: %d %v", n, err)
	}
	wait := func() {
		t.Helper()
		for range 200 {
			p.startDue(time.Now())
			queued := 0
			for _, b := range made {
				p.WaitMirror(b)
				if m, _ := p.store.Mirror(b); m.Queued != "" {
					queued++
				}
			}
			if queued == 0 {
				return
			}
		}
		t.Fatal("queued passes never ran")
	}
	p.startDue(time.Now())
	p.mirrors.mu.Lock()
	running := len(p.mirrors.jobs)
	p.mirrors.mu.Unlock()
	if running > maxMirrorJobs {
		t.Errorf("%d passes at once", running)
	}
	wait()
	for _, b := range made {
		if m, _ := p.store.Mirror(b); m.State != MirrorSynced {
			t.Fatalf("%s is %s after its pass: %+v", b, m.State, m.LastPass())
		}
	}

	n, err = p.ServerFreeze(admin, id, false)
	if err != nil || n != 3 {
		t.Fatalf("freeze: %d %v", n, err)
	}
	wait()
	for _, b := range made {
		if m, _ := p.store.Mirror(b); m.State != MirrorVerified {
			t.Fatalf("%s is %s after the final pass", b, m.State)
		}
	}
	userError(t, "forget with mirrors running", p.ForgetServer(admin, id))
	n, err = p.ServerComplete(ctx, admin, id)
	if err != nil || n != 3 {
		t.Fatalf("complete: %d %v", n, err)
	}
	got, err := getObject(ctx, p.vgw.As(webAccount(t, p, alice)), "mc-"+suffix, "f2.txt")
	if err != nil || got != "x" {
		t.Fatalf("a completed bucket's copy: %q %v", got, err)
	}
	if list, _ := p.ServerList(admin); len(list) != 1 || list[0].Done != 3 || list[0].Active != 0 {
		t.Errorf("list: %+v", list)
	}
	ok(t, "forget", p.ForgetServer(admin, id))
	if _, ok := p.store.Server(id); ok {
		t.Error("the server is still there")
	}
}

// firstErr is the error of a call returning a value and an error.
func firstErr[T any](_ T, err error) error { return err }

// The server mirror's pages and forms, over HTTP: the new server's form,
// its page's review table, mirroring the rows ticked, and an action.
func TestServerMirrorWebAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	admin := User{Name: "dana" + suffix, UID: 1005, GID: 1005, Admin: true}
	enroll(t, p, admin)
	srcAcct := Account{Access: "srw" + suffix, Secret: newSecret(), Role: "user", UserID: 2001, GroupID: 2001}
	ok(t, "source account", root.CreateAccount(ctx, srcAcct))
	t.Cleanup(func() { root.DeleteAccount(ctx, srcAcct.Access) })
	srcBucket := "sw-" + suffix
	ok(t, "source bucket", root.CreateBucket(ctx, srcBucket, srcAcct.Access))

	sessions := &Sessions{Key: []byte("0123456789abcdef0123456789abcdef"), TTL: 3600e9, Store: store}
	srv := httptest.NewServer(NewServer(p, stubAuth{user: admin}, nil, sessions, "t", "https://s3", "us-east-1").Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.PostForm(srv.URL+"/login", url.Values{"username": {admin.Name}, "password": {"pw"}})
	ok(t, "login", err)
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf := string(regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(page)[1])
	get := func(path string) string {
		t.Helper()
		resp, err := c.Get(srv.URL + path)
		ok(t, "GET "+path, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: HTTP %d\n%s", path, resp.StatusCode, body)
		}
		return string(body)
	}
	post := func(path string, form url.Values) string {
		t.Helper()
		form.Set("csrf", csrf)
		resp, err := c.PostForm(srv.URL+path, form)
		ok(t, "POST "+path, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return string(body)
	}

	if body := get("/admin/servers/new"); !strings.Contains(body, "List the server's buckets") {
		t.Fatalf("the new server form:\n%s", body)
	}
	body := post("/admin/servers", url.Values{
		"name": {"Web " + suffix}, "endpoint": {root.S3Endpoint}, "region": {"us-east-1"}, "addressing": {"path"},
		"access": {srcAcct.Access}, "secret": {srcAcct.Secret}, "owner": {admin.Name}, "every": {""},
	})
	if !strings.Contains(body, "Tick the buckets to mirror") || !strings.Contains(body, srcBucket) || strings.Contains(body, srcAcct.Secret) {
		t.Fatalf("the server's page after registering:\n%s", body)
	}
	id := "web-" + suffix
	body = post("/admin/server/create", url.Values{"id": {id}, "pick": {"0"},
		"source-0": {srcBucket}, "local-0": {"mw-" + suffix}, "owner-0": {admin.Name}})
	if !strings.Contains(body, "Mirroring 1 bucket: mw-"+suffix) {
		t.Fatalf("after mirroring the row ticked:\n%s", body)
	}
	if body := get("/admin?section=mirrors"); !strings.Contains(body, "Web "+suffix) || !strings.Contains(body, "mw-"+suffix) {
		t.Fatalf("the mirrors' list:\n%s", body)
	}
	if body := post("/admin/server/run", url.Values{"id": {id}}); !strings.Contains(body, "Queued a pass of 1 mirror") || !strings.Contains(body, "pass queued") {
		t.Fatalf("after running a pass of each:\n%s", body)
	}
	if body := post("/admin/server/freeze", url.Values{"id": {id}}); !strings.Contains(body, "Confirm that writes") {
		t.Fatalf("freezing without saying writes stopped:\n%s", body)
	}
}
