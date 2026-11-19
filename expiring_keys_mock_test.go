package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExpiringKeysMock renders expiring keys and s3-portal login's pages, with made-up
// data, into MOCK_OUT: to look at before they're built (docs/design-expiring-keys.md).
// Skipped without MOCK_OUT.
func TestExpiringKeysMock(t *testing.T) {
	out := os.Getenv("MOCK_OUT")
	if out == "" {
		t.Skip("MOCK_OUT not set")
	}
	s := NewServer(nil, nil, nil, nil, "", "https://s3.example.internal", "us-east-1")
	now := time.Now().UTC().Truncate(time.Minute)
	at := func(d time.Duration) *time.Time { t := now.Add(d); return &t }
	admin := &User{Name: "wrouesnel", UID: 1000, GID: 1000, Admin: true}
	alice := &User{Name: "alice", UID: 1001, GID: 1001}
	people := []PersonStatus{{User: "alice"}, {User: "bob"}, {User: "wrouesnel", Admin: true}}
	buckets := []BucketSummary{{Name: "alice-projects", Owner: "alice"}, {Name: "app-data", Owner: "alice"}, {Name: "backups", Owner: "bob"}}
	pol := DefaultKeyPolicy

	login := KeyEntry{Access: "VGWLOGINALICE000001", Key: &Key{Owner: "alice", Label: "alice-laptop", Created: now.Add(-3 * time.Hour),
		Expires: at(9 * time.Hour), Login: true, Computer: "alice-laptop"}}
	laptop := KeyEntry{Access: "VGWALICELAPTOP00001", Key: &Key{Owner: "alice", Label: "laptop rclone", Created: now.Add(-60 * day),
		Expires: at(30 * day), Buckets: map[string]Perm{"alice-projects": PermReadWrite}}}
	soon := KeyEntry{Access: "VGWALICEBACKUP00001", Key: &Key{Owner: "alice", Label: "nightly backup", Created: now.Add(-85 * day),
		Expires: at(5 * day), Buckets: map[string]Perm{"app-data": PermRead}}}
	old := KeyEntry{Access: "SVCALICEINHERIT01", Key: &Key{Owner: "alice", Label: "MinIO: backup-bot", Created: now.Add(-2 * day),
		Buckets: map[string]Perm{"app-data": PermReadWrite}, IssuedBy: "wrouesnel"}}
	never := KeyEntry{Access: "VGWBOBARCHIVE000001", Key: &Key{Owner: "bob", Label: "archive appliance", Created: now.Add(-10 * day),
		Buckets: map[string]Perm{"backups": PermWriteOnly}, NeverBy: "wrouesnel"}}
	mine := []KeyEntry{login, laptop, soon, old}
	caps := map[string]map[string]Caps{
		laptop.Access: {"alice-projects": PermReadWrite.Caps()}, soon.Access: {"app-data": PermRead.Caps()}, old.Access: {"app-data": PermReadWrite.Caps()},
	}
	reach := map[string]Perm{"alice-projects": PermReadWrite, "app-data": PermReadWrite, "shared-docs": PermRead}
	cli := func(state string) *CLILoginView {
		return &CLILoginView{State: state, Code: "HXQM-4TRW", Computer: "alice-laptop", From: "10.20.30.41", Asked: now.Add(-40 * time.Second),
			Lifetime: pol.Login, Reach: reach}
	}

	type view struct {
		tmpl string
		p    page
	}
	pages := map[string]view{
		"keys": {"keys.html", page{User: alice, Tab: "keys", Keys: mine, KeyCaps: caps, KeyPolicy: &pol, PortalURL: "https://s3.example.internal"}},
		"key-new": {"key_new.html", page{User: alice, Tab: "keys", Lifetimes: lifetimeChoices(pol, pol.Default, false, false),
			Buckets: []BucketView{{Name: "alice-projects"}, {Name: "app-data"}}}},
		"key-new-admin": {"key_new.html", page{User: admin, Tab: "keys", Lifetimes: lifetimeChoices(pol, pol.Default, true, false),
			Buckets: []BucketView{{Name: "ops"}}}},
		"key-edit": {"key_edit.html", page{User: alice, Tab: "keys", KeyAccess: soon.Access, KeyLabel: soon.Label, KeyExpires: soon.Expires,
			Grants: soon.Buckets, Lifetimes: lifetimeChoices(pol, pol.Default, false, false), Buckets: []BucketView{{Name: "alice-projects"}, {Name: "app-data"}}}},
		"key-created": {"key_created.html", page{User: alice, KeyAccess: laptop.Access, KeySecret: "s3cretS3cretS3cretS3cretS3cretS3cret0000",
			KeyLabel: laptop.Label, Grants: laptop.Buckets, KeyExpires: at(90 * day)}},
		"admin-keys": {"admin.html", page{User: admin, Tab: "admin", Section: "keys", AllKeys: append(mine, never), People: people, NeverCount: 2,
			Lifetimes: lifetimeChoices(pol, pol.Default, true, false)}},
		"admin-lifetimes": {"admin.html", page{User: admin, Tab: "admin", Section: "lifetimes", People: people, KeyPolicy: &pol, NeverCount: 2}},
		"admin-key-new": {"admin.html", page{User: admin, Tab: "admin", Section: "key-new", People: people, AllBuckets: buckets,
			Lifetimes: lifetimeChoices(pol, 30*day, true, false),
			AdminKey:  &AdminKeyForm{Owner: "alice", Buckets: []string{"alice-projects", "app-data"}, Bucket: "app-data", Level: PermReadWrite, Label: "Loading data into app-data"}}},
		"cli-enter":    {"login_cli.html", page{User: alice, CLILogin: &CLILoginView{State: "enter"}}},
		"cli-confirm":  {"login_cli.html", page{User: alice, CLILogin: cli("confirm")}},
		"cli-approved": {"login_cli.html", page{User: alice, CLILogin: cli("approved")}},
		"cli-denied":   {"login_cli.html", page{User: alice, CLILogin: cli("denied")}},
		"cli-expired":  {"login_cli.html", page{User: alice, CLILogin: cli("expired")}},
	}
	if err := os.MkdirAll(filepath.Join(out, "static"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"style.css", "app.js", "early.js", "bucket.svg", "file.svg", "folder.svg", "archive.js"} {
		data, _ := staticFS.ReadFile("static/" + f)
		if err := os.WriteFile(filepath.Join(out, "static", f), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, v := range pages {
		v.p.CSRF, v.p.ZFS = "mock", true
		w := httptest.NewRecorder()
		s.render(w, 200, v.tmpl, v.p)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "</html>") {
			t.Fatalf("%s: %d\n%s", name, w.Code, w.Body.String())
		}
		if err := os.WriteFile(filepath.Join(out, name+".html"), []byte(strings.ReplaceAll(w.Body.String(), s.assetPrefix, "static/")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
