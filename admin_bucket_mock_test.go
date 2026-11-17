package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAdminBucketMock renders an admin making a bucket for someone and
// issuing them a key to load data, with made-up data, into MOCK_OUT: to look
// at before it's built. Skipped without MOCK_OUT.
func TestAdminBucketMock(t *testing.T) {
	out := os.Getenv("MOCK_OUT")
	if out == "" {
		t.Skip("MOCK_OUT not set")
	}
	s := NewServer(nil, nil, nil, nil, "", "https://s3.example.internal", "us-east-1")
	created := time.Date(2026, 11, 16, 14, 30, 0, 0, time.UTC)
	admin := &User{Name: "wrouesnel", UID: 1000, GID: 1000, Admin: true}
	alice := &User{Name: "alice", UID: 1001, GID: 1001}
	people := []PersonStatus{{User: "alice"}, {User: "bob"}, {User: "photos-svc"}, {User: "carol", Disabled: true}, {User: "wrouesnel", Admin: true}}
	buckets := []BucketSummary{
		{Name: "alice-projects", Owner: "alice", Groups: map[string]Perm{"engineering": PermRead}},
		{Name: "app-data", Owner: "alice"},
		{Name: "backups", Owner: "bob"},
	}
	issued := KeyEntry{Access: "AKMIGRATE0123456789", Key: &Key{Owner: "alice", Label: "Loading data into app-data", Created: created,
		Buckets: map[string]Perm{"app-data": PermReadWrite}, IssuedBy: "wrouesnel"}}
	own := KeyEntry{Access: "AKALICELAPTOP000001", Key: &Key{Owner: "alice", Label: "laptop rclone", Created: created.Add(-48 * time.Hour),
		Buckets: map[string]Perm{"alice-projects": PermReadWrite}}}
	caps := map[string]map[string]Caps{
		issued.Access: {"app-data": PermReadWrite.Caps()}, own.Access: {"alice-projects": PermReadWrite.Caps()},
	}
	type view struct {
		tmpl string
		p    page
	}
	pages := map[string]view{
		"admin-buckets": {"admin.html", page{User: admin, Tab: "admin", Section: "buckets", AllBuckets: buckets, People: people, NewBucketOwner: "alice"}},
		"admin-key-new": {"admin.html", page{User: admin, Tab: "admin", Section: "key-new", People: people, AllBuckets: buckets,
			Notice: "Made app-data for alice. To load data into it, issue alice a key for it here.",
			AdminKey: &AdminKeyForm{Owner: "alice", Buckets: []string{"alice-projects", "app-data"}, Bucket: "app-data", Level: PermReadWrite,
				Label: "Loading data into app-data"}}},
		"admin-key-created": {"key_created.html", page{User: admin, KeyAccess: issued.Access, KeySecret: "s3cretS3cretS3cretS3cretS3cretS3cret0000",
			KeyLabel: issued.Label, Grants: issued.Buckets, IssuedFor: "alice"}},
		"admin-keys": {"admin.html", page{User: admin, Tab: "admin", Section: "keys", AllKeys: []KeyEntry{own, issued}, People: people}},
		"alice-keys": {"keys.html", page{User: alice, Tab: "keys", Keys: []KeyEntry{own, issued}, KeyCaps: caps}},
		"admin-tokens": {"admin.html", page{User: admin, Tab: "admin", Section: "tokens", People: people, ServerAPIToken: true, PortalURL: "https://s3.example.internal",
			APITokens: []APITokenView{
				{ID: "a1", Valid: true, APIToken: APIToken{Name: "migrator", Prefix: "s3p_Xy7Qa2", Created: created, By: "wrouesnel", LastUsed: created.Add(3 * time.Hour)}},
				{ID: "b2", Valid: false, Reason: "carol is no longer an admin", APIToken: APIToken{Name: "user-sync", Prefix: "s3p_Lm3Rt9", Created: created.Add(-720 * time.Hour), By: "carol"}},
			}}},
		"admin-token-created": {"admin.html", page{User: admin, Tab: "admin", Section: "token-created", People: people, PortalURL: "https://s3.example.internal",
			NewAPIToken: "s3p_Xy7Qa2mN4pR8sT1uV6wZ0bC3dF5gH9jK2", NewAPITokenName: "migrator"}},
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
		if err := os.WriteFile(filepath.Join(out, name+".html"), []byte(strings.ReplaceAll(w.Body.String(), s.assetPrefix, "static/")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
