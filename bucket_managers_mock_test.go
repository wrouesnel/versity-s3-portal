package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBucketManagersMock renders buckets managed by groups, and an admin transferring one,
// with made-up data, into MOCK_OUT: to look at before they're built
// (docs/design-bucket-managers.md). Skipped without MOCK_OUT.
func TestBucketManagersMock(t *testing.T) {
	out := os.Getenv("MOCK_OUT")
	if out == "" {
		t.Skip("MOCK_OUT not set")
	}
	s := NewServer(nil, nil, nil, nil, "", "https://s3.example.internal", "us-east-1")
	admin := &User{Name: "wrouesnel", UID: 1000, GID: 1000, Admin: true}
	alice := &User{Name: "alice", UID: 1001, GID: 1001}
	bob := &User{Name: "bob", UID: 1002, GID: 1002}
	rw, ro := PermReadWrite.Caps(), PermRead.Caps()
	team := BucketView{Name: "platform-data", Owner: "carol", Caps: rw, Via: []string{"platform-team"}, Manage: true, Manager: true, ManagedBy: []string{"platform-team"}}
	bobBuckets := []BucketView{
		{Name: "bob-scratch", Owner: "bob", Caps: rw, Manage: true},
		team,
		{Name: "shared-docs", Owner: "alice", Caps: ro, Via: []string{"engineering"}},
	}
	aliceOpen := BucketView{Name: "alice-projects", Owner: "alice", Caps: rw, Manage: true, ManagedBy: []string{"platform-team"}}
	people := []PersonStatus{
		{User: "alice", Known: true, Source: "ldap", Groups: []string{"engineering"}, Keys: 2},
		{User: "bob", Known: true, Source: "ldap", Groups: []string{"engineering", "platform-team"}, Keys: 1},
		{User: "carol", Known: true, Source: "ldap", Disabled: true, Reason: "not in the directory", Groups: []string{"platform-team"}, Owns: 3},
		{User: "wrouesnel", Known: true, Source: "ldap", Admin: true},
	}
	all := []BucketSummary{
		{Name: "alice-projects", Owner: "alice", Groups: map[string]Perm{"platform-team": PermManage, "engineering": PermRead}},
		{Name: "carol-archive", Owner: "carol"},
		{Name: "platform-data", Owner: "carol", Groups: map[string]Perm{"platform-team": PermManage}},
		{Name: "platform-logs", Owner: "carol", Groups: map[string]Perm{"platform-team": PermRead}},
	}

	type view struct {
		tmpl string
		p    page
	}
	pages := map[string]view{
		"owner-access": {"files.html", page{User: alice, Tab: "files", Buckets: []BucketView{aliceOpen}, Open: &aliceOpen, Settings: true, Section: "access",
			Grantees: map[string]Perm{"platform-team": PermManage, "engineering": PermRead}, GroupList: []string{"engineering", "platform-team", "finance"}}},
		"manager-files": {"files.html", page{User: bob, Tab: "files", Buckets: bobBuckets}},
		"manager-access": {"files.html", page{User: bob, Tab: "files", Buckets: bobBuckets, Open: &team, Settings: true, Section: "access",
			Grantees: map[string]Perm{"platform-team": PermManage}, GroupList: []string{"engineering", "platform-team"}}},
		"admin-people":  {"admin.html", page{User: admin, Tab: "admin", Section: "people", People: people, AllBuckets: all}},
		"admin-buckets": {"admin.html", page{User: admin, Tab: "admin", Section: "buckets", People: people, AllBuckets: all, Filter: "carol"}},
		"admin-transfer": {"admin.html", page{User: admin, Tab: "admin", Section: "bucket-transfer", People: people, AllBuckets: all,
			Transfer: &TransferForm{Bucket: "carol-archive", Owner: "carol", OwnerDisabled: true, OldOwnerKeys: 2}}},
		"admin-transfer-team": {"admin.html", page{User: admin, Tab: "admin", Section: "bucket-transfer", People: people, AllBuckets: all,
			Transfer: &TransferForm{Bucket: "platform-data", Owner: "carol", OwnerDisabled: true, ManagedBy: []string{"platform-team"},
				OldOwnerVia: "manages, via platform-team", OldOwnerKeys: 1}}},
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
		if !strings.Contains(w.Body.String(), "</html>") {
			t.Fatalf("%s:\n%s", name, w.Body.String())
		}
		if err := os.WriteFile(filepath.Join(out, name+".html"), []byte(strings.ReplaceAll(w.Body.String(), s.assetPrefix, "static/")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
