package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestServerMirrorMock renders the server mirror's pages with made-up data
// into MOCK_OUT, as static HTML with the portal's own files beside them,
// to look at before it's built. Skipped without MOCK_OUT.
func TestServerMirrorMock(t *testing.T) {
	out := os.Getenv("MOCK_OUT")
	if out == "" {
		t.Skip("MOCK_OUT not set")
	}
	s := NewServer(nil, nil, nil, nil, "S3 access keys", "https://s3.example.internal", "us-east-1")
	now := time.Date(2026, 11, 16, 14, 30, 0, 0, time.Local)
	admin := &User{Name: "wrouesnel", UID: 1000, GID: 1000, Admin: true}
	people := []PersonStatus{{User: "alice"}, {User: "bob"}, {User: "photos-svc"}, {User: "wrouesnel", Admin: true}}
	src := MirrorSource{Endpoint: "https://minio.old.example.internal", Region: "us-east-1", Access: "migration-ro"}
	pass := func(n int, copied, failed int64, ago time.Duration) PassSummary {
		return PassSummary{N: n, Kind: "scheduled", Started: now.Add(-ago - time.Minute), Finished: now.Add(-ago), Copied: copied, Failed: failed}
	}
	mirror := func(bucket, srcBucket, owner string, state MirrorState, passes ...PassSummary) MirrorView {
		ms := src
		ms.Bucket = srcBucket
		return MirrorView{Mirror: Mirror{Bucket: bucket, Owner: owner, Source: ms, Server: "old-minio", State: state, Passes: passes, Every: "hourly"}, HasSecret: true}
	}
	mirrors := []MirrorView{
		mirror("archive", "archive", "alice", MirrorVerified, pass(9, 0, 0, 20*time.Minute)),
		mirror("backups", "backups", "bob", MirrorSynced, pass(14, 12, 0, 35*time.Minute)),
		mirror("datasets", "datasets", "alice", MirrorSyncing, pass(3, 48211, 2, 50*time.Minute)),
		mirror("photos-old", "photos", "photos-svc", MirrorSyncing),
		mirror("scratch", "scratch", "alice", MirrorAbandoned, pass(2, 10, 0, 26*time.Hour)),
	}
	mirrors[3].Running = &ProgressView{Kind: "scheduled", Phase: "copying", Started: now.Add(-4 * time.Minute), Listed: 9120, Copied: 2311}
	server := ServerView{
		ServerMirror: ServerMirror{ID: "old-minio", Name: "old MinIO", Source: src, DefaultOwner: "alice", Every: "hourly", LimitMBps: 50, Created: now.Add(-72 * time.Hour), By: "wrouesnel"},
		HasSecret:    true,
		Mirrors:      mirrors,
		Listed:       now,
		Active:       4, Syncing: 2, Synced: 1, Verified: 1, Done: 1,
		Rows: []ServerRow{
			{Source: "invoices", Local: "invoices", Status: RowReady, Owner: "alice", Include: true, Note: "A new bucket here."},
			{Source: "logs-2025", Local: "logs-2025", Status: RowReady, Owner: "alice", Include: true, Note: "A new bucket here."},
			{Source: "reports", Local: "reports", Status: RowExistsEmpty, Owner: "bob", Include: true, Note: "reports is here already, empty, and bob's: it's used as it is."},
			{Source: "shared", Local: "shared", Status: RowClash, Owner: "alice", Note: "shared is here already, with things in it: give it another name here."},
			{Source: "Legacy_Data", Local: "legacy-data", Status: RowInvalid, Owner: "alice", Note: "Legacy_Data can't be a bucket name here: legacy-data is offered instead."},
			{Source: "website", Local: "website", Status: RowElsewhere, Owner: "bob", Note: "Already mirrored, from https://minio.old.example.internal/website, as website."},
		},
	}
	summaries := []ServerSummary{{ID: "old-minio", Name: "old MinIO", Endpoint: src.Endpoint, Buckets: 5, Active: 4, Verified: 1, Done: 1}}
	pages := map[string]page{
		"mirrors": {Section: "mirrors", Servers: summaries, Mirrors: mirrors},
		"server-new": {Section: "server-new", ServerForm: &ServerRequest{Name: "old MinIO", DefaultOwner: "alice", Every: "hourly",
			Source: MirrorSource{Region: "us-east-1"}}},
		"server": {Section: "server", Server: &server},
	}
	if err := os.MkdirAll(filepath.Join(out, "static"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"style.css", "app.js", "early.js", "bucket.svg", "file.svg", "folder.svg", "archive.js"} {
		data, err := staticFS.ReadFile("static/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "static", f), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, p := range pages {
		p.User, p.CSRF, p.Tab, p.ZFS, p.People = admin, "mock", "admin", true, people
		w := httptest.NewRecorder()
		s.render(w, 200, "admin.html", p)
		html := strings.ReplaceAll(w.Body.String(), s.assetPrefix, "static/")
		if err := os.WriteFile(filepath.Join(out, name+".html"), []byte(html), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
