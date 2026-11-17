package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestLiveRefreshInBrowser serves the admin pages with made-up data, the
// mirrors' "last pass" changing on every request, and has a real browser
// (Playwright, testdata/live_refresh.py, run by PLAYWRIGHT_PYTHON) check that
// a page refreshing itself changes only its live parts: no reload, the
// table's sort and filter kept, an open menu left open, typed and ticked
// fields kept; and that moving to another section doesn't snap back.
func TestLiveRefreshInBrowser(t *testing.T) {
	py := os.Getenv("PLAYWRIGHT_PYTHON")
	if py == "" {
		t.Skip("PLAYWRIGHT_PYTHON not set")
	}
	s := NewServer(nil, nil, nil, nil, "", "https://s3.example.internal", "us-east-1")
	admin := &User{Name: "wrouesnel", UID: 1000, GID: 1000, Admin: true}
	people := []PersonStatus{{User: "alice"}, {User: "bob"}, {User: "wrouesnel", Admin: true}}
	var n atomic.Int64
	now := time.Date(2026, 11, 17, 10, 0, 0, 0, time.Local)
	mirrors := func() []MirrorView {
		c := n.Add(1)
		mk := func(bucket, owner string, copied int64) MirrorView {
			return MirrorView{Mirror: Mirror{Bucket: bucket, Owner: owner, Server: "old", State: MirrorSyncing,
				Source: MirrorSource{Endpoint: "https://old.example", Bucket: bucket},
				Passes: []PassSummary{{N: 1, Finished: now, Copied: copied}}}}
		}
		return []MirrorView{mk("alpha", "alice", 100+c), mk("beta", "bob", 200+c), mk("gamma", "alice", 300+c)}
	}
	render := func(w http.ResponseWriter, p page) {
		p.User, p.CSRF, p.Tab, p.People = admin, "x", "admin", people
		rec := httptest.NewRecorder()
		s.render(rec, 200, "admin.html", p)
		// Refresh every second here, not every 10.
		// (And a <meta> refresh, as pages had before data-refresh: so the test
		// catches a page reloading itself, or snapping back, within its waits.)
		html := strings.ReplaceAll(rec.Body.String(), `data-refresh="10"`, `data-refresh="1"`)
		html = strings.ReplaceAll(html, `http-equiv="refresh" content="10"`, `http-equiv="refresh" content="1"`)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, html)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		data, err := staticFS.ReadFile("static/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(name, ".css") {
			w.Header().Set("Content-Type", "text/css")
		} else if strings.HasSuffix(name, ".js") {
			w.Header().Set("Content-Type", "text/javascript")
		}
		w.Write(data)
	})
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("section") {
		case "mirrors":
			ms := mirrors()
			render(w, page{Section: "mirrors", Mirrors: ms, AutoRefresh: true,
				Servers: []ServerSummary{{ID: "old", Name: "old server", Endpoint: "https://old.example", Buckets: len(ms), Active: len(ms)}}})
		default:
			render(w, page{Section: "people"})
		}
	})
	mux.HandleFunc("GET /admin/server", func(w http.ResponseWriter, r *http.Request) {
		ms := mirrors()
		render(w, page{Section: "server", AutoRefresh: true, Server: &ServerView{
			ServerMirror: ServerMirror{ID: "old", Name: "old server", Source: MirrorSource{Endpoint: "https://old.example", Region: "us-east-1"}, DefaultOwner: "alice"},
			HasSecret:    true, Mirrors: ms, Active: len(ms), Syncing: len(ms), Listed: now,
			Rows: []ServerRow{{Source: "delta", Local: "delta", Status: RowReady, Owner: "alice", Include: true, Note: "A new bucket here."}},
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	cmd := exec.Command(py, "testdata/live_refresh.py", srv.URL)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("the browser's checks: %v", err)
	}
}
