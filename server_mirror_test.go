package main

import (
	"strings"
	"testing"
)

// The review table's rows: a new bucket, an empty one here (used as it is,
// keeping its owner), a name taken here, one another mirror copies into,
// one mirrored from the server elsewhere, and a name that can't be a bucket
// here.
func TestPlanRow(t *testing.T) {
	owners := map[string]string{"reports": "bob", "shared": "alice", "busy": "alice", "orphan": ""}
	into := map[string]bool{"busy": true}
	elsewhere := map[string]string{"website": "website-old"}
	empty := func(b string) bool { return b == "reports" || b == "busy" || b == "orphan" }
	for src, want := range map[string]struct {
		status, local, owner string
		include              bool
	}{
		"invoices":    {RowReady, "invoices", "alice", true},
		"reports":     {RowExistsEmpty, "reports", "bob", true},
		"shared":      {RowClash, "shared", "alice", false},
		"busy":        {RowClash, "busy", "alice", false},
		"orphan":      {RowClash, "orphan", "alice", false}, // empty, but nobody the portal knows owns it
		"website":     {RowElsewhere, "website-old", "alice", false},
		"Legacy_Data": {RowInvalid, "legacy-data", "alice", false},
	} {
		r := planRow(src, "alice", owners, into, elsewhere, "https://minio.example.internal/", empty)
		if r.Status != want.status || r.Local != want.local || r.Owner != want.owner || r.Include != want.include || r.Note == "" {
			t.Errorf("%s: %+v, want %+v", src, r, want)
		}
	}
}

func TestSuggestBucketName(t *testing.T) {
	for in, want := range map[string]string{
		"Legacy_Data":            "legacy-data",
		"a":                      "a-0",
		"..x..":                  "x-0",
		"Photos 2024 (Final)":    "photos-2024-final",
		strings.Repeat("ab", 40): strings.Repeat("ab", 31) + "a",
	} {
		got := suggestBucketName(in)
		if got != want || !bucketRe.MatchString(got) {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestServerID(t *testing.T) {
	store, _ := OpenStore(t.TempDir() + "/state.json")
	p := &Portal{store: store}
	if id := p.serverID("Old MinIO (prod)"); id != "old-minio-prod" {
		t.Errorf("id %q", id)
	}
	if err := store.PutServer(&ServerMirror{ID: "old-minio-prod"}); err != nil {
		t.Fatal(err)
	}
	if id := p.serverID("old minio prod"); id != "old-minio-prod-2" {
		t.Errorf("a second's id %q", id)
	}
	if id := p.serverID("!!!"); id != "server" {
		t.Errorf("a name without letters' id %q", id)
	}
}
