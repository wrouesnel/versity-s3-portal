package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Downloading and deleting a selection, against the scratch gateway.
func TestSelectionAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	alice := User{Name: "alice" + suffix, UID: 1001, GID: 1001}
	bob := User{Name: "bob" + suffix, UID: 1002, GID: 1002}
	enroll(t, p, alice)
	enroll(t, p, bob)
	b := "sel-" + suffix
	ok(t, "create", p.CreateBucket(ctx, alice, b))
	files := map[string]string{
		"top.txt":           "top",
		"in/a.txt":          "a",
		"in/deep/b.txt":     "bb",
		"in/deep/é (1).txt": "accent",
		"other/c.txt":       "c",
	}
	for k, v := range files {
		ok(t, "put "+k, p.PutObject(ctx, alice, b, k, strings.NewReader(v), int64(len(v)), ""))
	}
	ok(t, "folder", p.CreateFolder(ctx, alice, b, "in/", "empty"))

	sel := Selection{Bucket: b, Prefix: "", Keys: []string{"top.txt"}, Folders: []string{"in/"}}
	want := []string{"in/a.txt=a", "in/deep/b.txt=bb", "in/deep/é (1).txt=accent", "in/empty/", "top.txt=top"}

	var buf bytes.Buffer
	_, _, err := p.WriteArchive(ctx, alice, sel, "tar", &buf)
	ok(t, "tar", err)
	var got []string
	tr := tar.NewReader(&buf)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		ok(t, "read tar", err)
		if h.Typeflag == tar.TypeDir {
			got = append(got, h.Name+"/")
			continue
		}
		data, _ := io.ReadAll(tr)
		got = append(got, h.Name+"="+string(data))
	}
	sort.Strings(got)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("tar holds %q, want %q", got, want)
	}

	buf.Reset()
	_, _, err = p.WriteArchive(ctx, alice, sel, "zip", &buf)
	ok(t, "zip", err)
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	ok(t, "read zip", err)
	got = nil
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			got = append(got, f.Name)
			continue
		}
		rc, err := f.Open()
		ok(t, "open "+f.Name, err)
		data, _ := io.ReadAll(rc)
		rc.Close()
		got = append(got, f.Name+"="+string(data))
	}
	sort.Strings(got)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("zip holds %q, want %q", got, want)
	}

	// Inside a folder, names are relative to it.
	buf.Reset()
	_, _, err = p.WriteArchive(ctx, alice, Selection{Bucket: b, Prefix: "in/", Folders: []string{"in/deep/"}}, "tar", &buf)
	ok(t, "tar of subfolder", err)
	tr = tar.NewReader(&buf)
	h, err := tr.Next()
	ok(t, "first entry", err)
	if !strings.HasPrefix(h.Name, "deep/") {
		t.Fatalf("entry %q isn't relative to in/", h.Name)
	}

	// Nothing outside the folder, and nobody without read access.
	userError(t, "key outside prefix", Selection{Bucket: b, Prefix: "in/", Keys: []string{"top.txt"}}.check())
	userError(t, "folder outside prefix", Selection{Bucket: b, Prefix: "in/", Folders: []string{"other/"}}.check())
	userError(t, "climbing key", Selection{Bucket: b, Prefix: "in/", Keys: []string{"/etc/passwd"}}.check())
	userError(t, "empty selection", Selection{Bucket: b}.check())
	_, _, err = p.WriteArchive(ctx, bob, sel, "zip", io.Discard)
	if err == nil {
		t.Fatal("bob archived alice's bucket")
	}
	_, err = p.DeleteSelection(ctx, bob, sel)
	if err == nil {
		t.Fatal("bob deleted from alice's bucket")
	}

	n, err := p.DeleteSelection(ctx, alice, sel)
	ok(t, "delete selection", err)
	if n != 5 { // top.txt, three files in in/, and in/empty/'s marker
		t.Fatalf("deleted %d objects, want 5", n)
	}
	list, err := p.ListObjects(ctx, alice, b, "", "")
	ok(t, "list after delete", err)
	if strings.Join(list.Prefixes, ",") != "other/" || len(list.Objects) != 0 {
		t.Fatalf("after delete: %+v", list)
	}
}
