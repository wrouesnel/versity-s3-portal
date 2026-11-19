package main

import (
	"errors"
	"strings"
	"testing"
)

func TestNameOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://s3.example.internal": "s3", "https://Storage-A.corp/": "storage-a", "https://10.0.0.5": "10-0-0-5", "http://localhost:8080": "localhost",
	} {
		if got := nameOf(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"s3.example.internal": "https://s3.example.internal", "https://s3.example.internal/": "https://s3.example.internal"} {
		if got, err := normalizeURL(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
}

// The default portal: S3_PORTAL, else the one recorded; never a guess.
func TestPick(t *testing.T) {
	ps := &Portals{Portals: map[string]*Portal{"s3": {URL: "https://s3.a"}, "lab": {URL: "https://s3.lab"}}}
	if _, err := ps.pick(); err == nil || !strings.Contains(err.Error(), "lab, s3") {
		t.Errorf("two portals, no default: %v", err)
	}
	ps.Default = "lab"
	if n, err := ps.pick(); err != nil || n != "lab" {
		t.Errorf("the default: %q %v", n, err)
	}
	t.Setenv("S3_PORTAL", "https://s3.a")
	if n, err := ps.pick(); err != nil || n != "s3" {
		t.Errorf("S3_PORTAL by URL: %q %v", n, err)
	}
	t.Setenv("S3_PORTAL", "nope")
	if _, err := ps.pick(); err == nil || !strings.Contains(err.Error(), "S3_PORTAL") {
		t.Errorf("a bad S3_PORTAL: %v", err)
	}
}

// Only s3-portal's own section is replaced or removed; everything else stays.
func TestINISection(t *testing.T) {
	ours := func(lines []string) bool { return hasLine(lines, "credential_process", "s3-portal") }
	text := "[default]\nregion = eu-west-1\n\n[profile other]\nregion = x\n"
	body := []string{`credential_process = "/bin/s3-portal" credentials s3`, "region = us-east-1"}
	out, err := iniSection(text, "[profile s3]", body, ours)
	if err != nil || out != text+"\n[profile s3]\n"+strings.Join(body, "\n")+"\n" {
		t.Fatalf("added: %v\n%s", err, out)
	}
	body2 := []string{`credential_process = "/bin/s3-portal" credentials s3`, "region = ap-southeast-2"}
	out2, err := iniSection(out, "[profile s3]", body2, ours)
	if err != nil || strings.Contains(out2, "us-east-1") || !strings.Contains(out2, "ap-southeast-2") || !strings.HasPrefix(out2, text) {
		t.Fatalf("replaced: %v\n%s", err, out2)
	}
	// In the middle of the file too.
	mid, _ := iniSection("[profile s3]\n"+strings.Join(body, "\n")+"\n\n[profile after]\nregion = y\n", "[profile s3]", body2, ours)
	if !strings.Contains(mid, "ap-southeast-2\n\n[profile after]\nregion = y\n") {
		t.Errorf("replaced mid-file:\n%s", mid)
	}
	if out3, err := iniSection(out2, "[profile s3]", nil, ours); err != nil || out3 != text {
		t.Errorf("removed: %v\n%q", err, out3)
	}
	if _, err := iniSection(text, "[profile other]", body, ours); !errors.Is(err, errNotOurs) {
		t.Errorf("someone else's profile: %v", err)
	}
}
