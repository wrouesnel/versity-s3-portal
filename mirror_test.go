package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestUncopyable(t *testing.T) {
	for key, bad := range map[string]bool{
		"a/b.txt":                       false,
		"folder/":                       false,
		"é (1).txt":                     false,
		"/abs":                          true,
		"a//b":                          true,
		".zfs/snapshot/x":               true,
		".zfsx":                         false,
		"a/./b":                         true,
		"../up":                         true,
		strings.Repeat("x", 256):        true,
		"d/" + strings.Repeat("x", 255): false,
	} {
		if got := uncopyable(key) != ""; got != bad {
			t.Errorf("uncopyable(%q) = %v, want %v", key, got, bad)
		}
	}
}

func TestMirrorLoc(t *testing.T) {
	v := NewVGW("https://s3.example.com", "", "us-east-1", "a", "s")
	if e, p := v.loc("bk", "a b/c"); e != "https://s3.example.com" || p != "/bk/a%20b/c" {
		t.Errorf("path style: %s %s", e, p)
	}
	v.Virtual = true
	if e, p := v.loc("bk", "a b/c"); e != "https://bk.s3.example.com" || p != "/a%20b/c" {
		t.Errorf("virtual: %s %s", e, p)
	}
	if e, p := v.loc("bk", ""); e != "https://bk.s3.example.com" || p != "/" {
		t.Errorf("virtual bucket: %s %s", e, p)
	}
}

func TestSortedRefusesDisorder(t *testing.T) {
	batches := [][]string{{"a", "c"}, {"b"}}
	s := newSorted("test", func(k string) string { return k }, func() ([]string, bool, error) {
		b := batches[0]
		batches = batches[1:]
		return b, len(batches) > 0, nil
	})
	var got []string
	for {
		k, ok := s.peek()
		if !ok {
			break
		}
		s.pop()
		got = append(got, k)
	}
	if s.err == nil || !strings.Contains(s.err.Error(), "out of order") {
		t.Fatalf("read %v with err %v", got, s.err)
	}
}

func TestRateLimit(t *testing.T) {
	l := newRateLimit(1e6)
	start := time.Now()
	for range 5 {
		l.wait(context.Background(), 100_000)
	}
	// Four waits of 0.1s after the first, which goes at once.
	if d := time.Since(start); d < 350*time.Millisecond || d > 2*time.Second {
		t.Fatalf("5 x 100 kB at 1 MB/s took %v", d)
	}
}

func TestMirrorStates(t *testing.T) {
	m := &Mirror{}
	m.setState(MirrorRegistered, "admin", "")
	m.setState(MirrorSyncing, "portal", "")
	m.setState(MirrorSyncing, "portal", "")
	if len(m.History) != 2 || !m.Active() || !m.syncing() {
		t.Fatalf("history %+v", m.History)
	}
	s := PassSummary{Uncopyable: 2, UncopyableSum: "x"}
	if s.Clean(nil) || !s.Clean(&UncopyableAcceptance{Sum: "x"}) || s.Clean(&UncopyableAcceptance{Sum: "y"}) {
		t.Fatal("acceptance of keys that can't be copied")
	}
}
