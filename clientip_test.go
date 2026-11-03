package main

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	proxies, err := ParseTrustedProxies("10.89.40.10, 172.16.0.0/12 ::ffff:192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTrustedProxies("10.0.0.0/8,proxy.example.com"); err == nil {
		t.Error("a host name is accepted")
	}
	if p, err := ParseTrustedProxies(""); err != nil || p != nil {
		t.Errorf("empty: %v %v", p, err)
	}
	for _, c := range []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"direct", "203.0.113.5:4000", nil, "203.0.113.5"},
		{"untrusted peer's header is ignored", "203.0.113.5:4000", []string{"198.51.100.1"}, "203.0.113.5"},
		{"through the proxy", "10.89.40.10:5000", []string{"198.51.100.1"}, "198.51.100.1"},
		{"a made-up hop to the left is ignored", "10.89.40.10:5000", []string{"1.2.3.4, 198.51.100.1"}, "198.51.100.1"},
		{"trusted hops are skipped", "10.89.40.10:5000", []string{"198.51.100.1, 172.20.0.3"}, "198.51.100.1"},
		{"several headers read as one list", "10.89.40.10:5000", []string{"1.2.3.4", "198.51.100.1"}, "198.51.100.1"},
		{"no header", "10.89.40.10:5000", nil, "10.89.40.10"},
		{"garbage", "10.89.40.10:5000", []string{"not an address"}, "10.89.40.10"},
		{"garbage left of a trusted hop", "10.89.40.10:5000", []string{"junk, 172.20.0.3"}, "172.20.0.3"},
		{"ipv6 client", "10.89.40.10:5000", []string{"2001:db8::1"}, "2001:db8::1"},
		{"mapped proxy", "[::ffff:10.89.40.10]:5000", []string{"198.51.100.1"}, "198.51.100.1"},
		{"mapped client", "10.89.40.10:5000", []string{"::ffff:198.51.100.1"}, "198.51.100.1"},
		{"all trusted", "10.89.40.10:5000", []string{"172.20.0.3"}, "172.20.0.3"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := clientIP(proxies, r); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
	// Nothing trusted: always the peer.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.89.40.10:5000"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	if got := clientIP(nil, r); got != "10.89.40.10" {
		t.Errorf("no trusted proxies: %s", got)
	}
}
