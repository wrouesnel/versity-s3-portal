package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ParseTrustedProxies reads TRUSTED_PROXIES: addresses or CIDR prefixes,
// separated by commas or spaces.
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES: %q is neither an address nor a prefix", f)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func trusted(proxies []netip.Prefix, a netip.Addr) bool {
	for _, p := range proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP is the address of whoever sent r, for logs. When r came from a
// trusted proxy, that's the nearest address in X-Forwarded-For that isn't
// a trusted proxy, read from the right: each proxy appends the address it
// got the request from, and anything to the left of the first untrusted
// one may have been made up by the client.
func clientIP(proxies []netip.Prefix, r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !trusted(proxies, peer.Unmap()) {
		return host
	}
	client := peer.Unmap()
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		client = a.Unmap()
		if !trusted(proxies, client) {
			break
		}
	}
	return client.String()
}

func (s *Server) clientIP(r *http.Request) string {
	return clientIP(s.TrustedProxies, r)
}
