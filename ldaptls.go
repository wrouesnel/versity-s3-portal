package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// resolver is the DNS lookups an LDAPS connection to a DC may need; tests
// replace it.
type resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

//nolint:gochecknoglobals // tests replace it
var dnsResolver resolver = net.DefaultResolver

// dialURL connects to one LDAP URL. An ldaps:// URL whose server's
// certificate doesn't have the name it was reached by (an address, or the
// domain's name, which few DCs' certificates have) is tried again by the
// name its address reverses to, if that name forward-resolves to the same
// address and is one of the domain's DCs (its _ldap._tcp.dc._msdcs SRV
// records, which only DCs register): its certificate must then have that
// name, and come from a trusted CA, as always. Any other name the address
// reverses to (a domain computer's, whose own certificate the domain's CA
// issued too) isn't taken: it could otherwise stand in for a DC by
// registering its own records, and be given every password the portal checks.
func (a *LDAPAuth) dialURL(u string, roots *x509.CertPool) (*ldap.Conn, error) {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Scheme != "ldaps" || a.ServerName != "" {
		return ldap.DialURL(u, ldap.DialWithTLSConfig(&tls.Config{ServerName: a.ServerName, RootCAs: roots, MinVersion: tls.VersionTLS12}))
	}
	host, port := parsed.Hostname(), parsed.Port()
	if port == "" {
		port = "636"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs := []string{host}
	if net.ParseIP(host) == nil {
		if addrs, err = dnsResolver.LookupHost(ctx, host); err != nil {
			return nil, fmt.Errorf("LDAP server %s: %w", host, err)
		}
	}
	dial := func(addr, name string) (*ldap.Conn, error) {
		return ldap.DialURL("ldaps://"+net.JoinHostPort(addr, port),
			ldap.DialWithTLSConfig(&tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS12}))
	}
	var dcs map[string]bool
	var errs []error
	for _, addr := range addrs {
		name := host
		if net.ParseIP(host) != nil {
			name = "" // its certificate must have the address
		}
		c, err := dial(addr, name)
		if err == nil {
			return c, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", addr, err))
		if !nameMismatch(err) {
			continue
		}
		if dcs == nil {
			dcs = a.domainControllers(ctx)
		}
		for _, rname := range confirmedNames(ctx, addr) {
			if !dcs[rname] {
				errs = append(errs, fmt.Errorf("%s is %s, which isn't one of the domain's DCs (%s's _ldap._tcp.dc._msdcs SRV records)",
					addr, rname, dnDomain(a.BaseDN)))
				continue
			}
			c, err := dial(addr, rname)
			if err == nil {
				slog.Info("LDAPS to a DC by the name its address has", "url", u, "address", addr, "name", rname)
				return c, nil
			}
			errs = append(errs, fmt.Errorf("%s as %s: %w", addr, rname, err))
		}
	}
	return nil, errors.Join(errs...)
}

// nameMismatch is whether a connection failed on its certificate's name.
func nameMismatch(err error) bool {
	var he x509.HostnameError
	return errors.As(err, &he) || strings.Contains(err.Error(), "certificate is valid for") ||
		strings.Contains(err.Error(), "doesn't contain any IP SANs")
}

// confirmedNames are the names an address reverses to which resolve
// forward to it again.
func confirmedNames(ctx context.Context, addr string) []string {
	names, err := dnsResolver.LookupAddr(ctx, addr)
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		ips, err := dnsResolver.LookupHost(ctx, n)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if net.ParseIP(ip).Equal(net.ParseIP(addr)) {
				out = append(out, n)
				break
			}
		}
	}
	return out
}

// domainControllers are the DCs of the base DN's domain, by name, from its
// _ldap._tcp.dc._msdcs SRV records: none if it has no such records.
func (a *LDAPAuth) domainControllers(ctx context.Context) map[string]bool {
	domain := dnDomain(a.BaseDN)
	if domain == "" {
		return nil
	}
	_, srvs, err := dnsResolver.LookupSRV(ctx, "ldap", "tcp", "dc._msdcs."+domain)
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for _, s := range srvs {
		out[strings.ToLower(strings.TrimSuffix(s.Target, "."))] = true
	}
	return out
}

// dnDomain is a DN's DNS domain, from its DC= parts: example.internal for
// DC=example,DC=internal.
func dnDomain(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return ""
	}
	var parts []string
	for _, rdn := range parsed.RDNs {
		for _, at := range rdn.Attributes {
			if strings.EqualFold(at.Type, "dc") {
				parts = append(parts, at.Value)
			}
		}
	}
	return strings.ToLower(strings.Join(parts, "."))
}
