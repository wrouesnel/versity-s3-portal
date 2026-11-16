package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeDNS is a resolver from tables.
type fakeDNS struct {
	hosts map[string][]string
	ptr   map[string][]string
	srv   map[string][]string
}

var errNXDomain = errors.New("no such host")

func (f fakeDNS) LookupHost(_ context.Context, h string) ([]string, error) {
	if a, ok := f.hosts[h]; ok {
		return a, nil
	}
	return nil, errNXDomain
}

func (f fakeDNS) LookupAddr(_ context.Context, a string) ([]string, error) {
	if n, ok := f.ptr[a]; ok {
		return n, nil
	}
	return nil, errNXDomain
}

func (f fakeDNS) LookupSRV(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
	var out []*net.SRV
	for _, t := range f.srv["_"+service+"._"+proto+"."+name] {
		out = append(out, &net.SRV{Target: t + ".", Port: 389})
	}
	if len(out) == 0 {
		return "", nil, errNXDomain
	}
	return "", out, nil
}

// tlsCA makes a CA, and a server certificate from it for names.
func tlsCA(t *testing.T, names ...string) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A DC reached by the domain's name, or an address, whose certificate has
// only its own name: taken by the name its address reverses to, when that
// resolves back to it and is one of the domain's DCs; refused otherwise.
func TestLDAPSByReverseName(t *testing.T) {
	roots, cert := tlsCA(t, "dc1.example.test")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); time.Sleep(time.Second); c.Close() }()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	good := fakeDNS{
		hosts: map[string][]string{"example.test": {"127.0.0.1"}, "dc1.example.test": {"127.0.0.1"}},
		ptr:   map[string][]string{"127.0.0.1": {"dc1.example.test."}},
		srv:   map[string][]string{"_ldap._tcp.dc._msdcs.example.test": {"dc1.example.test"}},
	}
	defer func(r resolver) { dnsResolver = r }(dnsResolver)
	a := &LDAPAuth{BaseDN: "DC=example,DC=test"}
	try := func(dns fakeDNS, u string) error {
		t.Helper()
		dnsResolver = dns
		c, err := a.dialURL(u, roots)
		if c != nil {
			c.Close()
		}
		return err
	}
	for _, u := range []string{"ldaps://example.test:" + port, "ldaps://127.0.0.1:" + port} {
		if err := try(good, u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for name, dns := range map[string]fakeDNS{
		// A domain computer's name: its address reverses to it, but it's no DC.
		"not a DC": {hosts: good.hosts, ptr: good.ptr, srv: map[string][]string{"_ldap._tcp.dc._msdcs.example.test": {"dc2.example.test"}}},
		// The reverse name resolves elsewhere.
		"forward mismatch": {hosts: map[string][]string{"example.test": {"127.0.0.1"}, "dc1.example.test": {"192.0.2.9"}}, ptr: good.ptr, srv: good.srv},
		"no reverse":       {hosts: good.hosts, srv: good.srv},
		"no DCs listed":    {hosts: good.hosts, ptr: good.ptr},
	} {
		if err := try(dns, "ldaps://example.test:"+port); err == nil || !strings.Contains(err.Error(), "certificate is valid for") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A certificate the CA didn't sign is never taken, whatever DNS says.
	other, _ := tlsCA(t, "dc1.example.test")
	dnsResolver = good
	if c, err := a.dialURL("ldaps://example.test:"+port, other); err == nil {
		c.Close()
		t.Error("a server whose certificate another CA signed was taken")
	}
	if d := dnDomain("OU=People,DC=Example,DC=Test"); d != "example.test" {
		t.Errorf("dnDomain: %q", d)
	}
}
