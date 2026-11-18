package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// The cut-over check: before DNS moves MinIO's hostname to the portal's
// server, that server must already answer for it, with a certificate for the
// name that clients trust, and take the imported keys signed for the name
// and MinIO's region. After, the name must lead there.

func checkCmd(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	name := fs.String("name", "", "MinIO's hostname, which clients use and DNS will move")
	address := fs.String("address", "", "the portal's server: its address or current name (port 443 unless given)")
	caFile := fs.String("ca-file", "", "CA certificates (PEM) clients trust, besides the system's")
	var m minioFlags
	m.register(fs)
	key := fs.String("key", "", "an imported key's access key ID, to sign a request with (its secret from MinIO's records, with --drive)")
	region := fs.String("region", "", "the region clients sign for (MinIO's, from --drive or --minio-env, else us-east-1)")
	bucket := fs.String("bucket", "", "a bucket the key may read: also list its objects, as clients would")
	after := fs.Bool("after", false, "DNS has moved: check the name leads to the server")
	minDays := fs.Int("min-days", 14, "warn if the certificate expires in fewer days")
	fs.Parse(args)
	if *name == "" || *address == "" {
		return errors.New("--name and --address are needed")
	}
	addr := *address
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	roots, err := rootCAs(*caFile)
	if err != nil {
		return err
	}
	c := &checker{}
	ctx := context.Background()

	// The certificate the server gives for the name.
	leaf := c.cert(ctx, "the server ("+addr+")", addr, *name, roots, *minDays)

	// A request signed with an imported key, for the name.
	secret, reg := "", *region
	if *key != "" {
		if m.drive == "" {
			return errors.New("--key needs --drive, for its secret")
		}
		iam, _, err := m.load()
		if err != nil {
			return err
		}
		id := iam.ServiceAccounts[*key]
		if id == nil {
			id = iam.Users[*key]
		}
		if id == nil {
			return fmt.Errorf("%s isn't in MinIO's records", *key)
		}
		secret = id.SecretKey
		if reg == "" {
			reg = iam.Region
		}
	}
	if reg == "" {
		reg = "us-east-1"
	}
	if *key != "" {
		c.signed(ctx, addr, *name, *key, secret, reg, *bucket, roots)
	} else {
		c.warn("S3: no --key given, so no request was signed with an imported key")
	}

	// DNS.
	host, _, _ := net.SplitHostPort(addr)
	serverIPs := c.lookup(ctx, host)
	nameIPs, err := net.DefaultResolver.LookupHost(ctx, *name)
	switch {
	case err != nil && *after:
		c.fail("DNS: %s doesn't resolve: %v", *name, err)
	case err != nil:
		c.ok("DNS: %s doesn't resolve yet", *name)
	case *after && !subset(nameIPs, serverIPs):
		c.fail("DNS: %s is %s, not the server's %s (or a cache still has the old answer: wait out its TTL)", *name, strings.Join(nameIPs, " "), strings.Join(serverIPs, " "))
	case *after:
		c.ok("DNS: %s is the server's %s", *name, strings.Join(nameIPs, " "))
		// The name's own connection reaches the same server and certificate.
		if got := c.cert(ctx, *name, net.JoinHostPort(*name, "443"), *name, roots, *minDays); leaf != nil && got != nil && !got.Equal(leaf) {
			c.fail("TLS: %s gives another certificate than the server does: something else answers for it", *name)
		}
	case subset(nameIPs, serverIPs):
		c.ok("DNS: %s is already the server's %s", *name, strings.Join(nameIPs, " "))
	default:
		c.ok("DNS: %s is still %s (MinIO); ready to move it to the server's %s, as an A record or a CNAME to its name", *name, strings.Join(nameIPs, " "), strings.Join(serverIPs, " "))
	}

	if c.fails > 0 {
		fmt.Printf("\n%d checks failed: don't move DNS until they pass.\n", c.fails)
		return failed{c.fails}
	}
	if !*after {
		fmt.Printf("\nThe server is ready for %s: move DNS, then run this again with --after.\n", *name)
	}
	return nil
}

type checker struct{ fails int }

func (c *checker) ok(format string, args ...any) { fmt.Printf("[ OK ] "+format+"\n", args...) }
func (c *checker) warn(format string, args ...any) {
	fmt.Printf("[WARN] "+format+"\n", args...)
}

func (c *checker) fail(format string, args ...any) {
	c.fails++
	fmt.Printf("[FAIL] "+format+"\n", args...)
}

// cert connects to addr asking for name, and checks the certificate it gives
// is for name and trusted.
func (c *checker) cert(ctx context.Context, what, addr, name string, roots *x509.CertPool, minDays int) *x509.Certificate {
	d := &tls.Dialer{Config: &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} // verified below, to say what's wrong
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		c.fail("TLS: %s: %v", what, err)
		return nil
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	leaf := certs[0]
	inter := x509.NewCertPool()
	for _, ic := range certs[1:] {
		inter.AddCert(ic)
	}
	desc := fmt.Sprintf("%s's certificate (names %s; from %s; until %s; sha256 %s)", what, strings.Join(leaf.DNSNames, " "),
		leaf.Issuer.CommonName, leaf.NotAfter.UTC().Format("2006-01-02"), fingerprint(leaf)[:16])
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: inter}); err != nil {
		if leaf.VerifyHostname(name) != nil {
			c.fail("TLS: %s isn't for %s: add it to the server's certificate (the deployer's certificate.dns_names) and deploy", desc, name)
		} else {
			c.fail("TLS: %s isn't trusted: %v", desc, err)
		}
		return leaf
	}
	if left := time.Until(leaf.NotAfter); left < time.Duration(minDays)*24*time.Hour {
		c.warn("TLS: %s expires in %d days", desc, int(left.Hours()/24))
	} else {
		c.ok("TLS: %s is for %s, and trusted", desc, name)
	}
	return leaf
}

func fingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

// signed lists buckets (and bucket's objects), signed with the key for the name and region,
// sent to addr.
func (c *checker) signed(ctx context.Context, addr, name, access, secret, region, bucket string, roots *x509.CertPool) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12},
		DialContext:     dialTo(addr),
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	body, ok := c.get(ctx, client, "https://"+name+"/", name, access, secret, region, "listing buckets")
	if !ok {
		return
	}
	var list struct {
		Buckets []struct {
			Name string `xml:"Name"`
		} `xml:"Buckets>Bucket"`
	}
	_ = xml.Unmarshal(body, &list)
	c.ok("S3: %s, signed for %s in %s, is taken (it owns %d buckets itself)", access, name, region, len(list.Buckets))
	if bucket == "" {
		c.warn("S3: no --bucket given, so no bucket was listed with the key")
		return
	}
	body, ok = c.get(ctx, client, "https://"+name+"/"+bucket+"?list-type=2&max-keys=5", name, access, secret, region, "listing "+bucket)
	if !ok {
		return
	}
	var objs struct {
		Keys []string `xml:"Contents>Key"`
	}
	_ = xml.Unmarshal(body, &objs)
	c.ok("S3: %s lists %s: %s", access, bucket, strings.Join(objs.Keys, " "))
}

// get is a GET of u, signed for region, and its body if it's 200.
func (c *checker) get(ctx context.Context, client *http.Client, u, name, access, secret, region, what string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		c.fail("S3: %v", err)
		return nil, false
	}
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	req.Header.Set("X-Amz-Content-Sha256", emptySHA256)
	creds := aws.Credentials{AccessKeyID: access, SecretAccessKey: secret}
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, emptySHA256, "s3", region, time.Now()); err != nil {
		c.fail("S3: signing: %v", err)
		return nil, false
	}
	resp, err := client.Do(req)
	if err != nil {
		c.fail("S3: %s as %s for %s: %v", what, access, name, err)
		return nil, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Code string `xml:"Code"`
		}
		_ = xml.Unmarshal(body, &e)
		hint := ""
		switch e.Code {
		case "InvalidAccessKeyId":
			hint = ": it isn't imported"
		case "SignatureDoesNotMatch":
			hint = ": its secret differs from MinIO's"
		case "AuthorizationHeaderMalformed", "InvalidRegion":
			hint = ": the gateway's region isn't " + region + ", which clients sign for"
		case "AccessDenied":
			hint = ": the key isn't granted it"
		}
		c.fail("S3: %s as %s for %s (region %s): %s %s%s", what, access, name, region, resp.Status, e.Code, hint)
		return nil, false
	}
	return body, true
}

// lookup is host's addresses (host itself, if it's one).
func (c *checker) lookup(ctx context.Context, host string) []string {
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) != nil {
		return []string{host}
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		c.warn("DNS: the server's name %s doesn't resolve: %v", host, err)
	}
	return ips
}

func subset(a, b []string) bool {
	if len(a) == 0 {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// dialTo connects to addr, whatever the request's host.
func dialTo(addr string) func(ctx context.Context, network, _ string) (net.Conn, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
}
