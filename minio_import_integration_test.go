package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Moving a MinIO server's keys with s3-portal-minio, the real binary: its
// plan of internal/minioiam/testdata/drive (MinIO's own records), edited as
// an admin would, a dry run, the import over the admin API, and again; then
// the imported keys work with MinIO's secrets, and the cut-over check passes
// for MinIO's name through a proxy which, like s3-tls, keeps the Host.
func TestMinIOImportAgainstGateway(t *testing.T) {
	ctx := context.Background()
	root := testGateway(t)
	dir := t.TempDir()
	tool := filepath.Join(dir, "s3-portal-minio")
	if out, err := exec.Command("go", "build", "-o", tool, "./cmd/s3-portal-minio").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	run := func(args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command(tool, args...)
		cmd.Env = append(os.Environ(), "MINIO_ROOT_USER=rootuser", "MINIO_ROOT_PASSWORD=rootpassword123")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	store, _ := OpenStore(filepath.Join(dir, "state.json"))
	p := NewPortal(root, store)
	ok(t, "reconcile", p.Reconcile(ctx))
	suffix := strings.ToLower(newAccessKey()[3:9])
	alice, dropper := "alice"+suffix, "dropper"+suffix
	p.dir = &fakeDir{entries: map[string]DirEntry{alice: {UID: 1021, GID: 1021}, dropper: {UID: 1022, GID: 1022}}}
	for _, who := range []string{alice, dropper} {
		_, err := p.RegisterFromDirectory(ctx, apiTokenAdmin, who)
		ok(t, "register "+who, err)
	}
	apps, logs, drop := "apps-"+suffix, "logs-"+suffix, "drop-"+suffix
	ok(t, "apps", p.CreateBucketFor(ctx, apiTokenAdmin, alice, apps))
	ok(t, "logs", p.CreateBucketFor(ctx, apiTokenAdmin, alice, logs))
	ok(t, "drop", p.CreateBucketFor(ctx, apiTokenAdmin, dropper, drop))
	srv := NewServer(p, stubAuth{}, nil, testSessions(t, store), "t", root.S3Endpoint, "us-east-1")
	srv.APIToken = "0123456789abcdef0123456789abcdef-token"
	portal := httptest.NewServer(srv.Handler())
	defer portal.Close()
	tokenFile := filepath.Join(dir, "token")
	os.WriteFile(tokenFile, []byte(srv.APIToken+"\n"), 0o600)
	imported := []string{"alice", "SVCALICEINHERIT01", "SVCALICEEMBED0001", "dropper"}
	for _, k := range imported {
		t.Cleanup(func() { root.DeleteAccount(ctx, k) })
	}

	// The plan, and the admin's edits: the portal's names for people and
	// buckets, and alice's keys only on her buckets.
	drive := "internal/minioiam/testdata/drive"
	planPath := filepath.Join(dir, "plan.json")
	out, err := run("plan", "--drive", drive, "--out", planPath)
	if err != nil || !strings.Contains(out, "Region: ap-southeast-2") || !strings.Contains(out, "5 of 9 keys to import") {
		t.Fatalf("plan: %v\n%s", err, out)
	}
	if out, err := run("plan", "--drive", drive, "--out", planPath); err == nil {
		t.Fatalf("plan over an edited plan: %s", out)
	}
	var plan struct {
		Source  string                       `json:"source"`
		Region  string                       `json:"region"`
		Buckets map[string]string            `json:"buckets"`
		Owners  map[string]string            `json:"owners"`
		Keys    []map[string]json.RawMessage `json:"keys"`
	}
	raw, _ := os.ReadFile(planPath)
	if strings.Contains(string(raw), "svcsecret") {
		t.Fatal("a secret is in the plan")
	}
	ok(t, "read the plan", json.Unmarshal(raw, &plan))
	plan.Buckets = map[string]string{"apps": apps, "logs": logs, "drop": drop}
	plan.Owners["alice"], plan.Owners["dropper"] = alice, dropper
	for _, k := range plan.Keys {
		var access string
		json.Unmarshal(k["access_key"], &access)
		switch access {
		case "alice", "SVCALICEINHERIT01":
			k["grants"] = json.RawMessage(`{"apps":"readwrite","logs":"readwrite"}`)
		case "bob":
			k["import"] = json.RawMessage(`false`) // nobody the portal knows
		}
	}
	raw, _ = json.MarshalIndent(plan, "", "  ")
	os.WriteFile(planPath, raw, 0o600)

	importArgs := []string{"import", "--drive", drive, "--plan", planPath, "--portal", portal.URL, "--token-file", tokenFile}
	out, err = run(importArgs...)
	if err != nil || strings.Count(out, "would be imported") != 4 || !strings.Contains(out, "Nothing was changed") {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	if _, ok := store.Get("SVCALICEINHERIT01"); ok {
		t.Fatal("the dry run imported a key")
	}
	out, err = run(append(importArgs, "--apply")...)
	if err != nil || strings.Count(out, " imported for ") != 4 {
		t.Fatalf("import: %v\n%s", err, out)
	}
	if k, _ := store.Get("SVCALICEINHERIT01"); k == nil || k.Owner != alice || k.Label != "MinIO: backup-bot" || k.Buckets[apps] != PermReadWrite {
		t.Fatalf("SVCALICEINHERIT01 as recorded: %+v", k)
	}
	out, err = run(append(importArgs, "--apply")...)
	if err != nil || strings.Count(out, "imported for") != 4 || strings.Count(out, "already") != 4 {
		t.Fatalf("import again: %v\n%s", err, out)
	}

	// MinIO's secrets work, as MinIO allowed.
	backup := as(root, "SVCALICEINHERIT01", "svcsecretaliceinherit01")
	ok(t, "backup-bot writes", putObject(ctx, backup, apps, "nightly.tar", "x"))
	embed := as(root, "SVCALICEEMBED0001", "svcsecretaliceembed0001")
	if got, err := getObject(ctx, embed, apps, "nightly.tar"); err != nil || got != "x" {
		t.Fatalf("the read-only key reads: %q %v", got, err)
	}
	denied(t, "the read-only key writes", putObject(ctx, embed, apps, "no.txt", "x"))
	ok(t, "dropper drops", putObject(ctx, as(root, "dropper", "droppersecret1"), drop, "in.txt", "x"))
	denied(t, "dropper reads", listObjects(ctx, as(root, "dropper", "droppersecret1"), drop))

	// The cut-over check, for MinIO's name, through a TLS proxy keeping the Host.
	const name = "minio.s3-portal.test"
	ca, caPEM := testCA(t)
	caFile := filepath.Join(dir, "ca.pem")
	os.WriteFile(caFile, caPEM, 0o600)
	target, _ := url.Parse(root.S3Endpoint)
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(target)
		r.Out.Host = r.In.Host
	}}
	serve := func(names ...string) string {
		s := httptest.NewUnstartedServer(proxy)
		s.TLS = &tls.Config{Certificates: []tls.Certificate{ca.issue(t, names...)}}
		s.StartTLS()
		t.Cleanup(s.Close)
		return s.Listener.Addr().String()
	}
	addr := serve("s3.s3-portal.test", name)
	check := []string{"check", "--name", name, "--address", addr, "--ca-file", caFile, "--drive", drive, "--key", "SVCALICEINHERIT01", "--bucket", apps}
	// MinIO's region is ap-southeast-2, and the gateway's us-east-1: clients would fail.
	if out, err := run(check...); err == nil || !strings.Contains(out, "region") {
		t.Fatalf("check, signing for MinIO's region: %v\n%s", err, out)
	}
	out, err = run(append(check, "--region", "us-east-1")...)
	if err != nil || !strings.Contains(out, "is for "+name+", and trusted") || !strings.Contains(out, "lists "+apps+": nightly.tar") || strings.Contains(out, "[WARN]") {
		t.Fatalf("check: %v\n%s", err, out)
	}
	if out, err := run("check", "--name", name, "--address", serve("s3.s3-portal.test"), "--ca-file", caFile); err == nil || !strings.Contains(out, "certificate.dns_names") {
		t.Fatalf("check, without the name on the certificate: %v\n%s", err, out)
	}
	if out, err := run("check", "--name", name, "--address", addr); err == nil || !strings.Contains(out, "isn't trusted") {
		t.Fatalf("check, without the CA: %v\n%s", err, out)
	}
	if out, err := run("check", "--name", name, "--address", addr, "--ca-file", caFile, "--after"); err == nil || !strings.Contains(out, "doesn't resolve") {
		t.Fatalf("check --after, DNS not moved: %v\n%s", err, out)
	}
}

type testCertAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func testCA(t *testing.T) (*testCertAuthority, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "s3-portal test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ok(t, "CA", err)
	cert, _ := x509.ParseCertificate(der)
	return &testCertAuthority{cert: cert, key: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (ca *testCertAuthority) issue(t *testing.T, names ...string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		DNSNames: names, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	ok(t, "certificate", err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
