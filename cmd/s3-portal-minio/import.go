package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/wrouesnel/versity-s3-portal/internal/minioiam"
)

var levels = map[string]bool{"read": true, "readwrite": true, "writeonly": true, "createonly": true}

func importCmd(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	var m minioFlags
	m.register(fs)
	planPath := fs.String("plan", "", "the plan, as plan wrote it and you reviewed it")
	portal := fs.String("portal", "", "the portal's URL, as https://s3.example.internal/")
	tokenFile := fs.String("token-file", "", "a file holding an admin's API token for the portal (the admin page's API tokens); else $S3_PORTAL_TOKEN")
	caFile := fs.String("ca-file", "", "CA certificates (PEM) to trust for the portal, besides the system's")
	apply := fs.Bool("apply", false, "import the keys; without it, check the plan and the portal and show what would be done")
	fs.Parse(args)
	if *planPath == "" || *portal == "" {
		return errors.New("--plan and --portal are needed")
	}
	raw, err := os.ReadFile(*planPath)
	if err != nil {
		return err
	}
	var plan minioiam.Plan
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&plan); err != nil {
		return fmt.Errorf("%s: %w", *planPath, err)
	}
	token := os.Getenv("S3_PORTAL_TOKEN")
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		return errors.New("give --token-file, or S3_PORTAL_TOKEN: an admin's API token from the portal's admin page")
	}
	iam, _, err := m.load()
	if err != nil {
		return err
	}
	client, err := httpClient(*caFile, "")
	if err != nil {
		return err
	}
	api := &portalAPI{base: strings.TrimRight(*portal, "/"), token: token, http: client}
	ctx := context.Background()

	type job struct {
		key            minioiam.PlanKey
		owner          string
		grants         map[string]string
		secret, reason string
	}
	var jobs []job
	owners := map[string]bool{}
	for _, k := range plan.Keys {
		if !k.Import {
			continue
		}
		j := job{key: k, owner: plan.OwnerOf(k), grants: map[string]string{}}
		id := iam.ServiceAccounts[k.AccessKey]
		if k.Kind == "user" {
			id = iam.Users[k.AccessKey]
		}
		var bad []string
		switch {
		case id == nil:
			bad = append(bad, "not in MinIO's records")
		case !id.Enabled():
			bad = append(bad, "disabled in MinIO")
		default:
			j.secret = id.SecretKey
		}
		if j.owner == "" {
			bad = append(bad, "no owner")
		}
		if len(k.Grants) == 0 {
			bad = append(bad, "no grants")
		}
		for b, l := range k.Grants {
			to, ok := plan.Buckets[b]
			switch {
			case !levels[l]:
				bad = append(bad, fmt.Sprintf("%s: %q isn't a level (read, readwrite, writeonly, createonly)", b, l))
			case !ok:
				bad = append(bad, b+" isn't in buckets")
			case to == "":
				bad = append(bad, b+" wasn't moved (buckets maps it to \"\"): take its grant out")
			default:
				j.grants[to] = l
			}
		}
		sort.Strings(bad)
		j.reason = strings.Join(bad, "; ")
		if j.reason == "" {
			owners[j.owner] = true
		}
		jobs = append(jobs, j)
	}

	// The owners: the directory must let each use the service.
	ownerProblem := map[string]string{}
	for o := range owners {
		var st struct {
			Known, Allowed bool
			Reason         string
		}
		if err := api.call(ctx, http.MethodGet, "/api/users/"+url.PathEscape(o)+"/directory", nil, &st); err != nil {
			ownerProblem[o] = err.Error()
		} else if !st.Allowed {
			ownerProblem[o] = "the directory doesn't let them use the service: " + st.Reason
		}
	}

	fails := 0
	for _, j := range jobs {
		k := j.key
		grants := describe(j.grants)
		if j.reason == "" && ownerProblem[j.owner] != "" {
			j.reason = j.owner + ": " + ownerProblem[j.owner]
		}
		if j.reason != "" {
			fails++
			fmt.Printf("[FAIL] %s (owner %s): %s\n", k.AccessKey, j.owner, j.reason)
			continue
		}
		if !*apply {
			fmt.Printf("[ OK ] %s would be imported for %s: %s, labelled %q\n", k.AccessKey, j.owner, grants, k.Label)
			continue
		}
		if err := api.call(ctx, http.MethodPost, "/api/users/"+url.PathEscape(j.owner)+"/register", nil, nil); err != nil {
			fails++
			fmt.Printf("[FAIL] %s: registering %s: %v\n", k.AccessKey, j.owner, err)
			continue
		}
		var res struct {
			Existing bool `json:"existing"`
		}
		err := api.call(ctx, http.MethodPost, "/api/keys", map[string]any{
			"owner": j.owner, "label": k.Label, "buckets": j.grants, "access_key": k.AccessKey, "secret_key": j.secret,
		}, &res)
		switch {
		case err != nil:
			fails++
			fmt.Printf("[FAIL] %s: %v\n", k.AccessKey, err)
		case res.Existing:
			fmt.Printf("[ OK ] %s was imported for %s already\n", k.AccessKey, j.owner)
		default:
			fmt.Printf("[ OK ] %s imported for %s: %s\n", k.AccessKey, j.owner, grants)
		}
	}
	skipped := len(plan.Keys) - len(jobs)
	fmt.Printf("\n%d keys to import, %d failed; %d not to import (import: false in the plan).\n", len(jobs), fails, skipped)
	if !*apply && fails == 0 {
		fmt.Println("Nothing was changed: give --apply to import them.")
	}
	if fails > 0 {
		return failed{fails}
	}
	return nil
}

func describe(grants map[string]string) string {
	var out []string
	for b, l := range grants {
		out = append(out, b+"="+l)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// portalAPI calls the portal's admin API with an API token.
type portalAPI struct {
	base, token string
	http        *http.Client
}

func (a *portalAPI) call(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return fmt.Errorf("the portal: %s", e.Error)
		}
		return fmt.Errorf("the portal answered %s: %.200s", resp.Status, b)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// httpClient trusts the system's CAs and caFile's, and connects to address
// (host or host:port) instead of each URL's host, if given.
func httpClient(caFile, address string) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	roots, err := rootCAs(caFile)
	if err != nil {
		return nil, err
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if address != "" {
		tr.DialContext = dialTo(address)
	}
	return &http.Client{Transport: tr, Timeout: time.Minute}, nil
}

func rootCAs(caFile string) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificates in it", caFile)
		}
	}
	return roots, nil
}
