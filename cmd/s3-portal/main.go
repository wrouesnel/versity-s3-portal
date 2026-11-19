// s3-portal logs in to versity-s3-portal from the command line: it gets a key, approved
// in the browser, which reaches the buckets you can, for some hours, and sets up the aws
// CLI, rclone and mc to use it. Several portals live side by side, each by name.
//
//	s3-portal login [PORTAL] [--name NAME] [--default] [--lifetime 12h] [--bucket NAME[=LEVEL]]... [--no-browser]
//	s3-portal logout [PORTAL]
//	s3-portal default [NAME]
//	s3-portal status
//	s3-portal credentials NAME
//
// See docs/design-expiring-keys.md.
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
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
)

const usage = `usage: s3-portal <command> [PORTAL] [flags]

  login [PORTAL]     log in: approve it in the browser, then aws, rclone and mc are set up
  logout [PORTAL]    revoke the portal's key, and remove what login set up
  default [NAME]     show the default portal, or make NAME it
  status             the portals logged in to, and until when
  credentials NAME   the key, for aws's credential_process

PORTAL is a portal's URL (https://s3.example.internal), or the name of one logged in to
before. Left out, it's S3_PORTAL if set, else the default: the first portal logged in to,
until "s3-portal default NAME" changes it. Each command says which it used.

Run "s3-portal <command> -h" for a command's flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"login": loginCmd, "logout": logoutCmd, "default": defaultCmd, "status": statusCmd, "credentials": credentialsCmd,
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		if os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
			fmt.Print(usage)
			return
		}
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := cmd(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "s3-portal:", err)
		os.Exit(1)
	}
}

// parse parses flags anywhere among args, and returns the positional ones.
func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		fs.Parse(args)
		rest := fs.Args()
		if len(rest) == 0 {
			return pos
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

type bucketFlags map[string]string

func (b bucketFlags) String() string { return "" }
func (b bucketFlags) Set(v string) error {
	name, level, _ := strings.Cut(v, "=")
	if level == "" {
		level = "readwrite"
	}
	switch level {
	case "read", "readwrite", "writeonly", "createonly":
	default:
		return fmt.Errorf("%q isn't a level: read, readwrite, writeonly or createonly", level)
	}
	b[name] = level
	return nil
}

func loginCmd(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	name := fs.String("name", "", "the portal's name here, and of its aws profile, rclone remote and mc alias (default: its URL's first label)")
	makeDefault := fs.Bool("default", false, "make this portal the default (the first one logged in to is anyway)")
	lifetime := fs.String("lifetime", "", "how long the key lasts, as 12h, 7d or 2w (default: the portal's login default), up to the portal's most")
	buckets := bucketFlags{}
	fs.Var(buckets, "bucket", "limit the key to a bucket, as NAME or NAME=LEVEL (read, readwrite, writeonly, createonly); repeat for more (default: everything you can reach)")
	noBrowser := fs.Bool("no-browser", false, "don't open a browser: print the link, to open anywhere")
	caFile := fs.String("ca-file", "", "CA certificates (PEM) to trust for the portal, besides the system's; remembered for it")
	noAWS := fs.Bool("no-aws", false, "don't set up an aws profile")
	noRclone := fs.Bool("no-rclone", false, "don't set up an rclone remote")
	noMC := fs.Bool("no-mc", false, "don't set up an mc alias")
	pos := parse(fs, args)
	if len(pos) > 1 {
		return errors.New("give one PORTAL")
	}
	ps, err := loadPortals()
	if err != nil {
		return err
	}

	var pname string
	var p *Portal
	switch {
	case len(pos) == 1 && isURL(pos[0]):
		u, err := normalizeURL(pos[0])
		if err != nil {
			return err
		}
		pname = *name
		for n, known := range ps.Portals {
			if known.URL == u && pname == "" {
				pname = n
			}
		}
		if pname == "" {
			pname = nameOf(u)
		}
		if !validName(pname) {
			return fmt.Errorf("%q isn't a name: letters, digits, - and _", pname)
		}
		if known := ps.Portals[pname]; known != nil && known.URL != u {
			return fmt.Errorf("%s is %s already: give this one another --name", pname, known.URL)
		}
		if ps.Portals[pname] == nil {
			ps.Portals[pname] = &Portal{URL: u}
		}
		p = ps.Portals[pname]
	case len(pos) == 1:
		if pname, err = ps.find(pos[0]); err != nil {
			return err
		}
		p = ps.Portals[pname]
	default:
		if pname, err = ps.pick(); err != nil {
			return err
		}
		p = ps.Portals[pname]
	}
	if *caFile != "" {
		p.CAFile = *caFile
	}
	client, err := httpClient(p.CAFile)
	if err != nil {
		return err
	}

	computer, _ := os.Hostname()
	var start struct {
		Code              string `json:"code"`
		VerifyURLComplete string `json:"verify_url_complete"`
		PollToken         string `json:"poll_token"`
		Interval          int    `json:"interval"`
		ExpiresIn         int    `json:"expires_in"`
	}
	req := map[string]any{"computer": computer, "lifetime": *lifetime}
	if len(buckets) > 0 {
		req["buckets"] = buckets
	}
	if err := call(client, p.URL+"/api/login/start", req, &start, nil); err != nil {
		return err
	}
	fmt.Printf("Logging in to %s (%s).\n\n", pname, p.URL)
	fmt.Printf("  Code: %s\n\n", start.Code)
	opened := !*noBrowser && openBrowser(start.VerifyURLComplete)
	if opened {
		fmt.Printf("Approve it in your browser, which is opening %s.\n", start.VerifyURLComplete)
	} else {
		fmt.Printf("Open %s in a browser, signed in to the portal, and approve the code.\n", start.VerifyURLComplete)
	}
	fmt.Printf("Waiting (the code lasts %d minutes; Ctrl-C to stop)...\n", start.ExpiresIn/60)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	interval := time.Duration(max(start.Interval, 1)) * time.Second
	var got struct {
		State       string    `json:"state"`
		User        string    `json:"user"`
		AccessKey   string    `json:"access_key"`
		SecretKey   string    `json:"secret_key"`
		Endpoint    string    `json:"endpoint"`
		Region      string    `json:"region"`
		LogoutToken string    `json:"logout_token"`
		Expires     time.Time `json:"expires"`
	}
	for {
		select {
		case <-ctx.Done():
			return errors.New("stopped before the code was approved")
		case <-time.After(interval):
		}
		var status int
		if err := call(client, p.URL+"/api/login/poll", map[string]string{"poll_token": start.PollToken}, &got, &status); err != nil && status == 0 {
			return err
		}
		if got.State == "approved" {
			break
		}
		if got.State == "denied" {
			return errors.New("the login was denied in the browser")
		}
		if got.State == "expired" {
			return errors.New("the code expired before it was approved: run s3-portal login again")
		}
	}

	// A key from before is revoked: this one replaces it.
	if old, err := loadCreds(pname); err == nil && old.LogoutToken != "" && old.AccessKey != got.AccessKey {
		_ = call(client, p.URL+"/api/login/logout", map[string]string{"access_key": old.AccessKey, "logout_token": old.LogoutToken}, nil, nil)
	}
	c := &Credentials{User: got.User, AccessKey: got.AccessKey, SecretKey: got.SecretKey, Expires: got.Expires,
		Endpoint: got.Endpoint, Region: got.Region, LogoutToken: got.LogoutToken}
	if err := saveCreds(pname, c); err != nil {
		return err
	}
	p.Tools = setupTools(pname, p, c, map[string]bool{"aws": *noAWS, "rclone": *noRclone, "mc": *noMC})
	if ps.Default == "" || *makeDefault {
		ps.Default = pname
	}
	if err := ps.save(); err != nil {
		return err
	}
	where, _ := credsPath(pname)
	fmt.Printf("\nLogged in to %s as %s until %s (%s).\n", pname, c.User, c.Expires.Local().Format("Mon 2 Jan 15:04"), left(c.Expires))
	fmt.Printf("The key is in %s.\n", where)
	for _, t := range p.Tools {
		switch t {
		case "aws":
			fmt.Printf("  aws:    aws --profile %s s3 ls s3://BUCKET/\n", pname)
		case "rclone":
			fmt.Printf("  rclone: rclone lsf %s:BUCKET\n", pname)
		case "mc":
			fmt.Printf("  mc:     mc ls %s/BUCKET\n", pname)
		}
	}
	fmt.Println("  (Name the bucket: a key lists no buckets of its own.)")
	if r := os.Getenv("AWS_REGION"); r != "" && r != c.Region && slices.Contains(p.Tools, "mc") {
		fmt.Fprintf(os.Stderr, "note: AWS_REGION=%s is set here, and mc signs for it rather than the portal's %s, which the portal refuses: "+
			"unset it for mc, or run AWS_REGION=%s mc ...\n", r, c.Region, c.Region)
	}
	if ps.Default == pname {
		fmt.Printf("%s is the default portal.\n", pname)
	} else {
		fmt.Printf("The default portal is %s: s3-portal default %s makes this one it.\n", ps.Default, pname)
	}
	return nil
}

// left is how long until t, roughly.
func left(t time.Time) string {
	d := time.Until(t)
	switch {
	case d <= 0:
		return "expired"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes())+1)
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()+0.5))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24+0.5))
}

// target is the portal a command names, or picks without PORTAL.
func target(ps *Portals, pos []string) (string, error) {
	switch len(pos) {
	case 0:
		return ps.pick()
	case 1:
		return ps.find(pos[0])
	}
	return "", errors.New("give one PORTAL")
}

func logoutCmd(args []string) error {
	fs := flag.NewFlagSet("logout", flag.ExitOnError)
	pos := parse(fs, args)
	ps, err := loadPortals()
	if err != nil {
		return err
	}
	name, err := target(ps, pos)
	if err != nil {
		return err
	}
	p := ps.Portals[name]
	if c, err := loadCreds(name); err == nil && c.LogoutToken != "" {
		client, err := httpClient(p.CAFile)
		if err != nil {
			return err
		}
		if err := call(client, p.URL+"/api/login/logout", map[string]string{"access_key": c.AccessKey, "logout_token": c.LogoutToken}, nil, nil); err != nil {
			return fmt.Errorf("revoking the key: %w (run logout again, or revoke it on the portal's Access keys page)", err)
		}
	}
	removeTools(name, p)
	if path, err := credsPath(name); err == nil {
		os.Remove(path)
	}
	delete(ps.Portals, name)
	if ps.Default == name {
		ps.Default = ""
	}
	if err := ps.save(); err != nil {
		return err
	}
	fmt.Printf("Logged out of %s: its key is revoked, and its aws profile, rclone remote and mc alias removed.\n", name)
	if ps.Default == "" && len(ps.Portals) > 0 {
		fmt.Printf("There's no default portal now: s3-portal default NAME sets one (%s).\n", strings.Join(ps.names(), ", "))
	}
	return nil
}

func defaultCmd(args []string) error {
	fs := flag.NewFlagSet("default", flag.ExitOnError)
	pos := parse(fs, args)
	ps, err := loadPortals()
	if err != nil {
		return err
	}
	where, _ := portalsPath()
	if len(pos) == 0 {
		if env := os.Getenv("S3_PORTAL"); env != "" {
			fmt.Printf("S3_PORTAL=%s overrides the default here.\n", env)
		}
		if ps.Default == "" {
			fmt.Printf("No default portal (in %s). Known: %s.\n", where, strings.Join(ps.names(), ", "))
			return nil
		}
		fmt.Printf("%s (%s), from %s\n", ps.Default, ps.Portals[ps.Default].URL, where)
		return nil
	}
	name, err := ps.find(pos[0])
	if err != nil {
		return err
	}
	ps.Default = name
	if err := ps.save(); err != nil {
		return err
	}
	fmt.Printf("%s (%s) is the default portal now.\n", name, ps.Portals[name].URL)
	return nil
}

func statusCmd(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	parse(fs, args)
	ps, err := loadPortals()
	if err != nil {
		return err
	}
	if len(ps.Portals) == 0 {
		fmt.Println("Not logged in to any portal: s3-portal login https://PORTAL")
		return nil
	}
	names := ps.names()
	sort.Strings(names)
	for _, n := range names {
		p := ps.Portals[n]
		mark := " "
		if n == ps.Default {
			mark = "*"
		}
		state := "no key: log in again"
		if c, err := loadCreds(n); err == nil {
			if time.Now().Before(c.Expires) {
				state = fmt.Sprintf("%s, until %s (%s)", c.User, c.Expires.Local().Format("Mon 2 Jan 15:04"), left(c.Expires))
			} else {
				state = c.User + ", expired: s3-portal login " + n
			}
		}
		fmt.Printf("%s %-12s %-40s %s\n", mark, n, p.URL, state)
	}
	if env := os.Getenv("S3_PORTAL"); env != "" {
		fmt.Printf("S3_PORTAL=%s overrides the default (*) here.\n", env)
	} else if ps.Default != "" {
		fmt.Println("* the default portal: s3-portal default NAME changes it.")
	}
	return nil
}

// credentialsCmd is aws's credential_process: the key as JSON, with its expiry, so the
// aws CLI and SDKs ask again rather than use it once expired.
func credentialsCmd(args []string) error {
	fs := flag.NewFlagSet("credentials", flag.ExitOnError)
	pos := parse(fs, args)
	if len(pos) != 1 {
		return errors.New("give the portal's NAME, as aws's credential_process does")
	}
	c, err := loadCreds(pos[0])
	if err != nil {
		return fmt.Errorf("not logged in to %s: run s3-portal login %s", pos[0], pos[0])
	}
	if !time.Now().Before(c.Expires) {
		return fmt.Errorf("the key for %s expired at %s: run s3-portal login %s", pos[0], c.Expires.Local().Format("Mon 2 Jan 15:04"), pos[0])
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"Version": 1, "AccessKeyId": c.AccessKey, "SecretAccessKey": c.SecretKey, "Expiration": c.Expires.UTC().Format(time.RFC3339),
	})
}

func httpClient(caFile string) (*http.Client, error) {
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
			return nil, fmt.Errorf("%s has no certificates", caFile)
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

// call POSTs body as JSON to u and reads the answer into out. status, if given, is the
// HTTP status, and the answer is read whatever it is.
func call(client *http.Client, u string, body, out any, status *int) error {
	b, _ := json.Marshal(body)
	resp, err := client.Post(u, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if status != nil {
		*status = resp.StatusCode
		if out != nil {
			_ = json.Unmarshal(data, out)
		}
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error string }
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("the portal: %s", e.Error)
		}
		return fmt.Errorf("the portal answered %s (is %s an s3-portal?)", resp.Status, u)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// openBrowser opens u, if there's a display to.
func openBrowser(u string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return false
		}
		cmd = exec.Command("xdg-open", u)
	}
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Start() == nil
}
