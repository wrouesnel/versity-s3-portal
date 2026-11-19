package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Portals are the portals logged in to, by name, and the default one.
type Portals struct {
	Default string             `json:"default,omitempty"`
	Portals map[string]*Portal `json:"portals"`
}

// Portal is one portal: where it is, and which tools' settings were made for it.
type Portal struct {
	URL    string `json:"url"`
	CAFile string `json:"ca_file,omitempty"`
	// Tools are the tools set up for it (aws, rclone, mc), to undo at logout.
	Tools []string `json:"tools,omitempty"`
}

// Credentials are a portal's login key, kept 0600.
type Credentials struct {
	User        string    `json:"user"`
	AccessKey   string    `json:"access_key"`
	SecretKey   string    `json:"secret_key"`
	Expires     time.Time `json:"expires"`
	Endpoint    string    `json:"endpoint"`
	Region      string    `json:"region"`
	LogoutToken string    `json:"logout_token,omitempty"`
}

// configDir is where s3-portal keeps its portals and keys: S3_PORTAL_CONFIG, else the
// system's configuration directory's s3-portal (~/.config/s3-portal on Linux).
func configDir() (string, error) {
	if d := os.Getenv("S3_PORTAL_CONFIG"); d != "" {
		return d, nil
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "s3-portal"), nil
}

func portalsPath() (string, error) {
	d, err := configDir()
	return filepath.Join(d, "portals.json"), err
}

func loadPortals() (*Portals, error) {
	p, err := portalsPath()
	if err != nil {
		return nil, err
	}
	ps := &Portals{Portals: map[string]*Portal{}}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return ps, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, ps); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if ps.Portals == nil {
		ps.Portals = map[string]*Portal{}
	}
	return ps, nil
}

func (ps *Portals) save() error {
	p, err := portalsPath()
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(ps, "", "  ")
	return writeFile(p, append(b, '\n'), 0o600)
}

// writeFile writes a file whole, through a temporary one, making its directory.
func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".s3-portal-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func credsPath(name string) (string, error) {
	d, err := configDir()
	return filepath.Join(d, name+".json"), err
}

func loadCreds(name string) (*Credentials, error) {
	p, err := credsPath(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return &c, nil
}

func saveCreds(name string, c *Credentials) error {
	p, err := credsPath(name)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return writeFile(p, append(b, '\n'), 0o600)
}

// nameOf is the name a portal's URL is given: its host's first label.
func nameOf(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Hostname() == "" {
		return "s3"
	}
	host := parsed.Hostname()
	if first, _, ok := strings.Cut(host, "."); ok && first != "" && !isNumeric(host) {
		return cleanName(first)
	}
	return cleanName(host)
}

func isNumeric(host string) bool {
	return strings.Trim(host, "0123456789.:[]") == ""
}

// cleanName is s as a name every tool takes: letters, digits, - and _.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		}
		return '-'
	}, s)
	if s = strings.Trim(s, "-"); s == "" {
		return "s3"
	}
	return s
}

func validName(s string) bool { return s != "" && cleanName(s) == s }

// normalizeURL is a portal's URL as kept: https:// unless given, without a trailing /.
func normalizeURL(u string) (string, error) {
	if !strings.Contains(u, "://") {
		u = "https://" + u
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return "", fmt.Errorf("%q isn't a portal's URL, as https://s3.example.internal", u)
	}
	return strings.TrimRight(parsed.Scheme+"://"+parsed.Host+parsed.Path, "/"), nil
}

// isURL is whether a PORTAL argument is a URL (or a host name), rather than a name.
func isURL(s string) bool { return strings.Contains(s, "://") || strings.Contains(s, ".") }

// pick is the portal a command without PORTAL uses, and why, said on standard error:
// S3_PORTAL, else the default. With neither, it refuses, listing the portals known.
func (ps *Portals) pick() (string, error) {
	where, _ := portalsPath()
	if env := os.Getenv("S3_PORTAL"); env != "" {
		name, err := ps.find(env)
		if err != nil {
			return "", fmt.Errorf("S3_PORTAL=%s: %w", env, err)
		}
		fmt.Fprintf(os.Stderr, "Using %s (%s): from S3_PORTAL\n", name, ps.Portals[name].URL)
		return name, nil
	}
	if ps.Default != "" && ps.Portals[ps.Default] != nil {
		fmt.Fprintf(os.Stderr, "Using %s (%s): the default, from %s (s3-portal default NAME changes it)\n", ps.Default, ps.Portals[ps.Default].URL, where)
		return ps.Default, nil
	}
	if len(ps.Portals) == 0 {
		return "", errors.New("no portal logged in to yet: run s3-portal login https://PORTAL")
	}
	return "", fmt.Errorf("no default portal: name one of %s, or set one with s3-portal default NAME", strings.Join(ps.names(), ", "))
}

// find is the name of a portal given by name or URL.
func (ps *Portals) find(s string) (string, error) {
	if ps.Portals[s] != nil {
		return s, nil
	}
	if isURL(s) {
		u, err := normalizeURL(s)
		if err != nil {
			return "", err
		}
		for name, p := range ps.Portals {
			if p.URL == u {
				return name, nil
			}
		}
		return "", fmt.Errorf("not logged in to %s: run s3-portal login %s", u, u)
	}
	return "", fmt.Errorf("no portal called %s (known: %s)", s, strings.Join(ps.names(), ", "))
}

func (ps *Portals) names() []string {
	var out []string
	for n := range ps.Portals {
		out = append(out, n)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return []string{"none"}
	}
	return out
}
