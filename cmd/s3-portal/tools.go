package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// Each tool is set up with a profile, remote or alias named for the portal. Only those
// s3-portal made are changed or removed: one of that name made otherwise is left alone,
// with a warning.

// errNotOurs is a tool's entry of the portal's name which s3-portal didn't make.
var errNotOurs = errors.New("not s3-portal's")

func home() string {
	h, _ := os.UserHomeDir()
	return h
}

func awsConfigPath() string {
	if p := os.Getenv("AWS_CONFIG_FILE"); p != "" {
		return p
	}
	return filepath.Join(home(), ".aws", "config")
}

func rcloneConfigPath() string {
	if p := os.Getenv("RCLONE_CONFIG"); p != "" {
		return p
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "rclone", "rclone.conf")
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "rclone", "rclone.conf")
	}
	return filepath.Join(home(), ".config", "rclone", "rclone.conf")
}

func mcConfigPath() string {
	if d := os.Getenv("MC_CONFIG_DIR"); d != "" {
		return filepath.Join(d, "config.json")
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home(), "mc", "config.json")
	}
	return filepath.Join(home(), ".mc", "config.json")
}

// iniSection replaces (or with body nil removes) the section header in an INI file's
// text, if it's absent or ours says it's s3-portal's, keeping everything else as it is.
func iniSection(text, header string, body []string, ours func(lines []string) bool) (string, error) {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if text == "" {
		lines = nil
	}
	start, end := -1, len(lines)
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if start >= 0 && strings.HasPrefix(t, "[") {
			end = i
			break
		}
		if t == header {
			start = i
		}
	}
	var out []string
	if start >= 0 {
		if !ours(lines[start+1 : end]) {
			return text, errNotOurs
		}
		out = append(out, lines[:start]...)
		if body != nil {
			out = append(out, header)
			out = append(out, body...)
		}
		// Keep a blank line between sections.
		rest := lines[end:]
		if body != nil && len(rest) > 0 {
			out = append(out, "")
		}
		for len(rest) > 0 && strings.TrimSpace(rest[0]) == "" {
			rest = rest[1:]
		}
		out = append(out, rest...)
	} else {
		out = lines
		if body != nil {
			if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
				out = append(out, "")
			}
			out = append(out, header)
			out = append(out, body...)
		}
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return "", nil
	}
	return strings.Join(out, "\n") + "\n", nil
}

func editINI(path, header string, body []string, ours func([]string) bool) error {
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	out, err := iniSection(string(b), header, body, ours)
	if err != nil {
		return err
	}
	if out == string(b) {
		return nil
	}
	return writeFile(path, []byte(out), 0o600)
}

func hasLine(lines []string, key, contains string) bool {
	for _, l := range lines {
		k, v, ok := strings.Cut(l, "=")
		if ok && strings.TrimSpace(k) == key && strings.Contains(v, contains) {
			return true
		}
	}
	return false
}

// exe is this program's path, for aws's credential_process.
func exe() string {
	p, err := os.Executable()
	if err != nil {
		return "s3-portal"
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p
}

func awsOurs(lines []string) bool { return hasLine(lines, "credential_process", "s3-portal") }

func setupAWS(name string, c *Credentials) error {
	return editINI(awsConfigPath(), "[profile "+name+"]", []string{
		fmt.Sprintf("credential_process = %q credentials %s", exe(), name),
		"endpoint_url = " + c.Endpoint,
		"region = " + c.Region,
		"s3 =",
		"  addressing_style = path",
	}, awsOurs)
}

func removeAWS(name string) error {
	return editINI(awsConfigPath(), "[profile "+name+"]", nil, awsOurs)
}

const rcloneMark = "s3-portal login"

func rcloneOurs(lines []string) bool { return hasLine(lines, "description", rcloneMark) }

func setupRclone(name string, c *Credentials) error {
	return editINI(rcloneConfigPath(), "["+name+"]", []string{
		"type = s3",
		"provider = Other",
		"env_auth = true",
		"profile = " + name,
		"endpoint = " + c.Endpoint,
		"region = " + c.Region,
		"force_path_style = true",
		"description = " + rcloneMark + ": its key is the aws profile " + name + "'s; run s3-portal login " + name + " when it expires",
	}, rcloneOurs)
}

func removeRclone(name string) error {
	return editINI(rcloneConfigPath(), "["+name+"]", nil, rcloneOurs)
}

// mc keeps aliases in JSON, with the key itself (it has no credential process): each login
// writes the new one. ours is whether s3-portal made the alias before.
func editMC(name string, c *Credentials, ours bool) error {
	path := mcConfigPath()
	cfg := map[string]any{}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &cfg); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	case errors.Is(err, os.ErrNotExist):
		if c == nil {
			return nil
		}
		cfg["version"] = "10"
	default:
		return err
	}
	aliases, _ := cfg["aliases"].(map[string]any)
	if aliases == nil {
		aliases = map[string]any{}
	}
	if _, exists := aliases[name]; exists && !ours {
		return errNotOurs
	}
	if c == nil {
		delete(aliases, name)
	} else {
		aliases[name] = map[string]any{"url": c.Endpoint, "accessKey": c.AccessKey, "secretKey": c.SecretKey, "api": "s3v4", "path": "on"}
	}
	cfg["aliases"] = aliases
	out, _ := json.MarshalIndent(cfg, "", "\t")
	return writeFile(path, append(out, '\n'), 0o600)
}

// setupTools sets up each tool not skipped, and returns those set up. A tool's entry made
// otherwise is left alone, with a warning.
func setupTools(name string, p *Portal, c *Credentials, skip map[string]bool) []string {
	var done []string
	for _, t := range []struct {
		tool, what string
		do         func() error
	}{
		{"aws", "aws profile", func() error { return setupAWS(name, c) }},
		{"rclone", "rclone remote", func() error { return setupRclone(name, c) }},
		{"mc", "mc alias", func() error { return editMC(name, c, slices.Contains(p.Tools, "mc")) }},
	} {
		if skip[t.tool] {
			continue
		}
		err := t.do()
		switch {
		case errors.Is(err, errNotOurs):
			fmt.Fprintf(os.Stderr, "warning: there's an %s %s which s3-portal didn't make: left alone (log in with --name to use another name)\n", t.what, name)
		case err != nil:
			fmt.Fprintf(os.Stderr, "warning: setting up the %s %s: %v\n", t.what, name, err)
		default:
			done = append(done, t.tool)
		}
	}
	return done
}

// removeTools undoes setupTools.
func removeTools(name string, p *Portal) {
	for _, t := range p.Tools {
		var err error
		switch t {
		case "aws":
			err = removeAWS(name)
		case "rclone":
			err = removeRclone(name)
		case "mc":
			err = editMC(name, nil, true)
		}
		if err != nil && !errors.Is(err, errNotOurs) {
			fmt.Fprintf(os.Stderr, "warning: removing %s's %s settings: %v\n", name, t, err)
		}
	}
}
