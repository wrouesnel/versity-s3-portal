// Package minioiam reads a MinIO server's users, service accounts, groups and
// policies straight from its drive, with their secrets, for moving its access
// keys to versity-s3-portal. MinIO's own export (mc admin cluster iam export)
// isn't in every version, and its admin API never shows secrets; the drive
// has them all. It reads what a single-drive server keeps under
// .minio.sys/config/iam (see xlmeta.go), from the drive or a copy of that
// directory, and never writes to it.
package minioiam

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

// Identity is a user's or service account's credentials, as MinIO keeps
// them (its auth.Credentials).
type Identity struct {
	AccessKey    string    `json:"accessKey"`
	SecretKey    string    `json:"secretKey"`
	SessionToken string    `json:"sessionToken"`
	Expiration   time.Time `json:"expiration"`
	Status       string    `json:"status"`
	ParentUser   string    `json:"parentUser"`
	Groups       []string  `json:"groups"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	// Claims are a service account's, from its session token: its parent,
	// whether it has a policy of its own ("sa-policy": "embedded-policy")
	// and that policy ("sessionPolicy", base64), and an LDAP parent's names.
	Claims map[string]any `json:"-"`
}

// Enabled is whether MinIO lets it be used.
func (i *Identity) Enabled() bool { return i.Status == "" || i.Status == "on" || i.Status == "enabled" }

// Expires is when it expires, if it does (MinIO's zero, or the Unix epoch, is never).
func (i *Identity) Expires() (time.Time, bool) {
	if i.Expiration.IsZero() || i.Expiration.Unix() <= 0 {
		return time.Time{}, false
	}
	return i.Expiration, true
}

func (i *Identity) claim(name string) string {
	s, _ := i.Claims[name].(string)
	return s
}

// EmbeddedPolicy is a service account's own policy, if it has one.
func (i *Identity) EmbeddedPolicy() (*Policy, error) {
	if i.claim("sa-policy") != "embedded-policy" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(i.claim("sessionPolicy"))
	if err != nil {
		return nil, fmt.Errorf("its policy: %w", err)
	}
	return parsePolicy(raw)
}

// Group is a MinIO group of users.
type Group struct {
	Status  string   `json:"status"`
	Members []string `json:"members"`
}

// IAM is what MinIO keeps of its users and their access.
type IAM struct {
	// Users are MinIO's own users, whose access key is their name.
	Users map[string]*Identity
	// ServiceAccounts are keys made for a user (their parent), by access key.
	ServiceAccounts map[string]*Identity
	Groups          map[string]Group
	// Policies are by name, MinIO's built-in ones too.
	Policies map[string]*Policy
	// UserPolicies are MinIO users' policies by name; STSUserPolicies an
	// LDAP user's, by DN; GroupPolicies a group's, by name (or LDAP DN).
	UserPolicies, STSUserPolicies, GroupPolicies map[string][]string
	// Buckets are the drive's buckets, if it was read from the drive.
	Buckets []string
	// Region is the server's region, if it was read from the drive and set.
	Region string
	// Unreadable is each record which couldn't be read, and why.
	Unreadable []string
}

// Load reads the IAM records under dir: a MinIO drive (holding
// .minio.sys), or a copy of its .minio.sys/config/iam. root is MinIO's root
// credentials, "ACCESS:SECRET", needed only for records an older MinIO
// encrypted with them.
func Load(fsys fs.FS, root string) (*IAM, error) {
	iamDir := "."
	fromDrive := false
	if st, err := fs.Stat(fsys, ".minio.sys/config/iam"); err == nil && st.IsDir() {
		iamDir, fromDrive = ".minio.sys/config/iam", true
	} else if !exists(fsys, "users") && !exists(fsys, "service-accounts") && !exists(fsys, "policydb") {
		return nil, errors.New("neither a MinIO drive (with .minio.sys/config/iam) nor a copy of its .minio.sys/config/iam")
	}
	sub, err := fs.Sub(fsys, iamDir)
	if err != nil {
		return nil, err
	}
	l := &loader{fsys: sub, root: root}
	iam := &IAM{
		Users: map[string]*Identity{}, ServiceAccounts: map[string]*Identity{}, Groups: map[string]Group{},
		Policies: builtinPolicies(), UserPolicies: map[string][]string{}, STSUserPolicies: map[string][]string{},
		GroupPolicies: map[string][]string{},
	}
	l.each("users", "identity.json", func(name string, b []byte) error {
		id, err := parseIdentity(b)
		if err == nil {
			iam.Users[name] = id
		}
		return err
	})
	l.each("service-accounts", "identity.json", func(name string, b []byte) error {
		id, err := parseIdentity(b)
		if err == nil {
			iam.ServiceAccounts[name] = id
		}
		return err
	})
	l.each("groups", "members.json", func(name string, b []byte) error {
		var g Group
		err := json.Unmarshal(b, &g)
		iam.Groups[name] = g
		return err
	})
	l.each("policies", "policy.json", func(name string, b []byte) error {
		p, err := parsePolicy(b)
		if err == nil {
			iam.Policies[name] = p
		}
		return err
	})
	for dir, m := range map[string]map[string][]string{
		"policydb/users": iam.UserPolicies, "policydb/sts-users": iam.STSUserPolicies, "policydb/groups": iam.GroupPolicies,
	} {
		l.eachFile(dir, func(name string, b []byte) error {
			var mp struct {
				Policy string `json:"policy"`
			}
			if err := json.Unmarshal(b, &mp); err != nil {
				return err
			}
			for _, p := range strings.Split(mp.Policy, ",") {
				if p = strings.TrimSpace(p); p != "" {
					m[name] = append(m[name], p)
				}
			}
			return nil
		})
	}
	iam.Unreadable = l.problems
	if fromDrive {
		iam.Buckets = driveBuckets(fsys)
		iam.Region = driveRegion(fsys, root)
	}
	return iam, nil
}

func exists(fsys fs.FS, name string) bool { _, err := fs.Stat(fsys, name); return err == nil }

type loader struct {
	fsys     fs.FS
	root     string
	problems []string
}

func (l *loader) read(name string) ([]byte, error) {
	b, err := readObject(l.fsys, name)
	if err != nil {
		return nil, err
	}
	return decrypt(b, l.root)
}

// each calls f with each <dir>/<name>/<file>'s plain bytes.
func (l *loader) each(dir, file string, f func(name string, b []byte) error) {
	entries, err := fs.ReadDir(l.fsys, dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		obj := path.Join(dir, e.Name(), file)
		b, err := l.read(obj)
		if err == nil {
			err = f(e.Name(), b)
		}
		if err != nil {
			l.problems = append(l.problems, fmt.Sprintf("%s: %v", obj, err))
		}
	}
}

// eachFile calls f with each <dir>/<name>.json's plain bytes.
func (l *loader) eachFile(dir string, f func(name string, b []byte) error) {
	entries, err := fs.ReadDir(l.fsys, dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		obj := path.Join(dir, e.Name())
		b, err := l.read(obj)
		if err == nil {
			err = f(name, b)
		}
		if err != nil {
			l.problems = append(l.problems, fmt.Sprintf("%s: %v", obj, err))
		}
	}
}

func parseIdentity(b []byte) (*Identity, error) {
	var rec struct {
		Credentials Identity `json:"credentials"`
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	id := &rec.Credentials
	if id.AccessKey == "" || id.SecretKey == "" {
		return nil, errors.New("no access key or secret in it")
	}
	if parts := strings.Split(id.SessionToken, "."); len(parts) == 3 {
		if raw, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			_ = json.Unmarshal(raw, &id.Claims)
		}
	}
	return id, nil
}

// driveBuckets are the drive's top-level directories, but MinIO's own.
func driveBuckets(fsys fs.FS) []string {
	entries, _ := fs.ReadDir(fsys, ".")
	var out []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// driveRegion is the region set in MinIO's configuration ("site" or the
// older "region"), if any. MINIO_SITE_REGION or MINIO_REGION in its
// environment override it, and aren't seen here.
func driveRegion(fsys fs.FS, root string) string {
	b, err := readObject(fsys, ".minio.sys/config/config.json")
	if err == nil {
		b, err = decrypt(b, root)
	}
	if err != nil {
		return ""
	}
	var cfg map[string]map[string][]struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return ""
	}
	for _, sub := range []string{"site", "region"} {
		for _, kv := range cfg[sub]["_"] {
			if (kv.Key == "region" || kv.Key == "name" && sub == "region") && kv.Value != "" {
				return kv.Value
			}
		}
	}
	return ""
}
