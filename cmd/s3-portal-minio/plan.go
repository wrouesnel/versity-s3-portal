package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/wrouesnel/versity-s3-portal/internal/minioiam"
)

// minioFlags are how a command finds MinIO's records.
type minioFlags struct {
	drive, env string
}

func (m *minioFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&m.drive, "drive", "", "MinIO's drive (the directory holding .minio.sys), or a copy of its .minio.sys/config/iam")
	fs.StringVar(&m.env, "minio-env", "", "MinIO's environment file (as /etc/default/minio), for its root user, region and KMS; "+
		"else MINIO_ROOT_USER and MINIO_ROOT_PASSWORD from this environment")
}

// minioEnv is what MinIO's environment says.
type minioEnv struct {
	rootUser, rootPassword, region string
	kms                            bool
}

func (m *minioFlags) environment() (minioEnv, error) {
	vars := map[string]string{}
	if m.env != "" {
		f, err := os.Open(m.env)
		if err != nil {
			return minioEnv{}, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sc.Text()), "export "))
			k, v, ok := strings.Cut(line, "=")
			if !ok || strings.HasPrefix(line, "#") {
				continue
			}
			vars[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	} else {
		for _, k := range []string{"MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY", "MINIO_REGION", "MINIO_SITE_REGION"} {
			vars[k] = os.Getenv(k)
		}
	}
	first := func(keys ...string) string {
		for _, k := range keys {
			if vars[k] != "" {
				return vars[k]
			}
		}
		return ""
	}
	e := minioEnv{
		rootUser:     first("MINIO_ROOT_USER", "MINIO_ACCESS_KEY"),
		rootPassword: first("MINIO_ROOT_PASSWORD", "MINIO_SECRET_KEY"),
		region:       first("MINIO_SITE_REGION", "MINIO_REGION_NAME", "MINIO_REGION"),
	}
	for k, v := range vars {
		if strings.HasPrefix(k, "MINIO_KMS_") && v != "" {
			e.kms = true
		}
	}
	return e, nil
}

// load reads MinIO's records.
func (m *minioFlags) load() (*minioiam.IAM, minioEnv, error) {
	if m.drive == "" {
		return nil, minioEnv{}, errors.New("--drive is needed")
	}
	env, err := m.environment()
	if err != nil {
		return nil, env, err
	}
	root := ""
	if env.rootUser != "" && env.rootPassword != "" {
		root = env.rootUser + ":" + env.rootPassword
	}
	iam, err := minioiam.Load(os.DirFS(m.drive), root)
	if err != nil {
		return nil, env, err
	}
	if env.region != "" {
		iam.Region = env.region
	}
	return iam, env, nil
}

func planCmd(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	var m minioFlags
	m.register(fs)
	out := fs.String("out", "", "write the plan here (it has no secrets), for review; an existing file is kept unless --force")
	force := fs.Bool("force", false, "overwrite --out")
	buckets := fs.String("buckets", "", "MinIO's buckets, comma-separated (from the drive by default; needed with a copy of .minio.sys/config/iam)")
	fs.Parse(args)
	if *out == "" {
		return errors.New("--out is needed")
	}
	if _, err := os.Stat(*out); err == nil && !*force {
		return fmt.Errorf("%s exists (it may have been edited): give --force to replace it", *out)
	}
	iam, env, err := m.load()
	if err != nil {
		return err
	}
	var bs []string
	for _, b := range strings.Split(*buckets, ",") {
		if b = strings.TrimSpace(b); b != "" {
			bs = append(bs, b)
		}
	}
	if len(bs) == 0 && len(iam.Buckets) == 0 {
		return errors.New("no buckets: give --buckets, as a copy of .minio.sys/config/iam doesn't have them")
	}
	plan := minioiam.BuildPlan(iam, m.drive, bs, env.rootUser, time.Now())
	b, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o600); err != nil {
		return err
	}
	report(os.Stdout, plan, env)
	fmt.Printf("\nWrote %s. Review it: set owners (and each key's owner, to override), map buckets to the portal's, "+
		"fix grants, and set import to true for keys to import. Then run import.\n", *out)
	return nil
}

// report is a plan, for people.
func report(w io.Writer, p *minioiam.Plan, env minioEnv) {
	if env.kms {
		fmt.Fprintln(w, "[WARN] MinIO has a KMS (MINIO_KMS_*): records it encrypted can't be read here, and are listed as unreadable.")
	}
	if env.rootUser == "" {
		fmt.Fprintln(w, "[WARN] MinIO's root user isn't known (give --minio-env): its service accounts look like an unknown user's, with no grants.")
	}
	for _, u := range p.Unreadable {
		fmt.Fprintln(w, "[FAIL] unreadable:", u)
	}
	region := p.Region
	if region == "" {
		region = "us-east-1 (MinIO's default)"
	}
	fmt.Fprintf(w, "Region: %s. Clients sign for it, so the gateway must have it too.\n", region)
	var names []string
	for b, to := range p.Buckets {
		if b != to {
			b += " -> " + to
		}
		names = append(names, b)
	}
	sort.Strings(names)
	fmt.Fprintf(w, "Buckets: %s\n\n", strings.Join(names, ", "))
	n := 0
	for _, k := range p.Keys {
		state := "skip  "
		if k.Import {
			state = "import"
			n++
		}
		owner := p.OwnerOf(k)
		if owner == "" {
			owner = "(nobody)"
		}
		var grants []string
		for b, l := range k.Grants {
			grants = append(grants, b+"="+l)
		}
		sort.Strings(grants)
		fmt.Fprintf(w, "%s %-22s %-16s MinIO %s, owner %s: %s\n", state, k.AccessKey, k.Kind, k.MinIOUser, owner, strings.Join(grants, " "))
		for _, note := range k.Notes {
			fmt.Fprintf(w, "         - %s\n", note)
		}
	}
	fmt.Fprintf(w, "\n%d of %d keys to import.\n", n, len(p.Keys))
}
