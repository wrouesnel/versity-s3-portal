package minioiam

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// testdata/drive is a MinIO single drive's IAM records and configuration,
// as MinIO (2026-02) wrote them, made with mc:
//
//	buckets apps, drop, logs; region ap-southeast-2
//	policies apps-read (Get, List on apps), drop-only (Put on drop/*),
//	  logs-prefix (Get, Put on logs/app1/*, List with a prefix condition)
//	alice: readwrite; bob: in group team, which has apps-read
//	carol: readonly, disabled; dropper: drop-only; logger: logs-prefix
//	service accounts: SVCALICEINHERIT01 (alice's, named backup-bot),
//	  SVCALICEEMBED0001 (alice's, its own policy: Get, List on apps),
//	  SVCROOT0000000001 (root's), SVCDROPOFF0000001 (dropper's, disabled)
//
// The root user is rootuser:rootpassword123; every secret is made up.
func TestLoadDrive(t *testing.T) {
	iam, err := Load(os.DirFS("testdata/drive"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(iam.Unreadable) != 0 {
		t.Fatalf("unreadable: %v", iam.Unreadable)
	}
	if got := len(iam.Users); got != 5 {
		t.Errorf("%d users", got)
	}
	if !reflect.DeepEqual(iam.Buckets, []string{"apps", "drop", "logs"}) || iam.Region != "ap-southeast-2" {
		t.Errorf("buckets %v, region %q", iam.Buckets, iam.Region)
	}
	sa := iam.ServiceAccounts["SVCALICEINHERIT01"]
	if sa == nil || sa.SecretKey != "svcsecretaliceinherit01" || sa.ParentUser != "alice" || sa.Name != "backup-bot" {
		t.Fatalf("SVCALICEINHERIT01: %+v", sa)
	}
	if !reflect.DeepEqual(iam.GroupPolicies["team"], []string{"apps-read"}) || iam.Groups["team"].Members[0] != "bob" {
		t.Errorf("team: %v %+v", iam.GroupPolicies["team"], iam.Groups["team"])
	}

	p := BuildPlan(iam, "testdata/drive", nil, "rootuser", time.Now())
	want := map[string]struct {
		owner  string
		grants map[string]string
		ok     bool
	}{
		"alice":             {"alice", map[string]string{"apps": "readwrite", "drop": "readwrite", "logs": "readwrite"}, true},
		"bob":               {"bob", map[string]string{"apps": "read"}, true},
		"carol":             {"carol", map[string]string{}, false}, // Get without List; disabled
		"dropper":           {"dropper", map[string]string{"drop": "writeonly"}, true},
		"logger":            {"logger", map[string]string{}, false}, // a prefix, a condition
		"SVCALICEINHERIT01": {"alice", map[string]string{"apps": "readwrite", "drop": "readwrite", "logs": "readwrite"}, true},
		"SVCALICEEMBED0001": {"alice", map[string]string{"apps": "read"}, true},
		"SVCROOT0000000001": {"", map[string]string{"apps": "readwrite", "drop": "readwrite", "logs": "readwrite"}, false},
		"SVCDROPOFF0000001": {"dropper", map[string]string{"drop": "writeonly"}, false},
	}
	if len(p.Keys) != len(want) {
		t.Errorf("%d keys", len(p.Keys))
	}
	for _, k := range p.Keys {
		w, found := want[k.AccessKey]
		if !found {
			t.Errorf("unexpected key %s", k.AccessKey)
			continue
		}
		if p.OwnerOf(k) != w.owner || !reflect.DeepEqual(k.Grants, w.grants) || k.Import != w.ok {
			t.Errorf("%s: owner %q, grants %v, import %v; notes %q", k.AccessKey, p.OwnerOf(k), k.Grants, k.Import, k.Notes)
		}
		if k.Import && len(k.Notes) != 0 {
			t.Errorf("%s is imported with notes %q", k.AccessKey, k.Notes)
		}
		if !k.Import && len(k.Notes) == 0 {
			t.Errorf("%s isn't imported, and nothing says why", k.AccessKey)
		}
	}
	byKey := map[string]PlanKey{}
	for _, k := range p.Keys {
		byKey[k.AccessKey] = k
	}
	if l := byKey["SVCALICEINHERIT01"].Label; l != "MinIO: backup-bot" {
		t.Errorf("label %q", l)
	}
	if n := strings.Join(byKey["logger"].Notes, "\n"); !strings.Contains(n, "condition") || !strings.Contains(n, "app1/*") {
		t.Errorf("logger's notes: %s", n)
	}
	if n := strings.Join(byKey["carol"].Notes, "\n"); !strings.Contains(n, "disabled") || !strings.Contains(n, "too little") {
		t.Errorf("carol's notes: %s", n)
	}
	if n := strings.Join(byKey["SVCROOT0000000001"].Notes, "\n"); !strings.Contains(n, "pick an owner") {
		t.Errorf("root's key's notes: %s", n)
	}
}

// testdata/encrypted is a copy of .minio.sys/config/iam from an older MinIO
// in fs mode: plain files, encrypted with the root credentials (madmin's
// EncryptData).
func TestLoadEncrypted(t *testing.T) {
	iam, err := Load(os.DirFS("testdata/encrypted"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(iam.Users) != 0 || len(iam.Unreadable) != 2 || !strings.Contains(iam.Unreadable[0], "root credentials") {
		t.Fatalf("without the root credentials: %d users, %q", len(iam.Users), iam.Unreadable)
	}
	if iam, _ = Load(os.DirFS("testdata/encrypted"), "rootuser:wrong"); len(iam.Unreadable) != 2 {
		t.Fatalf("with the wrong ones: %q", iam.Unreadable)
	}
	iam, err = Load(os.DirFS("testdata/encrypted"), "rootuser:rootpassword123")
	if err != nil || len(iam.Unreadable) != 0 {
		t.Fatalf("%v %q", err, iam.Unreadable)
	}
	if u := iam.Users["olduser"]; u == nil || u.SecretKey != "oldusersecret1" || iam.UserPolicies["olduser"][0] != "readonly" {
		t.Fatalf("olduser: %+v %v", u, iam.UserPolicies)
	}
}

func TestLoadNeither(t *testing.T) {
	if _, err := Load(os.DirFS("testdata/drive/apps"), ""); err == nil {
		t.Error("a bucket's directory was taken for MinIO's records")
	}
}

func TestLevel(t *testing.T) {
	for a, want := range map[Access][2]string{
		{List: true, Get: true, Put: true, Delete: true}: {"readwrite", ""},
		{List: true, Get: true, Put: true}:               {"createonly", "overwriting existing objects"},
		{List: true, Get: true}:                          {"read", ""},
		{List: true, Get: true, Delete: true}:            {"read", "delete"},
		{Put: true}:                                      {"writeonly", ""},
		{Put: true, Delete: true}:                        {"writeonly", "delete"},
		{Get: true}:                                      {"", "get"},
		{}:                                               {"", "nothing"},
	} {
		if l, lost := Level(a); l != want[0] || lost != want[1] {
			t.Errorf("%s: %q %q, want %q", a, l, lost, want)
		}
	}
}

func TestEval(t *testing.T) {
	buckets := []string{"a", "b", "logs-1", "logs-2"}
	got, notes := Eval([]Statement{
		{Effect: "Allow", Action: []string{"s3:*"}, Resource: []string{"arn:aws:s3:::*"}},
		{Effect: "Deny", Action: []string{"s3:DeleteObject"}, Resource: []string{"arn:aws:s3:::b/*"}},
	}, buckets)
	if _, ok := got["b"]; ok || len(got) != 3 || len(notes) != 1 {
		t.Errorf("a Deny: %v %q", got, notes)
	}
	got, notes = Eval([]Statement{
		{Effect: "Allow", Action: []string{"s3:Get*", "s3:ListBucket"}, Resource: []string{"arn:aws:s3:::logs-*"}},
		{Effect: "Allow", Action: []string{"s3:PutBucketPolicy", "s3:PutObject"}, Resource: []string{"arn:aws:s3:::a/*"}},
	}, buckets)
	if got["logs-1"] != (Access{List: true, Get: true}) || got["logs-2"] != got["logs-1"] || got["a"] != (Access{Put: true}) {
		t.Errorf("wildcards: %v", got)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "s3:putbucketpolicy") {
		t.Errorf("an action not carried over: %q", notes)
	}
	if _, notes = Eval([]Statement{{Effect: "Allow", Action: []string{"s3:GetObject"}, Resource: []string{"arn:aws:s3:::gone/*"}}}, buckets); len(notes) != 1 || !strings.Contains(notes[0], "isn't among the buckets") {
		t.Errorf("a bucket not moved: %q", notes)
	}
}
