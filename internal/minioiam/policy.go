package minioiam

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Policy is an IAM policy, as MinIO (and AWS) write them.
type Policy struct {
	Statement []Statement `json:"Statement"`
}

// Statement is one of a policy's statements.
type Statement struct {
	Effect      string         `json:"Effect"`
	Action      stringList     `json:"Action"`
	NotAction   stringList     `json:"NotAction"`
	Resource    stringList     `json:"Resource"`
	NotResource stringList     `json:"NotResource"`
	Condition   map[string]any `json:"Condition"`
}

// stringList is a string or a list of them.
type stringList []string

func (s *stringList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// parsePolicy reads a policy, as MinIO stores it now (wrapped, with its
// dates) or did (bare).
func parsePolicy(b []byte) (*Policy, error) {
	var doc struct {
		Policy *Policy `json:"Policy"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if doc.Policy != nil {
		return doc.Policy, nil
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// builtinPolicies are MinIO's own, which it never stores.
func builtinPolicies() map[string]*Policy {
	all := []string{"arn:aws:s3:::*"}
	return map[string]*Policy{
		"readwrite":   {Statement: []Statement{{Effect: "Allow", Action: []string{"s3:*"}, Resource: all}}},
		"readonly":    {Statement: []Statement{{Effect: "Allow", Action: []string{"s3:GetBucketLocation", "s3:GetObject"}, Resource: all}}},
		"writeonly":   {Statement: []Statement{{Effect: "Allow", Action: []string{"s3:PutObject"}, Resource: all}}},
		"diagnostics": {Statement: []Statement{{Effect: "Allow", Action: []string{"admin:ServerInfo", "admin:Profiling", "admin:ServerTrace", "admin:ConsoleLog", "admin:OBDInfo", "admin:TopLocksInfo", "admin:BandwidthMonitor", "admin:Prometheus"}, Resource: all}}},
		"consoleAdmin": {Statement: []Statement{
			{Effect: "Allow", Action: []string{"admin:*"}},
			{Effect: "Allow", Action: []string{"kms:*"}},
			{Effect: "Allow", Action: []string{"s3:*"}, Resource: all},
		}},
	}
}

// Access is what a key may do in one bucket.
type Access struct {
	List, Get, Put, Delete bool
}

func (a Access) none() bool { return a == Access{} }

func (a Access) and(b Access) Access {
	return Access{List: a.List && b.List, Get: a.Get && b.Get, Put: a.Put && b.Put, Delete: a.Delete && b.Delete}
}

func (a Access) or(b Access) Access {
	return Access{List: a.List || b.List, Get: a.Get || b.Get, Put: a.Put || b.Put, Delete: a.Delete || b.Delete}
}

func (a Access) String() string {
	var out []string
	for _, c := range []struct {
		on   bool
		name string
	}{{a.List, "list"}, {a.Get, "get"}, {a.Put, "put"}, {a.Delete, "delete"}} {
		if c.on {
			out = append(out, c.name)
		}
	}
	if len(out) == 0 {
		return "nothing"
	}
	return strings.Join(out, ", ")
}

// Level is the portal's level of access for a, the most it can give without
// giving more than a allows, and what a allows that it leaves out ("" if
// it's exact). "" for no level: a allows too little for any.
func Level(a Access) (level, lost string) {
	read := a.List && a.Get
	switch {
	case read && a.Put && a.Delete:
		return "readwrite", ""
	case read && a.Put:
		// The portal's read & write deletes too: add only (read, and add
		// what isn't there) is the most it gives without that.
		return "createonly", "overwriting existing objects"
	case read:
		lost := Access{Put: a.Put, Delete: a.Delete}
		if lost.none() {
			return "read", ""
		}
		return "read", lost.String()
	case a.Put:
		lost := Access{List: a.List, Get: a.Get, Delete: a.Delete}
		if lost.none() {
			return "writeonly", ""
		}
		return "writeonly", lost.String()
	}
	return "", a.String()
}

// objectActions are the S3 actions of a level of access; the others (bucket
// settings, tagging, versions and the like) the portal doesn't grant keys.
var objectActions = map[string]func(*Access){
	"s3:listbucket": func(a *Access) { a.List = true },
	"s3:getobject":  func(a *Access) { a.Get = true },
	"s3:putobject":  func(a *Access) { a.Put = true },
	"s3:deleteobject": func(a *Access) {
		a.Delete = true
	},
}

// harmless are actions which come with every level of access, or matter
// only with others, so a policy naming them loses nothing.
var harmless = map[string]bool{
	"s3:getbucketlocation": true, "s3:listallmybuckets": true, "s3:listmultipartuploadparts": true,
	"s3:abortmultipartupload": true, "s3:listbucketmultipartuploads": true, "s3:headbucket": true,
}

// Eval is what statements give each bucket: allowed, less anything a Deny
// statement touches, and notes on everything not carried over exactly.
func Eval(stmts []Statement, buckets []string) (map[string]Access, []string) {
	out := map[string]Access{}
	denied := map[string]bool{}
	var notes []string
	note := func(format string, args ...any) { notes = append(notes, fmt.Sprintf(format, args...)) }
	for i, st := range stmts {
		which := fmt.Sprintf("statement %d", i+1)
		deny := strings.EqualFold(st.Effect, "Deny")
		if len(st.NotAction) > 0 || len(st.NotResource) > 0 {
			if deny {
				for _, b := range buckets {
					denied[b] = true
				}
				note("%s denies with NotAction or NotResource: no bucket is granted", which)
			} else {
				note("%s allows with NotAction or NotResource: left out", which)
			}
			continue
		}
		if deny {
			for _, b := range buckets {
				if touches(st.Resource, b) {
					denied[b] = true
				}
			}
			note("%s denies %s on %s: those buckets aren't granted", which, strings.Join(st.Action, ", "), strings.Join(st.Resource, ", "))
			continue
		}
		if len(st.Condition) > 0 {
			c, _ := json.Marshal(st.Condition)
			note("%s has a condition (%s): left out", which, c)
			continue
		}
		var gives Access
		var other []string
		for _, act := range st.Action {
			act = strings.ToLower(act)
			matched := false
			for name, set := range objectActions {
				if wildcard(act, name) {
					set(&gives)
					matched = true
				}
			}
			if !matched && !harmless[act] && !strings.Contains(act, "*") {
				other = append(other, act)
			}
		}
		if len(other) > 0 {
			note("%s allows %s: not carried over", which, strings.Join(other, ", "))
		}
		if gives.none() {
			continue
		}
		for _, res := range st.Resource {
			pat, ok := strings.CutPrefix(res, "arn:aws:s3:::")
			if !ok {
				note("%s names %q, not a bucket: left out", which, res)
				continue
			}
			hit := false
			for _, b := range buckets {
				var a Access
				if wildcard(pat, b) {
					a.List = gives.List // listing is the bucket's
				}
				if wildcard(pat, b+"/*") { // all of its objects
					a.Get, a.Put, a.Delete = gives.Get, gives.Put, gives.Delete
				} else if strings.HasPrefix(pat, b+"/") {
					note("%s gives only %s of %s: left out", which, strings.TrimPrefix(pat, b+"/"), b)
					hit = true
					continue
				}
				if !a.none() {
					out[b] = out[b].or(a)
					hit = true
				}
			}
			if !hit {
				note("%s names %s, which isn't among the buckets", which, pat)
			}
		}
	}
	for b := range denied {
		delete(out, b)
	}
	sort.Strings(notes)
	return out, notes
}

// touches is whether resources name the bucket or anything in it.
func touches(resources []string, bucket string) bool {
	for _, res := range resources {
		pat := strings.TrimPrefix(res, "arn:aws:s3:::")
		if wildcard(pat, bucket) || wildcard(pat, bucket+"/*") || strings.HasPrefix(pat, bucket+"/") {
			return true
		}
	}
	return false
}

// wildcard matches s against pattern, with IAM's * (anything) and ? (one
// character).
func wildcard(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	switch pattern[0] {
	case '*':
		for i := 0; i <= len(s); i++ {
			if wildcard(pattern[1:], s[i:]) {
				return true
			}
		}
		return false
	case '?':
		return s != "" && wildcard(pattern[1:], s[1:])
	}
	return s != "" && pattern[0] == s[0] && wildcard(pattern[1:], s[1:])
}
