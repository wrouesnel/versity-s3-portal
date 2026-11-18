package minioiam

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Plan is what moving a MinIO server's keys to the portal would do, for an
// admin to review and edit before importing: each key, its owner and its
// grants. It has no secrets: the import reads them from MinIO's records again.
type Plan struct {
	// Source is where the records were read from.
	Source string `json:"source"`
	// Region is MinIO's, if its configuration sets one. Clients sign for
	// it: the gateway must have the same.
	Region string `json:"region,omitempty"`
	// Buckets maps each MinIO bucket to the portal's bucket it was moved
	// to; "" for one that wasn't. Grants are given by MinIO's names, and
	// imported as these.
	Buckets map[string]string `json:"buckets"`
	// Owners maps each MinIO user to the portal person who owns their keys;
	// "" for nobody yet (a key whose owner is "" isn't imported).
	Owners map[string]string `json:"owners"`
	Keys   []PlanKey         `json:"keys"`
	// Unreadable are MinIO's records which couldn't be read.
	Unreadable []string `json:"unreadable,omitempty"`
}

// PlanKey is one key.
type PlanKey struct {
	AccessKey string `json:"access_key"`
	// Kind is "user" (a MinIO user's own key: their name) or
	// "service-account".
	Kind string `json:"kind"`
	// MinIOUser is whose it is in MinIO: the user, or a service account's
	// parent.
	MinIOUser string `json:"minio_user"`
	// Owner overrides Owners for this key.
	Owner string `json:"owner,omitempty"`
	Label string `json:"label"`
	// Import is whether to import it. It starts true only for a key whose
	// access translates exactly and whose owner is known.
	Import bool `json:"import"`
	// Grants are its access, by MinIO bucket: read, readwrite, writeonly or
	// createonly, as the portal's levels.
	Grants map[string]string `json:"grants"`
	// MinIOAccess is what MinIO let it do, per bucket, for reference.
	MinIOAccess map[string]string `json:"minio_access,omitempty"`
	// Notes are everything about it not carried over exactly.
	Notes []string `json:"notes,omitempty"`
}

// OwnerOf is who owns k: its Owner, else its MinIO user's.
func (p *Plan) OwnerOf(k PlanKey) string {
	if k.Owner != "" {
		return k.Owner
	}
	return p.Owners[k.MinIOUser]
}

// RootUser is how a plan names MinIO's root user, whose keys need an owner
// chosen.
const RootUser = "(root)"

// BuildPlan is the plan for iam's keys. buckets are MinIO's buckets (else
// those on its drive); rootAccess is the root user's access key, which
// service accounts of root have as their parent.
func BuildPlan(iam *IAM, source string, buckets []string, rootAccess string, now time.Time) *Plan {
	if len(buckets) == 0 {
		buckets = iam.Buckets
	}
	p := &Plan{Source: source, Region: iam.Region, Buckets: map[string]string{}, Owners: map[string]string{}, Unreadable: iam.Unreadable}
	for _, b := range buckets {
		p.Buckets[b] = b
	}
	for name, id := range iam.Users {
		p.add(iam, buckets, "user", name, id, now)
	}
	for _, id := range iam.ServiceAccounts {
		parent := id.ParentUser
		if parent == "" || parent == rootAccess {
			parent = RootUser
		}
		p.add(iam, buckets, "service-account", parent, id, now)
	}
	sort.Slice(p.Keys, func(i, j int) bool {
		if p.Keys[i].MinIOUser != p.Keys[j].MinIOUser {
			return p.Keys[i].MinIOUser < p.Keys[j].MinIOUser
		}
		return p.Keys[i].AccessKey < p.Keys[j].AccessKey
	})
	return p
}

func (p *Plan) add(iam *IAM, buckets []string, kind, user string, id *Identity, now time.Time) {
	k := PlanKey{AccessKey: id.AccessKey, Kind: kind, MinIOUser: user, Grants: map[string]string{}, MinIOAccess: map[string]string{}}
	if _, ok := p.Owners[user]; !ok {
		p.Owners[user] = defaultOwner(user, id)
	}
	k.Label = label(kind, user, id)

	access, notes := iam.accessOf(kind, user, id, buckets)
	k.Notes = notes
	exact := len(notes) == 0
	for b, a := range access {
		k.MinIOAccess[b] = a.String()
		level, lost := Level(a)
		if lost != "" {
			exact = false
			if level == "" {
				k.Notes = append(k.Notes, fmt.Sprintf("%s: MinIO allows %s, too little for any of the portal's levels: not granted (read only also lists and gets)", b, a))
			} else {
				k.Notes = append(k.Notes, fmt.Sprintf("%s: %s, without %s", b, level, lost))
			}
		}
		if level != "" {
			k.Grants[b] = level
		}
	}
	if !id.Enabled() {
		exact = false
		k.Notes = append(k.Notes, "disabled in MinIO")
	}
	if t, ok := id.Expires(); ok {
		if !t.After(now) {
			exact = false
			k.Notes = append(k.Notes, "expired in MinIO at "+t.UTC().Format(time.RFC3339))
		} else {
			k.Notes = append(k.Notes, "expires in MinIO at "+t.UTC().Format(time.RFC3339)+"; the portal's keys don't expire")
		}
	}
	if len(k.Grants) == 0 {
		exact = false
		k.Notes = append(k.Notes, "no bucket to grant")
	}
	if p.Owners[user] == "" {
		exact = false
		k.Notes = append(k.Notes, "pick an owner: set owners[\""+user+"\"], or this key's owner")
	}
	k.Import = exact
	sort.Strings(k.Notes)
	p.Keys = append(p.Keys, k)
}

// accessOf is what MinIO lets a key do in each bucket.
func (iam *IAM) accessOf(kind, user string, id *Identity, buckets []string) (map[string]Access, []string) {
	var access map[string]Access
	var notes []string
	if kind == "user" || user != RootUser {
		stmts, n := iam.userStatements(user, id)
		notes = n
		var en []string
		access, en = Eval(stmts, buckets)
		notes = append(notes, en...)
	} else {
		access = map[string]Access{}
		for _, b := range buckets {
			access[b] = Access{List: true, Get: true, Put: true, Delete: true}
		}
		notes = append(notes, "a service account of MinIO's root user: everything, unless its own policy limits it")
	}
	if kind == "service-account" {
		own, err := id.EmbeddedPolicy()
		switch {
		case err != nil:
			return nil, append(notes, "its own policy can't be read: "+err.Error())
		case own != nil:
			limit, en := Eval(own.Statement, buckets)
			for _, n := range en {
				notes = append(notes, "its own policy: "+n)
			}
			for b, a := range access {
				if a = a.and(limit[b]); a.none() {
					delete(access, b)
				} else {
					access[b] = a
				}
			}
		}
	}
	return access, notes
}

// userStatements are a MinIO user's policies' statements: their own and
// their groups', or an LDAP user's by DN.
func (iam *IAM) userStatements(user string, id *Identity) ([]Statement, []string) {
	var names, notes []string
	ldapDN, _ := id.Claims["ldapUser"].(string)
	if ldapDN == "" && strings.Contains(user, "=") {
		ldapDN = user // a service account of an LDAP user: its parent is their DN
	}
	switch {
	case ldapDN != "":
		names = append(names, iam.STSUserPolicies[ldapDN]...)
		for g, ps := range iam.GroupPolicies {
			if strings.Contains(g, "=") {
				notes = append(notes, "LDAP group "+g+" has policies "+strings.Join(ps, ", ")+", and whether "+user+" is in it isn't known here")
			}
		}
	case iam.Users[user] != nil:
		names = append(names, iam.UserPolicies[user]...)
		for g, grp := range iam.Groups {
			if grp.Status != "" && grp.Status != "enabled" {
				continue
			}
			for _, m := range grp.Members {
				if m == user {
					names = append(names, iam.GroupPolicies[g]...)
				}
			}
		}
	default:
		notes = append(notes, "MinIO user "+user+" isn't one of its own (an OpenID or LDAP user?): their access isn't known here")
	}
	var stmts []Statement
	for _, n := range names {
		if pol := iam.Policies[n]; pol != nil {
			stmts = append(stmts, pol.Statement...)
		} else {
			notes = append(notes, "policy "+n+" isn't in MinIO's records")
		}
	}
	return stmts, notes
}

// defaultOwner is the portal person a MinIO user is taken to be: the same
// name, an LDAP user's account name, or nobody for root.
func defaultOwner(user string, id *Identity) string {
	if user == RootUser {
		return ""
	}
	if n, _ := id.Claims["ldapUsername"].(string); n != "" {
		return strings.ToLower(n)
	}
	if first, _, ok := strings.Cut(user, ","); ok {
		if _, v, ok := strings.Cut(first, "="); ok {
			return strings.ToLower(v)
		}
	}
	return user
}

// label is the imported key's name in the portal: where it came from.
func label(kind, user string, id *Identity) string {
	var l string
	switch {
	case kind == "user":
		l = "MinIO user " + user
	case id.Name != "":
		l = "MinIO: " + id.Name
	default:
		l = "MinIO key of " + user
	}
	if len(l) > 64 {
		l = l[:64]
	}
	return l
}
