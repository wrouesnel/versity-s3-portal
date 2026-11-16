package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestCaps(t *testing.T) {
	rw, ao, ro, wo := PermReadWrite.Caps(), PermCreateOnly.Caps(), PermRead.Caps(), PermWriteOnly.Caps()
	// Who covers whom: read ⊂ add-only ⊂ read & write, write-only ⊂ read & write.
	for _, c := range []struct {
		a, b Caps
		want bool
	}{
		{rw, ao, true}, {rw, ro, true}, {rw, wo, true},
		{ao, ro, true}, {ao, wo, false}, {ao, rw, false},
		{wo, ro, false}, {wo, ao, false}, {ro, ao, false},
		{ro.Union(wo), ao, true}, {ro.Union(wo), rw, false},
	} {
		if got := c.a.Covers(c.b); got != c.want {
			t.Errorf("%s covers %s: got %v", capsLabel(c.a), capsLabel(c.b), got)
		}
	}
	if got := rw.Intersect(ro.Union(wo)); got != (Caps{Read: true, Put: true}) {
		t.Errorf("read & write limited to read + write-only: %+v", got)
	}
	if got := wo.Intersect(ao); got != (Caps{Create: true}) {
		t.Errorf("write-only limited to add-only: %+v", got)
	}
	if got := ao.Intersect(Caps{}); got.Any() {
		t.Errorf("anything limited to nothing: %+v", got)
	}
	for _, p := range Perms {
		if capsLabel(p.Caps()) != p.Label() {
			t.Errorf("%s labels as %s", p, capsLabel(p.Caps()))
		}
	}
}

func TestBucketPolicy(t *testing.T) {
	if BucketPolicy("b", nil) != nil {
		t.Fatal("expected no policy without grants")
	}
	var doc policyDocument
	if err := json.Unmarshal(BucketPolicy("b", map[string]Caps{
		"R": PermRead.Caps(), "W": PermReadWrite.Caps(), "A": PermCreateOnly.Caps(), "D": PermWriteOnly.Caps(),
	}), &doc); err != nil {
		t.Fatal(err)
	}
	statements := map[string]policyStatement{}
	for _, st := range doc.Statement {
		statements[st.Sid] = st
		for _, a := range st.Action {
			switch a {
			case "s3:*", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketAcl", "s3:DeleteBucket", "s3:PutObjectAcl":
				t.Errorf("statement %s grants %s", st.Sid, a)
			}
		}
	}
	names := func(sid string) string { return strings.Join(statements[sid].Principal["AWS"], ",") }
	for sid, want := range map[string]string{
		"ReadBucket": "A,R,W", "ReadObjects": "A,R,W",
		"UploadObjects": "A,D,W", "PutObjects": "D,W",
		"CreateObjects": "A", "DeleteObjects": "W",
	} {
		if got := names(sid); got != want {
			t.Errorf("%s names %s, want %s", sid, got, want)
		}
	}
	create := statements["CreateObjects"]
	if create.Condition["StringEquals"]["s3:if-none-match"] != "*" || strings.Join(create.Action, ",") != "s3:PutObject" {
		t.Errorf("add-only statement: %+v", create)
	}
}

func testStore(t *testing.T) *Store {
	s, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testSessions(t *testing.T, store *Store, people ...string) *Sessions {
	for _, name := range people {
		store.PutPerson(name, &Person{UID: 1001, GID: 1001, Source: "ldap"})
	}
	return &Sessions{Key: []byte("0123456789abcdef0123456789abcdef"), TTL: time.Hour, Store: store}
}

func loginCookie(t *testing.T, s *Sessions, name string) *http.Cookie {
	rec := httptest.NewRecorder()
	if err := s.Start(rec, name); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()[0]
}

func TestSessions(t *testing.T) {
	store := testStore(t)
	s := testSessions(t, store, "alice")
	cookie := loginCookie(t, s, "alice")
	get := func(c *http.Cookie, s *Sessions) (*Session, error) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(c)
		return s.Get(req)
	}
	sess, err := get(cookie, s)
	if err != nil || sess.User.Name != "alice" || sess.User.UID != 1001 || sess.CSRF == "" {
		t.Fatalf("valid session rejected: %v %+v", err, sess)
	}

	tampered := *cookie
	tampered.Value = "x" + cookie.Value[1:]
	if _, err := get(&tampered, s); err == nil {
		t.Fatal("tampered session accepted")
	}
	other := &Sessions{Key: []byte("fedcba9876543210fedcba9876543210"), TTL: time.Hour, Store: store}
	if _, err := get(cookie, other); err == nil {
		t.Fatal("session signed with another key accepted")
	}

	// Admin rights come from the person now, not from login time.
	store.PutPerson("alice", &Person{UID: 1001, GID: 1001, Source: "ldap", Admin: true})
	if sess, _ := get(cookie, s); sess == nil || !sess.User.Admin {
		t.Fatal("admin rights didn't follow the person")
	}
	// Disabling the person ends the session at once.
	store.PutPerson("alice", &Person{UID: 1001, GID: 1001, Source: "ldap", Disabled: true})
	if _, err := get(cookie, s); err == nil {
		t.Fatal("disabled person's session accepted")
	}
	store.PutPerson("alice", &Person{UID: 1001, GID: 1001, Source: "ldap"})
	// Logging out ends the session server-side, so a copy of the cookie
	// stops working too.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(cookie)
	s.End(rec, req)
	if _, err := get(cookie, s); err == nil {
		t.Fatal("session survived logout")
	}
	// Ending all of someone's sessions.
	c1, c2 := loginCookie(t, s, "alice"), loginCookie(t, s, "alice")
	if n, _ := store.EndSessions("alice"); n != 2 {
		t.Fatalf("ended %d sessions", n)
	}
	if _, err := get(c1, s); err == nil {
		t.Fatal("ended session accepted")
	}
	_ = c2

	expired := &Sessions{Key: s.Key, TTL: -time.Minute, Store: store}
	if _, err := get(loginCookie(t, expired, "alice"), s); err == nil {
		t.Fatal("expired session accepted")
	}
}

func TestLDAPEntries(t *testing.T) {
	a := &LDAPAuth{
		AllowedGroup: "ou=s3-users,ou=groups,dc=example,dc=com",
		AdminGroup:   "ou=s3-admin,ou=groups,dc=example,dc=com",
		now:          func() time.Time { return time.Unix(20000*86400, 0) },
	}
	if got := userFilter("al*ce"); got != `(&(objectClass=posixAccount)(uid=al\2ace))` {
		t.Fatalf("filter %s", got)
	}
	entry := func(attrs map[string][]string) *ldap.Entry {
		base := map[string][]string{
			"uid": {"alice"}, "uidNumber": {"1001"}, "gidNumber": {"1001"},
			"memberOf": {"ou=s3-users,ou=groups,dc=example,dc=com", "OU=S3-Admin,ou=groups,dc=example,dc=com", "ou=photos,ou=groups,dc=example,dc=com"},
		}
		for k, v := range attrs {
			base[k] = v
		}
		return ldap.NewEntry("cn=alice,ou=users,dc=example,dc=com", base)
	}
	d, err := posixEntry(a, entry(nil))
	if err != nil || d.Disabled || !d.Admin || d.UID != 1001 || strings.Join(d.Groups, ",") != "S3-Admin,photos,s3-users" {
		t.Fatalf("alice: %+v %v", d, err)
	}
	for name, attrs := range map[string]map[string][]string{
		"not allowed":    {"memberOf": {"ou=photos,ou=groups,dc=example,dc=com"}},
		"glauth locked":  {"accountStatus": {"inactive"}},
		"389 locked":     {"nsAccountLock": {"TRUE"}},
		"ppolicy locked": {"pwdAccountLockedTime": {"20260101000000Z"}},
		"expired":        {"shadowExpire": {"19999"}},
		"root":           {"uidNumber": {"0"}},
	} {
		d, err := posixEntry(a, entry(attrs))
		if err != nil || !d.Disabled || d.Admin || d.Reason == "" {
			t.Errorf("%s: want disabled, got %+v %v", name, d, err)
		}
	}
	// In the admins' group alone: admins needn't be in the allowed group.
	if d, err := posixEntry(a, entry(map[string][]string{"memberOf": {"ou=s3-admin,ou=groups,dc=example,dc=com"}})); err != nil || d.Disabled || !d.Admin {
		t.Errorf("an admin outside the allowed group: %+v %v", d, err)
	}
	for name, attrs := range map[string]map[string][]string{
		"expires later": {"shadowExpire": {"20001"}},
		"never expires": {"shadowExpire": {"-1"}},
		"active":        {"accountStatus": {"active"}},
	} {
		if d, err := posixEntry(a, entry(attrs)); err != nil || d.Disabled {
			t.Errorf("%s: want enabled, got %+v %v", name, d, err)
		}
	}
	if _, err := posixEntry(a, entry(map[string][]string{"uidNumber": {""}})); err == nil {
		t.Fatal("an entry without uidNumber should be an error")
	}
	for _, name := range []string{"Bad Name", "a,cn=admin", "*", ""} {
		if _, err := a.Authenticate(name, "pw"); err != ErrBadCredentials {
			t.Errorf("%q: want bad credentials before any LDAP call, got %v", name, err)
		}
	}
	if g := groupName("ou=s3-users,ou=groups,dc=example,dc=com"); g != "s3-users" {
		t.Errorf("groupName: %q", g)
	}
}

// posixEntry is a posix directory's entry, its groups its own memberOf.
func posixEntry(a *LDAPAuth, e *ldap.Entry) (DirEntry, error) {
	return a.entry(e, func(g string) bool { return hasGroup(e, g) })
}

// An AD entry: named by sAMAccountName without case, its ids its RFC 2307
// ones, else mapped from its SID, else the defaults; disabled, locked out
// or expired by AD's own attributes; its groups nested as AD says.
func TestADEntries(t *testing.T) {
	a := &LDAPAuth{
		Schema:       SchemaAD,
		AllowedGroup: "CN=s3-users,OU=Groups,DC=example,DC=internal",
		AdminGroup:   "CN=s3-admins,OU=Groups,DC=example,DC=internal",
		now:          func() time.Time { return time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC) },
	}
	if got := a.filterFor("al*ce"); got != `(&(objectCategory=person)(objectClass=user)(sAMAccountName=al\2ace))` {
		t.Fatalf("filter %s", got)
	}
	if a.normalize("Alice") != "alice" || (&LDAPAuth{}).normalize("Alice") != "Alice" {
		t.Error("AD's names are matched without case; posix names are not")
	}
	// S-1-5-21-1-2-3-1104: its RID is 1104.
	sid := []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0x50, 0x04, 0, 0}
	if rid, ok := sidRID(sid); !ok || rid != 1104 {
		t.Fatalf("sidRID %d %v", rid, ok)
	}
	if _, ok := sidRID(sid[:10]); ok {
		t.Error("a short SID was read")
	}
	entry := func(attrs map[string][]string) *ldap.Entry {
		base := map[string][]string{
			"sAMAccountName": {"Alice"}, "userAccountControl": {"512"}, "accountExpires": {"9223372036854775807"},
			"primaryGroupID": {"513"}, "memberOf": {"CN=photos,OU=Groups,DC=example,DC=internal"},
		}
		for k, v := range attrs {
			base[k] = v
		}
		e := ldap.NewEntry("CN=Alice,OU=Users,DC=example,DC=internal", base)
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: "objectSid", ByteValues: [][]byte{sid}})
		return e
	}
	// Nested membership, as AD's in-chain rule gives it: in both groups.
	nested := func(string) bool { return true }
	if _, err := a.entry(entry(nil), nested); err == nil {
		t.Error("an AD entry with no ids, and no mapping or defaults, was taken")
	}
	a.IDRangeBase = 200000
	d, err := a.entry(entry(nil), nested)
	if err != nil || d.Disabled || !d.Admin || d.UID != 201104 || d.GID != 200513 || strings.Join(d.Groups, ",") != "photos" {
		t.Fatalf("alice by her SID: %+v %v", d, err)
	}
	if d, err := a.entry(entry(map[string][]string{"uidNumber": {"5001"}, "gidNumber": {"5000"}}), nested); err != nil || d.UID != 5001 || d.GID != 5000 {
		t.Errorf("alice by her RFC 2307 ids: %+v %v", d, err)
	}
	a.IDRangeBase, a.DefaultUID, a.DefaultGID = 0, 900, 900
	if d, err := a.entry(entry(nil), nested); err != nil || d.UID != 900 || d.GID != 900 {
		t.Errorf("alice by the defaults: %+v %v", d, err)
	}
	if d, _ := a.entry(entry(nil), func(string) bool { return false }); !d.Disabled || d.Admin {
		t.Errorf("in neither group: %+v", d)
	}
	if d, _ := a.entry(entry(nil), func(g string) bool { return strings.Contains(g, "s3-users") }); d.Disabled || d.Admin {
		t.Errorf("a user, not an admin: %+v", d)
	}
	// In the admins' group (nested, as AD counts it) and not the users':
	// admins needn't be in the allowed group.
	if d, _ := a.entry(entry(nil), func(g string) bool { return strings.Contains(g, "s3-admins") }); d.Disabled || !d.Admin {
		t.Errorf("an admin outside the allowed group: %+v", d)
	}
	// Disabled, an admin is still refused.
	if d, _ := a.entry(entry(map[string][]string{"userAccountControl": {"514"}}), func(g string) bool { return strings.Contains(g, "s3-admins") }); !d.Disabled || d.Admin {
		t.Errorf("a disabled admin: %+v", d)
	}
	for name, attrs := range map[string]map[string][]string{
		"disabled":   {"userAccountControl": {"514"}},
		"locked out": {"msDS-User-Account-Control-Computed": {"16"}},
		"expired":    {"accountExpires": {"133000000000000000"}}, // 2022
	} {
		if d, err := a.entry(entry(attrs), nested); err != nil || !d.Disabled || d.Admin || d.Reason == "" {
			t.Errorf("%s: want disabled, got %+v %v", name, d, err)
		}
	}
	for name, attrs := range map[string]map[string][]string{
		"never expires (0)": {"accountExpires": {"0"}},
		"expires later":     {"accountExpires": {"140000000000000000"}}, // 2044
		"not locked out":    {"msDS-User-Account-Control-Computed": {"0"}},
	} {
		if d, err := a.entry(entry(attrs), nested); err != nil || d.Disabled {
			t.Errorf("%s: want enabled, got %+v %v", name, d, err)
		}
	}
}

func TestAccess(t *testing.T) {
	meta := &BucketMeta{Groups: map[string]Perm{"photos": PermRead, "uploaders": PermWriteOnly, "archivists": PermCreateOnly}}
	alice := &Person{Groups: []string{"Photos", "uploaders"}}
	if c, via := access("alice", alice, "owner.alice", meta); c != PermReadWrite.Caps() || via != nil {
		t.Errorf("owner: %+v %v", c, via)
	}
	c, via := access("alice", alice, "owner.bob", meta)
	if c != (Caps{Read: true, Put: true}) || strings.Join(via, ",") != "photos,uploaders" {
		t.Errorf("member of two groups: %+v %v", c, via)
	}
	if c, _ := access("carol", &Person{}, "owner.bob", meta); c.Any() {
		t.Errorf("outsider: %+v", c)
	}
	alice.Disabled = true
	if c, _ := access("alice", alice, "owner.alice", meta); c.Any() {
		t.Errorf("disabled owner: %+v", c)
	}
}

func TestStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Put("K1", &Key{Owner: "alice", Label: "one", Created: time.Unix(1, 0), Buckets: map[string]Perm{"a": PermRead}})
	s.Put("K2", &Key{Owner: "alice", Label: "two", Created: time.Unix(2, 0), Buckets: map[string]Perm{"a": PermReadWrite, "b": PermRead}})
	s.Put("K3", &Key{Owner: "bob", Label: "three", Created: time.Unix(3, 0), Buckets: map[string]Perm{}})
	s.PutBucketMeta("a", &BucketMeta{Groups: map[string]Perm{"photos": PermRead}})
	s.PutPerson("alice", &Person{UID: 1, GID: 1, Groups: []string{"photos"}, Source: "ldap"})

	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.KeysFor("alice"); len(got) != 2 || got[0].Access != "K1" {
		t.Fatalf("KeysFor: %+v", got)
	}
	if g := reopened.Grants("a"); len(g) != 2 || g["K2"] != (KeyGrant{"alice", PermReadWrite}) {
		t.Fatalf("Grants: %v", g)
	}
	if m := reopened.BucketMeta("a"); m.Groups["photos"] != PermRead {
		t.Fatalf("BucketMeta: %+v", m)
	}
	// Returned values are copies.
	k, _ := reopened.Get("K1")
	k.Buckets["z"] = PermRead
	if k2, _ := reopened.Get("K1"); len(k2.Buckets) != 1 {
		t.Fatal("changing a returned key changed the store")
	}
	if g := reopened.KnownGroups(); strings.Join(g, ",") != "photos" {
		t.Fatalf("KnownGroups: %v", g)
	}
	reopened.Delete("K1")
	again, _ := OpenStore(path)
	if _, ok := again.Get("K1"); ok {
		t.Fatal("deleted key came back")
	}
}

func TestCSRFAndAuthRequired(t *testing.T) {
	store := testStore(t)
	sessions := testSessions(t, store, "alice")
	h := NewServer(NewPortal(nil, store), stubAuth{}, nil, sessions, "t", "https://s3", "us-east-1").Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/keys/delete", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated POST: want redirect, got %d", rec.Code)
	}

	req := httptest.NewRequest("POST", "/keys/delete", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(loginCookie(t, sessions, "alice"))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF token: want 403, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP header")
	}
}

func TestAdminUploadAndAPIGuards(t *testing.T) {
	store := testStore(t)
	sessions := testSessions(t, store, "alice")
	srv := NewServer(NewPortal(nil, store), stubAuth{}, nil, sessions, "t", "https://s3", "us-east-1")
	srv.APIToken = "0123456789abcdef0123456789abcdef-token"
	h := srv.Handler()
	cookie := loginCookie(t, sessions, "alice")

	do := func(method, path string, body string, hdr map[string]string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		if hdr["Authorization"] == "" {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := do("GET", "/admin", "", nil); c != http.StatusForbidden {
		t.Fatalf("non-admin GET /admin: want 403, got %d", c)
	}
	if c := do("PUT", "/upload?bucket=b&key=k", "x", nil); c != http.StatusForbidden {
		t.Fatalf("upload without CSRF header: want 403, got %d", c)
	}
	if c := do("GET", "/api/users/alice", "", nil); c != http.StatusUnauthorized {
		t.Fatalf("API from a non-admin session: want 401, got %d", c)
	}
	if c := do("GET", "/api/users/alice", "", map[string]string{"Authorization": "Bearer wrong"}); c != http.StatusUnauthorized {
		t.Fatalf("API with a wrong token: want 401, got %d", c)
	}
	if c := do("GET", "/api/users/alice", "", map[string]string{"Authorization": "Bearer " + srv.APIToken}); c != http.StatusOK {
		t.Fatalf("API with the token: want 200, got %d", c)
	}
	// Without a directory, checks are a clear error rather than a crash.
	if c := do("POST", "/api/users/alice/check", "", map[string]string{"Authorization": "Bearer " + srv.APIToken}); c != http.StatusBadRequest {
		t.Fatalf("check without a directory: want 400, got %d", c)
	}
	// Admin sessions need the CSRF header for API writes.
	store.PutPerson("alice", &Person{UID: 1001, GID: 1001, Source: "ldap", Admin: true})
	if c := do("POST", "/api/directory/sync", "", nil); c != http.StatusUnauthorized {
		t.Fatalf("admin API write without CSRF: want 401, got %d", c)
	}
	srv.APIToken = ""
	if c := do("GET", "/api/users/alice", "", map[string]string{"Authorization": "Bearer "}); c != http.StatusUnauthorized {
		t.Fatalf("empty token when none is set: want 401, got %d", c)
	}
}

func TestPaths(t *testing.T) {
	if got := s3Escape("dir/a b+c=d&é~.txt"); got != "dir/a%20b%2Bc%3Dd%26%C3%A9~.txt" {
		t.Errorf("s3Escape: %s", got)
	}
	if got := parentPrefix("a/b/c.txt"); got != "a/b/" {
		t.Errorf("parentPrefix: %s", got)
	}
	if got := parentPrefix("c.txt"); got != "" {
		t.Errorf("parentPrefix of a top-level key: %q", got)
	}
	if c := crumbs("a/b/"); len(c) != 2 || c[1].Name != "b" || c[1].Prefix != "a/b/" {
		t.Errorf("crumbs: %+v", c)
	}
	if got := humanSize(1536); got != "1.5 KiB" {
		t.Errorf("humanSize: %s", got)
	}
	for _, bad := range []string{"", "/abs", "a\x00b", "a\nb"} {
		if checkKey(bad) == nil {
			t.Errorf("checkKey accepted %q", bad)
		}
	}
	if checkPrefix("dir") == nil {
		t.Error("checkPrefix accepted a prefix without a trailing slash")
	}
}

// People with keys from before the portal kept records are learned from the
// directory, so their keys keep working after an upgrade.
func TestLearnPeople(t *testing.T) {
	store := testStore(t)
	store.Put("K1", &Key{Owner: "alice", Label: "old", Buckets: map[string]Perm{"a": PermRead}})
	store.Put("K2", &Key{Owner: "gone", Label: "old", Buckets: map[string]Perm{}})
	store.PutWeb("bob", &WebAccount{Access: "web.bob", Secret: "s"})
	store.PutPerson("carol", &Person{UID: 9, GID: 9, Source: "oidc"})
	p := NewPortal(nil, store)
	p.dir = &fakeDir{entries: map[string]DirEntry{
		"alice": {UID: 1001, GID: 1001, Groups: []string{"photos"}},
		"bob":   {UID: 1002, GID: 1002, Disabled: true, Reason: "account inactive"},
	}}
	if err := p.LearnPeople(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"alice": false, "bob": true, "gone": true} {
		person, ok := store.Person(name)
		if !ok || person.Source != "ldap" || person.Disabled != want {
			t.Errorf("%s: %+v", name, person)
		}
	}
	if a, _ := store.Person("alice"); a.UID != 1001 || !a.InGroup("photos") {
		t.Errorf("alice: %+v", a)
	}
	if c, _ := store.Person("carol"); c.Source != "oidc" {
		t.Error("an existing record was replaced")
	}
}
