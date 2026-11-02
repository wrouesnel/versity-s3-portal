package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Owner accounts own a person's buckets. Their secrets are thrown away, so
// nobody can sign as them: people reach buckets only through accounts the
// portal grants with bucket policies.
const ownerPrefix = "owner."

func ownerAccess(username string) string { return ownerPrefix + username }

// Web accounts are how the file browser reaches buckets: each bucket's
// policy gives each person's web account whatever that person may do there.
const webPrefix = "web."

func webAccess(username string) string { return webPrefix + username }

var bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

// UserError is a problem to show the user rather than log.
type UserError struct{ Msg string }

func (e *UserError) Error() string { return e.Msg }

func userErr(format string, args ...any) error { return &UserError{fmt.Sprintf(format, args...)} }

// Portal is the service's logic. Access to a bucket comes from owning it
// or from a group grant on it; keys and the file browser get that access,
// limited by what each key was asked for, through bucket policies the
// portal writes from its records and the directory's current view of
// people.
type Portal struct {
	mu    sync.Mutex
	vgw   *VGW
	store *Store
	// dir, when set, is asked about people after they log in.
	dir Directory

	// The gateway's bucket list, kept briefly: every page and file
	// operation checks who owns what, and listing every bucket each time
	// is most of the latency. The portal drops it whenever it creates or
	// deletes a bucket; only buckets changed behind its back can be stale,
	// for at most bucketCacheTTL.
	cacheMu      sync.Mutex
	bucketCache  []Bucket
	bucketCached time.Time

	// written is a hash of each bucket's policy as last written, so
	// resyncing everything only touches buckets whose policy changed.
	written map[string][32]byte
}

const bucketCacheTTL = 5 * time.Second

func NewPortal(vgw *VGW, store *Store) *Portal {
	return &Portal{vgw: vgw, store: store, written: map[string][32]byte{}}
}

// listBuckets is the gateway's bucket list, from the cache when it's fresh.
func (p *Portal) listBuckets(ctx context.Context) ([]Bucket, error) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	if p.bucketCache != nil && time.Since(p.bucketCached) < bucketCacheTTL {
		return p.bucketCache, nil
	}
	buckets, err := p.vgw.ListBuckets(ctx)
	if err != nil {
		return nil, err
	}
	p.bucketCache, p.bucketCached = buckets, time.Now()
	return buckets, nil
}

func (p *Portal) forgetBuckets() {
	p.cacheMu.Lock()
	p.bucketCache = nil
	p.cacheMu.Unlock()
}

func newAccessKey() string {
	b := make([]byte, 11)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "VGW" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)[:17]
}

// newSecret returns 40 alphanumerics, so the secret pastes cleanly into any
// config file.
func newSecret() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, 40)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			panic(err)
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out)
}

// ------------------------------------------------------------------ people

// Login records what a login proved about someone and returns them as a
// user. A person the directory had disabled is enabled again by logging
// in, since logging in means the directory let them.
func (p *Portal) Login(ctx context.Context, id Identity, source string) (User, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	old, existed := p.store.Person(id.Name)
	person := &Person{
		UID: id.UID, GID: id.GID, Groups: id.Groups, Admin: id.Admin,
		Source: source, Checked: time.Now().UTC(),
	}
	sort.Strings(person.Groups)
	if err := p.store.PutPerson(id.Name, person); err != nil {
		return User{}, err
	}
	if existed && p.accessChanged(old, person) {
		if err := p.syncAll(ctx); err != nil {
			return User{}, err
		}
	}
	return person.User(id.Name), nil
}

// accessChanged says whether a person's change affects bucket policies.
func (p *Portal) accessChanged(old, new *Person) bool {
	return old.Disabled != new.Disabled || strings.Join(old.Groups, "\n") != strings.Join(new.Groups, "\n")
}

// PersonStatus is what a check of someone found.
type PersonStatus struct {
	User     string    `json:"user"`
	Known    bool      `json:"known"`
	Source   string    `json:"source,omitempty"`
	Disabled bool      `json:"disabled"`
	Reason   string    `json:"reason,omitempty"`
	Groups   []string  `json:"groups,omitempty"`
	Admin    bool      `json:"admin"`
	Checked  time.Time `json:"checked,omitempty"`
	Changed  bool      `json:"changed"`
	// Sessions ended because of this check.
	EndedSessions int `json:"endedSessions,omitempty"`
	Keys          int `json:"keys"`
}

func statusOf(name string, person *Person, keys int) PersonStatus {
	return PersonStatus{
		User: name, Known: true, Source: person.Source, Disabled: person.Disabled,
		Reason: person.DisabledReason, Groups: person.Groups, Admin: person.Admin,
		Checked: person.Checked, Keys: keys,
	}
}

// Status returns what the portal knows about someone, without asking the
// directory.
func (p *Portal) Status(name string) PersonStatus {
	person, ok := p.store.Person(name)
	if !ok {
		return PersonStatus{User: name}
	}
	return statusOf(name, person, len(p.store.KeysFor(name)))
}

// applyDir updates a person from a directory answer and returns whether
// their access changed. Callers hold p.mu.
func (p *Portal) applyDir(name string, person *Person, d DirEntry) (changed bool, ended int, err error) {
	updated := copyPerson(person)
	updated.Checked = time.Now().UTC()
	updated.Disabled, updated.DisabledReason = d.Disabled, d.Reason
	if !d.Disabled {
		updated.Groups, updated.Admin = d.Groups, d.Admin
		if d.UID != person.UID || d.GID != person.GID {
			// Gateway accounts carry the old ids; new keys get the new ones.
			slog.Warn("person's uid or gid changed in the directory", "user", name,
				"uid", person.UID, "newUID", d.UID, "gid", person.GID, "newGID", d.GID)
			updated.UID, updated.GID = d.UID, d.GID
		}
	} else {
		updated.Admin = false
	}
	changed = p.accessChanged(person, updated) || person.Admin != updated.Admin
	if err := p.store.PutPerson(name, updated); err != nil {
		return false, 0, err
	}
	if updated.Disabled {
		if ended, err = p.store.EndSessions(name); err != nil {
			return false, 0, err
		}
	}
	if changed {
		if updated.Disabled {
			slog.Warn("directory disabled person: suspending their sessions, keys and file access",
				"user", name, "reason", updated.DisabledReason, "sessions", ended)
		} else if person.Disabled {
			slog.Warn("directory re-enabled person: restoring their keys and file access", "user", name)
		} else {
			slog.Info("person's groups or admin rights changed in the directory", "user", name,
				"groups", updated.Groups, "admin", updated.Admin)
		}
	}
	return changed, ended, nil
}

var errNoDirectory = userErr("There's no directory to check people against: only LDAP people can be checked.")

// CheckPerson asks the directory about one person now and applies the
// answer: disabling them ends their sessions and suspends their keys and
// file access; re-enabling restores them.
func (p *Portal) CheckPerson(ctx context.Context, name string) (PersonStatus, error) {
	if p.dir == nil {
		return PersonStatus{}, errNoDirectory
	}
	person, ok := p.store.Person(name)
	if !ok {
		return PersonStatus{User: name}, nil
	}
	if person.Source != "ldap" {
		return statusOf(name, person, len(p.store.KeysFor(name))), userErr("%s logs in with OIDC, so the directory can't be asked about them.", name)
	}
	d, err := p.dir.Check(name)
	if err != nil {
		return PersonStatus{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	person, _ = p.store.Person(name)
	changed, ended, err := p.applyDir(name, person, d)
	if err != nil {
		return PersonStatus{}, err
	}
	if changed {
		if err := p.syncAll(ctx); err != nil {
			return PersonStatus{}, err
		}
	}
	person, _ = p.store.Person(name)
	st := statusOf(name, person, len(p.store.KeysFor(name)))
	st.Changed, st.EndedSessions = changed, ended
	return st, nil
}

// SyncReport is what a whole-directory sync did.
type SyncReport struct {
	Checked  int            `json:"checked"`
	Changed  []PersonStatus `json:"changed"`
	Disabled int            `json:"disabled"`
	Took     string         `json:"took"`
}

// SyncDirectory checks everyone who logs in with LDAP against the
// directory at once.
func (p *Portal) SyncDirectory(ctx context.Context) (SyncReport, error) {
	if p.dir == nil {
		return SyncReport{}, errNoDirectory
	}
	start := time.Now()
	all, err := p.dir.CheckAll()
	if err != nil {
		return SyncReport{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	report := SyncReport{Changed: []PersonStatus{}}
	any := false
	people := p.store.People()
	for _, name := range sortedKeys(people) {
		person := people[name]
		if person.Source != "ldap" {
			continue
		}
		d, found := all[name]
		if !found {
			d = DirEntry{Disabled: true, Reason: "not in the directory"}
		}
		changed, ended, err := p.applyDir(name, person, d)
		if err != nil {
			return report, err
		}
		report.Checked++
		if d.Disabled {
			report.Disabled++
		}
		if changed || ended > 0 {
			updated, _ := p.store.Person(name)
			st := statusOf(name, updated, len(p.store.KeysFor(name)))
			st.Changed, st.EndedSessions = changed, ended
			report.Changed = append(report.Changed, st)
		}
		any = any || changed
	}
	if any {
		if err := p.syncAll(ctx); err != nil {
			return report, err
		}
	}
	report.Took = time.Since(start).Round(time.Millisecond).String()
	return report, nil
}

// PollDirectory syncs with the directory every interval until ctx ends.
func (p *Portal) PollDirectory(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		report, err := p.SyncDirectory(ctx)
		if err != nil {
			slog.Error("directory sync", "err", err)
			continue
		}
		if len(report.Changed) > 0 {
			slog.Info("directory sync", "checked", report.Checked, "changed", len(report.Changed), "took", report.Took)
		}
	}
}

// --------------------------------------------------------------- access

// BucketView is a bucket as one person sees it.
type BucketView struct {
	Name string
	// Owner is the owning person's username, or "" if no person owns it.
	Owner string
	Caps  Caps
	// Via is how a person who doesn't own it got access: the group grants
	// that apply to them.
	Via []string
	// Manage is whether they may change its grants or delete it.
	Manage bool
}

// Level names the access, for display.
func (b BucketView) Level() string { return capsLabel(b.Caps) }

func capsLabel(c Caps) string {
	for _, p := range Perms {
		if p.Caps() == c.norm() {
			return p.Label()
		}
	}
	var parts []string
	if c.Read {
		parts = append(parts, "read")
	}
	if c.Put {
		parts = append(parts, "write")
	} else if c.Create {
		parts = append(parts, "add")
	}
	if c.Delete {
		parts = append(parts, "delete")
	}
	if len(parts) == 0 {
		return "no access"
	}
	return strings.Join(parts, ", ")
}

// access is what person name may do in bucket, owned by ownerAcct, given
// its settings.
func access(name string, person *Person, ownerAcct string, meta *BucketMeta) (Caps, []string) {
	if person == nil || person.Disabled {
		return Caps{}, nil
	}
	if ownerAcct == ownerAccess(name) {
		return PermReadWrite.Caps(), nil
	}
	var c Caps
	var via []string
	for g, perm := range meta.Groups {
		if person.InGroup(g) {
			c = c.Union(perm.Caps())
			via = append(via, g)
		}
	}
	sort.Strings(via)
	return c, via
}

func ownerName(acct string) string {
	name, _ := strings.CutPrefix(acct, ownerPrefix)
	if name == acct {
		return ""
	}
	return name
}

// Buckets returns the buckets u may reach, theirs first.
func (p *Portal) Buckets(ctx context.Context, u User) ([]BucketView, error) {
	all, err := p.listBuckets(ctx)
	if err != nil {
		return nil, err
	}
	person, _ := p.store.Person(u.Name)
	var out []BucketView
	for _, b := range all {
		c, via := access(u.Name, person, b.Owner, p.store.BucketMeta(b.Name))
		if c.None() {
			continue
		}
		owner := ownerName(b.Owner)
		out = append(out, BucketView{Name: b.Name, Owner: owner, Caps: c, Via: via, Manage: owner == u.Name || u.Admin})
	}
	sort.Slice(out, func(i, j int) bool {
		oi, oj := out[i].Owner == u.Name, out[j].Owner == u.Name
		if oi != oj {
			return oi
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// Bucket returns how u sees one bucket, fresh from the gateway when
// fresh is set (for decisions that grant access). Admins may manage every
// bucket, even ones they can't read.
func (p *Portal) Bucket(ctx context.Context, u User, bucket string, fresh bool) (BucketView, error) {
	var all []Bucket
	var err error
	if fresh {
		all, err = p.vgw.ListBuckets(ctx)
	} else {
		all, err = p.listBuckets(ctx)
	}
	if err != nil {
		return BucketView{}, err
	}
	for _, b := range all {
		if b.Name != bucket {
			continue
		}
		person, _ := p.store.Person(u.Name)
		c, via := access(u.Name, person, b.Owner, p.store.BucketMeta(b.Name))
		owner := ownerName(b.Owner)
		v := BucketView{Name: b.Name, Owner: owner, Caps: c, Via: via, Manage: (owner == u.Name && c.Any()) || u.Admin}
		if c.None() && !v.Manage {
			break
		}
		return v, nil
	}
	return BucketView{}, userErr("No such bucket.")
}

// AllBuckets returns every bucket with its owner and grants, for admins.
func (p *Portal) AllBuckets(ctx context.Context) ([]BucketSummary, error) {
	all, err := p.listBuckets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]BucketSummary, 0, len(all))
	for _, b := range all {
		out = append(out, BucketSummary{Name: b.Name, Owner: ownerName(b.Owner), Groups: p.store.BucketMeta(b.Name).Groups})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// BucketSummary is a bucket on the admin page.
type BucketSummary struct {
	Name   string
	Owner  string
	Groups map[string]Perm
}

// ---------------------------------------------------------------- buckets

// ensureOwner creates the user's owner account if it doesn't exist.
func (p *Portal) ensureOwner(ctx context.Context, u User) error {
	accounts, err := p.vgw.ListAccounts(ctx)
	if err != nil {
		return err
	}
	for _, a := range accounts {
		if a.Access == ownerAccess(u.Name) {
			return nil
		}
	}
	return p.vgw.CreateAccount(ctx, Account{
		Access: ownerAccess(u.Name), Secret: newSecret(), Role: "user",
		UserID: u.UID, GroupID: u.GID,
	})
}

// BindSubject ties username to an OIDC identity the first time it logs in,
// and refuses a different identity later.
func (p *Portal) BindSubject(username, subject string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	bound, ok := p.store.Subject(username)
	if ok {
		if bound != subject {
			return userErr("The username %q already belongs to a different account. Ask an admin for help.", username)
		}
		return nil
	}
	if err := p.store.PutSubject(username, subject); err != nil {
		return err
	}
	slog.Info("bound username to OIDC identity", "user", username, "subject", subject)
	return nil
}

func (p *Portal) CreateBucket(ctx context.Context, u User, name string) error {
	if !bucketRe.MatchString(name) {
		return userErr("Bucket names are 3 to 63 lowercase letters, digits and hyphens, starting and ending with a letter or digit.")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureOwner(ctx, u); err != nil {
		return err
	}
	err := p.vgw.CreateBucket(ctx, name, ownerAccess(u.Name))
	p.forgetBuckets()
	if IsCode(err, "BucketAlreadyExists") || IsCode(err, "BucketAlreadyOwnedByYou") {
		return userErr("A bucket called %q already exists.", name)
	}
	if err != nil {
		return err
	}
	slog.Info("created bucket", "user", u.Name, "bucket", name)
	// Settings left over from an older bucket of the same name don't apply.
	if err := p.store.PutBucketMeta(name, &BucketMeta{}); err != nil {
		return err
	}
	// So the file browser can open it.
	if _, err := p.ensureWeb(ctx, u); err != nil {
		return err
	}
	return p.syncBuckets(ctx, []string{name})
}

func (p *Portal) DeleteBucket(ctx context.Context, u User, name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, err := p.Bucket(ctx, u, name, true)
	if err != nil {
		return err
	}
	if !v.Manage {
		return userErr("Only the bucket's owner or an admin can delete it.")
	}
	err = p.vgw.DeleteBucket(ctx, name)
	p.forgetBuckets()
	if IsCode(err, "BucketNotEmpty") {
		return userErr("Bucket %q isn't empty. Delete its contents first.", name)
	}
	if err != nil {
		return err
	}
	delete(p.written, name)
	for _, e := range p.store.Entries() {
		if _, ok := e.Buckets[name]; ok {
			delete(e.Buckets, name)
			if err := p.store.Put(e.Access, e.Key); err != nil {
				return err
			}
		}
	}
	if err := p.store.PutBucketMeta(name, &BucketMeta{}); err != nil {
		return err
	}
	slog.Info("deleted bucket", "user", u.Name, "bucket", name)
	return nil
}

var groupNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,63}$`)

// SetGroupGrant gives group a level of access to bucket, or with perm ""
// takes it away. Only the bucket's owner and admins may.
func (p *Portal) SetGroupGrant(ctx context.Context, u User, bucket, group string, perm Perm) error {
	group = strings.TrimSpace(group)
	if !groupNameRe.MatchString(group) {
		return userErr("That isn't a group name.")
	}
	if perm != "" && !perm.Valid() {
		return userErr("Pick a level of access.")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	v, err := p.Bucket(ctx, u, bucket, true)
	if err != nil {
		return err
	}
	if !v.Manage {
		return userErr("Only the bucket's owner or an admin can change who has access.")
	}
	meta := p.store.BucketMeta(bucket)
	// Group names compare without case; keep one spelling.
	for g := range meta.Groups {
		if strings.EqualFold(g, group) {
			delete(meta.Groups, g)
		}
	}
	if perm != "" {
		meta.Groups[group] = perm
	}
	if err := p.store.PutBucketMeta(bucket, meta); err != nil {
		return err
	}
	// Members need web accounts to browse it.
	if perm != "" {
		for name, person := range p.store.People() {
			if person.InGroup(group) && !person.Disabled {
				if _, err := p.ensureWebFor(ctx, name, person); err != nil {
					return err
				}
			}
		}
	}
	if err := p.syncBuckets(ctx, []string{bucket}); err != nil {
		return err
	}
	slog.Info("changed group access", "user", u.Name, "bucket", bucket, "group", group, "perm", perm)
	return nil
}

// Groups lists groups that can be granted access: the directory's, plus
// any the portal has seen.
func (p *Portal) Groups() []string {
	seen := map[string]string{}
	for _, g := range p.store.KnownGroups() {
		seen[strings.ToLower(g)] = g
	}
	if p.dir != nil {
		if groups, err := p.dir.Groups(); err == nil {
			for _, g := range groups {
				seen[strings.ToLower(g)] = g
			}
		} else {
			slog.Warn("list directory groups", "err", err)
		}
	}
	out := make([]string, 0, len(seen))
	for _, g := range seen {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// ------------------------------------------------------------------- keys

func (p *Portal) Keys(u User) []KeyEntry { return p.store.KeysFor(u.Name) }

func (p *Portal) Key(u User, access string) (*Key, error) {
	k, ok := p.store.Get(access)
	if !ok || k.Owner != u.Name {
		return nil, userErr("No such key.")
	}
	return k, nil
}

// KeyAccess is what a key can do in each bucket it asked for right now,
// which is less than it asked for when its owner has lost access.
func (p *Portal) KeyAccess(ctx context.Context, k *Key) map[string]Caps {
	all, err := p.listBuckets(ctx)
	if err != nil {
		return nil
	}
	owners := map[string]string{}
	for _, b := range all {
		owners[b.Name] = b.Owner
	}
	person, _ := p.store.Person(k.Owner)
	out := map[string]Caps{}
	for b, perm := range k.Buckets {
		c, _ := access(k.Owner, person, owners[b], p.store.BucketMeta(b))
		out[b] = perm.Caps().Intersect(c)
	}
	return out
}

// checkGrants makes sure u may give a key each level in grants. It asks
// the gateway rather than the cache, since it decides what a key can
// reach.
func (p *Portal) checkGrants(ctx context.Context, u User, grants map[string]Perm) error {
	for b, perm := range grants {
		if !perm.Valid() {
			return userErr("Pick a level of access for %s.", b)
		}
		v, err := p.Bucket(ctx, u, b, true)
		if err != nil || !v.Caps.Covers(perm.Caps()) {
			return userErr("You can't give a key %s access to %s: that's more than you have.", perm.Label(), b)
		}
	}
	return nil
}

func cleanLabel(label string) (string, error) {
	label = strings.TrimSpace(label)
	if label == "" || len(label) > 64 {
		return "", userErr("Give the key a name of up to 64 characters, so you know what it's for.")
	}
	return label, nil
}

// CreateKey issues a new access key for u and returns its secret, which
// isn't shown again.
func (p *Portal) CreateKey(ctx context.Context, u User, label string, grants map[string]Perm) (string, string, error) {
	label, err := cleanLabel(label)
	if err != nil {
		return "", "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkGrants(ctx, u, grants); err != nil {
		return "", "", err
	}

	access, secret := newAccessKey(), newSecret()
	if err := p.vgw.CreateAccount(ctx, Account{
		Access: access, Secret: secret, Role: "user", UserID: u.UID, GroupID: u.GID,
	}); err != nil {
		return "", "", err
	}
	if err := p.store.Put(access, &Key{Owner: u.Name, Label: label, Created: time.Now().UTC(), Buckets: grants}); err != nil {
		p.vgw.DeleteAccount(ctx, access)
		return "", "", err
	}
	if err := p.syncBuckets(ctx, keys(grants)); err != nil {
		p.store.Delete(access)
		p.syncBuckets(ctx, keys(grants))
		p.vgw.DeleteAccount(ctx, access)
		return "", "", err
	}
	slog.Info("created key", "user", u.Name, "access", access, "label", label, "buckets", grants)
	return access, secret, nil
}

func (p *Portal) UpdateKey(ctx context.Context, u User, access, label string, grants map[string]Perm) error {
	label, err := cleanLabel(label)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k, ok := p.store.Get(access)
	if !ok || k.Owner != u.Name {
		return userErr("No such key.")
	}
	// Grants the key already has may stay even if they're more than its
	// owner has now (they're limited when policies are written); new or
	// raised ones must be covered.
	changed := map[string]Perm{}
	for b, perm := range grants {
		if k.Buckets[b] != perm {
			changed[b] = perm
		}
	}
	if err := p.checkGrants(ctx, u, changed); err != nil {
		return err
	}
	affected := append(keys(k.Buckets), keys(grants)...)
	updated := &Key{Owner: k.Owner, Label: label, Created: k.Created, Buckets: grants}
	if err := p.store.Put(access, updated); err != nil {
		return err
	}
	if err := p.syncBuckets(ctx, affected); err != nil {
		return err
	}
	slog.Info("updated key", "user", u.Name, "access", access, "label", label, "buckets", grants)
	return nil
}

func (p *Portal) DeleteKey(ctx context.Context, u User, access string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	k, ok := p.store.Get(access)
	if !ok || k.Owner != u.Name {
		return userErr("No such key.")
	}
	if err := p.revoke(ctx, []string{access}); err != nil {
		return err
	}
	slog.Info("deleted key", "user", u.Name, "access", access)
	return nil
}

// revoke deletes keys from the store, the bucket policies and the gateway.
// Callers hold p.mu.
func (p *Portal) revoke(ctx context.Context, accesses []string) error {
	var affected []string
	for _, access := range accesses {
		k, ok := p.store.Get(access)
		if !ok {
			continue
		}
		affected = append(affected, keys(k.Buckets)...)
		if err := p.store.Delete(access); err != nil {
			return err
		}
	}
	// Policies before accounts: the gateway rejects policies naming accounts
	// that don't exist.
	if err := p.syncBuckets(ctx, affected); err != nil {
		return err
	}
	var errs []error
	for _, access := range accesses {
		if err := p.vgw.DeleteAccount(ctx, access); err != nil {
			errs = append(errs, fmt.Errorf("delete account %s: %w", access, err))
		}
	}
	return errors.Join(errs...)
}

// AllKeys returns every issued key, for admins.
func (p *Portal) AllKeys() []KeyEntry { return p.store.Entries() }

// RevokeKey revokes any key, for admins.
func (p *Portal) RevokeKey(ctx context.Context, admin User, access string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	k, ok := p.store.Get(access)
	if !ok {
		return userErr("No such key.")
	}
	if err := p.revoke(ctx, []string{access}); err != nil {
		return err
	}
	slog.Warn("admin revoked key", "admin", admin.Name, "user", k.Owner, "access", access)
	return nil
}

// RevokeKeys revokes every key, or with owner set every key of theirs, for
// admins. It returns how many it revoked.
func (p *Portal) RevokeKeys(ctx context.Context, admin User, owner string) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var accesses []string
	for _, e := range p.store.Entries() {
		if owner == "" || e.Owner == owner {
			accesses = append(accesses, e.Access)
		}
	}
	if err := p.revoke(ctx, accesses); err != nil {
		return 0, err
	}
	slog.Warn("admin revoked keys", "admin", admin.Name, "owner", owner, "count", len(accesses))
	return len(accesses), nil
}

// EndSessions logs someone out everywhere, for admins.
func (p *Portal) EndSessions(admin User, name string) (int, error) {
	n, err := p.store.EndSessions(name)
	if err == nil {
		slog.Warn("admin ended sessions", "admin", admin.Name, "user", name, "count", n)
	}
	return n, err
}

// ---------------------------------------------------------------- policies

// syncAll rewrites every bucket's policy that needs it. Callers hold p.mu.
func (p *Portal) syncAll(ctx context.Context) error {
	all, err := p.vgw.ListBuckets(ctx)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(all))
	for _, b := range all {
		names = append(names, b.Name)
	}
	return p.syncBuckets(ctx, names)
}

// syncBuckets rewrites the named buckets' policies. Callers hold p.mu.
func (p *Portal) syncBuckets(ctx context.Context, buckets []string) error {
	if len(buckets) == 0 {
		return nil
	}
	all, err := p.vgw.ListBuckets(ctx)
	if err != nil {
		return err
	}
	owners := map[string]string{}
	for _, b := range all {
		owners[b.Name] = b.Owner
	}
	people := p.store.People()
	done := map[string]bool{}
	var errs []error
	for _, b := range buckets {
		if done[b] {
			continue
		}
		done[b] = true
		owner, exists := owners[b]
		if !exists {
			continue
		}
		if err := p.syncBucket(ctx, b, owner, people); err != nil {
			errs = append(errs, fmt.Errorf("update policy for %s: %w", b, err))
		}
	}
	return errors.Join(errs...)
}

// policyGrants is who gets what in bucket: each key, limited to what its
// owner may do there now, and each person's web account.
func (p *Portal) policyGrants(bucket, owner string, people map[string]*Person) map[string]Caps {
	meta := p.store.BucketMeta(bucket)
	grants := map[string]Caps{}
	for acct, g := range p.store.Grants(bucket) {
		c, _ := access(g.Owner, people[g.Owner], owner, meta)
		if c = g.Perm.Caps().Intersect(c); c.Any() {
			grants[acct] = c
		}
	}
	for _, name := range p.store.WebUsers() {
		w, _ := p.store.Web(name)
		if c, _ := access(name, people[name], owner, meta); c.Any() {
			grants[w.Access] = c
		}
	}
	return grants
}

// syncBucket writes bucket's policy if it differs from what was last
// written. Callers hold p.mu.
func (p *Portal) syncBucket(ctx context.Context, bucket, owner string, people map[string]*Person) error {
	policy := BucketPolicy(bucket, p.policyGrants(bucket, owner, people))
	sum := sha256.Sum256(policy)
	if last, ok := p.written[bucket]; ok && last == sum {
		return nil
	}
	var err error
	if policy == nil {
		err = p.vgw.DeleteBucketPolicy(ctx, bucket)
		if IsCode(err, "NoSuchBucketPolicy") || IsCode(err, "NoSuchBucket") {
			err = nil
		}
	} else {
		err = p.vgw.PutBucketPolicy(ctx, bucket, policy)
	}
	if err != nil {
		delete(p.written, bucket)
		return err
	}
	p.written[bucket] = sum
	return nil
}

// Reconcile brings the gateway in line with the store at startup: it drops
// keys and web accounts the gateway no longer has and grants on buckets
// that are gone, then rewrites every bucket's policy.
func (p *Portal) Reconcile(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.written = map[string][32]byte{}
	accounts, err := p.vgw.ListAccounts(ctx)
	if err != nil {
		return err
	}
	exists := map[string]bool{}
	for _, a := range accounts {
		exists[a.Access] = true
	}
	buckets, err := p.vgw.ListBuckets(ctx)
	if err != nil {
		return err
	}
	bucketExists := map[string]bool{}
	for _, b := range buckets {
		bucketExists[b.Name] = true
	}

	for _, user := range p.store.WebUsers() {
		if w, _ := p.store.Web(user); !exists[w.Access] {
			slog.Warn("dropping web account missing from the gateway", "user", user)
			if err := p.store.DeleteWeb(user); err != nil {
				return err
			}
		}
	}
	for _, e := range p.store.Entries() {
		if !exists[e.Access] {
			slog.Warn("dropping key missing from the gateway", "access", e.Access, "user", e.Owner)
			if err := p.store.Delete(e.Access); err != nil {
				return err
			}
			continue
		}
		changed := false
		for b := range e.Buckets {
			if !bucketExists[b] {
				slog.Warn("dropping grant on a bucket that's gone", "access", e.Access, "bucket", b)
				delete(e.Buckets, b)
				changed = true
			}
		}
		if changed {
			if err := p.store.Put(e.Access, e.Key); err != nil {
				return err
			}
		}
	}
	for _, b := range p.store.BucketsWithMeta() {
		if !bucketExists[b] {
			if err := p.store.PutBucketMeta(b, &BucketMeta{}); err != nil {
				return err
			}
		}
	}
	return p.syncAll(ctx)
}

// ------------------------------------------------------------ file browser

// ensureWeb returns u's web account, creating it and opening their buckets
// to it if it's new. Callers hold p.mu.
func (p *Portal) ensureWeb(ctx context.Context, u User) (*WebAccount, error) {
	person, ok := p.store.Person(u.Name)
	if !ok {
		person = &Person{UID: u.UID, GID: u.GID}
	}
	return p.ensureWebFor(ctx, u.Name, person)
}

func (p *Portal) ensureWebFor(ctx context.Context, name string, person *Person) (*WebAccount, error) {
	if w, ok := p.store.Web(name); ok {
		return w, nil
	}
	w := &WebAccount{Access: webAccess(name), Secret: newSecret()}
	// Left over if the portal's state was lost: its secret went with it.
	p.vgw.DeleteAccount(ctx, w.Access)
	if err := p.vgw.CreateAccount(ctx, Account{
		Access: w.Access, Secret: w.Secret, Role: "user", UserID: person.UID, GroupID: person.GID,
	}); err != nil {
		return nil, err
	}
	if err := p.store.PutWeb(name, w); err != nil {
		return nil, err
	}
	if err := p.syncAll(ctx); err != nil {
		return nil, err
	}
	slog.Info("created web account", "user", name)
	return w, nil
}

// browser checks u may reach bucket and returns a client acting as their
// web account, so the gateway's policy confines it too, and what they may
// do there.
func (p *Portal) browser(ctx context.Context, u User, bucket string) (*VGW, Caps, error) {
	v, err := p.Bucket(ctx, u, bucket, false)
	if err != nil {
		return nil, Caps{}, err
	}
	if v.Caps.None() {
		return nil, Caps{}, userErr("You don't have access to the files in %s.", bucket)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	w, err := p.ensureWeb(ctx, u)
	if err != nil {
		return nil, Caps{}, err
	}
	return p.vgw.As(w.Access, w.Secret), v.Caps, nil
}

// checkKey rejects object keys the browser shouldn't make: empty, too long,
// not UTF-8, or with control characters.
func checkKey(key string) error {
	if key == "" || len(key) > 1024 || !utf8.ValidString(key) || strings.HasPrefix(key, "/") {
		return userErr("That isn't a usable file name.")
	}
	for _, r := range key {
		if unicode.IsControl(r) {
			return userErr("File names can't contain control characters.")
		}
	}
	return nil
}

// checkPrefix accepts "" (the bucket's top) or a folder path ending in /.
func checkPrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	if !strings.HasSuffix(prefix, "/") {
		return userErr("That isn't a folder.")
	}
	return checkKey(prefix)
}

const pageSize = 500

func (p *Portal) ListObjects(ctx context.Context, u User, bucket, prefix, token string) (*ObjectList, error) {
	if err := checkPrefix(prefix); err != nil {
		return nil, err
	}
	v, caps, err := p.browser(ctx, u, bucket)
	if err != nil {
		return nil, err
	}
	if !caps.Read {
		return nil, errNoList
	}
	list, err := v.ListObjects(ctx, bucket, prefix, "/", token, pageSize)
	if err != nil {
		return nil, err
	}
	// A folder's own marker object isn't a file in it.
	objects := list.Objects[:0]
	for _, o := range list.Objects {
		if o.Key != prefix {
			objects = append(objects, o)
		}
	}
	list.Objects = objects
	return list, nil
}

var errNoList = userErr("You can upload here, but not see what's in it.")

// GetObject returns the object's response for the caller to stream and close.
func (p *Portal) GetObject(ctx context.Context, u User, bucket, key string) (*http.Response, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	v, caps, err := p.browser(ctx, u, bucket)
	if err != nil {
		return nil, err
	}
	if !caps.Read {
		return nil, userErr("You can't download from %s.", bucket)
	}
	resp, err := v.GetObject(ctx, bucket, key)
	if IsCode(err, "NoSuchKey") {
		return nil, userErr("That file is gone.")
	}
	return resp, err
}

func (p *Portal) PutObject(ctx context.Context, u User, bucket, key string, body io.Reader, length int64, contentType string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	v, caps, err := p.browser(ctx, u, bucket)
	if err != nil {
		return err
	}
	if !caps.Put && !caps.Create {
		return userErr("You can't upload to %s.", bucket)
	}
	// Add-only access may create objects but not replace them.
	createOnly := !caps.Put
	err = v.PutObject(ctx, bucket, key, body, length, contentType, createOnly)
	if IsCode(err, "PreconditionFailed") {
		return userErr("%s already exists, and you can only add new files here.", key)
	}
	if err != nil {
		return err
	}
	slog.Info("uploaded", "user", u.Name, "bucket", bucket, "key", key, "size", length)
	return nil
}

// CreateFolder makes an empty folder under prefix, which S3 keeps as an
// empty object named for it.
func (p *Portal) CreateFolder(ctx context.Context, u User, bucket, prefix, name string) error {
	name = strings.TrimSpace(name)
	if name == "" || strings.Contains(name, "/") || name == "." || name == ".." {
		return userErr("Folder names can't be empty or contain /.")
	}
	if err := checkPrefix(prefix); err != nil {
		return err
	}
	return p.PutObject(ctx, u, bucket, prefix+name+"/", nil, 0, "")
}

func (p *Portal) DeleteObject(ctx context.Context, u User, bucket, key string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	v, caps, err := p.browser(ctx, u, bucket)
	if err != nil {
		return err
	}
	if !caps.Delete {
		return userErr("You can't delete files in %s.", bucket)
	}
	if err := v.DeleteObject(ctx, bucket, key); err != nil {
		return err
	}
	slog.Info("deleted object", "user", u.Name, "bucket", bucket, "key", key)
	return nil
}

// DeleteFolder deletes everything under prefix, and returns how many objects
// it deleted.
func (p *Portal) DeleteFolder(ctx context.Context, u User, bucket, prefix string) (int, error) {
	if prefix == "" {
		return 0, userErr("Delete the bucket itself instead.")
	}
	if err := checkPrefix(prefix); err != nil {
		return 0, err
	}
	v, caps, err := p.browser(ctx, u, bucket)
	if err != nil {
		return 0, err
	}
	if !caps.Delete || !caps.Read {
		return 0, userErr("You can't delete files in %s.", bucket)
	}
	deleted := 0
	for {
		// From the start each time: the previous page is gone.
		list, err := v.ListObjects(ctx, bucket, prefix, "", "", pageSize)
		if err != nil {
			return deleted, err
		}
		if len(list.Objects) == 0 {
			break
		}
		for _, o := range list.Objects {
			if err := v.DeleteObject(ctx, bucket, o.Key); err != nil {
				return deleted, err
			}
			deleted++
		}
	}
	slog.Info("deleted folder", "user", u.Name, "bucket", bucket, "prefix", prefix, "objects", deleted)
	return deleted, nil
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := keys(m)
	sort.Strings(out)
	return out
}
