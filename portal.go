package main

import (
	"context"
	"crypto/rand"
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

// Owner accounts own a user's buckets. Their secrets are thrown away, so
// nobody can sign as them: users reach their buckets only through keys the
// portal grants with bucket policies.
const ownerPrefix = "owner."

func ownerAccess(username string) string { return ownerPrefix + username }

// Web accounts are how the file browser reaches a person's buckets: each
// bucket's policy gives its owner's web account read & write.
const webPrefix = "web."

func webAccess(username string) string { return webPrefix + username }

var bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

// UserError is a problem to show the user rather than log.
type UserError struct{ Msg string }

func (e *UserError) Error() string { return e.Msg }

func userErr(format string, args ...any) error { return &UserError{fmt.Sprintf(format, args...)} }

type Portal struct {
	mu    sync.Mutex
	vgw   *VGW
	store *Store

	// The gateway's bucket list, kept briefly: every page and file
	// operation checks who owns what, and listing every bucket each time
	// is most of the latency. The portal drops it whenever it creates or
	// deletes a bucket; only buckets changed behind its back can be stale,
	// for at most bucketCacheTTL.
	cacheMu      sync.Mutex
	bucketCache  []Bucket
	bucketCached time.Time
}

const bucketCacheTTL = 5 * time.Second

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

func NewPortal(vgw *VGW, store *Store) *Portal {
	return &Portal{vgw: vgw, store: store}
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

// Buckets returns the names of the buckets u owns.
func (p *Portal) Buckets(ctx context.Context, u User) ([]string, error) {
	buckets, err := p.listBuckets(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, b := range buckets {
		if b.Owner == ownerAccess(u.Name) {
			out = append(out, b.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (p *Portal) ownsBucket(ctx context.Context, u User, bucket string) (bool, error) {
	buckets, err := p.Buckets(ctx, u)
	if err != nil {
		return false, err
	}
	for _, b := range buckets {
		if b == bucket {
			return true, nil
		}
	}
	return false, nil
}

func (p *Portal) Keys(u User) []KeyEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.store.KeysFor(u.Name)
}

func (p *Portal) Key(u User, access string) (*Key, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k, ok := p.store.Get(access)
	if !ok || k.Owner != u.Name {
		return nil, userErr("No such key.")
	}
	copied := *k
	return &copied, nil
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
	// So the file browser can open it.
	if _, err := p.ensureWeb(ctx, u); err != nil {
		return err
	}
	return p.syncBuckets(ctx, []string{name})
}

func (p *Portal) DeleteBucket(ctx context.Context, u User, name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	owns, err := p.ownsBucket(ctx, u, name)
	if err != nil {
		return err
	}
	if !owns {
		return userErr("No such bucket.")
	}
	err = p.vgw.DeleteBucket(ctx, name)
	p.forgetBuckets()
	if IsCode(err, "BucketNotEmpty") {
		return userErr("Bucket %q isn't empty. Delete its contents first.", name)
	}
	if err != nil {
		return err
	}
	for _, e := range p.store.KeysFor(u.Name) {
		if _, ok := e.Buckets[name]; ok {
			delete(e.Buckets, name)
			if err := p.store.Put(e.Access, e.Key); err != nil {
				return err
			}
		}
	}
	slog.Info("deleted bucket", "user", u.Name, "bucket", name)
	return nil
}

// checkGrants makes sure u owns every bucket in grants. It asks the gateway
// rather than the cache, since it decides what a key can reach.
func (p *Portal) checkGrants(ctx context.Context, u User, grants map[string]Perm) error {
	all, err := p.vgw.ListBuckets(ctx)
	if err != nil {
		return err
	}
	ownedSet := map[string]bool{}
	for _, b := range all {
		if b.Owner == ownerAccess(u.Name) {
			ownedSet[b.Name] = true
		}
	}
	for b, perm := range grants {
		if !ownedSet[b] || !perm.Valid() {
			return userErr("You can only grant access to your own buckets.")
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
	if err := p.checkGrants(ctx, u, grants); err != nil {
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
func (p *Portal) AllKeys() []KeyEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.store.Entries()
}

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
	done := map[string]bool{}
	for _, b := range buckets {
		if done[b] {
			continue
		}
		done[b] = true
		if err := p.syncBucket(ctx, b, owners[b]); err != nil {
			return fmt.Errorf("update policy for %s: %w", b, err)
		}
	}
	return nil
}

// syncBucket writes bucket's policy: its keys' grants, and read & write for
// its owner's web account.
func (p *Portal) syncBucket(ctx context.Context, bucket, owner string) error {
	grants := p.store.Grants(bucket)
	if user, ok := strings.CutPrefix(owner, ownerPrefix); ok {
		if w, ok := p.store.Web(user); ok {
			grants[w.Access] = PermReadWrite
		}
	}
	policy := BucketPolicy(bucket, grants)
	if policy == nil {
		err := p.vgw.DeleteBucketPolicy(ctx, bucket)
		if IsCode(err, "NoSuchBucketPolicy") || IsCode(err, "NoSuchBucket") {
			return nil
		}
		return err
	}
	return p.vgw.PutBucketPolicy(ctx, bucket, policy)
}

// Reconcile brings the gateway in line with the store at startup: it drops
// keys the gateway no longer has and grants on buckets their owner no longer
// owns, then rewrites the policy of every user-owned bucket.
func (p *Portal) Reconcile(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
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
	owner := map[string]string{}
	for _, b := range buckets {
		owner[b.Name] = b.Owner
	}

	for _, user := range p.store.WebUsers() {
		if w, _ := p.store.Web(user); !exists[w.Access] {
			slog.Warn("dropping web account missing from the gateway", "user", user)
			if err := p.store.DeleteWeb(user); err != nil {
				return err
			}
		}
	}

	for _, access := range p.store.AllKeys() {
		k, _ := p.store.Get(access)
		if !exists[access] {
			slog.Warn("dropping key missing from the gateway", "access", access, "user", k.Owner)
			if err := p.store.Delete(access); err != nil {
				return err
			}
			continue
		}
		changed := false
		for b := range k.Buckets {
			if owner[b] != ownerAccess(k.Owner) {
				slog.Warn("dropping grant on bucket the key's owner doesn't own", "access", access, "bucket", b)
				delete(k.Buckets, b)
				changed = true
			}
		}
		if changed {
			if err := p.store.Put(access, k); err != nil {
				return err
			}
		}
	}

	var owned []string
	for _, b := range buckets {
		if strings.HasPrefix(b.Owner, ownerPrefix) {
			owned = append(owned, b.Name)
		}
	}
	return p.syncBuckets(ctx, owned)
}

// ensureWeb returns u's web account, creating it and opening their buckets
// to it if it's new. Callers hold p.mu.
func (p *Portal) ensureWeb(ctx context.Context, u User) (*WebAccount, error) {
	if w, ok := p.store.Web(u.Name); ok {
		return w, nil
	}
	w := &WebAccount{Access: webAccess(u.Name), Secret: newSecret()}
	// Left over if the portal's state was lost: its secret went with it.
	p.vgw.DeleteAccount(ctx, w.Access)
	if err := p.vgw.CreateAccount(ctx, Account{
		Access: w.Access, Secret: w.Secret, Role: "user", UserID: u.UID, GroupID: u.GID,
	}); err != nil {
		return nil, err
	}
	if err := p.store.PutWeb(u.Name, w); err != nil {
		return nil, err
	}
	buckets, err := p.Buckets(ctx, u)
	if err != nil {
		return nil, err
	}
	if err := p.syncBuckets(ctx, buckets); err != nil {
		return nil, err
	}
	slog.Info("created web account", "user", u.Name)
	return w, nil
}

// browser checks u owns bucket and returns a client acting as their web
// account, so the gateway's policy confines it to their buckets too.
func (p *Portal) browser(ctx context.Context, u User, bucket string) (*VGW, error) {
	owns, err := p.ownsBucket(ctx, u, bucket)
	if err != nil {
		return nil, err
	}
	if !owns {
		return nil, userErr("No such bucket.")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	w, err := p.ensureWeb(ctx, u)
	if err != nil {
		return nil, err
	}
	return p.vgw.As(w.Access, w.Secret), nil
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
	v, err := p.browser(ctx, u, bucket)
	if err != nil {
		return nil, err
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

// GetObject returns the object's response for the caller to stream and close.
func (p *Portal) GetObject(ctx context.Context, u User, bucket, key string) (*http.Response, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	v, err := p.browser(ctx, u, bucket)
	if err != nil {
		return nil, err
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
	v, err := p.browser(ctx, u, bucket)
	if err != nil {
		return err
	}
	if err := v.PutObject(ctx, bucket, key, body, length, contentType); err != nil {
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
	v, err := p.browser(ctx, u, bucket)
	if err != nil {
		return err
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
	v, err := p.browser(ctx, u, bucket)
	if err != nil {
		return 0, err
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
