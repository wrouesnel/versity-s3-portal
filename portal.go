package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Owner accounts own a user's buckets. Their secrets are thrown away, so
// nobody can sign as them: users reach their buckets only through keys the
// portal grants with bucket policies.
const ownerPrefix = "owner."

func ownerAccess(username string) string { return ownerPrefix + username }

var bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

// UserError is a problem to show the user rather than log.
type UserError struct{ Msg string }

func (e *UserError) Error() string { return e.Msg }

func userErr(format string, args ...any) error { return &UserError{fmt.Sprintf(format, args...)} }

type Portal struct {
	mu    sync.Mutex
	vgw   *VGW
	store *Store
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
	buckets, err := p.vgw.ListBuckets(ctx)
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
	if IsCode(err, "BucketAlreadyExists") || IsCode(err, "BucketAlreadyOwnedByYou") {
		return userErr("A bucket called %q already exists.", name)
	}
	if err == nil {
		slog.Info("created bucket", "user", u.Name, "bucket", name)
	}
	return err
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

// checkGrants makes sure u owns every bucket in grants.
func (p *Portal) checkGrants(ctx context.Context, u User, grants map[string]Perm) error {
	owned, err := p.Buckets(ctx, u)
	if err != nil {
		return err
	}
	ownedSet := map[string]bool{}
	for _, b := range owned {
		ownedSet[b] = true
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
	// Policies first: the gateway rejects policies naming accounts that
	// don't exist.
	if err := p.store.Delete(access); err != nil {
		return err
	}
	if err := p.syncBuckets(ctx, keys(k.Buckets)); err != nil {
		return err
	}
	if err := p.vgw.DeleteAccount(ctx, access); err != nil {
		return err
	}
	slog.Info("deleted key", "user", u.Name, "access", access)
	return nil
}

func (p *Portal) syncBuckets(ctx context.Context, buckets []string) error {
	done := map[string]bool{}
	for _, b := range buckets {
		if done[b] {
			continue
		}
		done[b] = true
		if err := p.syncBucket(ctx, b); err != nil {
			return fmt.Errorf("update policy for %s: %w", b, err)
		}
	}
	return nil
}

func (p *Portal) syncBucket(ctx context.Context, bucket string) error {
	policy := BucketPolicy(bucket, p.store.Grants(bucket))
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

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
