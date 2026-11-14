package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Key is the portal's record of an access key it issued. The gateway holds
// the key itself; the portal holds who owns it and what it was granted.
type Key struct {
	Owner   string    `json:"owner"`
	Label   string    `json:"label"`
	Created time.Time `json:"created"`
	// Buckets is what the key was asked to have. What it gets is this
	// limited by what its owner may currently do in each bucket.
	Buckets map[string]Perm `json:"buckets"`
}

// WebAccount is the gateway account the portal acts as for someone in the
// file browser. It carries their uid and gid, so files they upload are
// theirs on disk. Its secret never leaves the portal.
type WebAccount struct {
	Access string `json:"access"`
	Secret string `json:"secret"`
}

// Person is what the portal last learned about someone from the directory
// or their OIDC login.
type Person struct {
	UID    int      `json:"uid"`
	GID    int      `json:"gid"`
	Groups []string `json:"groups,omitempty"`
	Admin  bool     `json:"admin,omitempty"`
	// Source is "ldap" or "oidc": only LDAP people can be re-checked.
	Source string `json:"source"`
	// Disabled, with why, stops their sessions, keys and file browser
	// until the directory says otherwise.
	Disabled       bool      `json:"disabled,omitempty"`
	DisabledReason string    `json:"disabledReason,omitempty"`
	Checked        time.Time `json:"checked"`
}

func (p *Person) InGroup(group string) bool { return containsFold(p.Groups, group) }

// User is the person as a logged-in user.
func (p *Person) User(name string) User {
	return User{Name: name, UID: p.UID, GID: p.GID, Admin: p.Admin}
}

// BucketMeta is the portal's settings for a bucket.
type BucketMeta struct {
	// Groups grants each group a level of access.
	Groups map[string]Perm `json:"groups,omitempty"`
	// Snapshots is how often to snapshot the bucket's dataset, if ever.
	Snapshots SnapshotSchedule `json:"snapshots,omitzero"`
	// ReadOnly holds everyone to reading, whatever they've been granted,
	// while the bucket is being mirrored in.
	ReadOnly bool `json:"readOnly,omitempty"`
}

// SnapshotSchedule takes a snapshot every Every and keeps the latest Keep.
type SnapshotSchedule struct {
	// Every is "hourly", "daily", "weekly", or "" for never.
	Every string `json:"every,omitempty"`
	Keep  int    `json:"keep,omitempty"`
}

func (m *BucketMeta) empty() bool {
	return len(m.Groups) == 0 && m.Snapshots.Every == "" && !m.ReadOnly
}

func copyMeta(m *BucketMeta) *BucketMeta {
	c := &BucketMeta{Groups: map[string]Perm{}, Snapshots: m.Snapshots, ReadOnly: m.ReadOnly}
	for g, p := range m.Groups {
		c.Groups[g] = p
	}
	return c
}

// SessionRecord is a server-side login session.
type SessionRecord struct {
	User    string    `json:"user"`
	CSRF    string    `json:"csrf"`
	Expires time.Time `json:"expires"`
}

type state struct {
	Keys map[string]*Key `json:"keys"`
	// Web is each person's web account, by username.
	Web map[string]*WebAccount `json:"web,omitempty"`
	// Subjects binds each username that has logged in with OIDC to the
	// provider's identity for them, so a second identity that maps to the
	// same username (a renamed account, or the same email local part at
	// another domain) can't take over their buckets and keys.
	Subjects map[string]string         `json:"subjects,omitempty"`
	People   map[string]*Person        `json:"people,omitempty"`
	Buckets  map[string]*BucketMeta    `json:"buckets,omitempty"`
	Sessions map[string]*SessionRecord `json:"sessions,omitempty"`
	// Mirrors are buckets being copied in from another S3 service, and
	// the record of ones that were, by bucket.
	Mirrors map[string]*Mirror `json:"mirrors,omitempty"`
}

// Store is a JSON file of the portal's state. Each method is safe to call
// concurrently; callers that read and then write hold Portal.mu as well.
// Values returned are copies, so callers can't change the store by
// accident.
type Store struct {
	mu    sync.Mutex
	path  string
	state state
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(data, &s.state); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	st := &s.state
	if st.Keys == nil {
		st.Keys = map[string]*Key{}
	}
	if st.Web == nil {
		st.Web = map[string]*WebAccount{}
	}
	if st.Subjects == nil {
		st.Subjects = map[string]string{}
	}
	if st.People == nil {
		st.People = map[string]*Person{}
	}
	if st.Buckets == nil {
		st.Buckets = map[string]*BucketMeta{}
	}
	if st.Sessions == nil {
		st.Sessions = map[string]*SessionRecord{}
	}
	if st.Mirrors == nil {
		st.Mirrors = map[string]*Mirror{}
	}
	return s, nil
}

// save writes the state. Callers hold s.mu.
func (s *Store) save() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func copyKey(k *Key) *Key {
	c := *k
	c.Buckets = make(map[string]Perm, len(k.Buckets))
	for b, p := range k.Buckets {
		c.Buckets[b] = p
	}
	return &c
}

func copyPerson(p *Person) *Person {
	c := *p
	c.Groups = append([]string(nil), p.Groups...)
	return &c
}

// ---------------------------------------------------------------- keys

func (s *Store) Get(access string) (*Key, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.state.Keys[access]
	if !ok {
		return nil, false
	}
	return copyKey(k), true
}

func (s *Store) Put(access string, k *Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Keys[access] = copyKey(k)
	return s.save()
}

func (s *Store) Delete(access string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Keys, access)
	return s.save()
}

// KeyEntry is a key with its access key ID.
type KeyEntry struct {
	Access string
	*Key
}

// Entries returns every key, by owner and then oldest first.
func (s *Store) Entries() []KeyEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]KeyEntry, 0, len(s.state.Keys))
	for access, k := range s.state.Keys {
		out = append(out, KeyEntry{access, copyKey(k)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Owner != out[j].Owner {
			return out[i].Owner < out[j].Owner
		}
		return out[i].Created.Before(out[j].Created)
	})
	return out
}

// AllKeys returns every access key ID.
func (s *Store) AllKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sortedKeys(s.state.Keys)
}

// KeysFor returns owner's keys, oldest first.
func (s *Store) KeysFor(owner string) []KeyEntry {
	var out []KeyEntry
	for _, e := range s.Entries() {
		if e.Owner == owner {
			out = append(out, e)
		}
	}
	return out
}

// Grants returns the keys asking for access to bucket.
func (s *Store) Grants(bucket string) map[string]KeyGrant {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]KeyGrant{}
	for access, k := range s.state.Keys {
		if p, ok := k.Buckets[bucket]; ok {
			out[access] = KeyGrant{Owner: k.Owner, Perm: p}
		}
	}
	return out
}

// KeyGrant is one key's request for access to a bucket.
type KeyGrant struct {
	Owner string
	Perm  Perm
}

// ---------------------------------------------------------- web accounts

func (s *Store) Web(user string) (*WebAccount, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.state.Web[user]
	if !ok {
		return nil, false
	}
	c := *w
	return &c, true
}

func (s *Store) PutWeb(user string, w *WebAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *w
	s.state.Web[user] = &c
	return s.save()
}

func (s *Store) DeleteWeb(user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Web, user)
	return s.save()
}

// WebUsers returns everyone with a web account.
func (s *Store) WebUsers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sortedKeys(s.state.Web)
}

// --------------------------------------------------------------- subjects

// Subject returns the OIDC identity bound to user, if any.
func (s *Store) Subject(user string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.state.Subjects[user]
	return sub, ok
}

func (s *Store) PutSubject(user, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Subjects[user] = subject
	return s.save()
}

// ----------------------------------------------------------------- people

func (s *Store) Person(name string) (*Person, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.state.People[name]
	if !ok {
		return nil, false
	}
	return copyPerson(p), true
}

func (s *Store) PutPerson(name string, p *Person) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.People[name] = copyPerson(p)
	return s.save()
}

// People returns everyone the portal knows, by name.
func (s *Store) People() map[string]*Person {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]*Person, len(s.state.People))
	for n, p := range s.state.People {
		out[n] = copyPerson(p)
	}
	return out
}

// KnownGroups returns every group anyone known is in, or has a grant.
func (s *Store) KnownGroups() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]string{}
	for _, p := range s.state.People {
		for _, g := range p.Groups {
			seen[strings.ToLower(g)] = g
		}
	}
	for _, b := range s.state.Buckets {
		for g := range b.Groups {
			seen[strings.ToLower(g)] = g
		}
	}
	out := make([]string, 0, len(seen))
	for _, g := range seen {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- buckets

// BucketMeta returns bucket's settings, empty if it has none.
func (s *Store) BucketMeta(bucket string) *BucketMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.state.Buckets[bucket]; ok {
		return copyMeta(m)
	}
	return &BucketMeta{Groups: map[string]Perm{}}
}

func (s *Store) PutBucketMeta(bucket string, m *BucketMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.empty() {
		delete(s.state.Buckets, bucket)
	} else {
		s.state.Buckets[bucket] = copyMeta(m)
	}
	return s.save()
}

// BucketsWithMeta returns every bucket that has settings.
func (s *Store) BucketsWithMeta() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sortedKeys(s.state.Buckets)
}

// ---------------------------------------------------------------- mirrors

// Mirror returns bucket's mirror record, if it has one.
func (s *Store) Mirror(bucket string) (*Mirror, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.state.Mirrors[bucket]
	if !ok {
		return nil, false
	}
	return m.clone(), true
}

func (s *Store) PutMirror(bucket string, m *Mirror) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Mirrors[bucket] = m.clone()
	return s.save()
}

func (s *Store) DeleteMirror(bucket string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Mirrors, bucket)
	return s.save()
}

// Mirrors returns every mirror record, by bucket.
func (s *Store) Mirrors() map[string]*Mirror {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]*Mirror, len(s.state.Mirrors))
	for b, m := range s.state.Mirrors {
		out[b] = m.clone()
	}
	return out
}

// --------------------------------------------------------------- sessions

func (s *Store) Session(id string) (*SessionRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.state.Sessions[id]
	if !ok {
		return nil, false
	}
	c := *r
	return &c, true
}

// PutSession saves a session, and drops expired ones while it's at it.
func (s *Store) PutSession(id string, r *SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, old := range s.state.Sessions {
		if now.After(old.Expires) {
			delete(s.state.Sessions, k)
		}
	}
	c := *r
	s.state.Sessions[id] = &c
	return s.save()
}

func (s *Store) DeleteSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Sessions[id]; !ok {
		return nil
	}
	delete(s.state.Sessions, id)
	return s.save()
}

// EndSessions ends all of user's sessions and returns how many there were.
func (s *Store) EndSessions(user string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, r := range s.state.Sessions {
		if r.User == user {
			delete(s.state.Sessions, id)
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, s.save()
}
