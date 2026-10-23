package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Perm is what an access key may do in one bucket.
type Perm string

const (
	PermRead      Perm = "read"
	PermReadWrite Perm = "readwrite"
)

func (p Perm) Valid() bool { return p == PermRead || p == PermReadWrite }

// Key is the portal's record of an access key it issued. The gateway holds
// the key itself; the portal holds who owns it and what it was granted.
type Key struct {
	Owner   string          `json:"owner"`
	Label   string          `json:"label"`
	Created time.Time       `json:"created"`
	Buckets map[string]Perm `json:"buckets"`
}

type state struct {
	Keys map[string]*Key `json:"keys"`
}

// Store is a JSON file of issued keys. Callers serialise access.
type Store struct {
	path  string
	state state
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, state: state{Keys: map[string]*Key{}}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if s.state.Keys == nil {
		s.state.Keys = map[string]*Key{}
	}
	return s, nil
}

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

func (s *Store) Get(access string) (*Key, bool) {
	k, ok := s.state.Keys[access]
	return k, ok
}

func (s *Store) Put(access string, k *Key) error {
	s.state.Keys[access] = k
	return s.save()
}

func (s *Store) Delete(access string) error {
	delete(s.state.Keys, access)
	return s.save()
}

// AllKeys returns every access key ID.
func (s *Store) AllKeys() []string {
	out := make([]string, 0, len(s.state.Keys))
	for access := range s.state.Keys {
		out = append(out, access)
	}
	sort.Strings(out)
	return out
}

// KeyEntry is a key with its access key ID.
type KeyEntry struct {
	Access string
	*Key
}

// KeysFor returns owner's keys, oldest first.
func (s *Store) KeysFor(owner string) []KeyEntry {
	var out []KeyEntry
	for access, k := range s.state.Keys {
		if k.Owner == owner {
			out = append(out, KeyEntry{access, k})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// Grants returns the keys granted access to bucket.
func (s *Store) Grants(bucket string) map[string]Perm {
	out := map[string]Perm{}
	for access, k := range s.state.Keys {
		if p, ok := k.Buckets[bucket]; ok {
			out[access] = p
		}
	}
	return out
}

// Buckets returns every bucket any key is granted.
func (s *Store) Buckets() []string {
	seen := map[string]bool{}
	for _, k := range s.state.Keys {
		for b := range k.Buckets {
			seen[b] = true
		}
	}
	out := make([]string, 0, len(seen))
	for b := range seen {
		out = append(out, b)
	}
	sort.Strings(out)
	return out
}
