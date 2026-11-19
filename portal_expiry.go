package main

import (
	"context"
	"log/slog"
	"time"
)

// KeyPolicy is how long keys last.
func (p *Portal) KeyPolicy() KeyPolicy { return p.store.KeyPolicy() }

// SetKeyPolicy sets how long keys last, for admins. Keys already made keep their expiry.
func (p *Portal) SetKeyPolicy(admin User, pol KeyPolicy) error {
	if err := requireAdmin(admin); err != nil {
		return err
	}
	switch {
	case pol.Default < time.Hour || pol.Login < time.Hour || pol.Max < time.Hour:
		return userErr("Every lifetime must be at least an hour.")
	case pol.Default > pol.Max:
		return userErr("The default for keys made on the Access keys page (%s) is longer than the most (%s).", lifetimeLabel(pol.Default), lifetimeLabel(pol.Max))
	case pol.Login > pol.Max:
		return userErr("The default for login keys (%s) is longer than the most (%s).", lifetimeLabel(pol.Login), lifetimeLabel(pol.Max))
	}
	if err := p.store.PutKeyPolicy(pol); err != nil {
		return err
	}
	slog.Info("set key lifetimes", "admin", admin.Name, "default", pol.Default, "login", pol.Login, "max", pol.Max)
	return nil
}

// expiry is when a key u asks for lasting lifetime ("" for def) expires: nil, and u's
// name, for "never", which only admins may ask for. Anyone but an admin gets no more than
// the most.
func (p *Portal) expiry(u User, lifetime string, def time.Duration) (*time.Time, string, error) {
	pol := p.KeyPolicy()
	d, never := def, false
	if lifetime != "" {
		var err error
		if d, never, err = parseLifetime(lifetime); err != nil {
			return nil, "", err
		}
	}
	if never {
		if !u.Admin {
			return nil, "", userErr("Only admins make keys which never expire: pick a lifetime of up to %s.", lifetimeLabel(pol.Max))
		}
		return nil, u.Name, nil
	}
	if d > pol.Max && !u.Admin {
		return nil, "", userErr("A key may last at most %s.", lifetimeLabel(pol.Max))
	}
	t := time.Now().UTC().Add(d).Truncate(time.Second)
	return &t, "", nil
}

// CreateKeyLasting is CreateKey with a lifetime: "" for the default.
func (p *Portal) CreateKeyLasting(ctx context.Context, u User, label string, grants map[string]Perm, lifetime string) (string, string, error) {
	expires, neverBy, err := p.expiry(u, lifetime, p.KeyPolicy().Default)
	if err != nil {
		return "", "", err
	}
	return p.createKey(ctx, u, label, grants, keyOpts{Expires: expires, NeverBy: neverBy})
}

// CreateKeyForLasting is CreateKeyFor with a lifetime: "" for the default, "never" too.
func (p *Portal) CreateKeyForLasting(ctx context.Context, admin User, owner, label string, grants map[string]Perm, lifetime string) (string, string, error) {
	if err := requireAdmin(admin); err != nil {
		return "", "", err
	}
	person, err := p.knownPerson(owner)
	if err != nil {
		return "", "", err
	}
	if len(grants) == 0 {
		return "", "", userErr("Pick the buckets the key is for.")
	}
	expires, neverBy, err := p.expiry(admin, lifetime, p.KeyPolicy().Default)
	if err != nil {
		return "", "", err
	}
	return p.createKey(ctx, person.User(owner), label, grants, keyOpts{IssuedBy: admin.Name, Expires: expires, NeverBy: neverBy})
}

// RenewKey gives a key a new expiry, lifetime from now: its owner's, or any key for an
// admin, who may also make it never expire. Its ID and secret stay as they are. Login keys
// aren't renewed: logging in again makes another.
func (p *Portal) RenewKey(ctx context.Context, u User, access, lifetime string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	k, ok := p.store.Get(access)
	if !ok || (k.Owner != u.Name && !u.Admin) {
		return userErr("No such key.")
	}
	if k.Login {
		return userErr("Login keys aren't renewed: run s3-portal login again for another.")
	}
	expires, neverBy, err := p.expiry(u, lifetime, p.KeyPolicy().Default)
	if err != nil {
		return err
	}
	k.Expires, k.NeverBy = expires, neverBy
	if err := p.store.Put(access, k); err != nil {
		return err
	}
	slog.Info("renewed key", "by", u.Name, "user", k.Owner, "access", access, "expires", expires, "neverBy", neverBy)
	return nil
}

// ReapExpired revokes every key past its expiry, and returns how many.
func (p *Portal) ReapExpired(ctx context.Context) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	var expired []string
	for _, e := range p.store.Entries() {
		if e.Expires != nil && !e.Expires.After(now) {
			expired = append(expired, e.Access)
			slog.Info("key expired", "user", e.Owner, "access", e.Access, "label", e.Label, "expires", e.Expires)
		}
	}
	if len(expired) == 0 {
		return 0, nil
	}
	return len(expired), p.revoke(ctx, expired)
}

// RunReaper revokes expired keys every interval, until ctx ends.
func (p *Portal) RunReaper(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := p.ReapExpired(ctx); err != nil {
			slog.Error("revoking expired keys", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// NeverExpire is how many keys never expire.
func (p *Portal) NeverExpire() int {
	n := 0
	for _, e := range p.store.Entries() {
		if e.Expires == nil {
			n++
		}
	}
	return n
}

// allBucketNames are the gateway's buckets, for keys reaching all their owner can.
func (p *Portal) allBucketNames(ctx context.Context) []string {
	all, err := p.vgw.ListBuckets(ctx)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(all))
	for _, b := range all {
		out = append(out, b.Name)
	}
	return out
}

// syncKeyBuckets rewrites the policies of the buckets k reaches: its grants', or every
// bucket for a login key reaching all its owner can. Callers hold p.mu.
func (p *Portal) syncKeyBuckets(ctx context.Context, k *Key) error {
	if k.Login && len(k.Buckets) == 0 {
		return p.syncAll(ctx)
	}
	return p.syncBuckets(ctx, keys(k.Buckets))
}
