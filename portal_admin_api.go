package main

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// nameNormalizer is a Directory which knows how the portal names people, such as AD's
// lowercased account names.
type nameNormalizer interface {
	Normalize(username string) string
}

// Normalize is the username as the portal knows it.
func (a *LDAPAuth) Normalize(username string) string { return a.normalize(username) }

// directoryName is name as the directory, and so the portal, knows it.
func (p *Portal) directoryName(name string) string {
	name = strings.TrimSpace(name)
	if n, ok := p.dir.(nameNormalizer); ok {
		return n.Normalize(name)
	}
	return name
}

// RegisterFromDirectory records someone the directory has, for admins, as their logging in
// would: with the directory's ids, groups and admin rights, and only if the directory lets
// them use the service. Then buckets and keys can be made for them before they've ever
// logged in. Someone the portal already knows is checked against the directory again, as
// CheckPerson does.
func (p *Portal) RegisterFromDirectory(ctx context.Context, admin User, name string) (PersonStatus, error) {
	if err := requireAdmin(admin); err != nil {
		return PersonStatus{}, err
	}
	if p.dir == nil {
		return PersonStatus{}, errNoDirectory
	}
	name = p.directoryName(name)
	if !usernameRe.MatchString(name) {
		return PersonStatus{User: name}, userErr("%q isn't a username the portal can have.", name)
	}
	if _, known := p.store.Person(name); known {
		return p.CheckPerson(ctx, name)
	}
	d, err := p.dir.Check(name)
	if err != nil {
		return PersonStatus{}, err
	}
	if d.Disabled {
		return PersonStatus{User: name, Disabled: true, Reason: d.Reason},
			userErr("%s can't use the service: %s.", name, d.Reason)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if person, known := p.store.Person(name); known {
		// They logged in, or were registered, meanwhile.
		return statusOf(name, person, len(p.store.KeysFor(name))), nil
	}
	person := &Person{
		UID: d.UID, GID: d.GID, Groups: append([]string{}, d.Groups...), Admin: d.Admin,
		Source: "ldap", Checked: time.Now().UTC(),
	}
	sort.Strings(person.Groups)
	if err := p.store.PutPerson(name, person); err != nil {
		return PersonStatus{}, err
	}
	slog.Info("registered person from the directory", "admin", admin.Name, "user", name)
	status := statusOf(name, person, 0)
	status.Changed = true
	return status, nil
}

// EnsureBucketFor makes a bucket for someone, for admins, as CreateBucketFor does, unless
// it's already theirs. It returns whether it made it. A bucket of that name owned by
// someone else is an error.
func (p *Portal) EnsureBucketFor(ctx context.Context, admin User, owner, name string) (bool, error) {
	if err := requireAdmin(admin); err != nil {
		return false, err
	}
	owner = strings.TrimSpace(owner)
	all, err := p.AllBuckets(ctx)
	if err != nil {
		return false, err
	}
	for _, b := range all {
		if b.Name != name {
			continue
		}
		if b.Owner != owner {
			return false, userErr("%s already exists, and isn't %s's.", name, owner)
		}
		// Theirs already: they may still not be allowed new buckets.
		if _, err := p.knownPerson(owner); err != nil {
			return false, err
		}
		return false, nil
	}
	if err := p.CreateBucketFor(ctx, admin, owner, name); err != nil {
		return false, err
	}
	return true, nil
}
