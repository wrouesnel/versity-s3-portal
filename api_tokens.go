package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// APIToken is an API token an admin issued, for a tool to drive the admin
// API (a migrator): its hash only, the token itself shown once. It acts as
// an admin while its maker is one, and its calls are recorded by its name.
type APIToken struct {
	Name string `json:"name"`
	// Hash is the token's SHA-256, hex.
	Hash string `json:"hash"`
	// Prefix is the token's first characters, to know it by.
	Prefix   string    `json:"prefix"`
	Created  time.Time `json:"created"`
	By       string    `json:"by"`
	LastUsed time.Time `json:"lastUsed,omitzero"`
}

// APITokenView is a token as the admin page lists it.
type APITokenView struct {
	ID string
	APIToken
	// Valid is whether it works now: its maker is still an admin.
	Valid  bool
	Reason string
}

const apiTokenPrefix = "s3p_"

func hashAPIToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// CreateAPIToken issues an API token, for admins, and returns its ID and
// the token, which isn't shown again.
func (p *Portal) CreateAPIToken(admin User, name string) (string, string, error) {
	if err := requireAdmin(admin); err != nil {
		return "", "", err
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return "", "", userErr("Name the token, up to 64 characters, for the tool it's for.")
	}
	for _, t := range p.store.APITokens() {
		if strings.EqualFold(t.Name, name) {
			return "", "", userErr("There's a token called %s already: revoke it, or name this one otherwise.", name)
		}
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	id := hex.EncodeToString(b)
	token := apiTokenPrefix + newSecret()
	t := &APIToken{Name: name, Hash: hashAPIToken(token), Prefix: token[:len(apiTokenPrefix)+6], Created: time.Now().UTC(), By: admin.Name}
	if err := p.store.PutAPIToken(id, t); err != nil {
		return "", "", err
	}
	slog.Info("issued an API token", "admin", admin.Name, "token", name, "id", id)
	return id, token, nil
}

// APITokenList lists the API tokens, for admins, oldest first.
func (p *Portal) APITokenList(admin User) ([]APITokenView, error) {
	if err := requireAdmin(admin); err != nil {
		return nil, err
	}
	var out []APITokenView
	for id, t := range p.store.APITokens() {
		v := APITokenView{ID: id, APIToken: *t}
		v.Valid, v.Reason = p.makerIsAdmin(t.By)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

// RevokeAPIToken deletes an API token, for admins: it stops working at once.
func (p *Portal) RevokeAPIToken(admin User, id string) (string, error) {
	if err := requireAdmin(admin); err != nil {
		return "", err
	}
	t, ok := p.store.APITokens()[id]
	if !ok {
		return "", userErr("There's no such API token.")
	}
	if err := p.store.DeleteAPIToken(id); err != nil {
		return "", err
	}
	slog.Info("revoked an API token", "admin", admin.Name, "token", t.Name, "id", id)
	return t.Name, nil
}

// makerIsAdmin is whether an API token's maker is still an admin the
// portal knows, enabled: a token works only while they are.
func (p *Portal) makerIsAdmin(name string) (bool, string) {
	person, ok := p.store.Person(name)
	switch {
	case !ok:
		return false, name + " is no longer known"
	case person.Disabled:
		return false, name + " is disabled"
	case !person.Admin:
		return false, name + " is no longer an admin"
	}
	return true, ""
}

// apiTokenUser is who an API token acts as, if it's one an admin issued
// and still works, recording its use (at most once a minute).
func (p *Portal) apiTokenUser(token string) (User, bool) {
	if !strings.HasPrefix(token, apiTokenPrefix) {
		return User{}, false
	}
	h := hashAPIToken(token)
	for id, t := range p.store.APITokens() {
		if subtle.ConstantTimeCompare([]byte(h), []byte(t.Hash)) != 1 {
			continue
		}
		if ok, why := p.makerIsAdmin(t.By); !ok {
			slog.Warn("an API token refused", "token", t.Name, "why", why)
			return User{}, false
		}
		if time.Since(t.LastUsed) > time.Minute {
			t.LastUsed = time.Now().UTC()
			_ = p.store.PutAPIToken(id, t)
		}
		return User{Name: "api:" + t.Name, Admin: true}, true
	}
	return User{}, false
}
