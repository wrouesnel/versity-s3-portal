package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

const sessionCookie = "s3portal_session"

// Session is a logged-in request's session: who, and their CSRF token.
// User is filled in from the portal's current record of the person, not
// from the time they logged in, so admin rights and groups follow the
// directory.
type Session struct {
	ID   string
	User User
	CSRF string
}

// Sessions keeps sessions server-side, in the store, so logging out and
// disabling someone end them at once. The cookie holds only the session's
// ID, signed.
type Sessions struct {
	Key    []byte
	TTL    time.Duration
	Secure bool
	Store  *Store
}

func (s *Sessions) sign(payload string) string {
	mac := hmac.New(sha256.New, s.Key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Sessions) Start(w http.ResponseWriter, user string) error {
	id := randomToken(24)
	rec := &SessionRecord{User: user, CSRF: randomToken(24), Expires: time.Now().Add(s.TTL)}
	if err := s.Store.PutSession(id, rec); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id + "." + s.sign("session:"+id),
		Path:     "/",
		Expires:  rec.Expires,
		HttpOnly: true,
		Secure:   s.Secure,
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

// End ends the request's session, if it has one, and clears the cookie.
func (s *Sessions) End(w http.ResponseWriter, r *http.Request) {
	if id, ok := s.id(r); ok {
		s.Store.DeleteSession(id)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode,
	})
}

var errNoSession = errors.New("no session")

func (s *Sessions) id(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	id, sig, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.sign("session:"+id))) {
		return "", false
	}
	return id, true
}

// Get returns the request's session, with User filled in from the store's
// record of the person. A disabled or unknown person has no session.
func (s *Sessions) Get(r *http.Request) (*Session, error) {
	id, ok := s.id(r)
	if !ok {
		return nil, errNoSession
	}
	rec, ok := s.Store.Session(id)
	if !ok || time.Now().After(rec.Expires) {
		return nil, errNoSession
	}
	person, ok := s.Store.Person(rec.User)
	if !ok || person.Disabled {
		return nil, errNoSession
	}
	return &Session{ID: id, User: person.User(rec.User), CSRF: rec.CSRF}, nil
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
