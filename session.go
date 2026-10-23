package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const sessionCookie = "s3portal_session"

// Session is the signed contents of the session cookie.
type Session struct {
	User    User      `json:"user"`
	CSRF    string    `json:"csrf"`
	Expires time.Time `json:"exp"`
}

type Sessions struct {
	Key    []byte
	TTL    time.Duration
	Secure bool
}

func (s *Sessions) sign(payload string) string {
	mac := hmac.New(sha256.New, s.Key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Sessions) Start(w http.ResponseWriter, user User) error {
	sess := Session{User: user, CSRF: randomToken(24), Expires: time.Now().Add(s.TTL)}
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	payload := base64.RawURLEncoding.EncodeToString(data)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    payload + "." + s.sign(payload),
		Path:     "/",
		Expires:  sess.Expires,
		HttpOnly: true,
		Secure:   s.Secure,
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (s *Sessions) End(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode,
	})
}

var errNoSession = errors.New("no session")

func (s *Sessions) Get(r *http.Request) (*Session, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, errNoSession
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.sign(payload))) {
		return nil, errNoSession
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, errNoSession
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil || time.Now().After(sess.Expires) {
		return nil, errNoSession
	}
	return &sess, nil
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
