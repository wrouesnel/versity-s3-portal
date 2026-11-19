package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// AdminKeyForm is the form an admin issues an owner's key on, for one of
// their buckets.
type AdminKeyForm struct {
	Owner   string
	Buckets []string
	Bucket  string
	Level   Perm
	Label   string
}

func adminKeyURL(bucket string) string { return "/admin/keys/new?bucket=" + url.QueryEscape(bucket) }

// adminCreateBucket makes a bucket for someone, then goes to issuing a key
// for it.
func (s *Server) adminCreateBucket(w http.ResponseWriter, r *http.Request, sess *Session) {
	name, owner := strings.TrimSpace(r.PostFormValue("name")), r.PostFormValue("owner")
	if err := s.Portal.CreateBucketFor(r.Context(), sess.User, owner, name); err != nil {
		redirectFlash(w, r, "/admin?section=buckets&for="+url.QueryEscape(owner), "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, adminKeyURL(name),
		fmt.Sprintf("Made %s for %s. To load data into it, issue %s a key for it here.", name, owner, owner), "")
}

// adminKeyForm is the form, for the bucket named (its owner's key, for any
// of their buckets).
func (s *Server) adminKeyForm(w http.ResponseWriter, r *http.Request, sess *Session, status int, f *AdminKeyForm, errMsg string) {
	p := s.base(w, r, sess, "admin")
	p.Section = "key-new"
	s.adminCounts(r, sess, &p)
	if errMsg != "" {
		p.Error = errMsg
	}
	for _, b := range p.AllBuckets {
		if b.Owner == f.Owner {
			f.Buckets = append(f.Buckets, b.Name)
		}
	}
	p.AdminKey = f
	s.render(w, status, "admin.html", p)
}

func (s *Server) adminNewKey(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket := r.URL.Query().Get("bucket")
	buckets, err := s.Portal.AllBuckets(r.Context())
	if err != nil {
		redirectFlash(w, r, "/admin?section=buckets", "", userMessage(r, sess, err))
		return
	}
	owner := ""
	for _, b := range buckets {
		if b.Name == bucket {
			owner = b.Owner
		}
	}
	if owner == "" {
		redirectFlash(w, r, "/admin?section=buckets", "", "Pick a bucket owned by someone the portal knows.")
		return
	}
	s.adminKeyForm(w, r, sess, http.StatusOK, &AdminKeyForm{
		Owner: owner, Bucket: bucket, Level: PermReadWrite, Label: "Loading data into " + bucket,
	}, "")
}

func (s *Server) adminCreateKey(w http.ResponseWriter, r *http.Request, sess *Session) {
	f := &AdminKeyForm{
		Owner: r.PostFormValue("owner"), Bucket: r.PostFormValue("bucket"),
		Level: Perm(r.PostFormValue("level")), Label: r.PostFormValue("label"),
	}
	grants := map[string]Perm{f.Bucket: f.Level}
	if f.Bucket == "" {
		grants = nil
	}
	lifetime := r.PostFormValue("lifetime")
	access, secret, err := s.Portal.CreateKeyForLasting(r.Context(), sess.User, f.Owner, f.Label, grants, lifetime)
	if err != nil {
		var ue *UserError
		if errors.As(err, &ue) {
			s.adminKeyForm(w, r, sess, http.StatusBadRequest, f, ue.Msg)
			return
		}
		redirectFlash(w, r, adminKeyURL(f.Bucket), "", userMessage(r, sess, err))
		return
	}
	s.render(w, http.StatusOK, "key_created.html", page{
		// The card's own layout, not the admin pages' sidebar.
		User: &sess.User, CSRF: sess.CSRF,
		KeyAccess: access, KeySecret: secret, KeyLabel: strings.TrimSpace(f.Label), Grants: grants, IssuedFor: f.Owner,
		KeyExpires: s.keyExpiry(access),
	})
}

func (s *Server) adminBucketRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /admin/buckets", s.authed(s.admin(s.adminCreateBucket)))
	mux.HandleFunc("GET /admin/keys/new", s.authedGet(s.admin(s.adminNewKey)))
	mux.HandleFunc("POST /admin/keys", s.authed(s.admin(s.adminCreateKey)))
}
