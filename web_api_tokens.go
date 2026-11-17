package main

import (
	"fmt"
	"net/http"
)

// adminCreateAPIToken issues an API token, and shows it once.
func (s *Server) adminCreateAPIToken(w http.ResponseWriter, r *http.Request, sess *Session) {
	name := r.PostFormValue("name")
	_, token, err := s.Portal.CreateAPIToken(sess.User, name)
	if err != nil {
		redirectFlash(w, r, "/admin?section=tokens", "", userMessage(r, sess, err))
		return
	}
	p := s.base(w, r, sess, "admin")
	p.Section = "token-created"
	s.adminCounts(r, sess, &p)
	p.NewAPIToken, p.NewAPITokenName = token, name
	s.render(w, http.StatusOK, "admin.html", p)
}

func (s *Server) adminRevokeAPIToken(w http.ResponseWriter, r *http.Request, sess *Session) {
	name, err := s.Portal.RevokeAPIToken(sess.User, r.PostFormValue("id"))
	if err != nil {
		redirectFlash(w, r, "/admin?section=tokens", "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, "/admin?section=tokens", fmt.Sprintf("Revoked the API token %s: it stops working at once.", name), "")
}

func (s *Server) apiTokenRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /admin/tokens", s.authed(s.admin(s.adminCreateAPIToken)))
	mux.HandleFunc("POST /admin/tokens/revoke", s.authed(s.admin(s.adminRevokeAPIToken)))
}
