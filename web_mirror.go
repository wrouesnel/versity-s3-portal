package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func mirrorURL(bucket string) string { return "/admin/mirror?bucket=" + url.QueryEscape(bucket) }

func (s *Server) adminMirror(w http.ResponseWriter, r *http.Request, sess *Session) {
	p := s.base(w, r, sess, "admin")
	p.Section = "mirror"
	s.adminCounts(r, sess, &p)
	m, err := s.Portal.MirrorDetail(sess.User, r.URL.Query().Get("bucket"))
	if err != nil {
		redirectFlash(w, r, "/admin?section=mirrors", "", userMessage(r, sess, err))
		return
	}
	p.Mirror = m
	p.AutoRefresh = m.Running != nil
	s.render(w, http.StatusOK, "admin.html", p)
}

func (s *Server) adminNewMirror(w http.ResponseWriter, r *http.Request, sess *Session) {
	p := s.base(w, r, sess, "admin")
	p.Section = "mirror-new"
	s.adminCounts(r, sess, &p)
	p.MirrorForm = &MirrorRequest{Source: MirrorSource{Region: "us-east-1"}, Every: "hourly"}
	s.render(w, http.StatusOK, "admin.html", p)
}

func (s *Server) adminCreateMirror(w http.ResponseWriter, r *http.Request, sess *Session) {
	limit, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("limit")))
	req := MirrorRequest{
		Bucket:   strings.TrimSpace(r.PostFormValue("bucket")),
		NewOwner: strings.TrimSpace(r.PostFormValue("owner")),
		Source: MirrorSource{
			Endpoint: r.PostFormValue("endpoint"),
			Region:   r.PostFormValue("region"),
			Bucket:   r.PostFormValue("source_bucket"),
			Virtual:  r.PostFormValue("addressing") == "virtual",
			Access:   r.PostFormValue("access"),
			Secret:   r.PostFormValue("secret"),
		},
		Every:     r.PostFormValue("every"),
		LimitMBps: limit,
	}
	if err := s.Portal.RegisterMirror(r.Context(), sess.User, req); err != nil {
		// Show the form again with what was typed, but never the secret.
		p := s.base(w, r, sess, "admin")
		p.Section = "mirror-new"
		s.adminCounts(r, sess, &p)
		req.Source.Secret = ""
		p.MirrorForm = &req
		p.Error = userMessage(r, sess, err)
		s.render(w, http.StatusBadRequest, "admin.html", p)
		return
	}
	redirectFlash(w, r, mirrorURL(req.Bucket), "Mirror set up. The first pass has started.", "")
}

// mirrorAction runs an admin action on the mirror named in the form and
// goes back to its page.
func (s *Server) mirrorAction(do func(r *http.Request, sess *Session, bucket string) (string, error)) handler {
	return func(w http.ResponseWriter, r *http.Request, sess *Session) {
		bucket := r.PostFormValue("bucket")
		notice, err := do(r, sess, bucket)
		if err != nil {
			redirectFlash(w, r, mirrorURL(bucket), "", userMessage(r, sess, err))
			return
		}
		to := mirrorURL(bucket)
		if r.PostFormValue("back") == "list" {
			to = "/admin?section=mirrors"
		}
		redirectFlash(w, r, to, notice, "")
	}
}

func (s *Server) mirrorRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/mirror", s.authedGet(s.admin(s.adminMirror)))
	mux.HandleFunc("GET /admin/mirrors/new", s.authedGet(s.admin(s.adminNewMirror)))
	mux.HandleFunc("POST /admin/mirrors", s.authed(s.admin(s.adminCreateMirror)))
	mux.HandleFunc("GET /admin/mirror/report", s.authedGet(s.admin(s.adminMirrorReport)))
	post := func(path string, do func(r *http.Request, sess *Session, bucket string) (string, error)) {
		mux.HandleFunc("POST "+path, s.authed(s.admin(s.mirrorAction(do))))
	}
	post("/admin/mirror/run", func(r *http.Request, sess *Session, b string) (string, error) {
		return "A pass has started.", s.Portal.RunMirrorPass(sess.User, b)
	})
	post("/admin/mirror/pause", func(r *http.Request, sess *Session, b string) (string, error) {
		paused := r.PostFormValue("paused") == "on"
		msg := "Scheduled passes will run again."
		if paused {
			msg = "Scheduled passes are paused. A pass already running carries on."
		}
		return msg, s.Portal.PauseMirror(sess.User, b, paused)
	})
	post("/admin/mirror/settings", func(r *http.Request, sess *Session, b string) (string, error) {
		limit, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("limit")))
		return "Saved.", s.Portal.UpdateMirror(r.Context(), sess.User, b, r.PostFormValue("every"), limit,
			r.PostFormValue("access"), r.PostFormValue("secret"))
	})
	post("/admin/mirror/accept", func(r *http.Request, sess *Session, b string) (string, error) {
		return "Accepted.", s.Portal.AcceptUncopyable(sess.User, b, r.PostFormValue("note"))
	})
	post("/admin/mirror/freeze", func(r *http.Request, sess *Session, b string) (string, error) {
		if r.PostFormValue("stopped") != "on" {
			return "", userErr("Confirm that writes to the source have stopped.")
		}
		return "The final pass has started.", s.Portal.FreezeMirror(sess.User, b, r.PostFormValue("deep") == "on")
	})
	post("/admin/mirror/complete", func(r *http.Request, sess *Session, b string) (string, error) {
		return fmt.Sprintf("%s is open to its users.", b), s.Portal.CompleteMirror(r.Context(), sess.User, b)
	})
	post("/admin/mirror/source-removed", func(r *http.Request, sess *Session, b string) (string, error) {
		return "Recorded.", s.Portal.MarkSourceRemoved(sess.User, b)
	})
	post("/admin/mirror/abandon", func(r *http.Request, sess *Session, b string) (string, error) {
		return fmt.Sprintf("Abandoned. %s keeps what was copied.", b), s.Portal.AbandonMirror(r.Context(), sess.User, b)
	})
	post("/admin/mirror/forget", func(r *http.Request, sess *Session, b string) (string, error) {
		return "Forgotten.", s.Portal.ForgetMirror(sess.User, b)
	})
}

func (s *Server) adminMirrorReport(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket := r.URL.Query().Get("bucket")
	n, _ := strconv.Atoi(r.URL.Query().Get("pass"))
	data, err := s.Portal.MirrorReport(sess.User, bucket, n)
	if err != nil {
		redirectFlash(w, r, mirrorURL(bucket), "", userMessage(r, sess, err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="mirror-%s-pass-%d.json"`, bucket, n))
	w.Write(data)
}
