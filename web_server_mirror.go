package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func serverURL(id string) string { return "/admin/server?id=" + url.QueryEscape(id) }

func (s *Server) adminServer(w http.ResponseWriter, r *http.Request, sess *Session) {
	p := s.base(w, r, sess, "admin")
	p.Section = "server"
	s.adminCounts(r, sess, &p)
	v, err := s.Portal.ServerDetail(r.Context(), sess.User, r.URL.Query().Get("id"))
	if err != nil {
		redirectFlash(w, r, "/admin?section=mirrors", "", userMessage(r, sess, err))
		return
	}
	p.Server = v
	for _, m := range v.Mirrors {
		if m.Running != nil || m.Queued != "" {
			p.AutoRefresh = true
		}
	}
	s.render(w, http.StatusOK, "admin.html", p)
}

func (s *Server) adminNewServer(w http.ResponseWriter, r *http.Request, sess *Session) {
	p := s.base(w, r, sess, "admin")
	p.Section = "server-new"
	s.adminCounts(r, sess, &p)
	p.ServerForm = &ServerRequest{Source: MirrorSource{Region: "us-east-1"}, Every: "hourly", DefaultOwner: sess.User.Name}
	s.render(w, http.StatusOK, "admin.html", p)
}

func (s *Server) adminCreateServer(w http.ResponseWriter, r *http.Request, sess *Session) {
	limit, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("limit")))
	req := ServerRequest{
		Name: r.PostFormValue("name"),
		Source: MirrorSource{
			Endpoint: r.PostFormValue("endpoint"),
			Region:   r.PostFormValue("region"),
			Virtual:  r.PostFormValue("addressing") == "virtual",
			Access:   r.PostFormValue("access"),
			Secret:   r.PostFormValue("secret"),
		},
		DefaultOwner: r.PostFormValue("owner"),
		Every:        r.PostFormValue("every"),
		LimitMBps:    limit,
	}
	id, err := s.Portal.RegisterServer(r.Context(), sess.User, req)
	if err != nil {
		// The form again, with what was typed, but never the secret.
		p := s.base(w, r, sess, "admin")
		p.Section = "server-new"
		s.adminCounts(r, sess, &p)
		req.Source.Secret = ""
		p.ServerForm = &req
		p.Error = userMessage(r, sess, err)
		s.render(w, http.StatusBadRequest, "admin.html", p)
		return
	}
	redirectFlash(w, r, serverURL(id), "Listed the server. Tick the buckets to mirror, and check their names and owners here.", "")
}

// adminCreateServerMirrors makes the mirrors of the rows ticked.
func (s *Server) adminCreateServerMirrors(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PostFormValue("id")
	if err := r.ParseForm(); err != nil {
		redirectFlash(w, r, serverURL(id), "", userMessage(r, sess, err))
		return
	}
	var picks []ServerPick
	for _, i := range r.PostForm["pick"] {
		if _, err := strconv.Atoi(i); err != nil {
			continue
		}
		picks = append(picks, ServerPick{
			Source: r.PostFormValue("source-" + i), Local: r.PostFormValue("local-" + i), Owner: r.PostFormValue("owner-" + i),
		})
	}
	made, err := s.Portal.CreateServerMirrors(r.Context(), sess.User, id, picks)
	notice := ""
	if len(made) > 0 {
		notice = fmt.Sprintf("Mirroring %s: %s. Their first passes take turns, two at a time.", plural(int64(len(made)), "bucket"), strings.Join(made, ", "))
	}
	errMsg := ""
	if err != nil {
		errMsg = userMessage(r, sess, err)
	}
	redirectFlash(w, r, serverURL(id), notice, errMsg)
}

// serverAction runs an action on the server named in the form, saying how
// many of its mirrors it did, and goes back to its page.
func (s *Server) serverAction(do func(r *http.Request, sess *Session, id string) (string, error)) handler {
	return func(w http.ResponseWriter, r *http.Request, sess *Session) {
		id := r.PostFormValue("id")
		notice, err := do(r, sess, id)
		errMsg := ""
		if err != nil {
			errMsg = userMessage(r, sess, err)
		}
		to := serverURL(id)
		if r.URL.Path == "/admin/server/forget" && err == nil {
			to = "/admin?section=mirrors"
		}
		redirectFlash(w, r, to, notice, errMsg)
	}
}

func (s *Server) serverRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/server", s.authedGet(s.admin(s.adminServer)))
	mux.HandleFunc("GET /admin/servers/new", s.authedGet(s.admin(s.adminNewServer)))
	mux.HandleFunc("POST /admin/servers", s.authed(s.admin(s.adminCreateServer)))
	mux.HandleFunc("POST /admin/server/create", s.authed(s.admin(s.adminCreateServerMirrors)))
	post := func(path string, do func(r *http.Request, sess *Session, id string) (string, error)) {
		mux.HandleFunc("POST "+path, s.authed(s.admin(s.serverAction(do))))
	}
	post("/admin/server/run", func(r *http.Request, sess *Session, id string) (string, error) {
		n, err := s.Portal.ServerRunPasses(sess.User, id)
		return fmt.Sprintf("Queued a pass of %s: they run two at a time.", plural(int64(n), "mirror")), err
	})
	post("/admin/server/pause", func(r *http.Request, sess *Session, id string) (string, error) {
		paused := r.PostFormValue("paused") == "on"
		n, err := s.Portal.ServerPause(sess.User, id, paused)
		if paused {
			return fmt.Sprintf("Paused %s. A pass already running carries on.", plural(int64(n), "mirror")), err
		}
		return fmt.Sprintf("Resumed %s.", plural(int64(n), "mirror")), err
	})
	post("/admin/server/freeze", func(r *http.Request, sess *Session, id string) (string, error) {
		if r.PostFormValue("stopped") != "on" {
			return "", userErr("Confirm that writes to every bucket on the server have stopped.")
		}
		n, err := s.Portal.ServerFreeze(sess.User, id, r.PostFormValue("deep") == "on")
		return fmt.Sprintf("Froze %s. Their final passes and checks are queued, two at a time.", plural(int64(n), "mirror")), err
	})
	post("/admin/server/complete", func(r *http.Request, sess *Session, id string) (string, error) {
		n, err := s.Portal.ServerComplete(r.Context(), sess.User, id)
		return fmt.Sprintf("%s open to their users.", plural(int64(n), "bucket")), err
	})
	post("/admin/server/key", func(r *http.Request, sess *Session, id string) (string, error) {
		n, err := s.Portal.ServerReplaceKey(r.Context(), sess.User, id, r.PostFormValue("access"), r.PostFormValue("secret"))
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("The new key is the server's, and %s'.", plural(int64(n), "running mirror")), nil
	})
	post("/admin/server/forget", func(r *http.Request, sess *Session, id string) (string, error) {
		return "Forgot the server and its key.", s.Portal.ForgetServer(sess.User, id)
	})
}
