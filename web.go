package main

import (
	"embed"
	"encoding/base64"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type Server struct {
	Portal     *Portal
	Auth       Authenticator
	Sessions   *Sessions
	Title      string
	S3URL      string
	Region     string
	tmpl       *template.Template
	failedWait time.Duration
}

func NewServer(portal *Portal, auth Authenticator, sessions *Sessions, title, s3URL, region string) *Server {
	tmpl := template.Must(template.New("").Funcs(template.FuncMap{
		"permLabel": func(p Perm) string {
			if p == PermReadWrite {
				return "read & write"
			}
			return "read only"
		},
	}).ParseFS(templateFS, "templates/*.html"))
	return &Server{
		Portal: portal, Auth: auth, Sessions: sessions,
		Title: title, S3URL: s3URL, Region: region,
		tmpl: tmpl, failedWait: time.Second,
	}
}

func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(staticFS, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.authed(s.logout))
	mux.HandleFunc("POST /buckets", s.authed(s.createBucket))
	mux.HandleFunc("POST /buckets/delete", s.authed(s.deleteBucket))
	mux.HandleFunc("GET /keys/new", s.authedGet(s.newKey))
	mux.HandleFunc("POST /keys", s.authed(s.createKey))
	mux.HandleFunc("GET /keys/edit", s.authedGet(s.editKey))
	mux.HandleFunc("POST /keys/edit", s.authed(s.updateKey))
	mux.HandleFunc("POST /keys/delete", s.authed(s.deleteKey))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type page struct {
	Title   string
	S3URL   string
	Region  string
	User    *User
	CSRF    string
	Error   string
	Notice  string
	Buckets []string
	Keys    []KeyEntry
	// Key forms and the created-key page.
	KeyAccess string
	KeySecret string
	KeyLabel  string
	Grants    map[string]Perm
}

func (s *Server) render(w http.ResponseWriter, status int, name string, p page) {
	p.Title, p.S3URL, p.Region = s.Title, s.S3URL, s.Region
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, name, p); err != nil {
		slog.Error("render", "template", name, "err", err)
	}
}

type handler func(w http.ResponseWriter, r *http.Request, sess *Session)

// authedGet requires a session.
func (s *Server) authedGet(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.Sessions.Get(r)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		h(w, r, sess)
	}
}

// authed requires a session and a matching CSRF token.
func (s *Server) authed(h handler) http.HandlerFunc {
	return s.authedGet(func(w http.ResponseWriter, r *http.Request, sess *Session) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if r.PostFormValue("csrf") != sess.CSRF {
			http.Error(w, "Your session has changed. Go back, reload the page and try again.", http.StatusForbidden)
			return
		}
		h(w, r, sess)
	})
}

// fail shows err on the dashboard: user errors as they are, anything else
// logged and reported generically.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, sess *Session, err error) {
	var ue *UserError
	msg := "Something went wrong talking to the storage gateway. Try again, and ask for help if it keeps happening."
	status := http.StatusInternalServerError
	if errors.As(err, &ue) {
		msg, status = ue.Msg, http.StatusBadRequest
	} else {
		slog.Error("request failed", "user", sess.User.Name, "path", r.URL.Path, "err", err)
	}
	s.dashboard(w, r, sess, status, msg, "")
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	sess, err := s.Sessions.Get(r)
	if err != nil {
		s.render(w, http.StatusOK, "login.html", page{})
		return
	}
	s.dashboard(w, r, sess, http.StatusOK, "", takeFlash(w, r))
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, sess *Session, status int, errMsg, notice string) {
	buckets, err := s.Portal.Buckets(r.Context(), sess.User)
	if err != nil {
		slog.Error("list buckets", "user", sess.User.Name, "err", err)
		errMsg = "Couldn't reach the storage gateway."
		status = http.StatusBadGateway
	}
	s.render(w, status, "dashboard.html", page{
		User: &sess.User, CSRF: sess.CSRF, Error: errMsg, Notice: notice,
		Buckets: buckets, Keys: s.Portal.Keys(sess.User),
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	username, password := r.PostFormValue("username"), r.PostFormValue("password")
	user, err := s.Auth.Authenticate(username, password)
	if err != nil {
		time.Sleep(s.failedWait)
		msg := "Wrong username or password."
		status := http.StatusUnauthorized
		if !errors.Is(err, ErrBadCredentials) {
			slog.Error("login", "user", username, "err", err)
			msg, status = "Couldn't check your password right now. Try again shortly.", http.StatusBadGateway
		} else {
			slog.Info("login failed", "user", username, "remote", r.RemoteAddr)
		}
		s.render(w, status, "login.html", page{Error: msg})
		return
	}
	if err := s.Sessions.Start(w, user); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	slog.Info("login", "user", user.Name, "remote", r.RemoteAddr)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.Sessions.End(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) createBucket(w http.ResponseWriter, r *http.Request, sess *Session) {
	name := r.PostFormValue("name")
	if err := s.Portal.CreateBucket(r.Context(), sess.User, name); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	redirectNotice(w, r, "Created bucket "+name+".")
}

func (s *Server) deleteBucket(w http.ResponseWriter, r *http.Request, sess *Session) {
	name := r.PostFormValue("name")
	if err := s.Portal.DeleteBucket(r.Context(), sess.User, name); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	redirectNotice(w, r, "Deleted bucket "+name+".")
}

// grantsFromForm reads a perm_<bucket> field for each of the user's buckets.
func grantsFromForm(r *http.Request, buckets []string) map[string]Perm {
	grants := map[string]Perm{}
	for _, b := range buckets {
		if p := Perm(r.PostFormValue("perm_" + b)); p.Valid() {
			grants[b] = p
		}
	}
	return grants
}

func (s *Server) keyForm(w http.ResponseWriter, r *http.Request, sess *Session, name string, status int, p page) {
	buckets, err := s.Portal.Buckets(r.Context(), sess.User)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	p.User, p.CSRF, p.Buckets = &sess.User, sess.CSRF, buckets
	if p.Grants == nil {
		p.Grants = map[string]Perm{}
	}
	s.render(w, status, name, p)
}

func (s *Server) newKey(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.keyForm(w, r, sess, "key_new.html", http.StatusOK, page{})
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request, sess *Session) {
	buckets, err := s.Portal.Buckets(r.Context(), sess.User)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	label := r.PostFormValue("label")
	grants := grantsFromForm(r, buckets)
	access, secret, err := s.Portal.CreateKey(r.Context(), sess.User, label, grants)
	if err != nil {
		var ue *UserError
		if errors.As(err, &ue) {
			s.keyForm(w, r, sess, "key_new.html", http.StatusBadRequest, page{Error: ue.Msg, KeyLabel: label, Grants: grants})
			return
		}
		s.fail(w, r, sess, err)
		return
	}
	s.render(w, http.StatusOK, "key_created.html", page{
		User: &sess.User, CSRF: sess.CSRF,
		KeyAccess: access, KeySecret: secret, KeyLabel: label, Grants: grants,
		Buckets: sortedKeys(grants),
	})
}

func (s *Server) editKey(w http.ResponseWriter, r *http.Request, sess *Session) {
	access := r.URL.Query().Get("access")
	k, err := s.Portal.Key(sess.User, access)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	s.keyForm(w, r, sess, "key_edit.html", http.StatusOK, page{KeyAccess: access, KeyLabel: k.Label, Grants: k.Buckets})
}

func (s *Server) updateKey(w http.ResponseWriter, r *http.Request, sess *Session) {
	buckets, err := s.Portal.Buckets(r.Context(), sess.User)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	access, label := r.PostFormValue("access"), r.PostFormValue("label")
	grants := grantsFromForm(r, buckets)
	if err := s.Portal.UpdateKey(r.Context(), sess.User, access, label, grants); err != nil {
		var ue *UserError
		if errors.As(err, &ue) {
			s.keyForm(w, r, sess, "key_edit.html", http.StatusBadRequest, page{Error: ue.Msg, KeyAccess: access, KeyLabel: label, Grants: grants})
			return
		}
		s.fail(w, r, sess, err)
		return
	}
	redirectNotice(w, r, "Updated key "+label+".")
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request, sess *Session) {
	if err := s.Portal.DeleteKey(r.Context(), sess.User, r.PostFormValue("access")); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	redirectNotice(w, r, "Revoked the key.")
}

const flashCookie = "s3portal_flash"

// redirectNotice shows notice on the dashboard after the redirect. It goes in
// a cookie rather than the URL so links can't put words on the page.
func redirectNotice(w http.ResponseWriter, r *http.Request, notice string) {
	http.SetCookie(w, &http.Cookie{
		Name: flashCookie, Value: base64.RawURLEncoding.EncodeToString([]byte(notice)),
		Path: "/", MaxAge: 60, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func takeFlash(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: "", Path: "/", MaxAge: -1})
	notice, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return ""
	}
	return string(notice)
}

func sortedKeys[V any](m map[string]V) []string {
	out := keys(m)
	sort.Strings(out)
	return out
}
