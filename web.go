package main

import (
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
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
		"humanSize": humanSize,
		// within shows a key or folder relative to the folder being browsed.
		"within": func(prefix, key string) string { return strings.TrimPrefix(key, prefix) },
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
	mux.HandleFunc("GET /browse", s.authedGet(s.browse))
	mux.HandleFunc("GET /download", s.authedGet(s.download))
	mux.HandleFunc("PUT /upload", s.authedUpload(s.upload))
	mux.HandleFunc("POST /folders", s.authed(s.createFolder))
	mux.HandleFunc("POST /folders/delete", s.authed(s.deleteFolder))
	mux.HandleFunc("POST /objects/delete", s.authed(s.deleteObject))
	mux.HandleFunc("GET /admin", s.authedGet(s.admin(s.adminPage)))
	mux.HandleFunc("POST /admin/revoke", s.authed(s.admin(s.adminRevoke)))
	mux.HandleFunc("POST /admin/revoke-user", s.authed(s.admin(s.adminRevokeUser)))
	mux.HandleFunc("POST /admin/revoke-all", s.authed(s.admin(s.adminRevokeAll)))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
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
	// The file browser.
	Bucket    string
	Prefix    string
	Crumbs    []crumb
	Listing   *ObjectList
	NextToken string
	// The admin page: every key, and everyone who has one.
	AllKeys []KeyEntry
	Owners  []string
}

// crumb is one step of the path above the folder being browsed.
type crumb struct {
	Name   string
	Prefix string
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
	notice, errMsg := takeFlash(w, r)
	s.dashboard(w, r, sess, http.StatusOK, errMsg, notice)
}

// userMessage is what to tell the user about err: user errors as they are,
// anything else logged and reported generically.
func userMessage(r *http.Request, sess *Session, err error) string {
	var ue *UserError
	if errors.As(err, &ue) {
		return ue.Msg
	}
	slog.Error("request failed", "user", sess.User.Name, "path", r.URL.Path, "err", err)
	return "Something went wrong talking to the storage gateway. Try again, and ask for help if it keeps happening."
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

// browseURL is the file browser's page for a folder.
func browseURL(bucket, prefix string) string {
	q := url.Values{"bucket": {bucket}}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	return "/browse?" + q.Encode()
}

// parentPrefix is the folder a key is in.
func parentPrefix(key string) string {
	if i := strings.LastIndex(key, "/"); i >= 0 {
		return key[:i+1]
	}
	return ""
}

func crumbs(prefix string) []crumb {
	var out []crumb
	parts := strings.Split(strings.TrimSuffix(prefix, "/"), "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		out = append(out, crumb{Name: part, Prefix: strings.Join(parts[:i+1], "/") + "/"})
	}
	return out
}

func (s *Server) browse(w http.ResponseWriter, r *http.Request, sess *Session) {
	q := r.URL.Query()
	bucket, prefix := q.Get("bucket"), q.Get("prefix")
	notice, errMsg := takeFlash(w, r)
	p := page{
		User: &sess.User, CSRF: sess.CSRF, Notice: notice, Error: errMsg,
		Bucket: bucket, Prefix: prefix, Crumbs: crumbs(prefix),
	}
	list, err := s.Portal.ListObjects(r.Context(), sess.User, bucket, prefix, q.Get("token"))
	if err != nil {
		var ue *UserError
		if errors.As(err, &ue) && ue.Msg == "No such bucket." {
			redirectFlash(w, r, "/", "", ue.Msg)
			return
		}
		p.Error = userMessage(r, sess, err)
		s.render(w, http.StatusBadGateway, "browse.html", p)
		return
	}
	p.Listing, p.NextToken = list, list.NextToken
	s.render(w, http.StatusOK, "browse.html", p)
}

// unlimited lifts the server's read and write deadlines for a request that
// streams a file, which may take as long as it takes.
func unlimited(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Time{})
	rc.SetWriteDeadline(time.Time{})
}

func (s *Server) download(w http.ResponseWriter, r *http.Request, sess *Session) {
	q := r.URL.Query()
	bucket, key := q.Get("bucket"), q.Get("key")
	resp, err := s.Portal.GetObject(r.Context(), sess.User, bucket, key)
	if err != nil {
		redirectFlash(w, r, browseURL(bucket, parentPrefix(key)), "", userMessage(r, sess, err))
		return
	}
	defer resp.Body.Close()
	unlimited(w)
	h := w.Header()
	// Always a download, never rendered here: the files are anyone's.
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(key)}))
	if resp.ContentLength >= 0 {
		h.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		slog.Warn("download cut short", "user", sess.User.Name, "bucket", bucket, "key", key, "err", err)
	}
}

// authedUpload requires a session, and the CSRF token in a header since the
// body is the file.
func (s *Server) authedUpload(h handler) http.HandlerFunc {
	return s.authedGet(func(w http.ResponseWriter, r *http.Request, sess *Session) {
		if r.Header.Get("X-CSRF-Token") != sess.CSRF {
			http.Error(w, "Your session has changed. Reload the page and try again.", http.StatusForbidden)
			return
		}
		h(w, r, sess)
	})
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request, sess *Session) {
	q := r.URL.Query()
	if r.ContentLength < 0 {
		http.Error(w, "The upload needs a length.", http.StatusLengthRequired)
		return
	}
	unlimited(w)
	err := s.Portal.PutObject(r.Context(), sess.User, q.Get("bucket"), q.Get("key"), r.Body, r.ContentLength, r.Header.Get("Content-Type"))
	if err != nil {
		var ue *UserError
		status := http.StatusBadGateway
		if errors.As(err, &ue) {
			status = http.StatusBadRequest
		}
		http.Error(w, userMessage(r, sess, err), status)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createFolder(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket, prefix, name := r.PostFormValue("bucket"), r.PostFormValue("prefix"), r.PostFormValue("name")
	if err := s.Portal.CreateFolder(r.Context(), sess.User, bucket, prefix, name); err != nil {
		redirectFlash(w, r, browseURL(bucket, prefix), "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, browseURL(bucket, prefix), "Created folder "+strings.TrimSpace(name)+".", "")
}

func (s *Server) deleteObject(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket, key, prefix := r.PostFormValue("bucket"), r.PostFormValue("key"), r.PostFormValue("prefix")
	if err := s.Portal.DeleteObject(r.Context(), sess.User, bucket, key); err != nil {
		redirectFlash(w, r, browseURL(bucket, prefix), "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, browseURL(bucket, prefix), "Deleted "+path.Base(key)+".", "")
}

func (s *Server) deleteFolder(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket, folder, prefix := r.PostFormValue("bucket"), r.PostFormValue("folder"), r.PostFormValue("prefix")
	n, err := s.Portal.DeleteFolder(r.Context(), sess.User, bucket, folder)
	if err != nil {
		redirectFlash(w, r, browseURL(bucket, prefix), "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, browseURL(bucket, prefix), fmt.Sprintf("Deleted folder %s and %d files in it.", path.Base(folder), n), "")
}

// admin restricts h to members of the admin group.
func (s *Server) admin(h handler) handler {
	return func(w http.ResponseWriter, r *http.Request, sess *Session) {
		if !sess.User.Admin {
			http.Error(w, "That's for S3 admins only.", http.StatusForbidden)
			return
		}
		h(w, r, sess)
	}
}

func (s *Server) adminPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	notice, errMsg := takeFlash(w, r)
	all := s.Portal.AllKeys()
	var owners []string
	for _, e := range all {
		if len(owners) == 0 || owners[len(owners)-1] != e.Owner {
			owners = append(owners, e.Owner)
		}
	}
	s.render(w, http.StatusOK, "admin.html", page{
		User: &sess.User, CSRF: sess.CSRF, Notice: notice, Error: errMsg,
		AllKeys: all, Owners: owners,
	})
}

func (s *Server) adminRevoke(w http.ResponseWriter, r *http.Request, sess *Session) {
	if err := s.Portal.RevokeKey(r.Context(), sess.User, r.PostFormValue("access")); err != nil {
		redirectFlash(w, r, "/admin", "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, "/admin", "Revoked the key.", "")
}

func (s *Server) adminRevokeUser(w http.ResponseWriter, r *http.Request, sess *Session) {
	owner := r.PostFormValue("owner")
	if owner == "" {
		redirectFlash(w, r, "/admin", "", "Pick whose keys to revoke.")
		return
	}
	n, err := s.Portal.RevokeKeys(r.Context(), sess.User, owner)
	if err != nil {
		redirectFlash(w, r, "/admin", "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, "/admin", fmt.Sprintf("Revoked %d of %s's keys.", n, owner), "")
}

// revokeAllPhrase must be typed to revoke every key, so it can't happen by a
// stray click.
const revokeAllPhrase = "revoke all"

func (s *Server) adminRevokeAll(w http.ResponseWriter, r *http.Request, sess *Session) {
	if strings.ToLower(strings.TrimSpace(r.PostFormValue("confirm"))) != revokeAllPhrase {
		redirectFlash(w, r, "/admin", "", "Type “revoke all” to confirm revoking every key.")
		return
	}
	n, err := s.Portal.RevokeKeys(r.Context(), sess.User, "")
	if err != nil {
		redirectFlash(w, r, "/admin", "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, "/admin", fmt.Sprintf("Revoked all %d keys.", n), "")
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

const flashCookie = "s3portal_flash"

// redirectNotice shows notice on the dashboard after the redirect.
func redirectNotice(w http.ResponseWriter, r *http.Request, notice string) {
	redirectFlash(w, r, "/", notice, "")
}

// redirectFlash shows a notice or an error on the page after the redirect.
// They go in a cookie rather than the URL so links can't put words on the
// page.
func redirectFlash(w http.ResponseWriter, r *http.Request, to, notice, errMsg string) {
	kind, msg := "n", notice
	if errMsg != "" {
		kind, msg = "e", errMsg
	}
	http.SetCookie(w, &http.Cookie{
		Name: flashCookie, Value: kind + base64.RawURLEncoding.EncodeToString([]byte(msg)),
		Path: "/", MaxAge: 60, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// takeFlash returns the notice or error left by redirectFlash.
func takeFlash(w http.ResponseWriter, r *http.Request) (notice, errMsg string) {
	c, err := r.Cookie(flashCookie)
	if err != nil || c.Value == "" {
		return "", ""
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: "", Path: "/", MaxAge: -1})
	msg, err := base64.RawURLEncoding.DecodeString(c.Value[1:])
	if err != nil {
		return "", ""
	}
	if c.Value[0] == 'e' {
		return "", string(msg)
	}
	return string(msg), ""
}

func sortedKeys[V any](m map[string]V) []string {
	out := keys(m)
	sort.Strings(out)
	return out
}
