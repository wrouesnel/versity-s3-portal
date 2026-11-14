package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/wrouesnel/versity-s3-portal/internal/zfsapi"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type Server struct {
	Portal *Portal
	// Auth checks passwords; nil when only OIDC is configured.
	Auth Authenticator
	// OIDC is nil when only passwords are configured.
	OIDC     *OIDCAuth
	Sessions *Sessions
	Title    string
	S3URL    string
	Region   string
	// APIToken, when set, lets automation call /api/ with
	// "Authorization: Bearer <token>".
	APIToken string
	// TrustedProxies are where the portal's TLS proxy connects from. Logs
	// take the client's address from X-Forwarded-For on their requests.
	TrustedProxies []netip.Prefix
	tmpl           *template.Template
	failedWait     time.Duration
	// assetPrefix is /static/<hash of the static files>/, so they can be
	// cached for good and still change with each release.
	assetPrefix string
}

func NewServer(portal *Portal, auth Authenticator, oidcAuth *OIDCAuth, sessions *Sessions, title, s3URL, region string) *Server {
	assetPrefix := "/static/" + staticHash() + "/"
	tmpl := template.Must(template.New("").Funcs(template.FuncMap{
		"asset":     func(name string) string { return assetPrefix + name },
		"permLabel": func(p Perm) string { return p.Label() },
		"capsLabel": capsLabel,
		"perms":     func() []Perm { return Perms },
		// covers says whether access c allows level p.
		"covers":    func(c Caps, p Perm) bool { return c.Covers(p.Caps()) },
		"humanSize": humanSize,
		// within shows a key or folder relative to the folder being browsed.
		"within": func(prefix, key string) string { return strings.TrimPrefix(key, prefix) },
		// folderName is a subfolder's name without its trailing slash.
		"folderName": func(prefix, key string) string { return strings.TrimSuffix(strings.TrimPrefix(key, prefix), "/") },
		"join":       strings.Join,
		"browseURL":  browseURL,
		"snapURL":    snapURL,
		"snapKind":   snapshotKind,
		"inc":        func(i int) int { return i + 1 },
		// size is a bucket's entry in Sizes, and whether there is one.
		"size": func(sizes map[string]zfsapi.BucketSize, bucket string) (zfsapi.BucketSize, error) {
			return sizes[bucket], nil
		},
		"sub": func(a, b int64) int64 { return max(0, a-b) },
		"pct": func(n, of int64) int64 {
			if of <= 0 {
				return 0
			}
			return min(100, n*100/of)
		},
		// selbar and rowsel give the selection templates what they need
		// from the page.
		"selbar": func(p page, canDelete bool) selView {
			return selView{CSRF: p.CSRF, Bucket: p.Open.Name, Snap: p.Snap, Prefix: p.Prefix, Delete: canDelete && p.Snap == ""}
		},
		"rowsel": func(p page, folder string, _ bool) selView {
			return selView{CSRF: p.CSRF, Bucket: p.Open.Name, Snap: p.Snap, Prefix: p.Prefix, Folder: folder}
		},
	}).ParseFS(templateFS, "templates/*.html"))
	return &Server{
		Portal: portal, Auth: auth, OIDC: oidcAuth, Sessions: sessions,
		Title: title, S3URL: s3URL, Region: region,
		tmpl: tmpl, failedWait: time.Second, assetPrefix: assetPrefix,
	}
}

// staticHash is a short hash of everything under static/.
func staticHash() string {
	h := sha256.New()
	fs.WalkDir(staticFS, "static", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := staticFS.ReadFile(name)
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s %d\n", name, len(data))
		h.Write(data)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}

func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(staticFS, "static")
	mux := http.NewServeMux()
	files := http.FileServerFS(static)
	mux.Handle("GET "+s.assetPrefix, http.StripPrefix(s.assetPrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		files.ServeHTTP(w, r)
	})))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /{$}", s.home)
	if s.Auth != nil {
		mux.HandleFunc("POST /login", s.login)
	}
	if s.OIDC != nil {
		mux.HandleFunc("GET /auth/login", s.oidcLogin)
		mux.HandleFunc("GET /auth/callback", s.oidcCallback)
	}
	mux.HandleFunc("POST /logout", s.authed(s.logout))
	// Files: buckets on the left, the open one on the right.
	mux.HandleFunc("GET /files", s.authedGet(s.files))
	mux.HandleFunc("GET /browse", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/files?"+r.URL.RawQuery, http.StatusMovedPermanently)
	})
	mux.HandleFunc("POST /buckets", s.authed(s.createBucket))
	mux.HandleFunc("POST /buckets/delete", s.authed(s.deleteBucket))
	mux.HandleFunc("GET /buckets/settings", s.authedGet(s.bucketSettings))
	mux.HandleFunc("POST /buckets/groups", s.authed(s.setGroupGrant))
	mux.HandleFunc("POST /buckets/keys/remove", s.authed(s.removeKeyFromBucket))
	mux.HandleFunc("POST /buckets/quota", s.authed(s.setQuota))
	mux.HandleFunc("POST /buckets/backup", s.authed(s.setBackup))
	mux.HandleFunc("POST /buckets/schedule", s.authed(s.setSchedule))
	mux.HandleFunc("GET /buckets/snapshots", s.authedGet(s.snapshotsPage))
	mux.HandleFunc("POST /buckets/snapshots", s.authed(s.takeSnapshot))
	mux.HandleFunc("POST /buckets/snapshots/delete", s.authed(s.deleteSnapshot))
	mux.HandleFunc("POST /restore", s.authed(s.restore))
	mux.HandleFunc("GET /download", s.authedGet(s.download))
	mux.HandleFunc("PUT /upload", s.authedUpload(s.upload))
	mux.HandleFunc("POST /folders", s.authed(s.createFolder))
	mux.HandleFunc("POST /folders/delete", s.authed(s.deleteFolder))
	mux.HandleFunc("POST /objects/delete", s.authed(s.deleteObject))
	// A selection: up to maxSelection names of up to 1 KiB each.
	mux.HandleFunc("POST /selection/archive", s.authedLimit(2<<20, s.archiveSelection))
	mux.HandleFunc("POST /selection/list", s.authedLimit(2<<20, s.listSelection))
	mux.HandleFunc("POST /selection/delete", s.authedLimit(2<<20, s.deleteSelection))
	// Keys.
	mux.HandleFunc("GET /keys", s.authedGet(s.keysPage))
	mux.HandleFunc("GET /keys/new", s.authedGet(s.newKey))
	mux.HandleFunc("POST /keys", s.authed(s.createKey))
	mux.HandleFunc("GET /keys/edit", s.authedGet(s.editKey))
	mux.HandleFunc("POST /keys/edit", s.authed(s.updateKey))
	mux.HandleFunc("POST /keys/delete", s.authed(s.deleteKey))
	// Admin.
	mux.HandleFunc("GET /admin", s.authedGet(s.admin(s.adminPage)))
	mux.HandleFunc("POST /admin/revoke", s.authed(s.admin(s.adminRevoke)))
	mux.HandleFunc("POST /admin/revoke-user", s.authed(s.admin(s.adminRevokeUser)))
	mux.HandleFunc("POST /admin/revoke-all", s.authed(s.admin(s.adminRevokeAll)))
	mux.HandleFunc("POST /admin/check", s.authed(s.admin(s.adminCheck)))
	mux.HandleFunc("POST /admin/sync", s.authed(s.admin(s.adminSync)))
	mux.HandleFunc("POST /admin/end-sessions", s.authed(s.admin(s.adminEndSessions)))
	mux.HandleFunc("POST /admin/trash/restore", s.authed(s.admin(s.adminRestoreTrash)))
	mux.HandleFunc("POST /admin/trash/purge", s.authed(s.admin(s.adminPurgeTrash)))
	// API, for automation and scripts.
	mux.HandleFunc("POST /api/directory/sync", s.api(s.apiSync))
	mux.HandleFunc("GET /api/users/{name}", s.api(s.apiUser))
	mux.HandleFunc("POST /api/users/{name}/check", s.api(s.apiCheckUser))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// Pages hold secrets and per-person data. Static files set their own.
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type page struct {
	Title  string
	S3URL  string
	Region string
	// The login page's choices.
	PasswordLogin bool
	OIDCName      string
	// Refresh, when set, sends the browser on to this page.
	Refresh string
	User    *User
	CSRF    string
	Error   string
	Notice  string
	// Tab is the header tab to mark: files, keys or admin.
	Tab string
	// Buckets the user can reach, for the sidebar and key forms.
	Buckets []BucketView
	// Open is the bucket being shown.
	Open *BucketView
	Keys []KeyEntry
	// KeyCaps is, for each key on the keys page, what it can do now.
	KeyCaps map[string]map[string]Caps
	// Key forms and the created-key page.
	KeyAccess string
	KeySecret string
	KeyLabel  string
	Grants    map[string]Perm
	// The file browser.
	Prefix    string
	Crumbs    []crumb
	Listing   *ObjectList
	NextToken string
	// Bucket settings.
	Settings bool
	// Section is the part of a settings or admin page being shown.
	Section string
	// Filter starts a page's table filter with some text.
	Filter     string
	BucketKeys []BucketKey
	GroupList  []string
	Grantees   map[string]Perm
	// ZFS: the open bucket's dataset, and the snapshot being browsed.
	ZFS     bool
	Storage *Storage
	// Sizes are the buckets' sizes from ZFS, when known.
	Sizes     map[string]zfsapi.BucketSize
	Snapshots bool
	Snap      string
	// The admin page.
	AllKeys    []KeyEntry
	Owners     []string
	People     []PersonStatus
	AllBuckets []BucketSummary
	Directory  bool
	Trash      []ZFSTrashEntry
}

// selView is what the selection bar and folder menus need.
type selView struct {
	CSRF, Bucket, Snap, Prefix, Folder string
	Delete                             bool
}

// crumb is one step of the path above the folder being browsed.
type crumb struct {
	Name   string
	Prefix string
}

func (s *Server) render(w http.ResponseWriter, status int, name string, p page) {
	p.Title, p.S3URL, p.Region = s.Title, s.S3URL, s.Region
	p.PasswordLogin = s.Auth != nil
	if s.OIDC != nil {
		p.OIDCName = s.OIDC.Name
	}
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
	return s.authedLimit(64<<10, h)
}

// authedLimit is authed for forms up to limit bytes, such as a selection
// of hundreds of file names.
func (s *Server) authedLimit(limit int64, h handler) http.HandlerFunc {
	return s.authedGet(func(w http.ResponseWriter, r *http.Request, sess *Session) {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		if r.PostFormValue("csrf") != sess.CSRF {
			http.Error(w, "Your session has changed. Go back, reload the page and try again.", http.StatusForbidden)
			return
		}
		h(w, r, sess)
	})
}

// Not "the gateway": it may be the directory, the ZFS helper or the portal.
const genericError = "Something went wrong on the server. Try again, and ask for help if it keeps happening."

// userMessage is what to tell the user about err: user errors as they are,
// anything else logged and reported generically.
func userMessage(r *http.Request, sess *Session, err error) string {
	var ue *UserError
	if errors.As(err, &ue) {
		return ue.Msg
	}
	slog.Error("request failed", "user", sess.User.Name, "path", r.URL.Path, "err", err)
	return genericError
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	sess, err := s.Sessions.Get(r)
	if err != nil {
		s.render(w, http.StatusOK, "login.html", page{})
		return
	}
	s.files(w, r, sess)
}

// base fills in what every logged-in page needs.
func (s *Server) base(w http.ResponseWriter, r *http.Request, sess *Session, tab string) page {
	notice, errMsg := takeFlash(w, r)
	return page{User: &sess.User, CSRF: sess.CSRF, Notice: notice, Error: errMsg, Tab: tab, ZFS: s.Portal.zfs != nil}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	username, password := r.PostFormValue("username"), r.PostFormValue("password")
	id, err := s.Auth.Authenticate(username, password)
	if err != nil {
		time.Sleep(s.failedWait)
		msg := "Wrong username or password."
		status := http.StatusUnauthorized
		if !errors.Is(err, ErrBadCredentials) {
			slog.Error("login", "user", username, "err", err)
			msg, status = "Couldn't check your password right now. Try again shortly.", http.StatusBadGateway
		} else {
			slog.Info("login failed", "user", username, "remote", s.clientIP(r))
		}
		s.render(w, status, "login.html", page{Error: msg})
		return
	}
	s.startSession(w, r, id, "ldap")
}

// startSession records a login and starts its session.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, id Identity, source string) bool {
	if _, err := s.Portal.Login(r.Context(), id, source); err != nil {
		slog.Error("record login", "user", id.Name, "err", err)
		s.render(w, http.StatusBadGateway, "login.html", page{Error: genericError})
		return false
	}
	if err := s.Sessions.Start(w, id.Name); err != nil {
		slog.Error("start session", "user", id.Name, "err", err)
		http.Error(w, "session error", http.StatusInternalServerError)
		return false
	}
	slog.Info("login", "user", id.Name, "via", source, "remote", s.clientIP(r))
	if source == "ldap" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	return true
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.Sessions.End(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ------------------------------------------------------------------- files

// browseURL is the file browser's page for a folder.
func browseURL(bucket, prefix string) string {
	q := url.Values{"bucket": {bucket}}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	return "/files?" + q.Encode()
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

// sidebar fills in the bucket list, and the open bucket if it's in it.
func (s *Server) sidebar(r *http.Request, sess *Session, p *page, open string) error {
	buckets, err := s.Portal.Buckets(r.Context(), sess.User)
	if err != nil {
		return err
	}
	p.Buckets = buckets
	p.Sizes = s.Portal.BucketSizes(r.Context())
	if open != "" {
		v, err := s.Portal.Bucket(r.Context(), sess.User, open, false)
		if err != nil {
			return err
		}
		p.Open = &v
	}
	return nil
}

func (s *Server) files(w http.ResponseWriter, r *http.Request, sess *Session) {
	q := r.URL.Query()
	bucket, prefix := q.Get("bucket"), q.Get("prefix")
	p := s.base(w, r, sess, "files")
	if err := s.sidebar(r, sess, &p, bucket); err != nil {
		var ue *UserError
		if errors.As(err, &ue) {
			redirectFlash(w, r, "/files", "", ue.Msg)
			return
		}
		p.Error = userMessage(r, sess, err)
		s.render(w, http.StatusBadGateway, "files.html", p)
		return
	}
	if p.Open == nil || p.Open.Caps.None() {
		s.render(w, http.StatusOK, "files.html", p)
		return
	}
	p.Prefix, p.Crumbs = prefix, crumbs(prefix)
	if snap := q.Get("snap"); snap != "" {
		p.Snap = snap
		list, err := s.Portal.ListSnapshot(r.Context(), sess.User, bucket, snap, prefix, q.Get("token"))
		if err != nil {
			p.Error = userMessage(r, sess, err)
			s.render(w, http.StatusBadRequest, "files.html", p)
			return
		}
		p.Listing, p.NextToken = list, list.NextToken
		s.render(w, http.StatusOK, "files.html", p)
		return
	}
	if p.Open.Caps.Read {
		list, err := s.Portal.ListObjects(r.Context(), sess.User, bucket, prefix, q.Get("token"))
		if err != nil {
			p.Error = userMessage(r, sess, err)
			s.render(w, http.StatusBadGateway, "files.html", p)
			return
		}
		p.Listing, p.NextToken = list, list.NextToken
	}
	s.render(w, http.StatusOK, "files.html", p)
}

func (s *Server) createBucket(w http.ResponseWriter, r *http.Request, sess *Session) {
	name := r.PostFormValue("name")
	if err := s.Portal.CreateBucket(r.Context(), sess.User, name); err != nil {
		redirectFlash(w, r, "/files", "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, browseURL(name, ""), "Created bucket "+name+".", "")
}

func (s *Server) deleteBucket(w http.ResponseWriter, r *http.Request, sess *Session) {
	name := r.PostFormValue("name")
	if err := s.Portal.DeleteBucket(r.Context(), sess.User, name); err != nil {
		redirectFlash(w, r, "/buckets/settings?section=delete&bucket="+url.QueryEscape(name), "", userMessage(r, sess, err))
		return
	}
	msg := "Deleted bucket " + name + "."
	if s.Portal.zfs != nil {
		msg += " An admin can still restore it from the trash."
	}
	redirectFlash(w, r, "/files", msg, "")
}

func (s *Server) bucketSettings(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket := r.URL.Query().Get("bucket")
	p := s.base(w, r, sess, "files")
	if err := s.sidebar(r, sess, &p, bucket); err != nil {
		redirectFlash(w, r, "/files", "", userMessage(r, sess, err))
		return
	}
	if !p.Open.Manage {
		redirectFlash(w, r, browseURL(bucket, ""), "", "Only the bucket's owner or an admin can change its settings.")
		return
	}
	p.Settings = true
	p.Section = r.URL.Query().Get("section")
	switch p.Section {
	case "keys", "delete":
	case "storage":
		if !p.ZFS {
			p.Section = "access"
		}
	default:
		p.Section = "access"
	}
	p.Grantees = s.Portal.store.BucketMeta(bucket).Groups
	p.GroupList = s.Portal.Groups()
	if p.Section == "keys" {
		keys, err := s.Portal.BucketKeys(r.Context(), sess.User, bucket)
		if err != nil {
			p.Error = userMessage(r, sess, err)
		}
		p.BucketKeys = keys
	}
	if p.ZFS && p.Section == "storage" {
		st, err := s.Portal.Storage(r.Context(), sess.User, bucket)
		if err != nil {
			p.Error = userMessage(r, sess, err)
		}
		p.Storage = st
	}
	s.render(w, http.StatusOK, "files.html", p)
}

func (s *Server) settingsURL(bucket string) string {
	return "/buckets/settings?bucket=" + url.QueryEscape(bucket)
}

func (s *Server) removeKeyFromBucket(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket, access := r.PostFormValue("bucket"), r.PostFormValue("access")
	back := s.settingsURL(bucket) + "&section=keys"
	if err := s.Portal.RemoveKeyFromBucket(r.Context(), sess.User, access, bucket); err != nil {
		redirectFlash(w, r, back, "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, back, "That key no longer reaches "+bucket+".", "")
}

func (s *Server) setQuota(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket := r.PostFormValue("bucket")
	bytes, err := ParseSize(r.PostFormValue("quota"))
	if err != nil {
		redirectFlash(w, r, s.settingsURL(bucket)+"&section=storage", "", "Give a size like 500G or 2T, or 0 for no limit.")
		return
	}
	if err := s.Portal.SetQuota(r.Context(), sess.User, bucket, bytes); err != nil {
		redirectFlash(w, r, s.settingsURL(bucket)+"&section=storage", "", userMessage(r, sess, err))
		return
	}
	msg := "Removed the size limit."
	if bytes > 0 {
		msg = "Limited " + bucket + " to " + humanSize(bytes) + "."
	}
	redirectFlash(w, r, s.settingsURL(bucket)+"&section=storage", msg, "")
}

func (s *Server) setBackup(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket := r.PostFormValue("bucket")
	include := r.PostFormValue("include") == "on"
	if err := s.Portal.SetBackup(r.Context(), sess.User, bucket, include); err != nil {
		redirectFlash(w, r, s.settingsURL(bucket)+"&section=storage", "", userMessage(r, sess, err))
		return
	}
	msg := bucket + " is no longer backed up."
	if include {
		msg = bucket + " will be included in backups."
	}
	redirectFlash(w, r, s.settingsURL(bucket)+"&section=storage", msg, "")
}

func (s *Server) setSchedule(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket := r.PostFormValue("bucket")
	spec := r.PostFormValue("every")
	if spec != "" && spec != "off" {
		spec += ":" + r.PostFormValue("keep")
	}
	sched, err := ParseSchedule(spec)
	if err != nil {
		redirectFlash(w, r, s.settingsURL(bucket)+"&section=storage", "", "Pick how often, and keep between 1 and 1000 snapshots.")
		return
	}
	if err := s.Portal.SetSchedule(r.Context(), sess.User, bucket, sched); err != nil {
		redirectFlash(w, r, s.settingsURL(bucket)+"&section=storage", "", userMessage(r, sess, err))
		return
	}
	msg := "Scheduled snapshots are off."
	if sched.Every != "" {
		msg = fmt.Sprintf("Snapshots %s, keeping the last %d.", sched.Every, sched.Keep)
	}
	redirectFlash(w, r, s.settingsURL(bucket)+"&section=storage", msg, "")
}

func (s *Server) snapshotsURL(bucket string) string {
	return "/buckets/snapshots?bucket=" + url.QueryEscape(bucket)
}

func (s *Server) snapshotsPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket := r.URL.Query().Get("bucket")
	p := s.base(w, r, sess, "files")
	if err := s.sidebar(r, sess, &p, bucket); err != nil {
		redirectFlash(w, r, "/files", "", userMessage(r, sess, err))
		return
	}
	p.Snapshots = true
	st, err := s.Portal.Storage(r.Context(), sess.User, bucket)
	if err != nil {
		p.Error = userMessage(r, sess, err)
	}
	p.Storage = st
	s.render(w, http.StatusOK, "files.html", p)
}

func (s *Server) takeSnapshot(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket := r.PostFormValue("bucket")
	snap, err := s.Portal.TakeSnapshot(r.Context(), sess.User, bucket)
	if err != nil {
		redirectFlash(w, r, s.snapshotsURL(bucket), "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, s.snapshotsURL(bucket), "Took snapshot "+snap.Name+".", "")
}

func (s *Server) deleteSnapshot(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket, snap := r.PostFormValue("bucket"), r.PostFormValue("snapshot")
	if err := s.Portal.DeleteSnapshot(r.Context(), sess.User, bucket, snap); err != nil {
		redirectFlash(w, r, s.snapshotsURL(bucket), "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, s.snapshotsURL(bucket), "Deleted snapshot "+snap+".", "")
}

// snapURL is the file browser's page for a folder in a snapshot.
func snapURL(bucket, snap, prefix string) string {
	q := url.Values{"bucket": {bucket}, "snap": {snap}}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	return "/files?" + q.Encode()
}

func (s *Server) restore(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket, snap := r.PostFormValue("bucket"), r.PostFormValue("snap")
	key, folder, prefix := r.PostFormValue("key"), r.PostFormValue("folder"), r.PostFormValue("prefix")
	back := snapURL(bucket, snap, prefix)
	if key == "" && folder == "" && r.PostFormValue("all") != "yes" {
		redirectFlash(w, r, back, "", "Pick what to restore.")
		return
	}
	res, err := s.Portal.Restore(r.Context(), sess.User, bucket, snap, key, folder)
	if err != nil {
		redirectFlash(w, r, back, "", userMessage(r, sess, err))
		return
	}
	msg := fmt.Sprintf("Restored %d file(s) from %s.", res.Objects, snap)
	if res.Skipped > 0 {
		msg += fmt.Sprintf(" %d with names too long to restore were skipped.", res.Skipped)
	}
	redirectFlash(w, r, back, msg, "")
}

func (s *Server) setGroupGrant(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket, group := r.PostFormValue("bucket"), r.PostFormValue("group")
	perm := Perm(r.PostFormValue("perm"))
	back := "/buckets/settings?bucket=" + url.QueryEscape(bucket)
	if err := s.Portal.SetGroupGrant(r.Context(), sess.User, bucket, group, perm); err != nil {
		redirectFlash(w, r, back, "", userMessage(r, sess, err))
		return
	}
	if perm == "" {
		redirectFlash(w, r, back, "Removed "+group+"'s access.", "")
		return
	}
	redirectFlash(w, r, back, "Gave "+group+" "+perm.Label()+" access.", "")
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
	bucket, key, snap := q.Get("bucket"), q.Get("key"), q.Get("snap")
	var resp *http.Response
	var err error
	back := browseURL(bucket, parentPrefix(key))
	if snap != "" {
		resp, err = s.Portal.GetSnapshotObject(r.Context(), sess.User, bucket, snap, key)
		back = snapURL(bucket, snap, parentPrefix(key))
	} else {
		resp, err = s.Portal.GetObject(r.Context(), sess.User, bucket, key)
	}
	if err != nil {
		redirectFlash(w, r, back, "", userMessage(r, sess, err))
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

// selection reads a file browser selection from a form.
func selection(r *http.Request) Selection {
	return Selection{
		Bucket: r.PostFormValue("bucket"), Snap: r.PostFormValue("snap"), Prefix: r.PostFormValue("prefix"),
		Keys: r.PostForm["key"], Folders: r.PostForm["folder"],
	}
}

// back is the folder a selection was made in.
func (sel Selection) back() string {
	if sel.Snap != "" {
		return snapURL(sel.Bucket, sel.Snap, sel.Prefix)
	}
	return browseURL(sel.Bucket, sel.Prefix)
}

// archiveSelection streams the selection as a .tar or .zip download.
func (s *Server) archiveSelection(w http.ResponseWriter, r *http.Request, sess *Session) {
	sel, format := selection(r), r.PostFormValue("format")
	if format != "tar" && format != "zip" {
		redirectFlash(w, r, sel.back(), "", "Archives can be .tar or .zip.")
		return
	}
	// Check what can be checked before anything is sent: after the first
	// byte, a failure can only cut the download short.
	if err := sel.check(); err != nil {
		redirectFlash(w, r, sel.back(), "", userMessage(r, sess, err))
		return
	}
	if _, err := s.Portal.Bucket(r.Context(), sess.User, sel.Bucket, false); err != nil {
		redirectFlash(w, r, sel.back(), "", userMessage(r, sess, err))
		return
	}
	unlimited(w)
	h := w.Header()
	h.Set("Content-Type", map[string]string{"tar": "application/x-tar", "zip": "application/zip"}[format])
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": sel.ArchiveName(format)}))
	h.Set("Cache-Control", "no-store")
	cw := &countingWriter{w: w}
	files, _, err := s.Portal.WriteArchive(r.Context(), sess.User, sel, format, cw)
	if err != nil && cw.n == 0 {
		redirectFlash(w, r, sel.back(), "", userMessage(r, sess, err))
		return
	}
	if err != nil {
		// Too late to say so: end the response without finishing it, so
		// the browser marks the download failed rather than complete.
		slog.Warn("archive cut short", "user", sess.User.Name, "bucket", sel.Bucket, "files", files, "err", err)
		panic(http.ErrAbortHandler)
	}
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// listSelection lists every file a selection covers, as JSON, for the
// browser to download one by one.
func (s *Server) listSelection(w http.ResponseWriter, r *http.Request, sess *Session) {
	sel := selection(r)
	type file struct {
		Key  string `json:"key"`
		Size int64  `json:"size"`
	}
	out := []file{}
	const max = 20000
	err := s.Portal.WalkSelection(r.Context(), sess.User, sel, func(o Object) error {
		if strings.HasSuffix(o.Key, "/") {
			return nil
		}
		if len(out) == max {
			return userErr("That's more than %d files: download it as a .tar or .zip instead.", max)
		}
		out = append(out, file{o.Key, o.Size})
		return nil
	})
	if err != nil {
		http.Error(w, userMessage(r, sess, err), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (s *Server) deleteSelection(w http.ResponseWriter, r *http.Request, sess *Session) {
	sel := selection(r)
	n, err := s.Portal.DeleteSelection(r.Context(), sess.User, sel)
	if err != nil {
		msg := userMessage(r, sess, err)
		if n > 0 {
			msg = fmt.Sprintf("Deleted %d files, then: %s", n, msg)
		}
		redirectFlash(w, r, sel.back(), "", msg)
		return
	}
	plural := func(n int, one string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %ss", n, one)
	}
	var parts []string
	if len(sel.Keys) > 0 {
		parts = append(parts, plural(len(sel.Keys), "file"))
	}
	if len(sel.Folders) > 0 {
		parts = append(parts, plural(len(sel.Folders), "folder")+" holding "+plural(n-len(sel.Keys), "file"))
	}
	redirectFlash(w, r, sel.back(), "Deleted "+strings.Join(parts, " and ")+".", "")
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

// -------------------------------------------------------------------- keys

func (s *Server) keysPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	p := s.base(w, r, sess, "keys")
	p.Keys = s.Portal.Keys(sess.User)
	p.KeyCaps = map[string]map[string]Caps{}
	for _, k := range p.Keys {
		p.KeyCaps[k.Access] = s.Portal.KeyAccess(r.Context(), k.Key)
	}
	s.render(w, http.StatusOK, "keys.html", p)
}

// grantsFromForm reads a perm_<bucket> field for each bucket the user can
// reach, and keeps grants the key already had on buckets they no longer
// can (those are shown, and kept unless changed).
func grantsFromForm(r *http.Request, buckets []BucketView, had map[string]Perm) map[string]Perm {
	grants := map[string]Perm{}
	seen := map[string]bool{}
	for _, b := range buckets {
		seen[b.Name] = true
		if p := Perm(r.PostFormValue("perm_" + b.Name)); p.Valid() {
			grants[b.Name] = p
		}
	}
	for b, p := range had {
		if !seen[b] && r.PostFormValue("perm_"+b) == string(p) {
			grants[b] = p
		}
	}
	return grants
}

func (s *Server) keyForm(w http.ResponseWriter, r *http.Request, sess *Session, name string, status int, p page) {
	base := s.base(w, r, sess, "keys")
	p.User, p.CSRF, p.Tab = base.User, base.CSRF, base.Tab
	buckets, err := s.Portal.Buckets(r.Context(), sess.User)
	if err != nil {
		p.Error = userMessage(r, sess, err)
		s.render(w, http.StatusBadGateway, name, p)
		return
	}
	p.Buckets = buckets
	if p.Grants == nil {
		p.Grants = map[string]Perm{}
	}
	s.render(w, status, name, p)
}

func (s *Server) newKey(w http.ResponseWriter, r *http.Request, sess *Session) {
	p := page{}
	// From a bucket's settings: start with that bucket at the most the
	// person can give.
	if b := r.URL.Query().Get("bucket"); b != "" {
		if v, err := s.Portal.Bucket(r.Context(), sess.User, b, false); err == nil {
			for _, perm := range Perms {
				if v.Caps.Covers(perm.Caps()) {
					p.Grants = map[string]Perm{b: perm}
					p.KeyLabel = b
					break
				}
			}
		}
	}
	s.keyForm(w, r, sess, "key_new.html", http.StatusOK, p)
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request, sess *Session) {
	buckets, err := s.Portal.Buckets(r.Context(), sess.User)
	if err != nil {
		redirectFlash(w, r, "/keys", "", userMessage(r, sess, err))
		return
	}
	label := r.PostFormValue("label")
	grants := grantsFromForm(r, buckets, nil)
	access, secret, err := s.Portal.CreateKey(r.Context(), sess.User, label, grants)
	if err != nil {
		var ue *UserError
		if errors.As(err, &ue) {
			s.keyForm(w, r, sess, "key_new.html", http.StatusBadRequest, page{Error: ue.Msg, KeyLabel: label, Grants: grants})
			return
		}
		redirectFlash(w, r, "/keys", "", userMessage(r, sess, err))
		return
	}
	s.render(w, http.StatusOK, "key_created.html", page{
		User: &sess.User, CSRF: sess.CSRF, Tab: "keys",
		KeyAccess: access, KeySecret: secret, KeyLabel: label, Grants: grants,
	})
}

func (s *Server) editKey(w http.ResponseWriter, r *http.Request, sess *Session) {
	access := r.URL.Query().Get("access")
	k, err := s.Portal.Key(sess.User, access)
	if err != nil {
		redirectFlash(w, r, "/keys", "", userMessage(r, sess, err))
		return
	}
	s.keyForm(w, r, sess, "key_edit.html", http.StatusOK, page{KeyAccess: access, KeyLabel: k.Label, Grants: k.Buckets})
}

func (s *Server) updateKey(w http.ResponseWriter, r *http.Request, sess *Session) {
	access, label := r.PostFormValue("access"), r.PostFormValue("label")
	k, err := s.Portal.Key(sess.User, access)
	if err != nil {
		redirectFlash(w, r, "/keys", "", userMessage(r, sess, err))
		return
	}
	buckets, err := s.Portal.Buckets(r.Context(), sess.User)
	if err != nil {
		redirectFlash(w, r, "/keys", "", userMessage(r, sess, err))
		return
	}
	grants := grantsFromForm(r, buckets, k.Buckets)
	if err := s.Portal.UpdateKey(r.Context(), sess.User, access, label, grants); err != nil {
		var ue *UserError
		if errors.As(err, &ue) {
			s.keyForm(w, r, sess, "key_edit.html", http.StatusBadRequest, page{Error: ue.Msg, KeyAccess: access, KeyLabel: label, Grants: grants})
			return
		}
		redirectFlash(w, r, "/keys", "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, "/keys", "Updated key "+label+".", "")
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request, sess *Session) {
	if err := s.Portal.DeleteKey(r.Context(), sess.User, r.PostFormValue("access")); err != nil {
		redirectFlash(w, r, "/keys", "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, "/keys", "Revoked the key.", "")
}

// ------------------------------------------------------------------- admin

// admin restricts h to admins.
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
	p := s.base(w, r, sess, "admin")
	p.Section = r.URL.Query().Get("section")
	switch p.Section {
	case "buckets", "keys", "trash", "revoke":
	default:
		p.Section = "people"
	}
	p.Filter = r.URL.Query().Get("owner")
	if p.Section == "buckets" {
		p.Sizes = s.Portal.BucketSizes(r.Context())
	}
	p.AllKeys = s.Portal.AllKeys()
	for _, e := range p.AllKeys {
		if len(p.Owners) == 0 || p.Owners[len(p.Owners)-1] != e.Owner {
			p.Owners = append(p.Owners, e.Owner)
		}
	}
	for _, name := range sortedKeys(s.Portal.store.People()) {
		p.People = append(p.People, s.Portal.Status(name))
	}
	p.Directory = s.Portal.dir != nil
	buckets, err := s.Portal.AllBuckets(r.Context())
	if err != nil {
		p.Error = userMessage(r, sess, err)
	}
	p.AllBuckets = buckets
	if trash, err := s.Portal.Trash(r.Context(), sess.User); err != nil {
		p.Error = userMessage(r, sess, err)
	} else {
		p.Trash = trash
	}
	s.render(w, http.StatusOK, "admin.html", p)
}

func (s *Server) adminRestoreTrash(w http.ResponseWriter, r *http.Request, sess *Session) {
	entry := r.PostFormValue("entry")
	if err := s.Portal.RestoreTrash(r.Context(), sess.User, entry); err != nil {
		redirectFlash(w, r, "/admin?section=trash", "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, "/admin?section=trash", "Restored the bucket. Give its groups and keys access again.", "")
}

func (s *Server) adminPurgeTrash(w http.ResponseWriter, r *http.Request, sess *Session) {
	entry := r.PostFormValue("entry")
	if err := s.Portal.PurgeTrash(r.Context(), sess.User, entry); err != nil {
		redirectFlash(w, r, "/admin?section=trash", "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, "/admin?section=trash", "Purged "+entry+" for good.", "")
}

func (s *Server) adminRevoke(w http.ResponseWriter, r *http.Request, sess *Session) {
	if err := s.Portal.RevokeKey(r.Context(), sess.User, r.PostFormValue("access")); err != nil {
		redirectFlash(w, r, "/admin?section=keys", "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, "/admin?section=keys", "Revoked the key.", "")
}

func (s *Server) adminRevokeUser(w http.ResponseWriter, r *http.Request, sess *Session) {
	owner := r.PostFormValue("owner")
	if owner == "" {
		redirectFlash(w, r, "/admin?section=people", "", "Pick whose keys to revoke.")
		return
	}
	n, err := s.Portal.RevokeKeys(r.Context(), sess.User, owner)
	if err != nil {
		redirectFlash(w, r, "/admin?section=people", "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, "/admin?section=people", fmt.Sprintf("Revoked %d of %s's keys.", n, owner), "")
}

// revokeAllPhrase must be typed to revoke every key, so it can't happen by a
// stray click.
const revokeAllPhrase = "revoke all"

func (s *Server) adminRevokeAll(w http.ResponseWriter, r *http.Request, sess *Session) {
	if strings.ToLower(strings.TrimSpace(r.PostFormValue("confirm"))) != revokeAllPhrase {
		redirectFlash(w, r, "/admin?section=revoke", "", "Type “revoke all” to confirm revoking every key.")
		return
	}
	n, err := s.Portal.RevokeKeys(r.Context(), sess.User, "")
	if err != nil {
		redirectFlash(w, r, "/admin?section=revoke", "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, "/admin?section=revoke", fmt.Sprintf("Revoked all %d keys.", n), "")
}

func (s *Server) adminCheck(w http.ResponseWriter, r *http.Request, sess *Session) {
	name := r.PostFormValue("user")
	st, err := s.Portal.CheckPerson(r.Context(), name)
	if err != nil {
		redirectFlash(w, r, "/admin?section=people", "", userMessage(r, sess, err))
		return
	}
	msg := name + " is active."
	if st.Disabled {
		msg = fmt.Sprintf("%s is disabled (%s): their keys are suspended and they're logged out.", name, st.Reason)
	}
	redirectFlash(w, r, "/admin?section=people", msg, "")
}

func (s *Server) adminSync(w http.ResponseWriter, r *http.Request, sess *Session) {
	report, err := s.Portal.SyncDirectory(r.Context())
	if err != nil {
		redirectFlash(w, r, "/admin?section=people", "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, "/admin?section=people", fmt.Sprintf("Checked %d people against the directory: %d changed, %d disabled.", report.Checked, len(report.Changed), report.Disabled), "")
}

func (s *Server) adminEndSessions(w http.ResponseWriter, r *http.Request, sess *Session) {
	name := r.PostFormValue("user")
	n, err := s.Portal.EndSessions(sess.User, name)
	if err != nil {
		redirectFlash(w, r, "/admin?section=people", "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, "/admin?section=people", fmt.Sprintf("Logged %s out of %d sessions.", name, n), "")
}

// --------------------------------------------------------------------- API

// api allows a request with the API token as a bearer token, or from an
// admin's session with the CSRF token in X-CSRF-Token. It answers in JSON.
func (s *Server) api(h func(r *http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowed, who := false, ""
		if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			allowed = s.APIToken != "" && subtle.ConstantTimeCompare([]byte(bearer), []byte(s.APIToken)) == 1
			who = "token"
		} else if sess, err := s.Sessions.Get(r); err == nil && sess.User.Admin {
			allowed = r.Method == http.MethodGet || r.Header.Get("X-CSRF-Token") == sess.CSRF
			who = sess.User.Name
		}
		w.Header().Set("Content-Type", "application/json")
		if !allowed {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		out, err := h(r)
		if err != nil {
			status := http.StatusBadGateway
			msg := genericError
			var ue *UserError
			if errors.As(err, &ue) {
				status, msg = http.StatusBadRequest, ue.Msg
			} else {
				slog.Error("api", "path", r.URL.Path, "by", who, "err", err)
			}
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]any{"error": msg, "result": out})
			return
		}
		if r.Method != http.MethodGet {
			slog.Info("api", "path", r.URL.Path, "by", who)
		}
		json.NewEncoder(w).Encode(out)
	}
}

func (s *Server) apiSync(r *http.Request) (any, error) {
	return s.Portal.SyncDirectory(r.Context())
}

func (s *Server) apiUser(r *http.Request) (any, error) {
	return s.Portal.Status(r.PathValue("name")), nil
}

func (s *Server) apiCheckUser(r *http.Request) (any, error) {
	return s.Portal.CheckPerson(r.Context(), r.PathValue("name"))
}

// ------------------------------------------------------------------ helpers

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
