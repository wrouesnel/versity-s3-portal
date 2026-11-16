package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
)

// ServerMirror is a whole S3 server being mirrored in: its buckets are
// listed, and each one an admin picks becomes a mirror of its own (Mirror,
// with Server set to this one's ID), with a bucket here made for its owner.
// The server's record keeps the source's endpoint and key, so buckets made
// on the source later can be added, and groups the mirrors for actions
// taken on all of them at once.
type ServerMirror struct {
	ID string `json:"id"`
	// Name is what admins call it, as "old MinIO".
	Name string `json:"name"`
	// Source is the server's endpoint and key, with no bucket.
	Source MirrorSource `json:"source"`
	// DefaultOwner owns the buckets made, unless the admin picks another
	// for one.
	DefaultOwner string    `json:"defaultOwner"`
	Every        string    `json:"every,omitempty"`
	LimitMBps    int       `json:"limitMBps,omitempty"`
	Created      time.Time `json:"created"`
	By           string    `json:"by"`
}

// ServerRequest is the new server mirror form.
type ServerRequest struct {
	Name         string
	Source       MirrorSource
	DefaultOwner string
	Every        string
	LimitMBps    int
}

// Row statuses: what the review table says of a source bucket not yet
// mirrored, and whether it is ticked.
const (
	RowReady       = "ready"        // a new bucket here, for its owner
	RowExistsEmpty = "exists-empty" // the bucket here is there, and empty: used as is
	RowClash       = "clash"        // a bucket here has the name, and holds things: give another name
	RowInvalid     = "invalid"      // the name can't be a bucket here: give another
	RowElsewhere   = "elsewhere"    // another mirror copies this source bucket already
)

// ServerRow is a source bucket not yet mirrored, as the review table shows
// it.
type ServerRow struct {
	// Source is the bucket's name on the source; Local its name here (the
	// same, unless the admin changes it).
	Source, Local string
	Status        string
	// Note says why a row isn't ticked, or what will happen.
	Note string
	// Owner is who will own the bucket here: the server's default, or the
	// bucket's owner for one that's there.
	Owner   string
	Include bool
}

// ServerView is a server mirror's page.
type ServerView struct {
	ServerMirror
	HasSecret bool
	// Mirrors are its buckets' mirrors.
	Mirrors []MirrorView
	// Rows are the source's buckets not yet mirrored, from a listing now.
	Rows []ServerRow
	// ListError is why the source couldn't be listed, if it couldn't.
	ListError string
	Listed    time.Time
	// Counts are its mirrors by state, for the summary and the buttons.
	Active, Syncing, Synced, Freezing, Verified, Done int
}

// ServerSummary is a line of the server mirrors' list.
type ServerSummary struct {
	ID, Name, Endpoint string
	Buckets            int
	Active, Verified   int
	Done               int
}

var serverNameRe = regexp.MustCompile(`[^a-z0-9]+`)

// serverID is a new server mirror's ID, made from its name: unique.
func (p *Portal) serverID(name string) string {
	base := strings.Trim(serverNameRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if base == "" {
		base = "server"
	}
	if len(base) > 40 {
		base = strings.Trim(base[:40], "-")
	}
	id := base
	for n := 2; ; n++ {
		if _, taken := p.store.Server(id); !taken {
			return id
		}
		id = fmt.Sprintf("%s-%d", base, n)
	}
}

// checkServerSource is checkSource without a bucket.
func checkServerSource(s *MirrorSource) error {
	s.Bucket = "-"
	err := checkSource(s)
	s.Bucket = ""
	return err
}

// sourceClient is the S3 client for a source.
func sourceClient(src MirrorSource) *VGW {
	v := NewVGW(src.Endpoint, "", src.Region, src.Access, src.Secret)
	v.Virtual = src.Virtual
	return v
}

// listServer lists the server's buckets, with a user's error when it
// can't.
func listServer(ctx context.Context, src MirrorSource) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	names, err := sourceClient(src).SourceBuckets(ctx)
	if err != nil {
		return nil, userErr("Couldn't list the server's buckets: %v. The key needs s3:ListAllMyBuckets, as well as reading each bucket.", err)
	}
	return names, nil
}

// RegisterServer saves a server to mirror buckets from, once its buckets
// can be listed with the key. Nothing is mirrored until the admin picks
// buckets (CreateServerMirrors).
func (p *Portal) RegisterServer(ctx context.Context, admin User, req ServerRequest) (string, error) {
	if err := requireAdmin(admin); err != nil {
		return "", err
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return "", userErr("Name the server, as admins will know it.")
	}
	if err := checkServerSource(&req.Source); err != nil {
		return "", err
	}
	if err := checkSchedule(req.Every, req.LimitMBps); err != nil {
		return "", err
	}
	req.DefaultOwner = strings.TrimSpace(req.DefaultOwner)
	if _, ok := p.store.Person(req.DefaultOwner); !ok {
		return "", userErr("Nobody called %q has logged in, so they can't own buckets yet.", req.DefaultOwner)
	}
	if _, err := listServer(ctx, req.Source); err != nil {
		return "", err
	}
	sm := &ServerMirror{
		ID: p.serverID(req.Name), Name: req.Name, Source: req.Source, DefaultOwner: req.DefaultOwner,
		Every: req.Every, LimitMBps: req.LimitMBps, Created: time.Now(), By: admin.Name,
	}
	if err := p.store.PutServer(sm); err != nil {
		return "", err
	}
	slog.Info("registered server mirror", "admin", admin.Name, "server", sm.ID, "endpoint", sm.Source.Endpoint)
	return sm.ID, nil
}

// server is a server mirror's record, and its mirrors, by bucket.
func (p *Portal) server(id string) (*ServerMirror, []*Mirror, error) {
	sm, ok := p.store.Server(id)
	if !ok {
		return nil, nil, userErr("There's no server mirror called %s.", id)
	}
	var ms []*Mirror
	all := p.store.Mirrors()
	for _, b := range sortedKeys(all) {
		if all[b].Server == id {
			ms = append(ms, all[b])
		}
	}
	return sm, ms, nil
}

// ServerList lists the server mirrors, for admins.
func (p *Portal) ServerList(admin User) ([]ServerSummary, error) {
	if err := requireAdmin(admin); err != nil {
		return nil, err
	}
	var out []ServerSummary
	all := p.store.Servers()
	for _, id := range sortedKeys(all) {
		sm, ms, err := p.server(id)
		if err != nil {
			continue
		}
		v := ServerSummary{ID: id, Name: sm.Name, Endpoint: sm.Source.Endpoint, Buckets: len(ms)}
		for _, m := range ms {
			switch {
			case m.State == MirrorVerified:
				v.Verified++
				v.Active++
			case m.Active():
				v.Active++
			default:
				v.Done++
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// sameEndpoint compares two endpoints as URLs.
func sameEndpoint(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(a, "/"), strings.TrimRight(b, "/"))
}

// ServerDetail is a server mirror's page: its mirrors, and its buckets not
// yet mirrored, from a listing of the server now.
func (p *Portal) ServerDetail(ctx context.Context, admin User, id string) (*ServerView, error) {
	if err := requireAdmin(admin); err != nil {
		return nil, err
	}
	sm, ms, err := p.server(id)
	if err != nil {
		return nil, err
	}
	v := &ServerView{ServerMirror: *sm, HasSecret: sm.Source.Secret != "", Listed: time.Now()}
	v.Source.Secret = ""
	ours := map[string]bool{}
	for _, m := range ms {
		ours[m.Source.Bucket] = true
		v.Mirrors = append(v.Mirrors, p.mirrorView(m, false))
		switch m.State {
		case MirrorRegistered, MirrorSyncing:
			v.Syncing++
		case MirrorSynced:
			v.Synced++
		case MirrorFreezing:
			v.Freezing++
		case MirrorVerified:
			v.Verified++
		default:
			v.Done++
		}
		if m.Active() {
			v.Active++
		}
	}
	if sm.Source.Secret == "" {
		v.ListError = "its key was forgotten: replace it to list the server again."
		return v, nil
	}
	names, err := listServer(ctx, sm.Source)
	if err != nil {
		v.ListError = userMessageText(err)
		return v, nil
	}
	here, err := p.vgw.ListBuckets(ctx)
	if err != nil {
		return nil, err
	}
	owners := map[string]string{}
	for _, b := range here {
		owners[b.Name] = ownerName(b.Owner)
	}
	// Mirrors from elsewhere of this server's buckets, and the buckets here
	// being mirrored into.
	elsewhere, into := map[string]string{}, map[string]bool{}
	for _, m := range p.store.Mirrors() {
		if m.Active() {
			into[m.Bucket] = true
		}
		if m.Server != id && m.Active() && sameEndpoint(m.Source.Endpoint, sm.Source.Endpoint) {
			elsewhere[m.Source.Bucket] = m.Bucket
		}
	}
	empty := func(bucket string) bool {
		objs, _, err := p.vgw.ListPage(ctx, bucket, "", 1)
		return err == nil && len(objs) == 0
	}
	owner := sm.DefaultOwner
	if _, ok := p.store.Person(owner); !ok {
		owner = ""
	}
	for _, name := range names {
		if ours[name] {
			continue
		}
		v.Rows = append(v.Rows, planRow(name, owner, owners, into, elsewhere, sm.Source.Endpoint, empty))
	}
	return v, nil
}

// planRow is the review table's row for a source bucket not yet mirrored
// from the server: what it would become here, and whether it's ticked.
func planRow(src, owner string, owners map[string]string, into map[string]bool, elsewhere map[string]string,
	endpoint string, empty func(string) bool,
) ServerRow {
	r := ServerRow{Source: src, Local: src, Owner: owner}
	if local, ok := elsewhere[src]; ok {
		r.Status, r.Local = RowElsewhere, local
		r.Note = fmt.Sprintf("Already mirrored, from %s/%s, as %s.", strings.TrimRight(endpoint, "/"), src, local)
		return r
	}
	if !bucketRe.MatchString(src) {
		r.Status, r.Local = RowInvalid, suggestBucketName(src)
		r.Note = fmt.Sprintf("%s can't be a bucket name here: %s is offered instead.", src, r.Local)
		return r
	}
	have, exists := owners[src]
	switch {
	case !exists:
		r.Status, r.Include = RowReady, true
		r.Note = "A new bucket here."
	case into[src]:
		r.Status = RowClash
		r.Note = fmt.Sprintf("%s is here already, and another mirror copies into it: give it another name here.", src)
	case have != "" && empty(src):
		r.Status, r.Include, r.Owner = RowExistsEmpty, true, have
		r.Note = fmt.Sprintf("%s is here already, empty, and %s's: it's used as it is.", src, have)
	default:
		r.Status = RowClash
		r.Note = fmt.Sprintf("%s is here already, with things in it: give it another name here.", src)
	}
	return r
}

var notBucketChars = regexp.MustCompile(`[^a-z0-9-]+`)

// suggestBucketName is a name here for a source bucket's which can't be one:
// lowercased, with anything else made hyphens, 3 to 63 characters.
func suggestBucketName(src string) string {
	n := strings.Trim(notBucketChars.ReplaceAllString(strings.ToLower(src), "-"), "-")
	n = regexp.MustCompile(`-{2,}`).ReplaceAllString(n, "-")
	if len(n) > 63 {
		n = strings.Trim(n[:63], "-")
	}
	for len(n) < 3 {
		n += "-0"
		n = strings.TrimLeft(n, "-")
	}
	return n
}

// ServerPick is a row the admin ticked: the source bucket, its name here,
// and its owner ("" for a bucket here already, which keeps its own).
type ServerPick struct{ Source, Local, Owner string }

// CreateServerMirrors makes a mirror of each bucket picked, as
// RegisterMirror does one: a bucket here for its owner (or the empty one
// there already), and its source checked. One that fails is left out, and
// said why; the others go ahead.
func (p *Portal) CreateServerMirrors(ctx context.Context, admin User, id string, picks []ServerPick) ([]string, error) {
	if err := requireAdmin(admin); err != nil {
		return nil, err
	}
	sm, ms, err := p.server(id)
	if err != nil {
		return nil, err
	}
	if sm.Source.Secret == "" {
		return nil, userErr("The server's key was forgotten: replace it first.")
	}
	if len(picks) == 0 {
		return nil, userErr("Tick the buckets to mirror.")
	}
	ours := map[string]bool{}
	for _, m := range ms {
		ours[m.Source.Bucket] = true
	}
	here, err := p.vgw.ListBuckets(ctx)
	if err != nil {
		return nil, err
	}
	exists := map[string]bool{}
	for _, b := range here {
		exists[b.Name] = true
	}
	var made []string
	var failed []string
	seen := map[string]bool{}
	for _, pk := range picks {
		pk.Local = strings.TrimSpace(pk.Local)
		fail := func(msg string) { failed = append(failed, fmt.Sprintf("%s: %s", pk.Source, msg)) }
		switch {
		case ours[pk.Source]:
			fail("it's mirrored from this server already.")
			continue
		case seen[pk.Local]:
			fail(fmt.Sprintf("%s is picked for another bucket too.", pk.Local))
			continue
		}
		seen[pk.Local] = true
		src := sm.Source
		src.Bucket = pk.Source
		req := MirrorRequest{Bucket: pk.Local, NewOwner: pk.Owner, Source: src, Every: sm.Every, LimitMBps: sm.LimitMBps, Server: id}
		if exists[pk.Local] {
			// The bucket here, which must be empty, keeps its owner.
			req.NewOwner = ""
		} else if req.NewOwner == "" {
			req.NewOwner = sm.DefaultOwner
		}
		if err := p.RegisterMirror(ctx, admin, req); err != nil {
			fail(userMessageText(err))
			continue
		}
		made = append(made, pk.Local)
	}
	if len(failed) > 0 {
		return made, userErr("%s not mirrored: %s", plural(int64(len(failed)), "bucket"), strings.Join(failed, " "))
	}
	return made, nil
}

// serverMirrorsDo runs fn on each of a server's mirrors, saying how many it
// did, and what it couldn't.
func (p *Portal) serverMirrorsDo(admin User, id string, fn func(m *Mirror) (bool, error)) (int, error) {
	if err := requireAdmin(admin); err != nil {
		return 0, err
	}
	_, ms, err := p.server(id)
	if err != nil {
		return 0, err
	}
	n := 0
	var failed []string
	for _, m := range ms {
		did, err := fn(m)
		if err != nil {
			failed = append(failed, m.Bucket+": "+userMessageText(err))
		}
		if did {
			n++
		}
	}
	p.wakeMirrors()
	if len(failed) > 0 {
		return n, userErr("%s", strings.Join(failed, " "))
	}
	return n, nil
}

// ServerRunPasses queues a pass of each of the server's mirrors still
// syncing and not paused: the scheduler runs them maxMirrorJobs at a time.
func (p *Portal) ServerRunPasses(admin User, id string) (int, error) {
	return p.serverMirrorsDo(admin, id, func(m *Mirror) (bool, error) {
		if !m.syncing() || m.Paused {
			return false, nil
		}
		return true, p.updateMirror(m.Bucket, func(m *Mirror) error {
			m.Queued, m.QueuedBy = "manual", admin.Name
			return nil
		})
	})
}

// ServerPause pauses, or resumes, the scheduled passes of each of the
// server's mirrors.
func (p *Portal) ServerPause(admin User, id string, paused bool) (int, error) {
	return p.serverMirrorsDo(admin, id, func(m *Mirror) (bool, error) {
		if !m.Active() || m.Paused == paused {
			return false, nil
		}
		return true, p.updateMirror(m.Bucket, func(m *Mirror) error {
			m.Paused = paused
			return nil
		})
	})
}

// ServerFreeze records, on the admin's word, that writes to the whole
// server have stopped, and queues each mirror's final pass and checks. A
// mirror whose first pass hasn't run is left syncing.
func (p *Portal) ServerFreeze(admin User, id string, deep bool) (int, error) {
	kind := "final"
	if deep {
		kind = "final-deep"
	}
	return p.serverMirrorsDo(admin, id, func(m *Mirror) (bool, error) {
		switch m.State {
		case MirrorSyncing, MirrorSynced, MirrorFreezing:
		case MirrorRegistered:
			return false, userErr("its first pass hasn't run yet: freeze it on its own page once it has.")
		default:
			return false, nil
		}
		err := p.updateMirror(m.Bucket, func(m *Mirror) error {
			if m.State != MirrorFreezing {
				m.setState(MirrorFreezing, admin.Name, "Writes to the whole server have stopped, on the admin's word.")
			}
			m.Verification = nil
			m.Queued, m.QueuedBy = kind, admin.Name
			return nil
		})
		if err != nil {
			return false, err
		}
		p.stopJob(m.Bucket)
		return true, nil
	})
}

// ServerComplete completes each of the server's verified mirrors.
func (p *Portal) ServerComplete(ctx context.Context, admin User, id string) (int, error) {
	return p.serverMirrorsDo(admin, id, func(m *Mirror) (bool, error) {
		if m.State != MirrorVerified {
			return false, nil
		}
		return true, p.CompleteMirror(ctx, admin, m.Bucket)
	})
}

// ServerReplaceKey uses a new key for the server, and for each of its
// mirrors still running, once the server's buckets can be listed with it.
func (p *Portal) ServerReplaceKey(ctx context.Context, admin User, id, access, secret string) (int, error) {
	if err := requireAdmin(admin); err != nil {
		return 0, err
	}
	sm, _, err := p.server(id)
	if err != nil {
		return 0, err
	}
	src := sm.Source
	src.Access, src.Secret = strings.TrimSpace(access), secret
	if src.Access == "" || src.Secret == "" {
		return 0, userErr("The key needs its access key ID and secret.")
	}
	if _, err := listServer(ctx, src); err != nil {
		return 0, err
	}
	sm.Source = src
	if err := p.store.PutServer(sm); err != nil {
		return 0, err
	}
	return p.serverMirrorsDo(admin, id, func(m *Mirror) (bool, error) {
		if !m.Active() {
			return false, nil
		}
		return true, p.UpdateMirror(ctx, admin, m.Bucket, m.Every, m.LimitMBps, src.Access, src.Secret)
	})
}

// ForgetServer deletes a server mirror's record and its key, once each of
// its mirrors is complete or abandoned. The mirrors' records stay.
func (p *Portal) ForgetServer(admin User, id string) error {
	if err := requireAdmin(admin); err != nil {
		return err
	}
	_, ms, err := p.server(id)
	if err != nil {
		return err
	}
	for _, m := range ms {
		if m.Active() {
			return userErr("%s is still being mirrored: complete or abandon it first.", m.Bucket)
		}
	}
	return p.store.DeleteServer(id)
}

// userMessageText is a user error's message, or, for another, a generic
// one (logged): for errors gathered for many buckets at once.
func userMessageText(err error) string {
	var ue *UserError
	if errors.As(err, &ue) {
		return ue.Msg
	}
	slog.Error("server mirror", "err", err)
	return genericError
}
