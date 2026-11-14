package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// A mirror copies a bucket on another S3 service into a bucket here, on a
// schedule, until an admin freezes the source, runs a final pass that
// checks the two match, and completes the move. See
// docs/design-bucket-mirror.md.

type MirrorState string

const (
	MirrorRegistered    MirrorState = "registered"
	MirrorSyncing       MirrorState = "syncing"
	MirrorSynced        MirrorState = "synced"
	MirrorFreezing      MirrorState = "freezing"
	MirrorVerified      MirrorState = "verified"
	MirrorComplete      MirrorState = "complete"
	MirrorSourceRemoved MirrorState = "source-removed"
	MirrorAbandoned     MirrorState = "abandoned"
)

// mirrorSteps are the states in the order the checklist shows them.
var mirrorSteps = []MirrorState{MirrorRegistered, MirrorSyncing, MirrorSynced, MirrorFreezing, MirrorVerified, MirrorComplete, MirrorSourceRemoved}

func (s MirrorState) Label() string {
	switch s {
	case MirrorRegistered:
		return "Registered"
	case MirrorSyncing:
		return "Syncing"
	case MirrorSynced:
		return "Synced"
	case MirrorFreezing:
		return "Source frozen, final pass"
	case MirrorVerified:
		return "Verified"
	case MirrorComplete:
		return "Complete"
	case MirrorSourceRemoved:
		return "Source removed"
	case MirrorAbandoned:
		return "Abandoned"
	}
	return string(s)
}

// MirrorSource is the bucket being copied from.
type MirrorSource struct {
	Endpoint string `json:"endpoint"`
	Region   string `json:"region"`
	Bucket   string `json:"bucket"`
	Virtual  bool   `json:"virtual,omitempty"`
	Access   string `json:"access"`
	// Secret is deleted when the mirror completes or is abandoned.
	Secret string `json:"secret,omitempty"`
}

// Label is the source as people read it.
func (s MirrorSource) Label() string {
	return strings.TrimRight(s.Endpoint, "/") + "/" + s.Bucket
}

// MirrorEvent is one change of state, and who made it.
type MirrorEvent struct {
	At    time.Time   `json:"at"`
	State MirrorState `json:"state"`
	By    string      `json:"by"`
	Note  string      `json:"note,omitempty"`
}

// PassSummary is what one pass did. The full lists are in its report.
type PassSummary struct {
	N        int       `json:"n"`
	Kind     string    `json:"kind"`
	By       string    `json:"by,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	// Error is why the pass stopped early, if it did.
	Error         string `json:"error,omitempty"`
	SourceObjects int64  `json:"sourceObjects"`
	SourceBytes   int64  `json:"sourceBytes"`
	Copied        int64  `json:"copied"`
	CopiedBytes   int64  `json:"copiedBytes"`
	Repaired      int64  `json:"repaired"`
	Deleted       int64  `json:"deleted"`
	Failed        int64  `json:"failed"`
	Uncopyable    int64  `json:"uncopyable"`
	// UncopyableSum identifies the set of keys that couldn't be copied,
	// so accepting them holds only while the set is the same.
	UncopyableSum string `json:"uncopyableSum,omitempty"`
	Unexpected    int64  `json:"unexpected"`
	// Mirrored is what the target holds from the source after the pass.
	MirroredObjects int64  `json:"mirroredObjects"`
	MirroredBytes   int64  `json:"mirroredBytes"`
	Snapshot        string `json:"snapshot,omitempty"`
	SnapshotError   string `json:"snapshotError,omitempty"`
}

// Clean is whether the pass finished with nothing left undone.
func (s PassSummary) Clean(accepted *UncopyableAcceptance) bool {
	return s.Error == "" && s.Failed == 0 && s.Unexpected == 0 && s.uncopyableOK(accepted)
}

func (s PassSummary) uncopyableOK(accepted *UncopyableAcceptance) bool {
	return s.Uncopyable == 0 || (accepted != nil && accepted.Sum == s.UncopyableSum)
}

// Changes is how many objects the pass copied, repaired or deleted.
func (s PassSummary) Changes() int64 { return s.Copied + s.Repaired + s.Deleted }

// UncopyableAcceptance is an admin agreeing that a pass's keys that can't
// be copied are left behind.
type UncopyableAcceptance struct {
	By    string    `json:"by"`
	At    time.Time `json:"at"`
	Note  string    `json:"note"`
	Sum   string    `json:"sum"`
	Count int64     `json:"count"`
	Pass  int       `json:"pass"`
}

// Verification is the outcome of the checks after the final pass.
type Verification struct {
	At   time.Time `json:"at"`
	Pass int       `json:"pass"`
	// FinalClean is whether the final pass itself finished cleanly.
	FinalClean bool `json:"finalClean"`
	// QuietChanges are differences between the source and the manifest
	// found by listing the source again after the final pass.
	QuietChanges int64 `json:"quietChanges"`
	Checked      int64 `json:"checked"`
	// EndToEnd objects' bytes match the source's own MD5.
	EndToEnd int64 `json:"endToEnd"`
	// SizeOnly objects match on size, and the target matches the MD5 of
	// what was read from the source, but the source had no MD5 to compare.
	SizeOnly int64 `json:"sizeOnly"`
	Deep     bool  `json:"deep,omitempty"`
	// DeepChecked objects were read back from the target and match the
	// MD5 of what was read from the source.
	DeepChecked int64 `json:"deepChecked"`
	Mismatched  int64 `json:"mismatched"`
	Missing     int64 `json:"missing"`
	Unexpected  int64 `json:"unexpected"`
	Passed      bool  `json:"passed"`
	// Problems are the first few differences found, to show.
	Problems []string `json:"problems,omitempty"`
	Snapshot string   `json:"snapshot,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// Mirror is a bucket being copied in from another S3 service, or the
// record of one that was.
type Mirror struct {
	Bucket string       `json:"bucket"`
	Owner  string       `json:"owner"`
	Source MirrorSource `json:"source"`
	// Every is "hourly", "daily", or "" for passes run by hand only.
	Every string `json:"every,omitempty"`
	// LimitMBps caps how fast passes read from the source, or 0.
	LimitMBps int  `json:"limitMBps,omitempty"`
	Paused    bool `json:"paused,omitempty"`
	// Account is the gateway account the mirror writes as: the owner's
	// uid and gid, read & write on the bucket while it mirrors.
	Account WebAccount `json:"account"`
	// Found is what the connection test learned about the source.
	Found        string                `json:"found,omitempty"`
	State        MirrorState           `json:"state"`
	History      []MirrorEvent         `json:"history"`
	Passes       []PassSummary         `json:"passes,omitempty"`
	Accepted     *UncopyableAcceptance `json:"accepted,omitempty"`
	Verification *Verification         `json:"verification,omitempty"`
}

// Active is whether the mirror still holds the bucket: before Complete,
// and not abandoned.
func (m *Mirror) Active() bool {
	switch m.State {
	case MirrorRegistered, MirrorSyncing, MirrorSynced, MirrorFreezing, MirrorVerified:
		return true
	}
	return false
}

// syncing is whether scheduled passes run.
func (m *Mirror) syncing() bool {
	return m.State == MirrorRegistered || m.State == MirrorSyncing || m.State == MirrorSynced
}

func (m *Mirror) clone() *Mirror {
	data, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	var c Mirror
	if err := json.Unmarshal(data, &c); err != nil {
		panic(err)
	}
	return &c
}

func (m *Mirror) setState(s MirrorState, by, note string) {
	if m.State == s && note == "" {
		return
	}
	m.State = s
	m.History = append(m.History, MirrorEvent{At: time.Now(), State: s, By: by, Note: note})
}

// LastPass is the most recent pass, if any.
func (m *Mirror) LastPass() *PassSummary {
	if len(m.Passes) == 0 {
		return nil
	}
	return &m.Passes[len(m.Passes)-1]
}

func (m *Mirror) nextPass() int {
	if p := m.LastPass(); p != nil {
		return p.N + 1
	}
	return 1
}

func (m *Mirror) sourceClient() *VGW {
	v := NewVGW(m.Source.Endpoint, "", m.Source.Region, m.Source.Access, m.Source.Secret)
	v.Virtual = m.Source.Virtual
	return v
}

// keptPasses is how many pass summaries a mirror keeps.
const keptPasses = 200

// mirrorEvery is how long each schedule waits between passes.
var mirrorEvery = map[string]time.Duration{"hourly": time.Hour, "daily": 24 * time.Hour}

func mirrorAccess(bucket string) string { return "mirror." + bucket }

// Dir is the directory the store's file is in.
func (s *Store) Dir() string { return filepath.Dir(s.path) }

func (p *Portal) mirrorDir(bucket string) string {
	return filepath.Join(p.store.Dir(), "mirrors", bucket)
}

// mirrors is the running side of mirroring.
type mirrors struct {
	mu   sync.Mutex
	jobs map[string]*mirrorJob
	// ctx bounds every job; RunMirrors sets it.
	ctx  context.Context
	wake chan struct{}
}

type mirrorJob struct {
	kind   string
	by     string
	cancel context.CancelFunc
	done   chan struct{}
	prog   *passProgress
}

// maxMirrorJobs is how many mirrors copy at once.
const maxMirrorJobs = 2

// updateMirror changes bucket's record under the mirrors lock.
func (p *Portal) updateMirror(bucket string, fn func(m *Mirror) error) error {
	p.mirrors.mu.Lock()
	defer p.mirrors.mu.Unlock()
	return p.updateMirrorLocked(bucket, fn)
}

func (p *Portal) updateMirrorLocked(bucket string, fn func(m *Mirror) error) error {
	m, ok := p.store.Mirror(bucket)
	if !ok {
		return userErr("There's no mirror for %s.", bucket)
	}
	if err := fn(m); err != nil {
		return err
	}
	return p.store.PutMirror(bucket, m)
}

// ------------------------------------------------------------- register

// MirrorRequest is the new-mirror form.
type MirrorRequest struct {
	Bucket string
	// NewOwner, when set, makes the bucket for them; otherwise Bucket
	// must exist and be empty.
	NewOwner  string
	Source    MirrorSource
	Every     string
	LimitMBps int
}

func checkSource(s *MirrorSource) error {
	s.Endpoint = strings.TrimRight(strings.TrimSpace(s.Endpoint), "/")
	u, err := url.Parse(s.Endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return userErr("The source endpoint is a URL like https://s3.example.com, with no path.")
	}
	s.Region = strings.TrimSpace(s.Region)
	if s.Region == "" {
		s.Region = "us-east-1"
	}
	s.Bucket = strings.TrimSpace(s.Bucket)
	if s.Bucket == "" || strings.ContainsAny(s.Bucket, "/ ") {
		return userErr("Name the source bucket.")
	}
	s.Access = strings.TrimSpace(s.Access)
	if s.Access == "" || s.Secret == "" {
		return userErr("The source needs an access key ID and secret.")
	}
	return nil
}

func checkSchedule(every string, limit int) error {
	if _, ok := mirrorEvery[every]; !ok && every != "" {
		return userErr("Passes run hourly, daily, or only by hand.")
	}
	if limit < 0 || limit > 100000 {
		return userErr("The speed limit is in MB/s, or 0 for none.")
	}
	return nil
}

// testSource checks the source can be listed and read, and says what it
// found that matters.
func testSource(ctx context.Context, src *VGW, bucket string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	objs, _, err := src.ListPage(ctx, bucket, "", 1)
	if err != nil {
		return "", userErr("Couldn't list the source bucket: %v", err)
	}
	var found []string
	if len(objs) == 0 {
		found = append(found, "The source bucket is empty.")
	} else {
		if _, err := src.Head(ctx, bucket, objs[0].Key); err != nil {
			return "", userErr("Listed the source, but couldn't read %q from it: %v", objs[0].Key, err)
		}
		found = append(found, "Listed and read the source.")
	}
	versioning, lock := src.BucketFeatures(ctx, bucket)
	switch versioning {
	case "Enabled", "Suspended":
		found = append(found, "Versioning is "+strings.ToLower(versioning)+": only current versions are copied.")
	case "":
		found = append(found, "Couldn't tell whether versioning is on; only current versions are copied.")
	}
	switch lock {
	case "Enabled":
		found = append(found, "Object lock is on at the source; retention isn't carried over.")
	case "":
		found = append(found, "Couldn't tell whether object lock is on.")
	}
	return strings.Join(found, " "), nil
}

// RegisterMirror sets up a mirror and starts its first pass.
func (p *Portal) RegisterMirror(ctx context.Context, admin User, req MirrorRequest) error {
	if !admin.Admin {
		return userErr("Only admins can set up mirrors.")
	}
	if !bucketRe.MatchString(req.Bucket) {
		return userErr("Bucket names are 3 to 63 lowercase letters, digits and hyphens, starting and ending with a letter or digit.")
	}
	if err := checkSource(&req.Source); err != nil {
		return err
	}
	if err := checkSchedule(req.Every, req.LimitMBps); err != nil {
		return err
	}
	if m, ok := p.store.Mirror(req.Bucket); ok && m.Active() {
		return userErr("%s is already being mirrored.", req.Bucket)
	}
	src := NewVGW(req.Source.Endpoint, "", req.Source.Region, req.Source.Access, req.Source.Secret)
	src.Virtual = req.Source.Virtual
	found, err := testSource(ctx, src, req.Source.Bucket)
	if err != nil {
		return err
	}

	owner := strings.TrimSpace(req.NewOwner)
	if owner != "" {
		person, ok := p.store.Person(owner)
		if !ok {
			return userErr("Nobody called %q has logged in, so they can't own a bucket yet.", owner)
		}
		if err := p.CreateBucket(ctx, person.User(owner), req.Bucket); err != nil {
			return err
		}
	} else {
		owner, err = p.emptyBucketOwner(ctx, req.Bucket)
		if err != nil {
			return err
		}
	}
	person, ok := p.store.Person(owner)
	if !ok {
		return userErr("The bucket's owner %q isn't known to the portal.", owner)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	acct := WebAccount{Access: mirrorAccess(req.Bucket), Secret: newSecret()}
	p.vgw.DeleteAccount(ctx, acct.Access)
	if err := p.vgw.CreateAccount(ctx, Account{Access: acct.Access, Secret: acct.Secret, Role: "user", UserID: person.UID, GroupID: person.GID}); err != nil {
		return fmt.Errorf("create mirror account: %w", err)
	}
	m := &Mirror{
		Bucket: req.Bucket, Owner: owner, Source: req.Source,
		Every: req.Every, LimitMBps: req.LimitMBps, Account: acct, Found: found,
	}
	m.setState(MirrorRegistered, admin.Name, "From "+req.Source.Label()+". "+found)
	p.mirrors.mu.Lock()
	err = p.store.PutMirror(req.Bucket, m)
	p.mirrors.mu.Unlock()
	if err != nil {
		return err
	}
	if err := p.setReadOnly(ctx, req.Bucket, true); err != nil {
		return err
	}
	slog.Info("registered mirror", "admin", admin.Name, "bucket", req.Bucket, "source", req.Source.Label())
	p.wakeMirrors()
	return nil
}

// emptyBucketOwner checks bucket exists, is owned by a person and holds
// nothing, and returns its owner.
func (p *Portal) emptyBucketOwner(ctx context.Context, bucket string) (string, error) {
	all, err := p.vgw.ListBuckets(ctx)
	if err != nil {
		return "", err
	}
	owner := ""
	found := false
	for _, b := range all {
		if b.Name == bucket {
			owner, found = ownerName(b.Owner), true
		}
	}
	if !found {
		return "", userErr("There's no bucket called %s. Name an owner to make it.", bucket)
	}
	if owner == "" {
		return "", userErr("%s isn't owned by anyone the portal knows.", bucket)
	}
	objs, _, err := p.vgw.ListPage(ctx, bucket, "", 1)
	if err != nil {
		return "", err
	}
	if len(objs) > 0 {
		return "", userErr("%s isn't empty. A mirror needs an empty bucket, so everything in it came from the source.", bucket)
	}
	return owner, nil
}

// setReadOnly holds bucket to reading, or lets it go, and rewrites its
// policy.
func (p *Portal) setReadOnly(ctx context.Context, bucket string, on bool) error {
	meta := p.store.BucketMeta(bucket)
	meta.ReadOnly = on
	if err := p.store.PutBucketMeta(bucket, meta); err != nil {
		return err
	}
	return p.syncBuckets(ctx, []string{bucket})
}

// ------------------------------------------------------- admin actions

func requireAdmin(u User) error {
	if !u.Admin {
		return userErr("Only admins can manage mirrors.")
	}
	return nil
}

// UpdateMirror changes the schedule and speed limit, and replaces the
// source key when a new one is given.
func (p *Portal) UpdateMirror(ctx context.Context, admin User, bucket, every string, limit int, access, secret string) error {
	if err := requireAdmin(admin); err != nil {
		return err
	}
	if err := checkSchedule(every, limit); err != nil {
		return err
	}
	access = strings.TrimSpace(access)
	if (access == "") != (secret == "") {
		return userErr("To replace the source key, give both its ID and secret.")
	}
	if access != "" {
		m, ok := p.store.Mirror(bucket)
		if !ok || !m.Active() {
			return userErr("There's no mirror running for %s.", bucket)
		}
		src := m.Source
		src.Access, src.Secret = access, secret
		c := NewVGW(src.Endpoint, "", src.Region, src.Access, src.Secret)
		c.Virtual = src.Virtual
		if _, err := testSource(ctx, c, src.Bucket); err != nil {
			return err
		}
	}
	err := p.updateMirror(bucket, func(m *Mirror) error {
		if !m.Active() {
			return userErr("The mirror for %s is finished.", bucket)
		}
		m.Every, m.LimitMBps = every, limit
		if access != "" {
			m.Source.Access, m.Source.Secret = access, secret
			m.History = append(m.History, MirrorEvent{At: time.Now(), State: m.State, By: admin.Name, Note: "Replaced the source key."})
		}
		return nil
	})
	p.wakeMirrors()
	return err
}

// PauseMirror stops or restarts scheduled passes.
func (p *Portal) PauseMirror(admin User, bucket string, paused bool) error {
	if err := requireAdmin(admin); err != nil {
		return err
	}
	err := p.updateMirror(bucket, func(m *Mirror) error {
		m.Paused = paused
		return nil
	})
	p.wakeMirrors()
	return err
}

// RunMirrorPass starts a pass now.
func (p *Portal) RunMirrorPass(admin User, bucket string) error {
	if err := requireAdmin(admin); err != nil {
		return err
	}
	m, ok := p.store.Mirror(bucket)
	if !ok || !m.syncing() {
		return userErr("Passes only run before the source is frozen. After that, run the final pass again.")
	}
	return p.startJob(bucket, "manual", admin.Name)
}

// AcceptUncopyable agrees that the last pass's keys that can't be copied
// are left behind.
func (p *Portal) AcceptUncopyable(admin User, bucket, note string) error {
	if err := requireAdmin(admin); err != nil {
		return err
	}
	note = strings.TrimSpace(note)
	if note == "" {
		return userErr("Say why it's all right to leave them behind.")
	}
	return p.updateMirror(bucket, func(m *Mirror) error {
		last := m.LastPass()
		if !m.Active() || last == nil || last.Uncopyable == 0 {
			return userErr("There's nothing to accept.")
		}
		m.Accepted = &UncopyableAcceptance{By: admin.Name, At: time.Now(), Note: note, Sum: last.UncopyableSum, Count: last.Uncopyable, Pass: last.N}
		m.History = append(m.History, MirrorEvent{At: time.Now(), State: m.State, By: admin.Name,
			Note: fmt.Sprintf("Accepted leaving %d keys that can't be copied behind: %s", last.Uncopyable, note)})
		if m.State == MirrorSyncing && last.Clean(m.Accepted) {
			m.setState(MirrorSynced, "portal", "")
		}
		return nil
	})
}

// FreezeMirror records that writes to the source have stopped, and runs
// the final pass and its checks. In Freezing, it runs them again.
func (p *Portal) FreezeMirror(admin User, bucket string, deep bool) error {
	if err := requireAdmin(admin); err != nil {
		return err
	}
	m, ok := p.store.Mirror(bucket)
	if !ok {
		return userErr("There's no mirror for %s.", bucket)
	}
	switch m.State {
	case MirrorSyncing, MirrorSynced, MirrorFreezing, MirrorVerified:
	default:
		return userErr("The final pass runs once the first pass has started.")
	}
	// Freezing first stops the scheduler starting passes; then any pass
	// already running is stopped.
	err := p.updateMirror(bucket, func(m *Mirror) error {
		if m.State != MirrorFreezing {
			m.setState(MirrorFreezing, admin.Name, "Writes to the source have stopped, on the admin's word.")
		}
		m.Verification = nil
		return nil
	})
	if err != nil {
		return err
	}
	p.stopJob(bucket)
	kind := "final"
	if deep {
		kind = "final-deep"
	}
	return p.startJob(bucket, kind, admin.Name)
}

// CompleteMirror opens the bucket to its users and forgets the source key.
func (p *Portal) CompleteMirror(ctx context.Context, admin User, bucket string) error {
	if err := requireAdmin(admin); err != nil {
		return err
	}
	return p.endMirror(ctx, admin, bucket, MirrorComplete, func(m *Mirror) error {
		if m.State != MirrorVerified {
			return userErr("A mirror completes only once its final check has passed.")
		}
		return nil
	})
}

// AbandonMirror stops a mirror, leaving the bucket with what was copied.
func (p *Portal) AbandonMirror(ctx context.Context, admin User, bucket string) error {
	if err := requireAdmin(admin); err != nil {
		return err
	}
	return p.endMirror(ctx, admin, bucket, MirrorAbandoned, func(m *Mirror) error {
		if !m.Active() {
			return userErr("The mirror for %s has already finished.", bucket)
		}
		return nil
	})
}

func (p *Portal) endMirror(ctx context.Context, admin User, bucket string, to MirrorState, check func(m *Mirror) error) error {
	m, ok := p.store.Mirror(bucket)
	if !ok {
		return userErr("There's no mirror for %s.", bucket)
	}
	if err := check(m); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var acct string
	err := p.updateMirror(bucket, func(m *Mirror) error {
		if err := check(m); err != nil {
			return err
		}
		acct = m.Account.Access
		m.Account = WebAccount{}
		m.Source.Secret = ""
		note := "The bucket is open to its users; the source key is forgotten."
		if to == MirrorAbandoned {
			note = "The bucket keeps what was copied, and is open to its users; the source key is forgotten."
		}
		m.setState(to, admin.Name, note)
		return nil
	})
	if err != nil {
		return err
	}
	// Ended, the mirror starts no more passes; one already running stops
	// before its account goes.
	p.stopJob(bucket)
	if acct != "" {
		if err := p.vgw.DeleteAccount(ctx, acct); err != nil {
			slog.Warn("delete mirror account", "bucket", bucket, "err", err)
		}
	}
	if err := p.setReadOnly(ctx, bucket, false); err != nil {
		return err
	}
	slog.Info("mirror ended", "admin", admin.Name, "bucket", bucket, "state", to)
	return nil
}

// MarkSourceRemoved records that the source bucket has been deleted.
func (p *Portal) MarkSourceRemoved(admin User, bucket string) error {
	if err := requireAdmin(admin); err != nil {
		return err
	}
	return p.updateMirror(bucket, func(m *Mirror) error {
		if m.State != MirrorComplete {
			return userErr("Mark the source removed after the move is complete.")
		}
		m.setState(MirrorSourceRemoved, admin.Name, "The source bucket "+m.Source.Label()+" has been deleted, on the admin's word.")
		return nil
	})
}

// ForgetMirror deletes a finished mirror's record and files.
func (p *Portal) ForgetMirror(admin User, bucket string) error {
	if err := requireAdmin(admin); err != nil {
		return err
	}
	m, ok := p.store.Mirror(bucket)
	if !ok {
		return userErr("There's no mirror for %s.", bucket)
	}
	if m.Active() {
		return userErr("Complete or abandon the mirror first.")
	}
	p.mirrors.mu.Lock()
	defer p.mirrors.mu.Unlock()
	if err := p.store.DeleteMirror(bucket); err != nil {
		return err
	}
	return os.RemoveAll(p.mirrorDir(bucket))
}

// forgetMirror drops any mirror for a bucket that's been deleted. Callers
// hold p.mu.
func (p *Portal) forgetMirror(bucket string) error {
	m, ok := p.store.Mirror(bucket)
	if !ok {
		return nil
	}
	p.stopJob(bucket)
	if m.Account.Access != "" {
		p.vgw.DeleteAccount(context.Background(), m.Account.Access)
	}
	p.mirrors.mu.Lock()
	defer p.mirrors.mu.Unlock()
	if err := p.store.DeleteMirror(bucket); err != nil {
		return err
	}
	return os.RemoveAll(p.mirrorDir(bucket))
}

// ------------------------------------------------------------- running

func (p *Portal) wakeMirrors() {
	select {
	case p.mirrors.wake <- struct{}{}:
	default:
	}
}

// RunMirrors runs mirrors' passes when they're due, until ctx ends.
func (p *Portal) RunMirrors(ctx context.Context, interval time.Duration) {
	p.mirrors.mu.Lock()
	p.mirrors.ctx = ctx
	p.mirrors.mu.Unlock()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		p.startDue(time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-p.mirrors.wake:
		}
	}
}

// startDue starts scheduled passes that are due, up to maxMirrorJobs.
func (p *Portal) startDue(now time.Time) {
	for bucket, m := range p.store.Mirrors() {
		if !m.syncing() || m.Paused {
			continue
		}
		last := m.LastPass()
		due := last == nil
		if !due {
			if every, ok := mirrorEvery[m.Every]; ok {
				due = now.Sub(last.Finished) >= every-time.Minute
			}
		}
		if due {
			if err := p.startJob(bucket, "scheduled", "portal"); err != nil && !errors.Is(err, errJobRunning) {
				slog.Debug("mirror pass not started", "bucket", bucket, "err", err)
			}
		}
	}
}

var (
	errJobRunning = errors.New("a pass is already running")
	errTooBusy    = errors.New("too many mirrors are copying")
)

// startJob runs a pass, or a final pass and its checks, in the background.
func (p *Portal) startJob(bucket, kind, by string) error {
	p.mirrors.mu.Lock()
	defer p.mirrors.mu.Unlock()
	if _, ok := p.mirrors.jobs[bucket]; ok {
		if kind == "scheduled" {
			return errJobRunning
		}
		return userErr("A pass is already running for %s.", bucket)
	}
	if kind == "scheduled" && len(p.mirrors.jobs) >= maxMirrorJobs {
		return errTooBusy
	}
	parent := p.mirrors.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	job := &mirrorJob{kind: kind, by: by, cancel: cancel, done: make(chan struct{}), prog: newProgress(kind)}
	p.mirrors.jobs[bucket] = job
	go func() {
		defer func() {
			cancel()
			p.mirrors.mu.Lock()
			delete(p.mirrors.jobs, bucket)
			p.mirrors.mu.Unlock()
			close(job.done)
			p.wakeMirrors()
		}()
		p.runJob(ctx, bucket, job)
	}()
	return nil
}

// stopJob cancels bucket's running job, if any, and waits for it.
func (p *Portal) stopJob(bucket string) {
	p.mirrors.mu.Lock()
	job := p.mirrors.jobs[bucket]
	p.mirrors.mu.Unlock()
	if job != nil {
		job.cancel()
		<-job.done
	}
}

// WaitMirror waits for bucket's running job, if any, to finish.
func (p *Portal) WaitMirror(bucket string) {
	p.mirrors.mu.Lock()
	job := p.mirrors.jobs[bucket]
	p.mirrors.mu.Unlock()
	if job != nil {
		<-job.done
	}
}

func (p *Portal) runJob(ctx context.Context, bucket string, job *mirrorJob) {
	m, ok := p.store.Mirror(bucket)
	if !ok {
		return
	}
	final := strings.HasPrefix(job.kind, "final")
	if m.State == MirrorRegistered {
		p.updateMirror(bucket, func(m *Mirror) error {
			if m.State == MirrorRegistered {
				m.setState(MirrorSyncing, "portal", "")
			}
			return nil
		})
	}
	sum := p.runPass(ctx, m, job.kind, job.by, job.prog)
	var ver *Verification
	if final && sum.Error == "" {
		job.prog.setPhase("checking")
		ver = p.verifyMirror(ctx, m, sum, job.kind == "final-deep", job.prog)
	}
	err := p.updateMirror(bucket, func(cur *Mirror) error {
		cur.Passes = append(cur.Passes, sum)
		if len(cur.Passes) > keptPasses {
			cur.Passes = cur.Passes[len(cur.Passes)-keptPasses:]
		}
		switch {
		case !cur.Active():
			// Ended while the pass ran.
		case final && cur.State == MirrorFreezing:
			if ver == nil {
				ver = &Verification{At: time.Now(), Pass: sum.N, Error: "The final pass didn't finish: " + sum.Error}
			}
			cur.Verification = ver
			if ver.Passed {
				cur.setState(MirrorVerified, "portal", fmt.Sprintf("Final pass %d and its checks found the buckets matching.", sum.N))
			} else {
				cur.History = append(cur.History, MirrorEvent{At: time.Now(), State: cur.State, By: "portal",
					Note: fmt.Sprintf("Final pass %d didn't verify. Fix what it found and run it again.", sum.N)})
			}
		case cur.syncing():
			if sum.Clean(cur.Accepted) {
				cur.setState(MirrorSynced, "portal", "")
			} else if sum.Error == "" || cur.State == MirrorSynced {
				cur.setState(MirrorSyncing, "portal", "")
			}
		}
		return nil
	})
	if err != nil {
		slog.Error("record mirror pass", "bucket", bucket, "err", err)
	}
	if ver != nil && ver.Passed && p.zfs != nil {
		snap, err := p.zfs.CreateSnapshot(context.Background(), bucket, "mirror-final")
		p.updateMirror(bucket, func(cur *Mirror) error {
			if cur.Verification != nil {
				if err != nil {
					cur.Verification.Snapshot = "failed: " + err.Error()
				} else {
					cur.Verification.Snapshot = snap.Name
				}
			}
			return nil
		})
	}
}

// ---------------------------------------------------------------- view

// MirrorView is a mirror as the admin pages show it, without secrets.
type MirrorView struct {
	Mirror
	HasSecret bool
	Running   *ProgressView
	Steps     []MirrorStep
	// Report is the most recent pass's report, cut short for the page.
	Report *PassReport
	// Newest is Passes, the latest first.
	Newest []PassSummary
}

// MirrorStep is one line of the checklist.
type MirrorStep struct {
	State   MirrorState
	Done    bool
	Current bool
	Event   *MirrorEvent
}

func (p *Portal) mirrorView(m *Mirror, withReport bool) MirrorView {
	v := MirrorView{Mirror: *m, HasSecret: m.Source.Secret != ""}
	v.Source.Secret, v.Account.Secret = "", ""
	for i := len(m.Passes) - 1; i >= 0; i-- {
		v.Newest = append(v.Newest, m.Passes[i])
	}
	p.mirrors.mu.Lock()
	if job := p.mirrors.jobs[m.Bucket]; job != nil {
		pv := job.prog.view()
		v.Running = &pv
	}
	p.mirrors.mu.Unlock()
	at := -1
	for i, s := range mirrorSteps {
		if s == m.State {
			at = i
		}
	}
	for i, s := range mirrorSteps {
		step := MirrorStep{State: s, Done: at >= i, Current: at == i}
		for j := len(m.History) - 1; j >= 0; j-- {
			if m.History[j].State == s {
				step.Event = &m.History[j]
				break
			}
		}
		v.Steps = append(v.Steps, step)
	}
	if withReport {
		if last := m.LastPass(); last != nil {
			if r, err := p.readReport(m.Bucket, last.N); err == nil {
				r.trim(50)
				v.Report = r
			}
		}
	}
	return v
}

// Mirrors lists every mirror, for admins.
func (p *Portal) MirrorList(admin User) ([]MirrorView, error) {
	if err := requireAdmin(admin); err != nil {
		return nil, err
	}
	var out []MirrorView
	for _, b := range sortedKeys(p.store.Mirrors()) {
		m, _ := p.store.Mirror(b)
		out = append(out, p.mirrorView(m, false))
	}
	return out, nil
}

// MirrorDetail is one mirror with its latest report, for admins.
func (p *Portal) MirrorDetail(admin User, bucket string) (*MirrorView, error) {
	if err := requireAdmin(admin); err != nil {
		return nil, err
	}
	m, ok := p.store.Mirror(bucket)
	if !ok {
		return nil, userErr("There's no mirror for %s.", bucket)
	}
	v := p.mirrorView(m, true)
	return &v, nil
}

// BucketMirror is bucket's mirror, for anyone who can see the bucket: the
// file browser's banner and the storage section's history.
func (p *Portal) BucketMirror(bucket string) *MirrorView {
	m, ok := p.store.Mirror(bucket)
	if !ok {
		return nil
	}
	v := p.mirrorView(m, false)
	return &v
}

// MirrorReport returns a pass's full report as JSON, for admins.
func (p *Portal) MirrorReport(admin User, bucket string, n int) ([]byte, error) {
	if err := requireAdmin(admin); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(p.mirrorDir(bucket), fmt.Sprintf("pass-%d.json", n)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, userErr("That pass's report is gone.")
	}
	return data, err
}
