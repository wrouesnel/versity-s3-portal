package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// TransferForm is the admin's form transferring a bucket: who owns it now, and what the
// old owner keeps (their groups' access) and loses.
type TransferForm struct {
	Bucket, Owner string
	OwnerDisabled bool
	ManagedBy     []string
	// OldOwnerVia is the access the old owner keeps through groups ("read only, via
	// engineering"), "" for none; OldOwnerKeys how many of their keys reach the bucket.
	OldOwnerVia  string
	OldOwnerKeys int
}

// ChangeBucketOwner gives a bucket to another gateway account.
func (v *VGW) ChangeBucketOwner(ctx context.Context, bucket, owner string) error {
	_, err := v.do(ctx, http.MethodPatch, v.AdminEndpoint, "/change-bucket-owner/",
		url.Values{"bucket": {bucket}, "owner": {owner}}, nil, nil)
	return err
}

// TransferForm is what transferring bucket would change, for an admin's form.
func (p *Portal) TransferForm(ctx context.Context, admin User, bucket string) (*TransferForm, error) {
	if err := requireAdmin(admin); err != nil {
		return nil, err
	}
	v, err := p.Bucket(ctx, admin, bucket, true)
	if err != nil {
		return nil, err
	}
	f := &TransferForm{Bucket: bucket, Owner: v.Owner, ManagedBy: v.ManagedBy}
	if v.Owner == "" {
		return f, nil
	}
	person, _ := p.store.Person(v.Owner)
	f.OwnerDisabled = person != nil && person.Disabled
	// What they'd have without owning it: their groups' grants.
	if person != nil {
		meta := p.store.BucketMeta(bucket)
		c, via := access(v.Owner, person, "", meta)
		if c.Any() {
			level := capsLabel(c)
			for _, g := range managers(meta) {
				if person.InGroup(g) {
					level = PermManage.Label()
				}
			}
			f.OldOwnerVia = level + ", via " + strings.Join(via, ", ")
		}
	}
	for _, e := range p.store.KeysFor(v.Owner) {
		if _, ok := e.Buckets[bucket]; ok || (e.Login && len(e.Buckets) == 0) {
			f.OldOwnerKeys++
		}
	}
	return f, nil
}

// TransferBucket gives a bucket to another person, for admins: someone the portal knows
// and who isn't disabled. Its grants, keys and settings stay; the old owner keeps what
// their groups give them. Not while the bucket is being mirrored in: its mirror writes as
// the owner.
func (p *Portal) TransferBucket(ctx context.Context, admin User, bucket, owner string) error {
	if err := requireAdmin(admin); err != nil {
		return err
	}
	owner = strings.TrimSpace(owner)
	person, err := p.knownPerson(owner)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	v, err := p.Bucket(ctx, admin, bucket, true)
	if err != nil {
		return err
	}
	if v.Owner == owner {
		return userErr("%s is %s's already.", bucket, owner)
	}
	if m, ok := p.store.Mirror(bucket); ok && m.Active() {
		return userErr("%s is being mirrored in: complete or stop its mirror before transferring it.", bucket)
	}
	if err := p.ensureOwner(ctx, person.User(owner)); err != nil {
		return err
	}
	if err := p.vgw.ChangeBucketOwner(ctx, bucket, ownerAccess(owner)); err != nil {
		return err
	}
	p.forgetBuckets()
	if err := p.syncBuckets(ctx, []string{bucket}); err != nil {
		return err
	}
	slog.Warn("admin transferred bucket", "admin", admin.Name, "bucket", bucket, "from", v.Owner, "to", owner)
	return nil
}

// OwnedBuckets is how many buckets each person owns.
func (p *Portal) OwnedBuckets(ctx context.Context) map[string]int {
	all, err := p.listBuckets(ctx)
	if err != nil {
		return nil
	}
	out := map[string]int{}
	for _, b := range all {
		if o := ownerName(b.Owner); o != "" {
			out[o]++
		}
	}
	return out
}

func (s *Server) adminTransferForm(w http.ResponseWriter, r *http.Request, sess *Session) {
	f, err := s.Portal.TransferForm(r.Context(), sess.User, r.URL.Query().Get("bucket"))
	if err != nil {
		redirectFlash(w, r, "/admin?section=buckets", "", userMessage(r, sess, err))
		return
	}
	p := s.base(w, r, sess, "admin")
	p.Section, p.Transfer = "bucket-transfer", f
	s.adminCounts(r, sess, &p)
	s.render(w, http.StatusOK, "admin.html", p)
}

func (s *Server) adminTransfer(w http.ResponseWriter, r *http.Request, sess *Session) {
	bucket, owner := r.PostFormValue("bucket"), r.PostFormValue("owner")
	if err := s.Portal.TransferBucket(r.Context(), sess.User, bucket, owner); err != nil {
		redirectFlash(w, r, "/admin/buckets/transfer?bucket="+url.QueryEscape(bucket), "", userMessage(r, sess, err))
		return
	}
	redirectFlash(w, r, "/admin?section=buckets", bucket+" is "+strings.TrimSpace(owner)+"'s now.", "")
}

// APIOwnerRequest gives a bucket to another owner.
type APIOwnerRequest struct {
	Owner string `json:"owner"`
}

func (s *Server) apiTransferBucket(r *http.Request) (any, error) {
	var req APIOwnerRequest
	if err := decodeAPI(r, &req); err != nil {
		return nil, err
	}
	bucket := r.PathValue("bucket")
	if err := s.Portal.TransferBucket(r.Context(), apiCaller(r), bucket, req.Owner); err != nil {
		return nil, err
	}
	return APIBucketResult{Name: bucket, Owner: strings.TrimSpace(req.Owner)}, nil
}
