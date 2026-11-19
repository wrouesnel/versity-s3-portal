package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// apiCallerKey holds, in an API request's context, who made the call.
type apiCallerKey struct{}

// apiTokenAdmin is who an API_TOKEN call acts as: an admin, recorded as "api-token" on the
// keys it issues and in the log.
var apiTokenAdmin = User{Name: "api-token", Admin: true}

// apiCaller is who made an API call: apiTokenAdmin for the token, or the admin whose session
// it was.
func apiCaller(r *http.Request) User {
	u, _ := r.Context().Value(apiCallerKey{}).(User)
	return u
}

// adminAPIRoutes are the admin page's "make a bucket for someone" and "issue a key to load
// data", for automation such as a migration: register someone from the directory, make
// their bucket, issue them a key on it, and revoke it after.
func (s *Server) adminAPIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/users/{name}/directory", s.api(s.apiDirectoryCheck))
	mux.HandleFunc("POST /api/users/{name}/register", s.api(s.apiRegisterUser))
	mux.HandleFunc("POST /api/buckets", s.api(s.apiEnsureBucket))
	mux.HandleFunc("POST /api/keys", s.api(s.apiIssueKey))
	mux.HandleFunc("DELETE /api/keys/{access}", s.api(s.apiRevokeKey))
}

// decodeAPI reads a JSON request body, refusing unknown fields and bodies over 64 KiB.
func decodeAPI(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return userErr("The request isn't valid JSON for this call: %v", err)
	}
	return nil
}

func (s *Server) apiDirectoryCheck(r *http.Request) (any, error) {
	return s.Portal.DirectoryCheck(apiCaller(r), r.PathValue("name"))
}

func (s *Server) apiRegisterUser(r *http.Request) (any, error) {
	return s.Portal.RegisterFromDirectory(r.Context(), apiCaller(r), r.PathValue("name"))
}

// APIBucketRequest asks for a bucket for someone.
type APIBucketRequest struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// APIBucketResult is a bucket made, or found already theirs.
type APIBucketResult struct {
	Name    string `json:"name"`
	Owner   string `json:"owner"`
	Created bool   `json:"created"`
}

func (s *Server) apiEnsureBucket(r *http.Request) (any, error) {
	var req APIBucketRequest
	if err := decodeAPI(r, &req); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	created, err := s.Portal.EnsureBucketFor(r.Context(), apiCaller(r), req.Owner, name)
	if err != nil {
		return nil, err
	}
	return APIBucketResult{Name: name, Owner: strings.TrimSpace(req.Owner), Created: created}, nil
}

// APIKeyRequest asks for a key for someone on their buckets, as the admin page's "issue a
// key to load data" does. With AccessKey and SecretKey, it imports a key from another S3
// server instead (see Portal.ImportKeyFor), so its clients keep working.
type APIKeyRequest struct {
	Owner     string          `json:"owner"`
	Label     string          `json:"label"`
	Buckets   map[string]Perm `json:"buckets"`
	AccessKey string          `json:"access_key,omitempty"`
	SecretKey string          `json:"secret_key,omitempty"`
	// Lifetime is how long it lasts: "12h", "30d", "2w" or "never"; by default the Access
	// keys page's default, or never for an imported key.
	Lifetime string `json:"lifetime,omitempty"`
}

// APIKeyResult is an issued key. The secret is given only here, and not for an imported
// key, whose caller has it. Existing is an imported key which was already, unchanged.
type APIKeyResult struct {
	Owner     string          `json:"owner"`
	AccessKey string          `json:"access_key"`
	SecretKey string          `json:"secret_key,omitempty"`
	Buckets   map[string]Perm `json:"buckets"`
	Imported  bool            `json:"imported,omitempty"`
	Existing  bool            `json:"existing,omitempty"`
	// Expires is when it expires; absent if it never does.
	Expires *time.Time `json:"expires,omitempty"`
}

func (s *Server) apiIssueKey(r *http.Request) (any, error) {
	var req APIKeyRequest
	if err := decodeAPI(r, &req); err != nil {
		return nil, err
	}
	for bucket, perm := range req.Buckets {
		if !perm.Valid() {
			return nil, userErr("%q isn't a level of access (for %s).", perm, bucket)
		}
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = "Issued by " + apiCaller(r).Name
	}
	if req.AccessKey != "" || req.SecretKey != "" {
		if req.AccessKey == "" || req.SecretKey == "" {
			return nil, userErr("Give both access_key and secret_key to import a key, or neither for a new one.")
		}
		existing, err := s.Portal.ImportKeyFor(r.Context(), apiCaller(r), req.Owner, label, req.Buckets, req.AccessKey, req.SecretKey, req.Lifetime)
		if err != nil {
			return nil, err
		}
		k, _ := s.Portal.store.Get(req.AccessKey)
		return APIKeyResult{Owner: strings.TrimSpace(req.Owner), AccessKey: req.AccessKey, Buckets: req.Buckets, Imported: true, Existing: existing, Expires: keyExpires(k)}, nil
	}
	access, secret, err := s.Portal.CreateKeyForLasting(r.Context(), apiCaller(r), req.Owner, label, req.Buckets, req.Lifetime)
	if err != nil {
		return nil, err
	}
	k, _ := s.Portal.store.Get(access)
	return APIKeyResult{Owner: strings.TrimSpace(req.Owner), AccessKey: access, SecretKey: secret, Buckets: req.Buckets, Expires: keyExpires(k)}, nil
}

func keyExpires(k *Key) *time.Time {
	if k == nil {
		return nil
	}
	return k.Expires
}

func (s *Server) apiRevokeKey(r *http.Request) (any, error) {
	caller := apiCaller(r)
	if err := requireAdmin(caller); err != nil {
		return nil, err
	}
	access := r.PathValue("access")
	if err := s.Portal.RevokeKey(r.Context(), caller, access); err != nil {
		var ue *UserError
		if errors.As(err, &ue) {
			// Revoking is idempotent: a key already gone is revoked.
			if _, exists := s.Portal.store.Get(access); !exists {
				return map[string]string{"revoked": access}, nil
			}
		}
		return nil, err
	}
	return map[string]string{"revoked": access}, nil
}
