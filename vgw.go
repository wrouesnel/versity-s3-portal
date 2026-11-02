package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// VGW talks to a versitygw gateway: as its root account, the admin API for
// accounts and bucket creation and the S3 API for bucket policies; as a
// person's web account (As), their objects.
type VGW struct {
	S3Endpoint    string
	AdminEndpoint string
	Region        string
	Creds         aws.Credentials
	HTTP          *http.Client
	// Streams has no overall timeout, for object bodies of any size; the
	// request's context bounds it.
	Streams *http.Client

	signer *v4.Signer
}

func NewVGW(s3Endpoint, adminEndpoint, region, access, secret string) *VGW {
	return &VGW{
		S3Endpoint:    strings.TrimRight(s3Endpoint, "/"),
		AdminEndpoint: strings.TrimRight(adminEndpoint, "/"),
		Region:        region,
		Creds:         aws.Credentials{AccessKeyID: access, SecretAccessKey: secret},
		HTTP:          &http.Client{Timeout: 30 * time.Second},
		Streams:       &http.Client{},
		// S3 signs the path as sent, not escaped a second time.
		signer: v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true }),
	}
}

// As returns a client for the same gateway that signs as another account.
func (v *VGW) As(access, secret string) *VGW {
	return NewVGW(v.S3Endpoint, v.AdminEndpoint, v.Region, access, secret)
}

// objectPath is the request path for a bucket, or an object in it. S3 signs
// the path with everything but unreserved characters and slashes
// percent-encoded, so it's built that way rather than with url.PathEscape,
// which leaves characters such as + and = alone.
func objectPath(bucket, key string) string {
	if key == "" {
		return "/" + s3Escape(bucket)
	}
	return "/" + s3Escape(bucket) + "/" + s3Escape(key)
}

func s3Escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~' || c == '/' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// Account mirrors versitygw's auth.Account, which the admin API sends as XML
// with Go's default element names: <Account> on its own, <Accounts> in lists.
type Account struct {
	Access    string
	Secret    string
	Role      string
	UserID    int
	GroupID   int
	ProjectID int
}

type Bucket struct {
	Name  string
	Owner string
}

// APIError is an error response from the gateway.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("gateway returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// IsCode reports whether err is a gateway error with the given S3 error code.
func IsCode(err error, code string) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == code
}

// newRequest builds a request for path, which is already escaped.
func newRequest(ctx context.Context, method, endpoint, path string, query url.Values, body io.Reader) (*http.Request, error) {
	u := endpoint + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	return http.NewRequestWithContext(ctx, method, u, body)
}

// apiError reads a gateway error response.
func apiError(resp *http.Response) error {
	apiErr := &APIError{Status: resp.StatusCode}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var parsed struct {
		Code    string
		Message string
	}
	if xml.Unmarshal(body, &parsed) == nil {
		apiErr.Code, apiErr.Message = parsed.Code, parsed.Message
	}
	return apiErr
}

func (v *VGW) do(ctx context.Context, method, endpoint, path string, query url.Values, body []byte, headers map[string]string) ([]byte, error) {
	req, err := newRequest(ctx, method, endpoint, path, query, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if err := v.signer.SignHTTP(ctx, v.Creds, req, payloadHash, "s3", v.Region, time.Now()); err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}

	resp, err := v.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, apiError(resp)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

// stream sends a request whose body isn't hashed (UNSIGNED-PAYLOAD), so it
// can be streamed, and returns the response for the caller to read and close.
func (v *VGW) stream(ctx context.Context, method, path string, body io.Reader, length int64, headers map[string]string) (*http.Response, error) {
	req, err := newRequest(ctx, method, v.S3Endpoint, path, nil, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = length
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	const unsigned = "UNSIGNED-PAYLOAD"
	req.Header.Set("X-Amz-Content-Sha256", unsigned)
	if err := v.signer.SignHTTP(ctx, v.Creds, req, unsigned, "s3", v.Region, time.Now()); err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}
	resp, err := v.Streams.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		return nil, apiError(resp)
	}
	return resp, nil
}

// Object is one object in a listing.
type Object struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// ObjectList is one page of a bucket listing under a prefix.
type ObjectList struct {
	// Prefixes are the "folders" directly under the prefix.
	Prefixes []string
	Objects  []Object
	// NextToken continues the listing when it's been cut short.
	NextToken string
}

// ListObjects lists a page of bucket under prefix. With a delimiter of "/",
// keys further down are folded into Prefixes.
func (v *VGW) ListObjects(ctx context.Context, bucket, prefix, delimiter, token string, max int) (*ObjectList, error) {
	q := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {strconv.Itoa(max)}}
	if delimiter != "" {
		q.Set("delimiter", delimiter)
	}
	if token != "" {
		q.Set("continuation-token", token)
	}
	body, err := v.do(ctx, http.MethodGet, v.S3Endpoint, objectPath(bucket, ""), q, nil, nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		Contents []struct {
			Key          string
			Size         int64
			LastModified time.Time
		}
		CommonPrefixes        []struct{ Prefix string }
		IsTruncated           bool
		NextContinuationToken string
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse object listing: %w", err)
	}
	list := &ObjectList{}
	for _, p := range result.CommonPrefixes {
		list.Prefixes = append(list.Prefixes, p.Prefix)
	}
	for _, c := range result.Contents {
		list.Objects = append(list.Objects, Object{Key: c.Key, Size: c.Size, LastModified: c.LastModified})
	}
	if result.IsTruncated {
		list.NextToken = result.NextContinuationToken
	}
	return list, nil
}

// GetObject returns the object's response, for the caller to stream and close.
func (v *VGW) GetObject(ctx context.Context, bucket, key string) (*http.Response, error) {
	return v.stream(ctx, http.MethodGet, objectPath(bucket, key), nil, 0, nil)
}

// PutObject streams length bytes of body into the object. With
// createOnly, it fails with PreconditionFailed if the object exists.
func (v *VGW) PutObject(ctx context.Context, bucket, key string, body io.Reader, length int64, contentType string, createOnly bool) error {
	headers := map[string]string{}
	if createOnly {
		headers["If-None-Match"] = "*"
	}
	if contentType != "" {
		headers["Content-Type"] = contentType
	}
	if length == 0 {
		body = http.NoBody
	}
	resp, err := v.stream(ctx, http.MethodPut, objectPath(bucket, key), body, length, headers)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (v *VGW) DeleteObject(ctx context.Context, bucket, key string) error {
	_, err := v.do(ctx, http.MethodDelete, v.S3Endpoint, objectPath(bucket, key), nil, nil, nil)
	return err
}

func (v *VGW) CreateAccount(ctx context.Context, acc Account) error {
	body, err := xml.Marshal(acc)
	if err != nil {
		return err
	}
	_, err = v.do(ctx, http.MethodPatch, v.AdminEndpoint, "/create-user", nil, body, nil)
	return err
}

func (v *VGW) DeleteAccount(ctx context.Context, access string) error {
	_, err := v.do(ctx, http.MethodPatch, v.AdminEndpoint, "/delete-user", url.Values{"access": {access}}, nil, nil)
	return err
}

func (v *VGW) ListAccounts(ctx context.Context) ([]Account, error) {
	body, err := v.do(ctx, http.MethodPatch, v.AdminEndpoint, "/list-users", nil, nil, nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		Accounts []Account `xml:"Accounts"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse list-users: %w", err)
	}
	return result.Accounts, nil
}

func (v *VGW) ListBuckets(ctx context.Context) ([]Bucket, error) {
	body, err := v.do(ctx, http.MethodPatch, v.AdminEndpoint, "/list-buckets", nil, nil, nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		Buckets []Bucket `xml:"Buckets"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse list-buckets: %w", err)
	}
	return result.Buckets, nil
}

func (v *VGW) CreateBucket(ctx context.Context, bucket, owner string) error {
	_, err := v.do(ctx, http.MethodPatch, v.AdminEndpoint, objectPath(bucket, "")+"/create", nil, nil,
		map[string]string{"x-vgw-owner": owner})
	return err
}

func (v *VGW) DeleteBucket(ctx context.Context, bucket string) error {
	_, err := v.do(ctx, http.MethodDelete, v.S3Endpoint, objectPath(bucket, ""), nil, nil, nil)
	return err
}

func (v *VGW) PutBucketPolicy(ctx context.Context, bucket string, policy []byte) error {
	_, err := v.do(ctx, http.MethodPut, v.S3Endpoint, objectPath(bucket, ""), url.Values{"policy": {""}}, policy,
		map[string]string{"Content-Type": "application/json"})
	return err
}

func (v *VGW) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	_, err := v.do(ctx, http.MethodDelete, v.S3Endpoint, objectPath(bucket, ""), url.Values{"policy": {""}}, nil, nil)
	return err
}
