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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// VGW talks to a versitygw gateway as its root account: the admin API for
// accounts and bucket creation, and the S3 API for bucket policies.
type VGW struct {
	S3Endpoint    string
	AdminEndpoint string
	Region        string
	Creds         aws.Credentials
	HTTP          *http.Client

	signer *v4.Signer
}

func NewVGW(s3Endpoint, adminEndpoint, region, access, secret string) *VGW {
	return &VGW{
		S3Endpoint:    strings.TrimRight(s3Endpoint, "/"),
		AdminEndpoint: strings.TrimRight(adminEndpoint, "/"),
		Region:        region,
		Creds:         aws.Credentials{AccessKeyID: access, SecretAccessKey: secret},
		HTTP:          &http.Client{Timeout: 30 * time.Second},
		signer:        v4.NewSigner(),
	}
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

func (v *VGW) do(ctx context.Context, method, endpoint, path string, query url.Values, body []byte, headers map[string]string) ([]byte, error) {
	u := endpoint + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
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
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &APIError{Status: resp.StatusCode}
		var parsed struct {
			Code    string
			Message string
		}
		if xml.Unmarshal(respBody, &parsed) == nil {
			apiErr.Code, apiErr.Message = parsed.Code, parsed.Message
		}
		return nil, apiErr
	}
	return respBody, nil
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
	_, err := v.do(ctx, http.MethodPatch, v.AdminEndpoint, "/"+url.PathEscape(bucket)+"/create", nil, nil,
		map[string]string{"x-vgw-owner": owner})
	return err
}

func (v *VGW) DeleteBucket(ctx context.Context, bucket string) error {
	_, err := v.do(ctx, http.MethodDelete, v.S3Endpoint, "/"+url.PathEscape(bucket), nil, nil, nil)
	return err
}

func (v *VGW) PutBucketPolicy(ctx context.Context, bucket string, policy []byte) error {
	_, err := v.do(ctx, http.MethodPut, v.S3Endpoint, "/"+url.PathEscape(bucket), url.Values{"policy": {""}}, policy,
		map[string]string{"Content-Type": "application/json"})
	return err
}

func (v *VGW) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	_, err := v.do(ctx, http.MethodDelete, v.S3Endpoint, "/"+url.PathEscape(bucket), url.Values{"policy": {""}}, nil, nil)
	return err
}
