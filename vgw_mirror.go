package main

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// What mirroring needs from an S3 service: whole-bucket listings with
// ETags, reads and writes that carry metadata, and multipart uploads for
// objects too big for one PUT. These work against any S3 service, with
// path or virtual-hosted addressing, so the same client reads a mirror's
// source and writes its target.

// loc is the endpoint and escaped path for bucket, or an object in it.
func (v *VGW) loc(bucket, key string) (endpoint, path string) {
	if !v.Virtual {
		return v.S3Endpoint, objectPath(bucket, key)
	}
	u, err := url.Parse(v.S3Endpoint)
	if err != nil || u.Host == "" {
		return v.S3Endpoint, objectPath(bucket, key)
	}
	u.Host = bucket + "." + u.Host
	path = "/"
	if key != "" {
		path += s3Escape(key)
	}
	return strings.TrimRight(u.String(), "/"), path
}

// ListedObject is one object in a full listing.
type ListedObject struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
}

// ListPage lists up to max objects of the whole bucket (no delimiter),
// starting after token, in the service's key order.
func (v *VGW) ListPage(ctx context.Context, bucket, token string, max int) ([]ListedObject, string, error) {
	q := url.Values{"list-type": {"2"}, "max-keys": {strconv.Itoa(max)}, "encoding-type": {"url"}}
	if token != "" {
		q.Set("continuation-token", token)
	}
	endpoint, path := v.loc(bucket, "")
	body, err := v.do(ctx, http.MethodGet, endpoint, path, q, nil, nil)
	if err != nil {
		return nil, "", err
	}
	var result struct {
		EncodingType string
		Contents     []struct {
			Key          string
			Size         int64
			ETag         string
			LastModified time.Time
		}
		IsTruncated           bool
		NextContinuationToken string
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		return nil, "", fmt.Errorf("parse object listing: %w", err)
	}
	out := make([]ListedObject, 0, len(result.Contents))
	for _, c := range result.Contents {
		key := c.Key
		// Keys can hold characters XML can't, so they're asked for
		// URL-encoded. Not every service honours that, and says so.
		if result.EncodingType == "url" {
			if k, err := url.QueryUnescape(c.Key); err == nil {
				key = k
			}
		}
		out = append(out, ListedObject{Key: key, Size: c.Size, ETag: cleanETag(c.ETag), LastModified: c.LastModified})
	}
	next := ""
	if result.IsTruncated {
		next = result.NextContinuationToken
		if next == "" {
			return nil, "", fmt.Errorf("listing of %s was cut short without a continuation token", bucket)
		}
	}
	return out, next, nil
}

func cleanETag(e string) string { return strings.Trim(e, `"`) }

// Get returns an object's response, for the caller to read and close.
func (v *VGW) Get(ctx context.Context, bucket, key string, headers map[string]string) (*http.Response, error) {
	endpoint, path := v.loc(bucket, key)
	return v.streamAt(ctx, http.MethodGet, endpoint, path, nil, nil, 0, headers)
}

// Head returns an object's headers.
func (v *VGW) Head(ctx context.Context, bucket, key string) (http.Header, error) {
	endpoint, path := v.loc(bucket, key)
	resp, err := v.streamAt(ctx, http.MethodHead, endpoint, path, nil, nil, 0, nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return resp.Header, nil
}

// Put writes length bytes of body as the object, with headers, and
// returns its ETag.
func (v *VGW) Put(ctx context.Context, bucket, key string, body io.Reader, length int64, headers map[string]string) (string, error) {
	if length == 0 {
		body = http.NoBody
	}
	endpoint, path := v.loc(bucket, key)
	resp, err := v.streamAt(ctx, http.MethodPut, endpoint, path, nil, body, length, headers)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	return cleanETag(resp.Header.Get("ETag")), nil
}

// Delete removes an object.
func (v *VGW) Delete(ctx context.Context, bucket, key string) error {
	endpoint, path := v.loc(bucket, key)
	_, err := v.do(ctx, http.MethodDelete, endpoint, path, nil, nil, nil)
	return err
}

// CreateMultipart starts a multipart upload with the object's headers.
func (v *VGW) CreateMultipart(ctx context.Context, bucket, key string, headers map[string]string) (string, error) {
	endpoint, path := v.loc(bucket, key)
	body, err := v.do(ctx, http.MethodPost, endpoint, path, url.Values{"uploads": {""}}, nil, headers)
	if err != nil {
		return "", err
	}
	var result struct{ UploadId string }
	if err := xml.Unmarshal(body, &result); err != nil || result.UploadId == "" {
		return "", fmt.Errorf("parse CreateMultipartUpload: %v", err)
	}
	return result.UploadId, nil
}

// UploadPart sends part n of a multipart upload and returns its ETag.
func (v *VGW) UploadPart(ctx context.Context, bucket, key, upload string, n int, body io.Reader, length int64) (string, error) {
	endpoint, path := v.loc(bucket, key)
	q := url.Values{"partNumber": {strconv.Itoa(n)}, "uploadId": {upload}}
	resp, err := v.streamAt(ctx, http.MethodPut, endpoint, path, q, body, length, nil)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	return cleanETag(resp.Header.Get("ETag")), nil
}

type completedPart struct {
	PartNumber int
	ETag       string
}

// CompleteMultipart finishes a multipart upload and returns the object's
// ETag.
func (v *VGW) CompleteMultipart(ctx context.Context, bucket, key, upload string, parts []completedPart) (string, error) {
	type part struct {
		PartNumber int
		ETag       string
	}
	doc := struct {
		XMLName xml.Name `xml:"CompleteMultipartUpload"`
		Parts   []part   `xml:"Part"`
	}{}
	for _, p := range parts {
		doc.Parts = append(doc.Parts, part{p.PartNumber, `"` + p.ETag + `"`})
	}
	data, err := xml.Marshal(doc)
	if err != nil {
		return "", err
	}
	endpoint, path := v.loc(bucket, key)
	body, err := v.do(ctx, http.MethodPost, endpoint, path, url.Values{"uploadId": {upload}}, data,
		map[string]string{"Content-Type": "application/xml"})
	if err != nil {
		return "", err
	}
	// S3 can answer 200 and still fail, with an Error document.
	var result struct {
		XMLName xml.Name
		ETag    string
		Code    string
		Message string
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse CompleteMultipartUpload: %w", err)
	}
	if result.XMLName.Local == "Error" {
		return "", &APIError{Status: http.StatusOK, Code: result.Code, Message: result.Message}
	}
	return cleanETag(result.ETag), nil
}

// AbortMultipart throws away a multipart upload's parts.
func (v *VGW) AbortMultipart(ctx context.Context, bucket, key, upload string) error {
	endpoint, path := v.loc(bucket, key)
	_, err := v.do(ctx, http.MethodDelete, endpoint, path, url.Values{"uploadId": {upload}}, nil, nil)
	return err
}

// BucketFeatures reports whether versioning and object lock are on. Either
// is "" when the service wouldn't say.
func (v *VGW) BucketFeatures(ctx context.Context, bucket string) (versioning, objectLock string) {
	endpoint, path := v.loc(bucket, "")
	if body, err := v.do(ctx, http.MethodGet, endpoint, path, url.Values{"versioning": {""}}, nil, nil); err == nil {
		var r struct{ Status string }
		if xml.Unmarshal(body, &r) == nil {
			versioning = r.Status
			if versioning == "" {
				versioning = "Off"
			}
		}
	}
	body, err := v.do(ctx, http.MethodGet, endpoint, path, url.Values{"object-lock": {""}}, nil, nil)
	switch {
	case err == nil:
		var r struct{ ObjectLockEnabled string }
		if xml.Unmarshal(body, &r) == nil {
			objectLock = r.ObjectLockEnabled
			if objectLock == "" {
				objectLock = "Off"
			}
		}
	case IsCode(err, "ObjectLockConfigurationNotFoundError"):
		objectLock = "Off"
	}
	return versioning, objectLock
}

// SourceBuckets lists the buckets the key may see, with S3's ListBuckets
// (s3:ListAllMyBuckets), page by page: a server mirror's source.
func (v *VGW) SourceBuckets(ctx context.Context) ([]string, error) {
	var out []string
	token := ""
	for range 1000 {
		q := url.Values{"max-buckets": {"1000"}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		body, err := v.do(ctx, http.MethodGet, v.S3Endpoint, "/", q, nil, nil)
		if err != nil {
			return nil, err
		}
		var result struct {
			Buckets struct {
				Bucket []struct {
					Name string `xml:"Name"`
				} `xml:"Bucket"`
			} `xml:"Buckets"`
			ContinuationToken string `xml:"ContinuationToken"`
		}
		if err := xml.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("parse the bucket list: %w", err)
		}
		for _, b := range result.Buckets.Bucket {
			out = append(out, b.Name)
		}
		if result.ContinuationToken == "" || result.ContinuationToken == token {
			sort.Strings(out)
			return out, nil
		}
		token = result.ContinuationToken
	}
	return nil, errors.New("the bucket list goes on for more than a million buckets")
}
