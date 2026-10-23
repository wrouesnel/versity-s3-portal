package main

import (
	"encoding/json"
	"sort"
)

// Actions granted by each Perm. Bucket policy management, ACLs and other
// bucket configuration are left out, so a key can't widen its own access or
// remove the policy that scopes it.
var (
	readBucketActions  = []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketLocation", "s3:GetBucketVersioning"}
	readObjectActions  = []string{"s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes", "s3:GetObjectTagging"}
	writeBucketActions = []string{"s3:ListBucketMultipartUploads"}
	writeObjectActions = []string{
		"s3:PutObject", "s3:PutObjectTagging", "s3:DeleteObject", "s3:DeleteObjectVersion",
		"s3:DeleteObjectTagging", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts",
	}
)

type policyStatement struct {
	Sid       string              `json:"Sid"`
	Effect    string              `json:"Effect"`
	Principal map[string][]string `json:"Principal"`
	Action    []string            `json:"Action"`
	Resource  []string            `json:"Resource"`
}

type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

// BucketPolicy builds the policy granting each key its Perm on bucket, or
// nil when no key has access.
func BucketPolicy(bucket string, grants map[string]Perm) []byte {
	var readers, writers []string
	for access, p := range grants {
		switch p {
		case PermRead:
			readers = append(readers, access)
		case PermReadWrite:
			writers = append(writers, access)
		}
	}
	if len(readers)+len(writers) == 0 {
		return nil
	}
	sort.Strings(readers)
	sort.Strings(writers)

	bucketARN := "arn:aws:s3:::" + bucket
	objectARN := bucketARN + "/*"
	all := append(append([]string{}, readers...), writers...)
	sort.Strings(all)

	doc := policyDocument{Version: "2012-10-17"}
	add := func(sid string, principals, actions []string, resource string) {
		doc.Statement = append(doc.Statement, policyStatement{
			Sid: sid, Effect: "Allow",
			Principal: map[string][]string{"AWS": principals},
			Action:    actions, Resource: []string{resource},
		})
	}
	add("ReadBucket", all, readBucketActions, bucketARN)
	add("ReadObjects", all, readObjectActions, objectARN)
	if len(writers) > 0 {
		add("WriteBucket", writers, writeBucketActions, bucketARN)
		add("WriteObjects", writers, writeObjectActions, objectARN)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return out
}
