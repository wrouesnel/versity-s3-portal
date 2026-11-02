package main

import (
	"encoding/json"
	"sort"
)

// Perm is a named level of access to one bucket. Each is a set of Caps.
type Perm string

const (
	// PermRead lists and reads.
	PermRead Perm = "read"
	// PermReadWrite reads, writes, overwrites and deletes.
	PermReadWrite Perm = "readwrite"
	// PermWriteOnly uploads (and may overwrite) but can't list, read or
	// delete: a drop box.
	PermWriteOnly Perm = "writeonly"
	// PermCreateOnly reads and adds new objects, but can't overwrite or
	// delete anything. The gateway enforces it by allowing uploads only
	// with If-None-Match: *, which fails if the object exists.
	PermCreateOnly Perm = "createonly"
)

// Perms lists the levels, most to least access, for forms.
var Perms = []Perm{PermReadWrite, PermCreateOnly, PermRead, PermWriteOnly}

func (p Perm) Valid() bool { _, ok := permCaps[p]; return ok }

func (p Perm) Label() string {
	switch p {
	case PermRead:
		return "read only"
	case PermReadWrite:
		return "read & write"
	case PermWriteOnly:
		return "write only"
	case PermCreateOnly:
		return "add only"
	}
	return string(p)
}

// Caps is what a grant allows, as independent capabilities.
type Caps struct {
	Read   bool // list and get
	Put    bool // upload, overwriting freely
	Create bool // upload only where nothing exists (If-None-Match: *)
	Delete bool
}

var permCaps = map[Perm]Caps{
	PermRead:       {Read: true},
	PermReadWrite:  {Read: true, Put: true, Delete: true},
	PermWriteOnly:  {Put: true},
	PermCreateOnly: {Read: true, Create: true},
}

func (p Perm) Caps() Caps { return permCaps[p] }

// Union is everything either allows.
func (c Caps) Union(o Caps) Caps {
	return Caps{Read: c.Read || o.Read, Put: c.Put || o.Put, Create: c.Create || o.Create, Delete: c.Delete || o.Delete}.norm()
}

// Intersect is what both allow. Put includes Create: overwriting freely
// covers creating.
func (c Caps) Intersect(o Caps) Caps {
	return Caps{
		Read:   c.Read && o.Read,
		Put:    c.Put && o.Put,
		Create: (c.Put || c.Create) && (o.Put || o.Create),
		Delete: c.Delete && o.Delete,
	}.norm()
}

func (c Caps) norm() Caps {
	if c.Put {
		c.Create = false
	}
	return c
}

// Covers says whether c allows everything o does.
func (c Caps) Covers(o Caps) bool { return c.Intersect(o) == o.norm() }

func (c Caps) None() bool { return c == Caps{} }

// Any says whether c allows anything at all.
func (c Caps) Any() bool { return !c.None() }

// Actions granted for each capability. Bucket policy management, ACLs and
// other bucket configuration are left out, so a key can't widen its own
// access or remove the policy that scopes it.
var (
	readBucketActions = []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketLocation", "s3:GetBucketVersioning"}
	readObjectActions = []string{"s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes", "s3:GetObjectTagging"}
	// Multipart uploads are authorised as s3:PutObject, apart from these.
	uploadBucketActions = []string{"s3:ListBucketMultipartUploads"}
	uploadObjectActions = []string{"s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"}
	putObjectActions    = []string{"s3:PutObject", "s3:PutObjectTagging"}
	deleteObjectActions = []string{"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteObjectTagging"}
)

type policyStatement struct {
	Sid       string                       `json:"Sid"`
	Effect    string                       `json:"Effect"`
	Principal map[string][]string          `json:"Principal"`
	Action    []string                     `json:"Action"`
	Resource  []string                     `json:"Resource"`
	Condition map[string]map[string]string `json:"Condition,omitempty"`
}

type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

// BucketPolicy builds the policy granting each account its Caps on bucket,
// or nil when nobody has access.
func BucketPolicy(bucket string, grants map[string]Caps) []byte {
	var readers, uploaders, putters, creators, deleters []string
	for access, c := range grants {
		c = c.norm()
		if c.Read {
			readers = append(readers, access)
		}
		if c.Put || c.Create {
			uploaders = append(uploaders, access)
		}
		if c.Put {
			putters = append(putters, access)
		}
		if c.Create {
			creators = append(creators, access)
		}
		if c.Delete {
			deleters = append(deleters, access)
		}
	}
	bucketARN := "arn:aws:s3:::" + bucket
	objectARN := bucketARN + "/*"
	doc := policyDocument{Version: "2012-10-17"}
	add := func(sid string, principals, actions []string, resource string, cond map[string]map[string]string) {
		if len(principals) == 0 {
			return
		}
		sort.Strings(principals)
		doc.Statement = append(doc.Statement, policyStatement{
			Sid: sid, Effect: "Allow",
			Principal: map[string][]string{"AWS": principals},
			Action:    actions, Resource: []string{resource}, Condition: cond,
		})
	}
	add("ReadBucket", readers, readBucketActions, bucketARN, nil)
	add("ReadObjects", readers, readObjectActions, objectARN, nil)
	add("UploadBucket", uploaders, uploadBucketActions, bucketARN, nil)
	add("UploadObjects", uploaders, uploadObjectActions, objectARN, nil)
	add("PutObjects", putters, putObjectActions, objectARN, nil)
	// s3:if-none-match may only qualify s3:PutObject.
	add("CreateObjects", creators, []string{"s3:PutObject"}, objectARN,
		map[string]map[string]string{"StringEquals": {"s3:if-none-match": "*"}})
	add("DeleteObjects", deleters, deleteObjectActions, objectARN, nil)
	if len(doc.Statement) == 0 {
		return nil
	}
	out, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return out
}
