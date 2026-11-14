# S3 client compatibility

How the AWS CLI, rclone and MinIO mc behave against the stack in
`deploy/` (versitygw 1.10.0 behind the s3-tls nginx). Tested with AWS CLI
2.40.3, rclone 1.60.1 and mc built from source (Nov 2025).

## Works

All three clients handle these:

- listing a bucket, uploading and downloading files
- multipart uploads, recursive copies, and sync or mirror
- presigned GET links, and stat or head
- the checksum headers newer AWS CLIs send (CRC64NVME, CRC32, SHA256 and
  trailing checksums)

Every access level allows and refuses exactly what `policy.go` says.

## To fix

1. **Refused uploads over about 256 KB come back as a 502, and clients
   retry them.**
   - This affects read-only and wrong-bucket keys, and add-only
     "already exists" errors.
   - The cause: versitygw answers 403 or 412 before reading the request
     body, then closes the connection with the body unread. nginx gets a
     reset while still sending, and loses the response.
   - What clients do:
     - aws: retries, then shows `(502) … Bad Gateway`.
     - rclone: `expected element type <Error> but have <html>`.
     - mc: sometimes prints nginx's HTML.
   - Proxy fix: `error_page 502 = @s3_refused`, mapped on
     `$request_method $upstream_bytes_sent`, so a PUT whose body was
     partly sent gets an S3 XML 403 and anything else an XML 503. The
     catch: add-only "already exists" over ~256 KB then shows as 403,
     not 412.
   - Upstream fix: versitygw should drain the body, up to a limit, or
     close gracefully on early errors.
2. **Listing buckets shows nothing.**
   - `aws s3 ls`, `rclone lsd s3:` and `mc ls alias` all come back empty,
     because versitygw's ListBuckets only shows buckets a `user` account
     owns, not ones granted by policy.
   - The portal can't fix this. The key page should say to name the
     bucket. Worth raising with versitygw upstream too.
3. **The CreateBucket shim answers 409 even for buckets that don't
   exist.**
   - So `rclone mkdir s3:newname` appears to succeed, and the next copy
     fails with NoSuchBucket. `aws s3 mb` and `mc mb` print a misleading
     message.
   - Fix: send the signed CreateBucket to an internal location that makes
     an anonymous `HEAD /<bucket>` to the gateway.
     - 403 means the bucket exists: answer 409 BucketAlreadyOwnedByYou.
     - 404 means it doesn't: answer 403 "keys can't create buckets: make
       it in the portal".
   - This reveals nothing new, because anonymous HEAD already shows
     whether a bucket exists.
4. **Presigned POST (`mc share upload`) goes to the portal.**
   - Its signature is in the form body, which the routing map can't see.
     The portal answers 200 with HTML, and nothing is uploaded.
   - Fix: add `$request_method $content_type` to the `$s3_upstream` map,
     and send `POST multipart/form-data` to the gateway. The portal never
     takes multipart forms.
5. **The proxy hard-codes the gateway port.** The regexes `~:7070$` and
   `\S+:7070  ` both depend on it, so comment them.
6. **Key page and docs.** Add an mc snippet:
   `mc alias set s3 URL ACCESS SECRET --api S3v4 --path on`. Then
   document the following.
   - **Listing:** name the bucket; listing all buckets shows nothing.
   - **Write-only keys:**
     - rclone: set `no_head = true` and use `copy --no-check-dest` (or
       `--no-traverse`). Never use `sync`, or `copy` without those flags:
       it uploads, reports Forbidden, and uploads again three times.
     - aws: `s3 cp` works, `s3 sync` doesn't.
     - mc: `cp` works, `mirror` doesn't.
   - **Add-only keys:**
     - aws: `s3 cp --no-overwrite` works. Set
       `s3.multipart_threshold = 5GB` for files over 8 MB. `s3 sync`
       doesn't work.
     - mc: `cp -H "If-None-Match:*" --disable-multipart` works.
     - rclone 1.60 can't send `If-None-Match`, so it can't use add-only
       keys at all.
   - **mc mirror bug:** never use `mc mirror` with read-only or add-only
     keys. It reports success when every upload is refused.
   - **mc errors:** `mc admin` doesn't apply, and fails with a confusing
     region message.

## Not tested

- A region other than us-east-1.
- Real ZFS datasets.
- Files over 5 GB.
- rclone newer than 1.60.
