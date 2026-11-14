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

## Fixed

These were found in that testing, and are fixed in `deploy/`'s proxy
config and the key page. Each fix was checked with the client that showed
the problem.

1. **Refused uploads over about 256 KB came back as a 502, and clients
   retried them.** versitygw answers 403 or 412 before reading the body,
   then closes the connection with the body unread. nginx, still
   sending, got a reset and lost the answer.
   - The proxy now answers a PUT or POST that the gateway cut off part
     way with an S3 `AccessDenied`, saying the gateway refused the
     upload. A gateway that's down gets an XML `ServiceUnavailable` (503),
     and a portal that's down gets nginx's own page.
   - The catch: an add-only "already exists" over ~256 KB shows as 403,
     not 412, so `aws s3 cp --no-overwrite` reports a failure instead of
     skipping.
   - Upstream, versitygw should drain the body, up to a limit, or close
     gracefully on early errors.
2. **CreateBucket was answered as "already yours" even for buckets that
   don't exist.** The proxy now asks the gateway with an anonymous
   `HEAD /<bucket>`.
   - 403 means the bucket exists: the answer is `BucketAlreadyOwnedByYou`.
   - 404 means it doesn't: the answer is a 403 saying keys can't create
     buckets.
   - `rclone mkdir`, `aws s3 mb` and `mc mb` of a new name now fail
     clearly, while rclone's check before uploading still passes for
     buckets that exist.
3. **Presigned POST (`mc share upload`) went to the portal.** Multipart
   form posts now go to the gateway; the portal never takes them.
4. **The gateway port is hard-coded.** `site.conf` now says so where it
   matters.
5. **The key page** has an mc snippet, says that listing all buckets
   shows nothing, and gives per-client advice when the key has a
   write-only or add-only bucket.

## Still open

- **Listing buckets shows nothing.** `aws s3 ls`, `rclone lsd s3:` and
  `mc ls alias` come back empty, because versitygw's ListBuckets only
  shows buckets a `user` account owns, not ones granted by policy. The
  portal can't fix this; the key page says to name the bucket. Worth
  raising with versitygw upstream.
- **Client limits, documented on the key page:**
  - **Write-only keys:**
    - rclone: set `no_head = true` and use `copy --no-check-dest` (or
      `--no-traverse`). Never `sync`, or `copy` without those flags.
    - aws: `s3 cp` works, `s3 sync` doesn't.
    - mc: `cp` works, `mirror` doesn't.
  - **Add-only keys:**
    - aws: `s3 cp --no-overwrite` works. Set
      `s3.multipart_threshold = 5GB` for files over 8 MB.
    - mc: `cp -H "If-None-Match:*" --disable-multipart` works.
    - rclone 1.60 can't send `If-None-Match`, so it can't use add-only
      keys at all.
  - **mc mirror:** it reports success when every upload is refused, so
    don't use it with read-only or add-only keys.
  - **mc admin:** it doesn't apply here, and fails with a confusing
    region message.

## Not tested

- A region other than us-east-1.
- Real ZFS datasets.
- Files over 5 GB.
- rclone newer than 1.60.
