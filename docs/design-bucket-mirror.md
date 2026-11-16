# Design: mirroring a bucket in, then cutting over

Status: built. Where the build differs from the proposal below, the
differences are listed under "As built" at the end.

An admin registers a bucket here as a **mirror** of a bucket on another
S3 service. The portal copies the source into it on a schedule. When the
admin is ready, they stop writes to the source, run a **final pass**, and
the portal shows whether the two buckets match. The admin can then remove
the source bucket.

The process isn't meant to be invisible to users. Instead, the portal
shows each step as it happens, with evidence: what was copied, what
changed, and what couldn't be copied.

This replaces the hand-run `rclone sync` passes in
`design-minio-migration.md`. Pull-through mirroring stays out of scope.

## The steps

A mirror moves through these states. Each change of state is recorded
with when it happened and which admin did it. The admin page shows them
as a checklist, with every step's evidence.

| State | Who moves it on | What it means |
|---|---|---|
| **Registered** | admin | Source endpoint, bucket and credentials saved. Connection test passed (below). |
| **Syncing** | portal | Passes run on the schedule. The first pass is the initial copy. |
| **Synced** | portal | The most recent pass finished with nothing left to copy, and no failures. Passes keep running. |
| **Freezing** | admin | The admin confirms that writes to the source have stopped. Scheduled passes stop. |
| **Verified** | portal | The final pass and its check found the buckets matching, with nothing changed since the last pass, or every change accounted for. |
| **Complete** | admin | The bucket opens to its users. The source credentials are deleted. |
| **Source removed** | admin (optional) | The admin records that the source bucket was deleted. The portal never deletes anything on the source. |

From any state before Complete, an admin can **abandon** the mirror. The
bucket stays, with whatever was copied, and becomes an ordinary bucket.
The credentials are deleted.

## Registering

The admin page gets a **Mirrors** section, as a two-pane like the
others. **New mirror** asks for:

- **The target bucket:** a new bucket here (name and owner), or an
  existing empty one. A non-empty bucket is refused, so every object in
  the target can only have come from the source.
- **The source:**
  - endpoint URL, region, and bucket;
  - path or virtual-hosted style;
  - access key ID and secret.

  It should be a read-only key, and the form says so.
- **The schedule:** how often to run a pass (hourly, daily, or manual
  only), and an optional bandwidth limit.

**Connection test.** The source is checked before anything is saved:

- List the bucket (one page), and HEAD one object.
- Report whether the source has versioning or object lock turned on.
  Neither is carried over; only current versions are copied.

Whether the key can write isn't tested, since testing it would mean
writing to the source.

## While mirroring, the target is read-only

From registration until Complete, the portal treats the bucket as
read-only for everyone except the mirror:

- `syncBucket` writes every grant on the bucket as read only, including
  the owner's own access.
- The file browser shows a banner: "Being mirrored from <source>. Read
  only until the move is complete."
- The key form and bucket settings still let people set grants, so keys
  can be prepared ahead. The portal records what was asked and applies
  it at Complete, the same way a key's `Buckets` already records what was
  asked.

This is what makes the final check mean something. If nobody else can
write, every difference between the source and the target is either a
change on the source or a mirror failure.

People can browse and download from the target while it mirrors. That's
a cheap way to have owners spot-check their files before cut-over.

## A pass

Each pass is a merge of three listings, all sorted by key and read page
by page, so memory stays flat however many objects there are:

1. **The source:** ListObjectsV2 of the whole bucket.
2. **The manifest:** the portal's record of what it copied.
   - Per key: the source ETag, size and last-modified, and the MD5 and
     size of the bytes written here.
   - It's one sorted file per mirror (see "State" below).
3. **The target:** a listing of the bucket here.

For each key:

| Source | Manifest | Target | Action |
|---|---|---|---|
| present | missing, or a different ETag or size | – | **Copy** |
| present | matches | present, same size | nothing |
| present | matches | missing or a different size | **Copy**, and count it as *repaired* (something changed the target) |
| missing | present | present | **Delete** from the target, and from the manifest |
| missing | missing | present | Report as **unexpected** (the target is read-only, so this shouldn't happen). Never deleted automatically. |

**Copying an object:**

- GET from the source, and PUT here as the bucket owner's web account.
  versitygw's `--chuid` gives the file the owner's uid and gid, as with
  any upload.
- The PUT carries the source's Content-Type, Content-Encoding,
  Content-Disposition, Cache-Control, Expires and `x-amz-meta-*`.
  `VGW.PutObject` grows a headers argument for this.
- The body is hashed (MD5) on the way through, and the source's
  Last-Modified is saved as `x-amz-meta-mirror-mtime`.
- **Objects over 5 GB** use a multipart upload here. The target's ETag
  then can't be compared with an MD5, so the manifest's MD5, taken while
  streaming, is what the check uses.
- If the source object changes mid-copy (the GET is made with `If-Match`
  on the listed ETag), the copy is retried once, then left for the next
  pass.

**Keys versitygw can't hold.** The posix backend stores objects as files,
so some keys can't exist here:

- a key that is also a "directory" of another key (`a` and `a/b`);
- a path segment over 255 bytes;
- `.` or `..` segments, and some keys with an empty segment (`a//b`).

These go in the pass report as **can't be copied**, with the reason.
They're never silently skipped. Synced and Verified both require the
list to be empty, or each entry to be dismissed by an admin with a note.

**Failures.** One object failing doesn't stop a pass. It's retried on
the next pass, and reported with the error. A failure in a listing does
stop the pass, since a partial listing would look like deletions.

**After each pass:**

- A ZFS snapshot of the bucket, labelled `mirror-<pass number>`. The last
  few are kept, plus the first and the final one. This gives a history to
  compare and roll back to, and costs little on ZFS.
- A pass report: started and finished times; objects and bytes copied,
  repaired and deleted; failures; can't-be-copied keys; the source's total
  object count and bytes, and the target's.

## The final pass and verification

The admin clicks **Freeze**. The page asks them to confirm that writes
to the source have stopped, with the usual ways listed:

- a read-only policy for every user of the source bucket;
- revoking the source's keys;
- blocking clients at the network.

The portal can't check this, so it's recorded as the admin's statement.

Then the portal runs:

1. **A final pass,** as above.
2. **A quiet check.** A second listing of the source, compared with the
   manifest.
   - If anything differs, the source is still being written to. The state
     stays Freezing, and the page shows what changed. The admin fixes the
     source and runs the final pass again.
3. **A content check:**
   - For each object: the target's size matches, and the target's ETag
     (or, for multipart, the manifest MD5) matches the MD5 recorded when
     copying.
   - Where the source's ETag is a plain MD5 (a single-part upload, no
     SSE-KMS), it's compared with the MD5 recorded too. That confirms the
     bytes end to end without reading the source again.
   - Multipart-uploaded source objects have no MD5 to compare with. An
     optional **deep check** reads them from both sides and compares
     hashes. It costs a full read of those objects, so it's off by
     default and shows how many objects and bytes it would read.
   - The results: matched, matched by size only (source multipart, no
     deep check), and mismatched. Any mismatch blocks Verified.

When all three pass, the state is **Verified**. The final snapshot is
taken as `mirror-final`, and isn't pruned.

**Changes found during the final pass are allowed.** Writes between the
last scheduled pass and the freeze are expected. The final pass copies
them, and the report lists them, so the admin can see exactly what came
over at cut-over. Only changes after the final pass (the quiet check)
block Verified.

## Completing

**Complete** is a separate click, after Verified, so the admin can switch
DNS and clients over first (`design-minio-migration.md`, cut-over steps).

At Complete:

- The bucket's recorded grants are applied, and it's an ordinary bucket.
- The source secret is deleted from the store.
- The mirror's record stays, read-only:
  - the state history;
  - the pass reports;
  - the final verification;
  - the manifest, until an admin deletes it.

  It shows on the bucket's Storage section, so the owner can see where
  the bucket came from and that it was checked.

**Source removed** is a checkbox the admin ticks once the source bucket
is deleted on the old service. It's just a record, so the checklist
ends complete.

## State

- **The mirror record** goes in the portal's store as a new `Mirrors` map,
  keyed by target bucket. It holds:
  - the source endpoint, bucket and options;
  - the schedule;
  - the state and its history;
  - a summary of each pass.
- **The source secret.** It's kept in the store with the record, the same
  way web account secrets are. It's never shown back, and the form shows
  "(saved)", with a way to replace it. It's deleted at Complete or
  Abandon.
- **Manifests** are too big for the JSON store. Each is a sorted,
  gzipped JSON-lines file per mirror, next to the store
  (`mirrors/<bucket>/manifest.jsonl.gz`).
  - A pass writes a new manifest alongside the old one, and renames it
    into place at the end, so a pass that dies leaves the last good one.
  - The objects a dead pass already copied are found again in the next
    pass: the source ETag differs from the manifest, but the target
    exists. They're copied again, which is safe, if wasteful.
- **Full pass reports**, including the lists of failures and keys that
  can't be copied, go next to the manifest as `pass-<n>.json`, and are
  downloadable from the page.

## Running

- **`RunMirrors`** is a loop like `RunSnapshots`. It starts due passes,
  one at a time per mirror, with at most two mirrors running at once.
- Within a pass, a few objects copy at once (4 by default).
- A restart of the portal stops a running pass. The next round starts it
  again from the beginning, which is safe, because a pass is driven by
  the listings.
- **The page:**
  - progress (listed, copied, bytes) while a pass runs, refreshed on
    reload with no live push needed;
  - a **Run pass now** button;
  - a **Pause** button that stops scheduled passes.

## What isn't carried over

The registration page and the final report both say this:

- old versions, delete markers, object lock and retention, tags, ACLs,
  bucket policies, lifecycle rules, and notifications;
- **keys:** importing the source's access keys is separate. It's
  described in `design-minio-migration.md` under "Importing keys", and
  isn't needed for mirroring.

## What it needs

- `VGW`: a ListObjectsV2 that pages without a delimiter, and a PUT and
  multipart upload with headers.
- A small S3 client for the source, with virtual-hosted style and a
  configurable region. It's the same SigV4 code as `VGW`, pointed
  elsewhere.
- The store: `Mirrors`. `syncBucket` caps grants on mirror buckets.
- The files under `mirrors/` in the state directory.
- The ZFS snapshots after each pass (the helper already has them).
- **The UI:**
  - an admin **Mirrors** section: a list, plus a detail page with the
    checklist, pass reports and buttons;
  - a banner in the file browser;
  - the mirror history on the bucket's Storage section.
- **Tests:**
  - a second throwaway versitygw as the source, testing passes, deletions,
    changes mid-pass, keys that can't be copied, the quiet check catching
    a write after freeze, and resuming after a killed pass;
  - for MinIO specifically, one run against a MinIO container, for its
    listing order and ETags.

## Open questions

1. **Deletions on the source.** The design copies them: an object deleted
   at the source is deleted here on the next pass, and the ZFS snapshots
   keep it recoverable. The alternative is never deleting, and listing
   them in the report. That's safer if the source is ever emptied by
   mistake, but then the target drifts from the source.
2. **Read-only while mirroring.** It's what makes the check mean
   something. Do owners need to write into a bucket while it mirrors?
   If so, the check can only cover keys that came from the source.
3. **The source secret in the store,** rather than in a separate
   root-only file. The store already holds the web account secrets, so it
   adds no new class of risk. But it does mean the secret is entered in
   a browser form.

## As built

Decisions on the open questions:

1. **Deletions** are copied, as designed.
2. **Read-only** applies while mirroring, as designed.
3. **The source secret** is kept in the store.

Differences from the proposal:

- **The mirror's account.** It writes as `mirror.<bucket>`, a gateway
  account with the owner's uid and gid, granted read & write on the bucket
  until the mirror ends. It isn't the owner's web account, which is held to
  reading like everyone else. Ending the mirror deletes the account.
- **Changes mid-copy.** Copies don't use `If-Match`. The manifest records
  the ETag and size from the GET response itself, which always describe
  the bytes that were read. A change mid-copy then simply shows up as a
  change on the next pass.
- **The content check:**
  - An object counts as matching end to end when the source's ETag, the
    MD5 of what was read, and the target's ETag are all the same.
  - Otherwise it's matched by size, and the target's ETag must be the one
    the gateway gave when it was written. That covers sources uploaded in
    parts, sources that encrypt, and anything over the part threshold here.
  - The deep check reads these objects back from the target and compares
    them with the MD5 taken while copying. It doesn't read the source
    again: the quiet check has already shown the source's ETags haven't
    changed.
- **Keys that can't be copied:**
  - Keys that are invalid as paths are found by name.
  - Keys under `.zfs/` or `.sgwtmp/` are reserved here, and are also found
    by name.
  - A file and a folder with the same name is found when the gateway
    refuses the write. Its error codes are `ExistingObjectIsDirectory`,
    `ObjectParentIsFile` and `DirectoryObjectContainsData`.
  - Accepting them records the set's hash. The acceptance holds while
    later passes find the same set.
- **Listings** must come back in key order. A pass stops with an error if
  either side's listing goes backwards, rather than risk wrong deletions.
  versitygw and MinIO both list in byte order.
- **Stopping.**
  - Freezing, abandoning and completing all stop a running pass first.
  - A pass that stops early leaves the previous manifest in place, and
    the next pass copies again whatever it can't vouch for.
  - Restarting the portal stops a pass the same way. A final pass that was
    stopped is run again by hand.
- **Not built:** a live progress push. The mirror's page reloads itself
  every 10 seconds while a pass runs.

Tested against versitygw 1.10.0 as the target, and versitygw and a MinIO
server built from source as sources. The MinIO test covers keys needing
URL encoding, a multipart-uploaded source object, and `a-b` sorting
before `a/b`.

## Server mirrors

Status: built. An admin moving a whole S3 service (a MinIO server) would
otherwise register each bucket by hand. A **server mirror** lists the
service's buckets and makes a mirror of each one picked. Each is then an
ordinary mirror, with every step and check above.

- **Registering.** The form takes the service's endpoint, region,
  addressing and key, a name for it, the default owner of the buckets
  made, and the schedule. The key is checked by listing the buckets (S3's
  ListBuckets, paged), so it needs `s3:ListAllMyBuckets` as well as reading
  each bucket. Nothing is mirrored yet.
- **The review table.** The server's page lists the service's buckets not
  yet mirrored from it, every time it's opened:

  | The name here | Ticked | What happens |
  |---|---|---|
  | no bucket has it | yes | a new bucket, for the default owner, or the one picked |
  | an empty bucket owned by someone the portal knows | yes | that bucket is used as it is, and keeps its owner |
  | a bucket with things in it, or one another mirror copies into | no | give it another name here, or leave it |
  | not a valid bucket name here (`Legacy_Data`) | no | a valid one is offered (`legacy-data`) |
  | another mirror copies this source bucket already | can't be | shown, for the record |

  Ticked rows are registered one by one, as single mirrors are, each source
  checked first. One that fails is left out, with why; the others go ahead.
- **Acting on them all.** The server's page runs a pass of each, pauses or
  resumes them, freezes them, completes the verified ones, and replaces the
  key for the server and every mirror still running. A freeze is the
  admin's word that the whole service has stopped taking writes; a mirror
  whose first pass hasn't run is left out of it, saying so.
- **Queued passes.** A pass asked for of many mirrors at once is queued on
  each (`Mirror.Queued`), not started: the scheduler starts queued passes
  first, at most two running at a time (`maxMirrorJobs`), as it does
  scheduled ones. A queued pass is dropped if its mirror's state no longer
  takes it (a manual pass of a mirror since frozen).
- **State.** The server's record (`Servers` in the store) keeps the endpoint
  and key; each mirror keeps its own copy of the key, and its server's ID.
  The record, and its key, is forgotten by hand once every mirror from it
  is complete or abandoned. The mirrors' records stay.
- **Not built:** reading owners from the source's IAM. Each bucket's owner
  is the default, or whom the admin picks for it.
