# Design: moving from MinIO

Status: built, except several hostnames in the portal and virtual-hosted
style. The copying in the steps below is a portal feature, the server
mirror, with the steps and checks shown in the admin page: see
`design-bucket-mirror.md`. Importing the keys, and checking the server is
ready for MinIO's hostname before DNS moves, is `s3-portal-minio`: see
`minio-keys.md`, the procedure. For a small number of users and buckets,
the **one-off migration** below is the recommended path. **Pull-through
mirroring** is written up for the record, in case a migration ever has to
happen with no downtime at all.

The goal is that existing users don't notice the move. Their endpoint
hostname, access key IDs and secrets keep working, and their files are
all there.

## What exists today

- **Several hostnames, path style.** These already work for the S3 API.
  nginx (`deploy/files/etc/s3-tls/site.conf`) is the default server for
  every name, and passes `Host` through unchanged. SigV4 signs `Host`,
  and versitygw checks the signature against whatever host the request
  carries. So the old MinIO hostname can point at this server, as long as
  the TLS certificate covers it.
- **Virtual-hosted style (`bucket.host`).** This isn't supported.
  - versitygw 1.10.0 has `--virtual-domain`, but it takes a single base
    domain.
  - The proxy routes on the bucket in the path.
  - Supporting it means a wildcard certificate, `--virtual-domain`, and
    nginx routing by host.
- **The portal.** It shows one `PUBLIC_S3_URL` on key pages, and OIDC has
  one callback URL.
- **Access key IDs.**
  - `versitygw admin create-user` takes any access key and secret.
  - The portal's own keys start with `VGW`, but nothing depends on that;
    only web accounts are recognised by a prefix (`web.`).
  - So keys with foreign IDs can live alongside portal keys.

## Recommended: a one-off migration

### Before cut-over (MinIO still in use)

1. **Inventory.**
   - Buckets and sizes: `mc ls`, `mc du`.
   - Users, groups, policies and service accounts:
     `mc admin cluster iam export`.
   - The addressing style each client uses. Virtual-hosted clients need
     the work described above, or a config change.
   - Whether any user logs in to MinIO through LDAP or OIDC. They only
     ever had temporary STS credentials, so there's nothing of theirs to
     carry over.
2. **People and buckets.**
   - Each MinIO bucket gets an owner among the portal's people, which
     also decides who owns the files on disk.
   - The bucket is made in the portal, so it's a dataset with the usual
     quota, snapshots and backup flag.
   - Group grants are set to match who used it.
3. **Pre-copy.** For each bucket:
   - Make a temporary read & write key owned by the bucket's owner.
     versitygw's `--chuid --chgid` then gives the files the owner's uid
     and gid.
   - Run `rclone sync minio:<bucket> new:<bucket>`. rclone keeps
     content types, and keeps modification times as metadata. Multipart
     ETags differ from MinIO's, and rclone records MD5s to check against.
   - Run it again as often as needed; each pass only copies what
     changed.
   - See `docs/client-compatibility.md` for rclone settings.
4. **Translate the keys.** Turn the IAM export into portal keys (see
   "Importing keys"), and review anything that doesn't translate
   exactly.

### Cut-over (short downtime)

1. Make MinIO read-only: change every user's policy to read-only, or
   stop clients at the network.
2. Run a final `rclone sync` per bucket, then `rclone check` to confirm
   both sides match.
3. Import the keys.
4. Add the old hostname to the certificate, then point DNS at this
   server, either as the old name or as a CNAME.
5. Check from a client with an imported key.
6. Keep MinIO read-only for a rollback window. Rolling back is a DNS
   change, as long as nothing has been written here yet.
7. Revoke the temporary migration keys.

Downtime is the final sync of whatever changed since the last pre-copy,
plus the DNS switch.

## Importing keys

Built as `s3-portal-minio` and the admin API's key import: see
`minio-keys.md`. What was found building it:

- `mc admin cluster iam export` isn't in every MinIO version. The tool reads
  the records from the drive instead, where every secret is: plain JSON
  since 2022, encrypted with the root credentials before.
- Clients sign for MinIO's region, and the gateway refuses another: the
  gateway must have MinIO's (on sde-s3, `s3.region`).
- MinIO's built-in `readonly` gets without listing, which no level here
  matches: it's noted, not widened to `read`.

The design, as proposed:

- **Where it comes from.** An admin-only page (or a CLI) takes a MinIO
  IAM export.
  - Secrets: `mc admin user info` and `svcacct info` never show them. We
    expect `mc admin cluster iam export` to include them for static users
    and service accounts, since it exists to move IAM between clusters.
    **This needs confirming on the MinIO version in use.**
  - If it doesn't, the IAM objects under `.minio.sys/config/iam/` can be
    decrypted with the root credentials. That's an offline step, done
    once.
- **Mapping.**
  - Each MinIO user, or each service account's parent user, maps to one
    of the portal's people. That's who owns the key, whose uid and gid
    its uploads get, and whose current access limits it, as with any
    key.
  - MinIO policies become bucket and level grants:
    - `s3:*` or read and write actions → read & write;
    - Get and List → read only;
    - Put without Get → write only.
  - Anything that doesn't map exactly is listed for an admin to decide,
    never silently widened or dropped. That covers prefix conditions,
    Deny statements, IP conditions, and policies naming buckets that
    weren't migrated.
- **Creating the keys.**
  - Each key is created in versitygw with its original ID and secret.
  - It's recorded in the portal's store with its owner and grants, and
    labelled with where it came from (for example "imported: minio user
    backup-bot").
  - Policies are written as usual.
  - An ID that clashes with an existing account is refused.
- **What owners see.** Imported keys appear on their Access keys page,
  and on each bucket's Access keys section, and can be edited or revoked
  like any other.
- **Secrets.** They're only held in memory during the import, and never
  written to the portal's state or logs. versitygw stores them as it
  stores every key.

## Several hostnames in the portal

This is small and independent of the rest:

- `PUBLIC_S3_URL` becomes a list. The first entry is shown in key
  snippets, and the others are listed as also working.
- nginx needs nothing more than a certificate covering every name.
- The portal itself can stay on one name; nothing requires otherwise.

## Not recommended for now: pull-through mirroring

For a migration with no downtime: a bucket is marked as a mirror of a
remote bucket, objects are copied in the background, and requests for
objects not yet copied are served from the source and copied on the way.
It's admin-only, and the source should be read-only.

**Shape.** A small service (`s3-mirror`) between nginx and versitygw.
nginx routes only mirror buckets to it, by the bucket in the path. Every
request goes to versitygw first, unchanged, so versitygw still checks
signatures and permissions, and the mirror never decides who may do
what.

| Request | While the mirror is active |
|---|---|
| GET or HEAD gives NoSuchKey | versitygw has already said the caller may read here. Fetch from the source with the migration credentials, stream it to the client, and write it into the bucket at the same time. Range requests are served from the source, with the whole object copied in the background. |
| LIST | Merge the local and source listings page by page, with a continuation token that carries both positions. This is the hardest part. |
| PUT | Local. The copier never overwrites an object that already exists locally. |
| DELETE | Local, plus a tombstone, so the copier doesn't bring it back. |
| CopyObject, or multipart copy, from an object not yet copied | Pull the source object in first, then pass the request on. |

- **Copier.** It walks the source and copies what's missing and not
  tombstoned, keeping metadata.
- **Ownership.** It writes as the bucket owner's web account, so files
  are owned correctly.
- **Finishing.** Progress (objects, bytes, errors) shows on the bucket's
  Storage page. A full pass that finds nothing to copy ends the mirror,
  and nginx stops routing through it.
- **Credentials.** The source credentials live in a root-only file, never
  in the portal's state.

**Why not now.** It's a new process in the data path, with the
merged-listing and tombstone logic to get right. For a few users, a
planned cut-over with a final sync gets the same result with far less to
build and keep working.

## Open questions

1. Do the clients use path style or virtual-hosted style?
2. Are the MinIO credentials static users, service accounts, or LDAP or
   OIDC logins?
3. Does `mc admin cluster iam export` on the version in use include
   secret keys?
4. How much data is there, and how much changes per day? Together these
   set the length of the final sync, and so the downtime.
