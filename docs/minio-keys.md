# Moving a MinIO server's keys, and its hostname

`s3-portal-minio` moves a MinIO server's access keys to the portal with their
IDs and secrets, so its clients keep working unchanged once the server's
hostname points here. It also checks that the portal's server is ready for
that name before DNS moves. The buckets' data moves separately, by a
server mirror (`design-bucket-mirror.md`); this is the rest of the cut-over
in `design-minio-migration.md`.

The tool knows MinIO; the portal doesn't. The portal only gains an admin API
call that imports a key with a given ID and secret (`POST /api/keys` with
`access_key` and `secret_key`), which any migration can use.

## Where the keys come from

MinIO's admin API never shows secrets, and `mc admin cluster iam export`
isn't in every version. Its drive has them all: under
`.minio.sys/config/iam/`,

| Path | What |
| --- | --- |
| `users/<name>/identity.json` | a MinIO user's credentials: their access key is their name |
| `service-accounts/<key>/identity.json` | a service account's: its secret, its parent user, its own policy if it has one (in its session token's claims) |
| `groups/<name>/members.json` | a group's members |
| `policies/<name>/policy.json` | policies made in MinIO (its built-in ones aren't stored) |
| `policydb/users/<name>.json`, `policydb/groups/<name>.json`, `policydb/sts-users/<dn>.json` | the policies of each user, group and LDAP user |

On a single drive each is a directory holding `xl.meta`, with the record
inline; on an old "fs" mode install, a plain file. MinIO since 2022 keeps
them as plain JSON; before, it encrypted them with the root credentials, and
the tool decrypts those, given them. Records encrypted by a KMS
(`MINIO_KMS_*`) can't be read without it, and are reported as unreadable.
Erasure-coded servers (more than one drive) split records across drives,
and aren't read.

The tool only reads. It can run on the MinIO host, against the drive
itself, or anywhere against a copy (`.minio.sys/config/iam`, and the bucket
list with `--buckets`). The records hold every secret: keep a copy as
you would a credentials file, and delete it after.

## 1. Plan

On the MinIO host, as root (or a user who can read the drive):

```sh
s3-portal-minio plan --drive /data --minio-env /etc/default/minio --out plan.json
```

`--minio-env` gives MinIO's root user (whose service accounts need an owner
chosen, and to decrypt older records), its region, and whether it has a KMS.
Without it, `MINIO_ROOT_USER` and `MINIO_ROOT_PASSWORD` are read from the
environment.

The plan (`plan.json`, no secrets in it) lists every key:

- **Owner.** Each MinIO user, and each service account's parent, maps to one
  of the portal's people, by `owners` (the same name by default; an LDAP
  user's account name; nobody for the root user). A key's own `owner`
  overrides it. The owner's uid and gid are what its uploads get, and the
  key reaches no more than they can, as any key.
- **Grants.** What MinIO let the key do in each bucket becomes one of the
  portal's levels: never more than MinIO allowed.

  | MinIO allowed (per bucket) | Grant |
  | --- | --- |
  | list, get, put and delete (as `s3:*`, `readwrite`) | `readwrite` |
  | list and get | `read` |
  | put alone (as `writeonly`) | `writeonly` |
  | list, get and put, without delete | `createonly` (noted: overwriting isn't carried over) |
  | get without list (as MinIO's `readonly`) | nothing (noted: `read` also lists) |

  A service account with its own policy gets what both it and its parent
  allow. Deny statements, conditions, `NotAction`/`NotResource`, prefixes
  within a bucket, other actions and buckets that weren't moved are never
  carried over silently: each is a note on the key.
- **Import.** A key starts as `"import": true` only if it translates exactly
  and has an owner. Disabled and expired keys, keys with notes, and the root
  user's service accounts start false.
- **Buckets.** `buckets` maps each MinIO bucket to the portal's bucket it was
  mirrored into: the same name by default, another if the server mirror
  renamed it, or `""` if it wasn't moved.

Edit it: set `owners`, map `buckets`, change grants, and set `import` on the
keys to move. `plan` won't overwrite an edited plan without `--force`.

## 2. Import

Issue an API token on the portal's admin page (API tokens), and keep it in a
file. Then, where the drive (or its copy) is:

```sh
s3-portal-minio import --drive /data --minio-env /etc/default/minio \
  --plan plan.json --portal https://s3.example.internal --token-file token
```

Without `--apply` this changes nothing. It checks each key to import is in
MinIO's records and enabled, has an owner the directory lets use the
service, and has grants on mapped buckets, and shows what it would do. With
`--apply` it registers each owner from the directory and imports each key,
labelled with where it came from (`MinIO: backup-bot`, `MinIO user alice`),
so owners see it on their Access keys page, and can revoke it.

The portal refuses an ID it has already (another key, a web account, its root
account), and a grant on a bucket the owner can't use. Importing again is
safe: a key imported before, with the same owner and secret, is reported as
already there and left alone. The secrets go only to the gateway, which keeps
every key's; they're never in the plan, the portal's state or its logs.

Import after the final mirror pass (MinIO frozen), so nothing changes in
MinIO after its keys are read. Importing earlier is fine too, to test with:
the imported keys work on the portal's own name right away.

## 3. Check, then move DNS

Clients sign every request for the host they use, and verify its certificate.
So before MinIO's hostname moves, the portal's server must already answer for
it:

1. **Its certificate covers the old name.** Add it to the server's
   certificate (on sde-s3, the deployer's `certificate.dns_names`), and
   deploy. With AD CS, the template must take names from the request.
2. **Its region is MinIO's.** Clients sign for MinIO's region (`us-east-1`
   unless MinIO set `MINIO_SITE_REGION` or `site region=`, which the plan
   shows). The gateway refuses a request signed for another region. On
   sde-s3, set `s3.region`.
3. **Run the check**, from a client's network, pointing at the server's
   current address or name, with an imported key and a bucket it may read:

   ```sh
   s3-portal-minio check --name minio.example.internal --address s3.example.internal \
     --ca-file site-ca.pem --drive /data --key SVCACCOUNTKEY --bucket backups
   ```

   It connects to the server asking for the old name, and checks the
   certificate it gets is for that name, trusted (by the system's CAs and
   `--ca-file`) and not about to expire. Then it lists buckets, and the
   bucket's objects, with the key, signed for the old name and MinIO's region,
   as a client would. It shows what the name resolves to now. Every line
   must be `[ OK ]` before DNS moves.
4. **Lower the name's TTL** well ahead (a day before, to a few minutes), so
   the move takes effect quickly, and a rollback too.
5. **Move DNS:** point the name at the server, as an A record or a CNAME to
   its name.
6. **Check again, after:**

   ```sh
   s3-portal-minio check --name minio.example.internal --address s3.example.internal \
     --ca-file site-ca.pem --drive /data --key SVCACCOUNTKEY --bucket backups --after
   ```

   This also checks the name now resolves to the server, and that
   connecting by the name gives the same certificate. A resolver still
   caching the old answer fails it: wait out the old TTL.

Keep MinIO read-only for a rollback window. Rolling back is moving DNS back,
as long as nothing has been written here since.

Virtual-hosted style (`bucket.minio.example.internal`) isn't served; clients
using it need path style first (see `design-minio-migration.md`).
