# versity-s3-portal

A small web app that lets people log in with their LDAP password or an
OpenID Connect provider, make buckets on a [versitygw](https://github.com/versity/versitygw) gateway,
browse, upload and download files, share buckets with groups, and issue S3
access keys limited to the buckets and levels they pick. Access follows the
directory: people who are disabled or leave a group lose it at once. Admins
can see everyone, every bucket and every key.

S3 signs every request with a secret the server must already hold, so S3
clients can't log in with an LDAP password. Instead people log in here, and
get long-lived keys for rclone, backups and apps, each limited to the buckets
they pick.

## How it works

- **Login:** search-then-bind.
  - A search account looks the user up with
    `(&(objectClass=posixAccount)(uid=<user>))`. They must have
    `ALLOWED_GROUP_DN` in `memberOf` when it's set, and not be disabled (see
    the directory below).
  - The portal then binds as the returned DN to check the password.
  - Their groups are the first value of each `memberOf` DN, so
    `ou=photos,ou=groups,dc=example,dc=com` is the group `photos`.
  - The user's uid and gid come from the entry's `uidNumber` and `gidNumber`.
  - Root (uid or gid 0) is always refused.
  - With glauth's PAM backend, the search account must be in its
    `groupWithSearchCapability` group, and group DNs look like
    `ou=<group>,ou=groups,<base DN>`. Users need a `uid`
    attribute, which glauth 2.3 emits only with `nameformat = "uid"`.
- **Active Directory** (`LDAP_SCHEMA=ad`): the same search-then-bind, on
  AD's own schema.
  - People are found by `sAMAccountName`
    (`(&(objectCategory=person)(objectClass=user)(sAMAccountName=<user>))`),
    without case: `Alice` logs in as `alice`.
  - `ALLOWED_GROUP_DN` and `ADMIN_GROUP_DN` count nested groups (AD's
    `LDAP_MATCHING_RULE_IN_CHAIN`), so a site's own groups can be made
    members of them. Admins may log in without being in the allowed group
    too, with LDAP of either schema and with OIDC. The groups shown for grants are the person's direct
    `memberOf`.
  - Their uid and gid are their `uidNumber` and `gidNumber` where AD has
    them (its RFC 2307 attributes). Otherwise, with `LDAP_ID_RANGE_BASE`,
    the base plus their RID (the last part of their `objectSid`) and their
    primary group's, as sssd's ID mapping gives a domain a range: unique
    per person in one domain. Otherwise `LDAP_DEFAULT_UID`/`GID`, one
    service user for everyone, as with OIDC.
  - A person is disabled when their account is disabled
    (`userAccountControl`), locked out (`msDS-User-Account-Control-Computed`,
    which AD works out from its lockout policy), or past `accountExpires`.
  - Groups to suggest are `(objectClass=group)`.
  - The search account needs only to read users and groups: any domain
    user can. Bind as its DN or `name@domain`.
  - **LDAPS to DCs.** Few DCs' certificates have the domain's name, or an
    address: only the DC's own host name. When a server reached by
    `ldaps://` presents a certificate without the name (or address) it was
    reached by, the portal looks its address up in reverse, and tries again
    by that name if it resolves back to the same address and is one of the
    domain's DCs (the `_ldap._tcp.dc._msdcs` SRV records of the base DN's
    domain, which only DCs register). The certificate must still have that
    name and come from a trusted CA. A name that isn't a DC's is never
    taken: any domain computer has a certificate from the domain's CA, and
    could otherwise stand in for a DC by registering its own records.
- **OIDC login** (optional, alongside or instead of LDAP): the
  authorization code flow with PKCE, a nonce, and a signed short-lived cookie
  holding the flow's state.
  - The username comes from `OIDC_USERNAME_CLAIM` (default
    `preferred_username`). An email address becomes its local part, and the
    name is lowercased. It must fit the same pattern as LDAP usernames,
    since gateway accounts are named after it.
  - The first login binds the username to the provider's issuer and `sub`.
    Another identity that maps to the same name is refused, so a renamed
    account, or `alice@` at another domain, can't take over alice's buckets.
  - The uid and gid come from `OIDC_UID_CLAIM`/`OIDC_GID_CLAIM` when the
    provider has them. Otherwise everyone gets `OIDC_DEFAULT_UID`/`GID`:
    S3 access is still separate per person, but on disk every file is owned
    by that one service user.
  - Group membership for `OIDC_ALLOWED_GROUP` and `OIDC_ADMIN_GROUP` comes
    from the groups claim, in the ID token or from the userinfo endpoint.
    It's read at login.
  - LDAP and OIDC users with the same username are the same person here.
    When both are on, make sure the names come from the same directory.
- **Access levels.** Every grant, to a group or a key, is one of four
  levels per bucket. The gateway enforces each one through the bucket
  policy:

  | Level | List and download | Upload | Overwrite | Delete |
  | --- | --- | --- | --- | --- |
  | Read & write | yes | yes | yes | yes |
  | Add only | yes | new names only | no | no |
  | Read only | yes | no | no | no |
  | Write only | no | yes | yes | no |

  - Add-only uploads are allowed only with `If-None-Match: *`, which the
    gateway refuses with `412 PreconditionFailed` when the name exists, both
    for PUT and copy. Clients must send that header: `aws s3api put-object
    --if-none-match '*'` does, but `aws s3 cp` and rclone don't, and their
    uploads are denied. The gateway doesn't check the condition on
    multipart uploads, so add-only keys can't use them, and each upload is
    a single PUT.
  - Write-only is a drop box: uploads work (multipart too), but listing,
    downloading and deleting don't.
- **Buckets** belong to a person. Each person has an owner account in the
  gateway, `owner.<user>`, whose secret is random and thrown away, so nobody
  can sign as it. The portal creates buckets through the admin API with that
  account as owner, and deletes them over S3 as root, only when they're
  empty. The owner always has read & write, and manages it, with admins
  and any group given *manages*.
- **Group grants.** A bucket's owner, or an admin, can give any group a
  level on it. Members see the bucket under "Shared with you", use the file
  browser at their level, and can make keys up to it. Someone in several
  groups with grants gets everything they allow together. Group names
  compare without case. The settings page suggests the directory's groups
  (`LDAP_GROUP_FILTER`, default `(objectClass=posixGroup)`) and any the
  portal has seen in OIDC logins.
- **Groups which manage a bucket.** A group may be given *manages*: read &
  write, and managing the bucket as its owner does: who has access (other
  managing groups too), the keys reaching it, storage and backups, and
  deleting it. So a team's bucket isn't stuck when its owner leaves.
  Managing is a group's alone: keys only read and write. The owner keeps
  read & write whatever managers do.
- **Transfers.** Admins give a bucket to another person (admin page,
  Buckets, Transfer; or `POST /api/buckets/{bucket}/owner` with
  `{"owner": "bob"}`), through the gateway's `change-bucket-owner`. Grants,
  managing groups, keys and settings stay; the old owner keeps what their
  groups give them, and their keys with it. Files keep their owners on
  disk. Not while the bucket is being mirrored in. The People section marks
  a suspended person who still owns buckets. See
  `docs/design-bucket-managers.md`.
- **Access keys:**
  - Each key is a gateway account with the `user` role and the person's uid
    and gid. With the posix backend's `--chuid --chgid`, everything a key
    writes is owned by that person on disk.
  - A `user` account can't create buckets. It reaches buckets only through
    bucket policies, which the portal writes in full from its records
    whenever anything they depend on changes. Only policies that actually
    changed are sent. Tools that create the bucket before uploading, as
    rclone does, would fail with AccessDenied, so the TLS proxy in
    `deploy/` answers a signed CreateBucket itself: BucketAlreadyOwnedByYou
    when the bucket exists, and otherwise a refusal saying to make it in
    the portal. The proxy also turns the gateway's early refusals of large
    uploads into S3 errors, and sends presigned POST uploads to the
    gateway; see [docs/client-compatibility.md](docs/client-compatibility.md).
  - A key asks for a level on each bucket, no more than its owner has when
    it's made. What it gets is that level limited by what its owner has
    *now*. When someone leaves a group, is disabled, or a grant is taken
    away, their keys shrink or stop in the same moment, and come back if
    the access does. The keys page marks a key that's limited this way.
  - **Keys expire.** Each new key lasts a lifetime its maker picks, up to
    the most an admin allows (admin page, Key lifetimes: by default 90
    days for keys made on the Access keys page, 12 hours for login keys,
    and 1 year at most). Past it, the key is revoked and deleted, within a
    minute. Its owner renews it (Edit) before then, keeping its ID and
    secret. Only admins make keys which never expire, or make a key so;
    keys made before expiry existed, and imported keys, never expire, and
    the admin's key list flags them. See `docs/design-expiring-keys.md`.
  - **`s3-portal login`** (`cmd/s3-portal`, for Linux, Windows and macOS)
    gets a login key from the command line: it shows a code, which its
    user approves in the portal in their browser (`/login/cli`), signed in
    as usual. The key reaches everything they can, following their access,
    for the login lifetime, and the command sets up an aws profile (by
    `credential_process`), an rclone remote and an mc alias named for the
    portal. Several portals live side by side, by name; the default one is
    the first logged in to, until `s3-portal default NAME`, or
    `S3_PORTAL`. `logout` revokes the key.
  - Bucket policy, ACL and bucket configuration actions are never granted,
    so a key can't widen its own access.
- **File browser:** each person also has a web account in the gateway,
  `web.<user>`, with their uid and gid. Every bucket's policy gives it what
  that person may do there, so the gateway confines the browser just as it
  does keys, and uploads are owned by the person on disk. Uploads and
  downloads stream through the portal, so files of any size work.
  Downloads are always served as attachments.
- **The directory.** With LDAP configured, the portal checks everyone who
  has logged in with LDAP every `DIRECTORY_POLL_INTERVAL` (default 5m), and
  once at startup. A person is disabled when:
  - they're missing from the directory;
  - they're out of `ALLOWED_GROUP_DN`;
  - their entry is locked or expired: glauth's `accountStatus: inactive`,
    389-ds's `nsAccountLock`, the password policy overlay's
    `pwdAccountLockedTime`, or a past `shadowExpire`;
  - they have uid or gid 0.

  Disabling someone ends all their sessions, and drops their keys and web
  account from every bucket policy. The keys still exist, but they reach
  nothing. Their own buckets stay, and so do group members' access to
  them. When the directory lists them again, everything comes back. Group
  membership and admin rights are refreshed by the same check, so they
  change without a new login.

  People who log in with OIDC can't be checked this way. Their groups are
  read at each login, and their sessions last at most 12 hours.
- **Sessions** are kept server-side, in the state file. The cookie holds
  only a signed session ID, so logging out, being disabled, or an admin's
  "Log out" end a session everywhere at once. Admin rights and groups come
  from the portal's current record of the person, not from when they
  logged in.
- **Admins** (members of `ADMIN_GROUP_DN`, or `OIDC_ADMIN_GROUP`) see
  everyone the portal knows, with their status and groups, every bucket with
  its owner and groups, and every key. They can:
  - check someone or everyone against the directory now;
  - log someone out;
  - revoke a key, a person's keys, or every key (typing "revoke all");
  - change any bucket's group grants, or delete it;
  - make a bucket for someone (Admin → Buckets → New bucket for someone),
    theirs as if they'd made it;
  - issue someone a key on their buckets, to load data in, as a migration
    would (Admin → Buckets → Issue a key to load data). It's the owner's
    key: what it writes is theirs on disk, it reaches no more than they
    can, and it's on their keys page, marked as issued by the admin, to
    revoke. rclone sync, aws s3 sync and mc mirror need read & write;
    write only takes aws s3 cp and rclone copy --no-check-dest to a path
    ending in `/`. With mc, set `AWS_REGION` to the gateway's region: with
    another, mc mirror copies nothing and still exits 0.

  Admins don't get to read anyone's files by being admins.
- **API.** For automation, such as a user-management job that disables
  someone and wants them cut off at once, rather than at the next poll:
  - `POST /api/directory/sync` checks everyone now and returns what changed;
  - `POST /api/users/<name>/check` checks one person now and returns their
    status;
  - `GET /api/users/<name>` returns their status as last recorded.

  And the admin page's "make a bucket for someone" and "issue a key to load
  data", for a migration loading data in for people:
  - `GET /api/users/<name>/directory` says whether the directory would let
    someone be registered (`allowed`, else the `reason`), recording nothing:
    for a migration's dry run.
  - `POST /api/users/<name>/register` records someone the directory has as
    their logging in would (its ids, groups and admin rights), so buckets and
    keys can be made for them before they've logged in. It's refused, and
    nothing is recorded, if the directory wouldn't let them log in: not in
    it, not in the users group, disabled, locked or expired. Someone already
    known is checked again instead.
  - `POST /api/buckets` with `{"owner": "alice", "name": "home-alice"}`
    makes the bucket theirs, as the admin page does, and answers
    `{"created": true}`. A bucket of that name already theirs answers
    `{"created": false}`; anyone else's is refused.
  - `POST /api/keys` with `{"owner": "alice", "label": "...",
    "buckets": {"home-alice": "readwrite"}}` issues them a key, as the admin
    page does, and answers with `access_key` and `secret_key`, given only
    then. The levels are `read`, `readwrite`, `createonly` and `writeonly`.
    With `access_key` and `secret_key` too, it imports a key from another S3
    server with that ID and secret, so its clients keep working, and answers
    `{"imported": true}` without the secret. An ID the gateway has already is
    refused, unless it's this key imported before, with the same owner and
    secret (`{"existing": true}`, unchanged). IDs are 3 to 128 letters,
    digits and `._@+=-`; secrets 8 to 128 printable characters.
    `"lifetime": "12h" | "30d" | "2w" | "never"` sets how long a key lasts:
    by default the Access keys page's default, or never for an imported
    key. The answer has `expires`, absent for a key that never expires.
  - `DELETE /api/keys/<access key>` revokes it. A key already gone counts as
    revoked.

  Keys issued with the token are recorded as issued by `api-token`; with an
  admin's session, by that admin.

  Calls need `Authorization: Bearer <token>`, or an admin's session
  with the CSRF token in `X-CSRF-Token`. The token is either:
  - one an admin issued on the admin page (**Admin → API tokens**), one per
    tool (a migrator): shown once, kept only as its hash, listed with who
    issued it and when it was last used, and revoked there. It acts as an
    admin while the admin who issued it is one (known, enabled, still in the
    admins' group), and its calls, and the keys it issues, are recorded as
    `api:NAME`. Tokens are issued only on the admin page, never over the API;
  - or the server's own, `API_TOKEN`, set where the portal is deployed,
    recorded as `api-token`.

  The API tokens page shows what a token can do, as curl. For example:

  ```sh
  curl -fsS -X POST -H "Authorization: Bearer $(cat /run/secrets/s3-api-token)" \
    https://s3.example.com/api/users/alice/check
  ```
- **ZFS** (optional, with `ZFS_HELPER_SOCKET`): every bucket is its own ZFS
  dataset, managed by `s3-zfs-helper`, a small unprivileged service on the
  host with ZFS rights delegated over the buckets only, and
  `s3-zfs-mounter`, which mounts for it without access to ZFS. The portal
  talks to the helper over a unix socket (see
  [docs/zfs-helper.md](docs/zfs-helper.md)).
  - A new bucket is made by the gateway as usual, then moved, still empty,
    into its own dataset with the gateway's metadata (owner, ACL, policy
    xattrs) carried over.
  - **Deleting** an empty bucket moves its dataset to a trash dataset
    instead of destroying it. The bucket disappears from S3 at once, but
    its snapshots survive, the host's own included. Admins see deleted
    buckets on the admin page, and can restore one (its data, snapshots
    and owner come back; group and key grants must be given again) or
    purge it for good.
  - **Quotas:** admins set each bucket's size limit (ZFS `refquota`, so
    snapshots don't count against it). New buckets get `ZFS_DEFAULT_QUOTA`.
  - **Backups:** admins mark buckets for the host's backups. That sets the
    ZFS user property `backupctl:include=on`, which the backup job reads.
  - **Snapshots:** a bucket's owner or an admin sets a schedule (hourly,
    daily or weekly, keeping the last N) and can take or delete snapshots
    by hand. New buckets get `ZFS_DEFAULT_SNAPSHOTS`. Anyone who can read a
    bucket can browse its snapshots and download from them. People with
    read & write can restore a file, a folder or everything, replacing
    what's there now (files added since are kept). The portal only touches
    its own snapshots, named `s3portal-…`.
- **Mirrors** (admins): copy a bucket on another S3 service, such as
  MinIO, into a bucket here.
  - **Passes:** they run hourly, daily or by hand. Each one copies new and
    changed objects with their metadata, deletes what the source deleted,
    and repairs copies that went missing. It records what it copied in a
    manifest, snapshots the bucket on ZFS, and writes a report.
  - **Read only:** while it mirrors, the bucket is read only for everyone,
    its owner included. So any difference from the source is either a
    change at the source or a failed copy.
  - **Moving over:**
    1. The admin stops writes to the source and freezes the mirror.
    2. A final pass copies the last changes.
    3. The source is listed again, to catch anything still writing.
    4. Every object is checked against the MD5 of what was copied, and
       against the source's own MD5 where it has one. A deep check reads
       back the objects that have no source MD5.
    5. Once that passes, the admin completes the move. The bucket opens to
       its users, and the source key is forgotten.
  - **What the page shows:** each step, who took it, and the evidence.
  - **What it doesn't do:** it never writes to the source, and nothing
    else is carried over (versions, tags, ACLs, policies, the source's
    keys).
  - **Server mirrors:** "Mirror a server" takes another S3 service's
    endpoint and a read-only key that may list every bucket
    (`s3:ListAllMyBuckets`), and lists its buckets. Admins tick which to
    mirror, and check each one's name and owner here: new buckets go to a
    default owner unless another is picked. A name already taken here by a
    bucket with things in it, or one that can't be a bucket name here, is
    left unticked, to be given another name; an empty bucket here of the name
    is used as it is. Each ticked bucket becomes a mirror of its own, as
    above. The server's page acts on them all at once: a pass of each,
    pause and resume, freeze (on the admin's word that the whole server has
    stopped taking writes), complete the verified ones, and replace the key.
    Passes asked for at once are queued, two running at a time. Listing the
    server again finds buckets made there since.
  - See `docs/design-bucket-mirror.md`.
- **Moving from MinIO:** `s3-portal-minio` (`cmd/s3-portal-minio`, run
  outside the portal) reads a MinIO server's users, service accounts and
  policies from its drive, secrets too, and plans their keys' owners and
  grants for an admin to review. It then imports them over the admin API
  with their IDs and secrets, so clients keep working, and checks the
  portal's server answers for MinIO's hostname with a trusted certificate,
  an imported key and MinIO's region, before and after DNS moves. See
  `docs/minio-keys.md`.
- **State:** `STATE_FILE` is a JSON file with each key's owner, name and
  grants, bucket group grants, everyone the portal knows, sessions, web
  account credentials, and mirrors, with their source keys until each
  move is complete. Key secrets live only in the gateway. Each mirror's
  manifest and pass reports are under `mirrors/<bucket>/` beside it.
- **Reconcile at startup:** the portal drops keys and web accounts the
  gateway no longer has, and grants and settings for buckets that are gone.
  Then it rewrites every bucket's policy.

### Gateway requirements

- Internal IAM (`--iam-dir`).
- Run with `--iam-cache-disable`. In versitygw 1.10.0, `IAMCache.CreateAccount`
  caches new accounts without their uid and gid, so for up to the 120 s cache
  TTL a new key's files are created as root.
- The posix backend with `--chuid --chgid` if files should be owned per user.
- The admin API (`--admin-port`) reachable from the portal, and nowhere it
  doesn't need to be.

## Configuration

| Variable | Meaning |
| --- | --- |
| `VGW_S3_ENDPOINT` | Gateway S3 API, e.g. `http://versitygw:7070` |
| `VGW_ADMIN_ENDPOINT` | Gateway admin API, e.g. `http://versitygw:7071` |
| `VGW_REGION` | Gateway region (default `us-east-1`) |
| `VGW_ROOT_ACCESS`, `VGW_ROOT_SECRET` | Gateway root credentials (or `*_FILE`) |
| `LDAP_URL` | e.g. `ldaps://ldap.example.com:636`, or several separated by spaces, tried in turn (as a domain's DCs: `ldaps://dc1.example.com ldaps://dc2.example.com`). Leave unset to turn off password login. |
| `LDAP_SERVER_NAME` | TLS server name, when the URL is an IP |
| `LDAP_CA_FILE` | CA bundle for the LDAP server (default: system roots) |
| `LDAP_BASE_DN` | Where users are searched for, e.g. `dc=example,dc=com` |
| `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD` | The search account (or `LDAP_BIND_PASSWORD_FILE`) |
| `ALLOWED_GROUP_DN` | Only users with this group in `memberOf` may log in (default: anyone in the directory) |
| `ADMIN_GROUP_DN` | Users with this group in `memberOf` are admins (default: nobody) |
| `LDAP_GROUP_FILTER` | Finds groups to suggest for grants (default `(objectClass=posixGroup)`, or `(objectClass=group)` for AD) |
| `LDAP_SCHEMA` | `posix` (default: glauth, OpenLDAP, 389-ds) or `ad` (Active Directory); see above |
| `LDAP_ID_RANGE_BASE` | With `ad`, an account without `uidNumber` is uid base+RID, gid base+primary group's RID, e.g. `200000` |
| `LDAP_DEFAULT_UID`, `LDAP_DEFAULT_GID` | With `ad`, the uid and gid of an account given no others (not 0) |
| `DIRECTORY_POLL_INTERVAL` | How often to check people against LDAP (default `5m`, at least `10s`) |
| `ZFS_HELPER_SOCKET` | The `s3-zfs-helper` socket, e.g. `/run/s3-zfs-helper/helper.sock`; turns on ZFS datasets per bucket |
| `ZFS_DEFAULT_QUOTA` | Size limit for new buckets, e.g. `500G` (default: none) |
| `ZFS_DEFAULT_SNAPSHOTS` | Snapshot schedule for new buckets, e.g. `daily:14` (default: none) |
| `API_TOKEN` | At least 32 characters; enables bearer-token calls to `/api/` (or `API_TOKEN_FILE`) |
| `OIDC_ISSUER` | The provider's issuer URL. Leave unset to turn off OIDC. |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | The portal's client at the provider (or `OIDC_CLIENT_SECRET_FILE`) |
| `OIDC_REDIRECT_URL` | `https://<portal host>/auth/callback`, as registered at the provider |
| `OIDC_NAME` | Shown as "Sign in with …" (default `single sign-on`) |
| `OIDC_SCOPES` | Space-separated (default `openid profile email`, plus `groups` when a group is set) |
| `OIDC_USERNAME_CLAIM` | Default `preferred_username`; `email` works too |
| `OIDC_GROUPS_CLAIM` | Default `groups` |
| `OIDC_ALLOWED_GROUP`, `OIDC_ADMIN_GROUP` | Group names as the provider sends them |
| `OIDC_UID_CLAIM`, `OIDC_GID_CLAIM` | Claims holding numeric uid and gid, if the provider has them |
| `OIDC_DEFAULT_UID`, `OIDC_DEFAULT_GID` | The uid and gid for everyone otherwise (not 0) |
| `SESSION_KEY` | At least 32 random characters for signing session cookies (or `SESSION_KEY_FILE`) |
| `STATE_FILE` | Where key records are kept. Its directory must be writable: mirrors keep files there too |
| `PUBLIC_S3_URL` | The S3 endpoint as users should configure it |
| `TITLE` | Shown in the header and as the page title (default: none in the header, and "S3" as the page title) |
| `LISTEN` | Listen address (default `:8080`) |
| `TRUSTED_PROXIES` | Addresses or prefixes, comma-separated, of the TLS proxy in front. Logs take the client's address from `X-Forwarded-For` on requests from them (default: none, so logs show the proxy) |
| `INSECURE_COOKIES` | Set to drop the cookie `Secure` flag, for testing over plain HTTP |

Run it behind a TLS-terminating proxy, which should set
`X-Forwarded-For`, and put its address in `TRUSTED_PROXIES` so logins are
logged with the client's address. The header is read only on requests
from those addresses, from the right, stopping at the first address that
isn't one of them, so a client can't put words in it. To serve the portal and the S3 API on
one host name, have the proxy send requests that carry an S3 signature (an
`Authorization` header starting `AWS`, or `X-Amz-Signature`/`Signature` in the
query string) to the gateway, and the rest to the portal: browsers never sign
requests, and S3 clients always do. For uploads of any size, don't limit or
buffer request bodies on the way to the portal either.

On a shared host name, the proxy **must** add
`Content-Security-Policy: sandbox; default-src 'none'` and
`X-Content-Type-Options: nosniff` to every response from the gateway. The
gateway serves objects with whatever content type the uploader chose.
Without those headers, an HTML file opened from a presigned link runs as the
portal's origin and can act as whoever opened it. Separate host names for
the portal and the S3 API avoid the problem entirely.

Mount the gateway's bucket root somewhere that people on the host can't
reach (for example a `0700` root-owned directory). The gateway runs as root
and follows symlinks when reading, so someone who can write into their own
bucket directory on the host could otherwise read any file the gateway can,
including its IAM file of secrets.

## Deploying

[deploy/](deploy/README.md) describes a whole install: the three
containers, the two host services, and every file, directory, secret,
user, dataset and grant, with its owner and mode, and the order to set
them up.

## The web UI

Pages are plain server-rendered HTML and work without JavaScript. With it,
`static/app.js` loads links and forms in place and swaps the page body,
prefetching a page while the pointer rests on its link. So moving around,
creating buckets and deleting files don't reload the page, and back and
forward keep their place. Uploads take a file or folder picker, or drag and
drop, three files at a time. A page that follows something running (a mirror's pass) keeps
itself up to date without reloading: only its live parts (`data-live`) are fetched again and
replaced, and one the user is in (focused, a menu open, a field changed) waits until they've
left it, so their place, sort, filter, open menus and what they've typed stay as they left them
(without the script, it reloads every 10 seconds). Static files are served under a content hash
and cached for good. The gateway's bucket list is cached for 5 seconds and
dropped whenever the portal creates or deletes a bucket. Grant checks always
ask the gateway.

## Building and testing

Dependencies are vendored, so `podman build .` needs no network access beyond
the base images.

```sh
go test ./...
```

`TestLDAPAuthIntegration` drives a real LDAP server when the `LDAP_TEST_*`
variables described in `ldap_integration_test.go` are set, and
`TestADIntegration` an AD domain controller (or Samba's) with the
`AD_TEST_*` variables described in `ad_integration_test.go`: nested groups,
a disabled account, and IDs mapped from SIDs.

`TestZFSAgainstGateway` runs the real `s3-zfs-helper` over its socket with
a fake `zfs` whose datasets are directories in the gateway's root, so it
needs `VGW_TEST_DATA` too.

The gateway integration tests drive a real gateway when `VGW_TEST_S3`,
`VGW_TEST_ADMIN`, `VGW_TEST_ACCESS` and `VGW_TEST_SECRET` are set. With
`VGW_TEST_DATA` naming the gateway's posix root as the tests see it, they also
check that uploads are owned by the uploader and, if they can write there,
that the gateway follows symlinks planted in a bucket directory.
`TestPermissionsAgainstGateway` pins down what keys, web accounts and
anonymous callers can and can't do, as observed on the gateway: run it after
any gateway upgrade.
The mirror tests use other buckets on the same gateway as sources. With
`MIRROR_TEST_S3`, `MIRROR_TEST_ACCESS` and `MIRROR_TEST_SECRET` pointing
at another S3 service, such as a MinIO server, one also mirrors from that.

```sh
podman run -d --name vgw -p 7070:7070 -p 7071:7071 \
  -e ROOT_ACCESS_KEY_ID=rootkey -e ROOT_SECRET_ACCESS_KEY=rootsecret12345678 \
  docker.io/versity/versitygw:v1.10.0 \
  --port :7070 --admin-port :7071 --iam-dir /tmp --iam-cache-disable posix --chuid --chgid /tmp
VGW_TEST_S3=http://127.0.0.1:7070 VGW_TEST_ADMIN=http://127.0.0.1:7071 \
VGW_TEST_ACCESS=rootkey VGW_TEST_SECRET=rootsecret12345678 go test ./...
```

## License

MIT; see [LICENSE](LICENSE). The vendored dependencies in `vendor/` keep
their own licenses.
