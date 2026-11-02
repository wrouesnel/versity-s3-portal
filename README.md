# s3-key-portal

A small web app that lets people log in with their LDAP password or an
OpenID Connect provider, make buckets on a [versitygw](https://github.com/versity/versitygw) gateway,
browse, upload and download their files, and issue S3 access keys limited to
buckets they own. Admins can see and revoke everyone's keys.

S3 signs every request with a secret the server must already hold, so S3
clients can't log in with an LDAP password. Instead people log in here, and
get long-lived keys for rclone, backups and apps, each limited to the buckets
they pick.

## How it works

- **Login:** search-then-bind.
  - A search account looks the user up with
    `(&(objectClass=posixAccount)(uid=<user>))`, plus a `memberOf` term when
    `ALLOWED_GROUP_DN` is set.
  - The portal then binds as the returned DN to check the password.
  - The user's uid and gid come from the entry's `uidNumber` and `gidNumber`.
  - Root (uid or gid 0) is always refused.
  - With glauth's PAM backend, the search account must be in its
    `groupWithSearchCapability` group, and group DNs look like
    `ou=<group>,ou=groups,<base DN>`.
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
- **Buckets:** each user has an owner account in the gateway, `owner.<user>`,
  that owns their buckets. Its secret is random and thrown away, so nobody can
  sign as it. The portal creates buckets through the admin API with that
  account as owner, and deletes them over S3 as root, but only when they're
  empty.
- **Access keys:**
  - Each key is a gateway account with the `user` role and the person's uid
    and gid. With the posix backend's `--chuid --chgid`, everything a key
    writes is owned by that person on disk.
  - A `user` account can't create buckets. It reaches buckets only through
    bucket policies, which the portal writes in full from its own records
    every time a key changes.
  - A key gets read-only or read & write access to each bucket. Bucket
    policy, ACL and bucket configuration actions are never granted, so a key
    can't widen its own access.
- **File browser:** each user also has a web account in the gateway,
  `web.<user>`, with their uid and gid. The portal creates it the first time
  it's needed and gives it read & write in each of the user's bucket
  policies, then browses, uploads, downloads and deletes as that account, so
  uploads are owned by the user on disk and the gateway confines the account
  to their buckets as well. Uploads and downloads stream through the portal,
  so files of any size work; downloads are always served as attachments.
- **Admins:** members of `ADMIN_GROUP_DN` get an admin page listing every key,
  where they can revoke any key, all of one person's keys, or every key at
  once (typing "revoke all" to confirm). Revoking keys leaves buckets, files
  and the file browser alone. Membership is read at login.
- **State:** `STATE_FILE` is a JSON file recording each key's owner, name and
  bucket grants, and each web account's credentials. Key secrets live only in
  the gateway.
- **Reconcile at startup:** the portal drops keys the gateway no longer has
  and grants on buckets the owner no longer owns. Then it rewrites the policy
  of every bucket owned by an `owner.*` account.

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
| `LDAP_URL` | e.g. `ldaps://ldap.example.com:636`. Leave unset to turn off password login. |
| `LDAP_SERVER_NAME` | TLS server name, when the URL is an IP |
| `LDAP_CA_FILE` | CA bundle for the LDAP server (default: system roots) |
| `LDAP_BASE_DN` | Where users are searched for, e.g. `dc=example,dc=com` |
| `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD` | The search account (or `LDAP_BIND_PASSWORD_FILE`) |
| `ALLOWED_GROUP_DN` | Only users with this group in `memberOf` may log in (default: anyone in the directory) |
| `ADMIN_GROUP_DN` | Users with this group in `memberOf` are admins (default: nobody) |
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
| `STATE_FILE` | Where key records are kept |
| `PUBLIC_S3_URL` | The S3 endpoint as users should configure it |
| `TITLE` | Page title (default `S3 access keys`) |
| `LISTEN` | Listen address (default `:8080`) |
| `INSECURE_COOKIES` | Set to drop the cookie `Secure` flag, for testing over plain HTTP |

Run it behind a TLS-terminating proxy. To serve the portal and the S3 API on
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

## The web UI

Pages are plain server-rendered HTML and work without JavaScript. With it,
`static/app.js` loads links and forms in place and swaps the page body,
prefetching a page while the pointer rests on its link. So moving around,
creating buckets and deleting files don't reload the page, and back and
forward keep their place. Uploads take a file or folder picker, or drag and
drop, three files at a time. Static files are served under a content hash
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
variables described in `ldap_integration_test.go` are set.

The gateway integration tests drive a real gateway when `VGW_TEST_S3`,
`VGW_TEST_ADMIN`, `VGW_TEST_ACCESS` and `VGW_TEST_SECRET` are set. With
`VGW_TEST_DATA` naming the gateway's posix root as the tests see it, they also
check that uploads are owned by the uploader and, if they can write there,
that the gateway follows symlinks planted in a bucket directory.
`TestPermissionsAgainstGateway` pins down what keys, web accounts and
anonymous callers can and can't do, as observed on the gateway: run it after
any gateway upgrade.

```sh
podman run -d --name vgw -p 7070:7070 -p 7071:7071 \
  -e ROOT_ACCESS_KEY_ID=rootkey -e ROOT_SECRET_ACCESS_KEY=rootsecret12345678 \
  docker.io/versity/versitygw:v1.10.0 \
  --port :7070 --admin-port :7071 --iam-dir /tmp --iam-cache-disable posix --chuid --chgid /tmp
VGW_TEST_S3=http://127.0.0.1:7070 VGW_TEST_ADMIN=http://127.0.0.1:7071 \
VGW_TEST_ACCESS=rootkey VGW_TEST_SECRET=rootsecret12345678 go test ./...
```
