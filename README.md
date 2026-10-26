# s3-key-portal

A small web app that lets people log in with their LDAP password and issue
[versitygw](https://github.com/versity/versitygw) S3 access keys limited to
buckets they own.

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
- **State:** `STATE_FILE` is a JSON file recording each key's owner, name and
  bucket grants. The secrets live only in the gateway.
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
| `LDAP_URL` | e.g. `ldaps://ldap.example.com:636` |
| `LDAP_SERVER_NAME` | TLS server name, when the URL is an IP |
| `LDAP_CA_FILE` | CA bundle for the LDAP server (default: system roots) |
| `LDAP_BASE_DN` | Where users are searched for, e.g. `dc=example,dc=com` |
| `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD` | The search account (or `LDAP_BIND_PASSWORD_FILE`) |
| `ALLOWED_GROUP_DN` | Only users with this group in `memberOf` may log in (default: anyone in the directory) |
| `SESSION_KEY` | At least 32 random characters for signing session cookies (or `SESSION_KEY_FILE`) |
| `STATE_FILE` | Where key records are kept |
| `PUBLIC_S3_URL` | The S3 endpoint as users should configure it |
| `TITLE` | Page title (default `S3 access keys`) |
| `LISTEN` | Listen address (default `:8080`) |
| `INSECURE_COOKIES` | Set to drop the cookie `Secure` flag, for testing over plain HTTP |

Run it behind a TLS-terminating proxy.

## Building and testing

Dependencies are vendored, so `podman build .` needs no network access beyond
the base images.

```sh
go test ./...
```

`TestLDAPAuthIntegration` drives a real LDAP server when the `LDAP_TEST_*`
variables described in `ldap_integration_test.go` are set.

The gateway integration test drives a real gateway when `VGW_TEST_S3`,
`VGW_TEST_ADMIN`, `VGW_TEST_ACCESS` and `VGW_TEST_SECRET` are set:

```sh
podman run -d --name vgw -p 7070:7070 -p 7071:7071 \
  -e ROOT_ACCESS_KEY_ID=rootkey -e ROOT_SECRET_ACCESS_KEY=rootsecret12345678 \
  docker.io/versity/versitygw:v1.10.0 \
  --port :7070 --admin-port :7071 --iam-dir /tmp --iam-cache-disable posix --chuid --chgid /tmp
VGW_TEST_S3=http://127.0.0.1:7070 VGW_TEST_ADMIN=http://127.0.0.1:7071 \
VGW_TEST_ACCESS=rootkey VGW_TEST_SECRET=rootsecret12345678 go test ./...
```
