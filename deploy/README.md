# Deploying s3-key-portal

This directory describes a complete install on one host: what runs, where
every file goes, who owns it, and the order to set it up. `files/` holds
the reference files at the paths they're installed to, so
`files/etc/systemd/system/s3-zfs-helper.service` goes to
`/etc/systemd/system/s3-zfs-helper.service`.

## What runs

```
                 :80, :443
                     │
   ┌─ versitygw's network namespace ─────────────┐
   │  s3-tls (nginx)                              │
   │    signed requests ──▶ versitygw :7070       │   container
   │    everything else ──▶ s3-key-portal :8080 ──┼─▶ s3-key-portal
   │  versitygw :7070 S3, :7071 admin             │   (as nobody)
   └──────────────────────────────────────────────┘        │
            │ /data = /storage/s3/buckets (rslave)          │ /run/s3-zfs-helper/helper.sock
            │                                               ▼
            │                                   s3-zfs-helper (host, user s3zfs,
            │                                     zfs allow over the buckets)
            │                                               │ /run/s3-zfs-mounter/socket
            ▼                                               ▼
   storage/s3/buckets/<bucket> datasets  ◀── mounts ── s3-zfs-mounter (host, root,
   storage/s3/trash/<bucket>-<time>                      CAP_SYS_ADMIN only)
```

- **Containers** (Quadlet, rootful podman): `versitygw`, `s3-key-portal`
  and `s3-tls`, on a private network `s3` (10.89.40.0/24). Only 80 and 443
  are published. The gateway's admin API is reachable only from that
  network.
- **Host services** (systemd, socket-activated): `s3-zfs-helper` and
  `s3-zfs-mounter`. They're optional: without them every bucket is a
  plain directory and the portal has no quotas, snapshots, backup flag or
  trash (see "Without ZFS"). How they work is in
  [../docs/zfs-helper.md](../docs/zfs-helper.md).

## Names to change

The files use these. Change them consistently everywhere they appear.

| Name | Meaning |
| --- | --- |
| `/storage/s3` | The service's directory, on the same pool as the datasets |
| `storage/s3/buckets` | The buckets' parent dataset, mounted at `/storage/s3/buckets` |
| `storage/s3/trash` | Deleted buckets, in the same pool, outside the parent, never mounted |
| `10.89.40.0/24`, `.10`, `.11` | The `s3` network, the gateway's and the portal's addresses |
| `s3.example.com` | The public name, in `PUBLIC_S3_URL` and the certificate |
| `COMMIT` | The portal image's tag: the commit it was built from |
| `S3_ZFS_GID` | The host's `s3-zfs` group id |
| LDAP settings | In `s3-key-portal.container`; or OIDC instead (README's configuration table) |

## What goes where

### From `files/`

| Host path | Owner, mode | What |
| --- | --- | --- |
| `/etc/containers/systemd/s3.network` | root, 0644 | The private network |
| `/etc/containers/systemd/versitygw.container` | root, 0644 | The gateway |
| `/etc/containers/systemd/s3-key-portal.container` | root, 0644 | The portal |
| `/etc/containers/systemd/s3-tls.container` | root, 0644 | TLS, in the gateway's network namespace |
| `/etc/s3-tls/nginx.conf` | root, 0644 | nginx's main config |
| `/etc/s3-tls/site.conf` | root, 0644 | The routing: signed to the gateway, the rest to the portal, with a sandboxing CSP on everything from the gateway |
| `/etc/systemd/system/s3-zfs-mounter.socket` | root, 0644 | The mounter's socket, root:s3zfs 0660 |
| `/etc/systemd/system/s3-zfs-mounter.service` | root, 0644 | The mounter |
| `/etc/systemd/system/s3-zfs-helper.socket` | root, 0644 | The helper's socket, root:s3-zfs 0660 |
| `/etc/systemd/system/s3-zfs-helper.service` | root, 0644 | The helper |
| `/etc/tmpfiles.d/s3-zfs-mounter.conf` | root, 0644 | `/run/s3-zfs-mounter`, root:s3zfs 0750 |
| `/etc/tmpfiles.d/s3-zfs-helper.conf` | root, 0644 | `/run/s3-zfs-helper`, root:s3-zfs 0750 |

### Made on the host

| Path | Owner, mode | What |
| --- | --- | --- |
| `/storage/s3` | root, 0755 | The service's directory |
| `/storage/s3/buckets` | root, **0700** | The buckets' parent dataset's mount. Must stay root 0700: the gateway runs as root and follows symlinks, so anyone who could reach a bucket directory could plant one and read anything through it |
| `/storage/s3/buckets/<bucket>` | the bucket's owner | Each bucket's dataset, made by the helper and mounted by the mounter |
| `/storage/s3/.s3-zfs-staging` | root, **0700** | Where the helper sets up a new dataset before it goes in place. Must be root 0700, outside the buckets, on the same filesystem as them |
| `/storage/s3/iam` | root, 0700 | The gateway's accounts, secrets included |
| `/storage/s3/portal` | 65534, 0700 | The portal's state file |
| `/storage/s3/secrets` | root, 0700 | The secrets below |
| `/storage/s3/secrets/versitygw.env` | root, 0600 | `ROOT_ACCESS_KEY_ID`, `ROOT_SECRET_ACCESS_KEY` |
| `/storage/s3/secrets/s3-key-portal.env` | root, 0600 | `VGW_ROOT_ACCESS`, `VGW_ROOT_SECRET` (the same two), `SESSION_KEY`, `API_TOKEN`, and `LDAP_BIND_PASSWORD` or `OIDC_CLIENT_SECRET` |
| `/storage/s3/secrets/api-token` | root, 0600 | The API token alone, for automation such as a user-management job |
| `/etc/s3-tls/tls/fullchain.pem` | root, 0644 | The certificate for `s3.example.com`, with its chain |
| `/etc/s3-tls/tls/privkey.pem` | root, 0600 | Its key |
| `/usr/local/sbin/s3-zfs-helper` | root, 0755 | From the image's `zfs-helper` stage |
| `/usr/local/sbin/s3-zfs-mounter` | root, 0755 | Likewise |
| `/var/lib/s3-zfs-helper` | s3zfs, 0700 | The helper's state; systemd makes it (`StateDirectory=`) |

Secrets go in env files, never in `Environment=` lines: Quadlet puts those
on the `podman run` command line, which anyone on the host can read.

### Users, groups and ZFS

| What | Why |
| --- | --- |
| user and group `s3zfs` (system, no home, nologin) | The helper runs as it; the mounter's socket is its group's |
| group `s3-zfs` (system) | Who may use the helper's socket: the portal's container, through `--group-add` |
| `storage/s3/buckets` with `setuid=off devices=off exec=off xattr=sa` | Every bucket inherits them for its boot-time mount. `xattr=sa` keeps the gateway's metadata xattrs fast |
| `storage/s3/trash` with `canmount=off mountpoint=none` | Deleted buckets |
| `zfs allow` grants to `s3zfs` (below) | Exactly what the helper may do. Never `mountpoint` |

## Setting it up

Run as root, in this order.

1. **Users and groups.**

   ```sh
   groupadd --system s3zfs
   useradd --system --gid s3zfs --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin s3zfs
   groupadd --system s3-zfs
   getent group s3-zfs   # its gid is S3_ZFS_GID
   ```

2. **Datasets and grants.** Here `storage/s3` exists only as their parent
   and doesn't mount, so `/storage/s3` is a directory of the pool's root
   dataset.

   ```sh
   zfs create -o canmount=off storage/s3
   mkdir -p -m 0755 /storage/s3
   zfs create -o mountpoint=/storage/s3/buckets \
       -o setuid=off -o devices=off -o exec=off -o xattr=sa storage/s3/buckets
   chown root:root /storage/s3/buckets && chmod 0700 /storage/s3/buckets
   zfs create -o canmount=off -o mountpoint=none storage/s3/trash

   zfs allow -l -u s3zfs create,mount storage/s3/buckets
   zfs allow -l -u s3zfs create,mount storage/s3/trash
   zfs allow -d -u s3zfs destroy,rename,mount,snapshot,refquota,readonly,canmount,userprop storage/s3/buckets
   zfs allow -d -u s3zfs destroy,rename,mount,readonly,canmount storage/s3/trash
   ```

   If buckets already exist as directories in `/storage/s3/buckets`, stop
   the gateway, move them aside, create the dataset, and move them back
   into it. They stay plain directories inside the
   parent dataset, without quotas or snapshots of their own; only buckets
   made after this get datasets.

   Consider the module parameter `zfs_snapshot_no_setuid=1`
   (`/etc/modprobe.d/zfs.conf`, and
   `/sys/module/zfs/parameters/zfs_snapshot_no_setuid` until the next
   boot): ZFS mounts snapshots under `.zfs/snapshot` with `suid` unless
   it's set.

3. **Directories.**

   ```sh
   install -d -o root -g root -m 0700 /storage/s3/.s3-zfs-staging /storage/s3/iam /storage/s3/secrets
   install -d -o 65534 -g 65534 -m 0700 /storage/s3/portal
   install -d -o root -g root -m 0755 /etc/s3-tls /etc/s3-tls/tls
   ```

4. **Secrets.** Made once, never printed. `printf` is the shell's
   builtin, so the values don't appear on a command line.

   ```sh
   cd /storage/s3/secrets && umask 077
   for s in root-access root-secret session-key; do
       [ -e "$s" ] || head -c 30 /dev/urandom | base64 | tr -dc A-Za-z0-9 > "$s"
   done
   [ -e api-token ] || head -c 48 /dev/urandom | base64 | tr -dc A-Za-z0-9 > api-token
   printf 'ROOT_ACCESS_KEY_ID=%s\nROOT_SECRET_ACCESS_KEY=%s\n' \
       "$(cat root-access)" "$(cat root-secret)" > versitygw.env
   printf 'VGW_ROOT_ACCESS=%s\nVGW_ROOT_SECRET=%s\nSESSION_KEY=%s\nAPI_TOKEN=%s\n' \
       "$(cat root-access)" "$(cat root-secret)" "$(cat session-key)" "$(cat api-token)" > s3-key-portal.env
   ```

   Then add `LDAP_BIND_PASSWORD=<the search account's password>` (or
   `OIDC_CLIENT_SECRET=…`) to `s3-key-portal.env` with an editor, and put
   the certificate and key in `/etc/s3-tls/tls/`.

5. **Binaries and images.** From a checkout of this repository at the
   commit being deployed:

   ```sh
   podman build -t localhost/s3-key-portal:$(git rev-parse HEAD) .
   podman build --target zfs-helper --output type=local,dest=out .
   install -o root -g root -m 0755 out/s3-zfs-helper out/s3-zfs-mounter /usr/local/sbin/
   ```

   Pin every image by version (`versitygw:v1.10.0`, `nginx:1.31.8`), never
   `latest`.

6. **Files.** Copy `files/` into place, then set `COMMIT`, `S3_ZFS_GID`,
   the host name and the directory settings in `s3-key-portal.container`.

   ```sh
   cp -r files/etc/. /etc/
   systemd-tmpfiles --create /etc/tmpfiles.d/s3-zfs-mounter.conf /etc/tmpfiles.d/s3-zfs-helper.conf
   systemctl daemon-reload
   ```

7. **Start**, the mounter's socket first: the helper checks with it at
   startup.

   ```sh
   systemctl enable --now s3-zfs-mounter.socket
   systemctl enable --now s3-zfs-helper.socket
   systemctl start versitygw s3-tls s3-key-portal
   ```

   Quadlet services are enabled through their `[Install]` sections; they
   start at boot from then on.

## Checking it

- `curl -fsS https://s3.example.com/` gets the portal's login page, and
  `curl -s -H 'Authorization: AWS4-HMAC-SHA256 x' https://s3.example.com/`
  gets an S3 XML error from the gateway.
- `zfs allow storage/s3/buckets` and `zfs allow storage/s3/trash` show
  exactly the grants above.
- `systemctl status s3-zfs-helper` shows it running as `s3zfs`
  (socket activation starts it on the portal's first request), and
  `journalctl -u s3-zfs-mounter` shows it serving with `allow=s3zfs`.
- Log in, make a bucket, upload a file, take a snapshot and browse it.
  Then `findmnt /storage/s3/buckets/<bucket>` on the host and
  `findmnt -N "$(podman inspect -f '{{.State.Pid}}' versitygw)" /data/<bucket>`
  in the gateway's container should both show the dataset with
  `nosuid,nodev,noexec`.
- Delete the bucket, and restore it from Admin → Deleted buckets.

## Without ZFS

Skip the users, datasets, grants, staging directory, binaries and the
`s3-zfs-*` and `tmpfiles.d` files. Make `/storage/s3/buckets` an ordinary
root 0700 directory, and from `s3-key-portal.container` remove
`ZFS_HELPER_SOCKET`, the `--group-add` line, the `/run/s3-zfs-helper`
volume and `s3-zfs-helper.socket` from `Wants=` and `After=`.

## Upgrading

- **The portal:** build the new commit's image, change `COMMIT`,
  `systemctl daemon-reload && systemctl restart s3-key-portal`.
- **The helper and mounter:** install the new binaries, then
  `systemctl try-restart s3-zfs-mounter s3-zfs-helper`. Both are
  socket-activated, so a stopped one starts on the next request.
- **versitygw:** run `TestPermissionsAgainstGateway` (the repository's
  README) against the new version first. It pins down what keys and web
  accounts can and can't do.
