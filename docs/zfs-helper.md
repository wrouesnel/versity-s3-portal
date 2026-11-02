# s3-zfs-helper

`s3-zfs-helper` keeps each of the gateway's buckets in its own ZFS dataset
for s3-key-portal, so every bucket gets its own quota, backup flag and
snapshots. It runs as root on the host, beside the gateway, and serves a
small JSON API on a unix socket that only the portal can reach. It uses the
host's own `zfs` command.

## What it does

- **Adopt.** versitygw refuses to create a bucket over an existing
  directory, so the portal creates the bucket through the gateway first,
  then asks the helper to adopt it while it's still empty:
  1. check the bucket directory holds nothing but the gateway's `.sgwtmp`
     directory, itself holding only directories. Then save the directory's
     owner, mode, times and xattrs (where the gateway keeps the bucket's
     owner, ACL and policy) to the state directory, synced to disk;
  2. `zfs create -o mountpoint=<staging>/<bucket> <parent>/<bucket>`, check
     the new root is really a separate mount, and put the saved metadata
     on it. Nothing in the buckets tree changes during this step;
  3. check the bucket directory again, remove the gateway's empty
     temporary directories (it makes them again when it needs them), and
     `rmdir` it;
  4. `zfs set mountpoint=<root>/<bucket>`, which moves the finished dataset
     into its place, then check it's mounted there;
  5. delete the saved metadata.

  If a step fails, whatever had been done is undone: the dataset is
  destroyed (including one that was created but failed to mount), and the
  directory is put back from the saved metadata. If the helper dies part
  way through, it finishes or undoes the adoption at its next start, from
  the saved metadata. A dataset that's mounted at its bucket is done;
  anything else is destroyed (it's new and empty) and the directory put
  back. Adopting a bucket that's already a mounted dataset does nothing, so
  it's safe to repeat. A dataset that exists but isn't mounted at its
  bucket is reported as a conflict, not treated as adopted.
- **Destroy.** Only an empty bucket is destroyed: empty as the gateway
  means it, so nothing at the dataset's root but `.sgwtmp` (any uploads in
  progress there are abandoned with the bucket) and `.zfs`. An empty folder
  is a folder object and counts as content. The helper refuses
  (`HasHostSnapshots`) while the dataset has any snapshot that isn't the
  portal's, because `zfs destroy -r` would destroy the host's snapshots
  too. Those have to be removed on the host first. Before the final
  emptiness check, the dataset is set `readonly=on`, so nothing can be
  written between the check and the destroy. If the check fails, readonly
  is inherited again. Any mountpoint directory zfs leaves behind is
  removed, so the gateway no longer sees the bucket.
- **Quota.** The `refquota` property, so snapshots don't count against
  it. 0 removes it.
- **Backup flag.** `backupctl:include=on` when on. When off, the property
  is inherited, i.e. unset.
- **Snapshots.** Named `s3portal-<UTC yyyymmddThhmmssZ>[-<label>]`. The
  helper lists, browses, restores from and destroys only snapshots with
  that prefix. Other snapshots of the same datasets, such as the host's
  `weekly_<date>`, are invisible to it.
- **Browse and restore.** It reaches a snapshot from the bucket's open
  root, one component at a time (`.zfs`, `snapshot`, the name). Listings
  work like S3's (prefix, `/` delimiter, start-after, max-keys up to 1000);
  a directory carrying the gateway's `user.etag` xattr is listed as a
  folder object. A restore copies one object, everything under a folder,
  or the whole snapshot back over the live bucket. Each file is written to
  a temporary file beside its target, then renamed into place. It gets the
  snapshot's owner, its permission bits (masked to 0777, plus sticky on
  directories, so never setuid or setgid), its times, and its `user.*` and
  `system.posix_acl_*` xattrs (the gateway's etag and content type among
  them), but no other xattrs. Objects only in the live bucket are left
  alone. Paths too long to be object keys (over 1024 bytes) are skipped,
  logged and counted in the reply's `skipped`.

### Safety

- Bucket names must match `^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`, and
  snapshot names the pattern above, so it only ever touches direct
  children of `-parent`. A bucket's dataset must report `mounted=yes` at
  `<root>/<bucket>`, and its root must be a different filesystem (fsid and
  device) from `-root`, before the helper treats it as a dataset. It checks
  at startup that `-parent` is mounted at `-root`.
- Below a bucket's root, every path is opened one component at a time with
  `openat(O_NOFOLLOW)`. A symlink anywhere in a key is refused, whether in
  the snapshot or the live bucket, and nothing can be swapped for a link
  between a check and its use. A file is first opened with `O_PATH` and
  must be a regular file before it's opened for reading, so FIFOs and
  devices are never opened. Listings skip anything that isn't a file or
  directory. Keys can't be absolute or contain `.`, `..` or empty
  components.
- Bounds:
  - request bodies are limited to 64 KiB;
  - a directory may have at most 100,000 entries, read in batches;
  - a recursive listing or restore covers at most 200,000 objects;
  - at most 8 reads and 2 restores run at once, and further requests wait
    up to 10 s, then get `Busy` (503);
  - restores lock only their own bucket and stop between files when the
    request is cancelled;
  - every zfs command has a 10-minute limit.
- Every change is logged.

### On the host

- `-staging` (default `.s3-zfs-staging` beside `-root`) and `-state-dir`
  (default `/var/lib/s3-zfs-helper`) must be on the same host, outside the
  buckets tree, and only root may use them. The helper makes them `0700`
  and refuses to start if they're owned by someone else, are links, or if
  staging is inside `-root`.
- Set `setuid=off`, `devices=off` and `exec=off` on the parent dataset, so
  every bucket inherits them: nothing anyone uploads can run, or act as a
  device, on the host.

  ```sh
  zfs set setuid=off devices=off exec=off storage/s3/buckets
  ```

## API

All JSON. Errors are `{"error": "...", "code": "..."}`, where code is one of:

| Code | Status | Meaning |
| --- | --- | --- |
| `BadRequest` | 400 | |
| `NotFound` | 404 | |
| `NotDataset` | 404 | the bucket isn't one of the helper's datasets, or isn't mounted |
| `NotEmpty` | 409 | |
| `HasHostSnapshots` | 409 | |
| `Conflict` | 409 | |
| `Busy` | 503 | |
| `Internal` | 500 | |

| Request | Body | Reply |
| --- | --- | --- |
| `POST /buckets/{b}/adopt` | | 201 `{"dataset"}`, or 200 if it already was one |
| `GET /buckets/{b}` | | `{"dataset","used","referenced","refquota","available","usedbysnapshots","backup"}` |
| `DELETE /buckets/{b}` | | 204 |
| `PUT /buckets/{b}/quota` | `{"bytes": N}` | 204 |
| `PUT /buckets/{b}/backup` | `{"include": bool}` | 204 |
| `GET /buckets/{b}/snapshots` | | `[{"name","created","used"}]`, newest first |
| `POST /buckets/{b}/snapshots` | `{"label": "optional"}` | 201 `{"name","created"}` |
| `DELETE /buckets/{b}/snapshots/{s}` | | 204 |
| `GET /buckets/{b}/snapshots/{s}/list?prefix=&delimiter=/&start-after=&max-keys=` | | `{"objects":[{"key","size","modified"}],"prefixes":[],"nextStartAfter"}` |
| `GET /buckets/{b}/snapshots/{s}/object?key=` | | the file |
| `POST /buckets/{b}/snapshots/{s}/restore` | `{"key"}`, `{"prefix": "folder/"}` or `{"all": true}` | `{"objects": n, "skipped": n}` |
| `GET /healthz` | | `ok` |

The portal's client is `ZFSHelper` in `zfsclient.go`.

## Building

```sh
CGO_ENABLED=0 go build -mod=vendor -trimpath -o s3-zfs-helper ./cmd/s3-zfs-helper
```

Flags:
- `-parent`: default `storage/s3/buckets`;
- `-root`: default `/storage/s3/buckets`;
- `-staging`;
- `-state-dir`;
- `-zfs`: default `/usr/sbin/zfs`;
- when not socket-activated, `-socket PATH`, with `-socket-group GID` to make it 0660 for that group.

## Running it under systemd

**No mount namespace.** `zfs create` and `zfs set mountpoint=` mount the
dataset in the mount namespace of whoever runs them. Any of systemd's
filesystem sandboxing options puts the service in its own mount namespace,
and systemd's documentation says those options "disconnect propagation of
mounts from the unit's processes to the host". The options include
`ProtectSystem=`, `ProtectHome=`, `ReadWritePaths=`/`ReadOnlyPaths=`,
`PrivateTmp=`, `PrivateDevices=`, `PrivateMounts=`,
`ProtectKernelTunables=`, `ProtectControlGroups=`, `TemporaryFileSystem=`
and `BindPaths=`. `MountFlags=shared` doesn't help. Those options first
make the unit's mounts slave to the host, and `MountFlags=` only sets the
final mode within the unit's namespace: mounts made in it still don't
reach the host. A dataset mounted there would be invisible to the host and
to the gateway. So the unit uses hardening that doesn't create a mount
namespace: a capability bounding set, a device cgroup, a syscall filter,
resource limits, and no network.

Check this once on the host: adopt a test bucket, then run
`findmnt /storage/s3/buckets/<b>` on the host and in the gateway's container
(which needs `:rslave` on its bind mount); both should show the dataset.

Make a group for the socket, and give the portal's container that group
(`--group-add s3-zfs`):

```sh
groupadd --system s3-zfs
```

`/etc/systemd/system/s3-zfs-helper.socket`:

```ini
[Unit]
Description=s3-zfs-helper socket

[Socket]
ListenStream=/run/s3-zfs-helper.sock
SocketUser=root
SocketGroup=s3-zfs
SocketMode=0660
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
```

`/etc/systemd/system/s3-zfs-helper.service`:

```ini
[Unit]
Description=s3-zfs-helper: ZFS datasets for S3 buckets
Requires=s3-zfs-helper.socket
After=zfs-mount.service s3-zfs-helper.socket

[Service]
ExecStart=/usr/local/sbin/s3-zfs-helper -parent storage/s3/buckets -root /storage/s3/buckets -staging /storage/s3/.s3-zfs-staging -state-dir /var/lib/s3-zfs-helper -zfs /usr/sbin/zfs
User=root
# mount/umount (zfs create, set mountpoint, destroy): SYS_ADMIN. Setting
# owners, modes, times and xattrs on people's files: CHOWN, FOWNER.
# Reading and writing in people's directories: DAC_OVERRIDE,
# DAC_READ_SEARCH.
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH
AmbientCapabilities=
NoNewPrivileges=yes
# A device cgroup, not a namespace.
DevicePolicy=closed
DeviceAllow=/dev/zfs rw
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service @mount @chown @file-system
SystemCallErrorNumber=EPERM
UMask=0077
# Resource limits.
MemoryMax=512M
TasksMax=64
LimitNOFILE=4096
```

If `zfs` turns out to need more than this bounding set on the host (zfs
2.4 normally works through `/dev/zfs` ioctls plus `mount(2)`), the journal
will show EPERM; add the missing capability rather than dropping the
bounding set.
