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
  1. read the bucket directory's owner, mode, times and xattrs (the gateway
     keeps the bucket's owner, ACL and policy in `user.*` xattrs);
  2. check it holds nothing but the gateway's `.sgwtmp` directory, itself
     holding only directories, and remove those (the gateway makes them
     again when it needs them);
  3. `rmdir` it, then `zfs create -o mountpoint=<root>/<bucket> <parent>/<bucket>`;
  4. put the owner, mode, times and xattrs back on the new dataset's root.

  If `zfs create` or step 4 fails, the dataset is destroyed and the
  directory put back as it was. Adopting a bucket that's already a dataset
  does nothing, so it's safe to repeat.
- **Destroy.** Only an empty bucket is destroyed: empty as the gateway
  means it, so nothing at the dataset's root but `.sgwtmp` (uploads in
  progress there are abandoned with the bucket) and `.zfs`. An empty folder
  is a folder object and counts as content. `zfs destroy -r` also removes
  the bucket's snapshots, the host's weekly ones included. Any mountpoint
  directory zfs leaves behind is removed, so the gateway no longer sees the
  bucket.
- **Quota.** The `refquota` property, so snapshots don't count against
  it. 0 removes it.
- **Backup flag.** `backupctl:include=on` when on. When off, the property
  is inherited, i.e. unset.
- **Snapshots.** Named `s3portal-<UTC yyyymmddThhmmssZ>[-<label>]`. The
  helper lists, browses, restores from and destroys only snapshots with
  that prefix. Other snapshots of the same datasets, such as the host's
  `weekly_<date>`, are invisible to it.
- **Browse and restore.** It reads snapshots through
  `<mountpoint>/.zfs/snapshot/<name>/`. Listings work like S3's (prefix,
  `/` delimiter, start-after, max-keys up to 1000); a directory carrying
  the gateway's `user.etag` xattr is listed as a folder object. A restore
  copies one object, everything under a folder, or the whole snapshot back
  over the live bucket. Each file is written to a temporary file beside its
  target, with the snapshot's owner, mode, times and xattrs (etag and
  content type among them), then renamed into place. Objects that exist
  only in the live bucket are left alone.

### Safety

- Bucket names must match `^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`, and
  snapshot names the pattern above, so it only ever touches direct
  children of `-parent`, mounted where `-root` says. It checks at startup
  that `-parent` is mounted at `-root`.
- Below a bucket's root, every path is opened one component at a time with
  `openat(O_NOFOLLOW)`. A symlink anywhere in a key is refused, whether in
  the snapshot or the live bucket, and nothing can be swapped for a link
  between a check and its use. Listings skip links and anything else that
  isn't a file or directory. Keys can't be absolute or contain `.`, `..` or
  empty components.
- Request bodies are limited to 64 KiB. Everything that changes a dataset
  or files is serialised and logged.

## API

All JSON. Errors are `{"error": "...", "code": "..."}`, where code is
`BadRequest` (400), `NotFound` (404), `NotDataset` (404: the bucket isn't
one of the helper's datasets), `NotEmpty` (409), `Conflict` (409) or
`Internal` (500).

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
| `POST /buckets/{b}/snapshots/{s}/restore` | `{"key"}`, `{"prefix": "folder/"}` or `{"all": true}` | `{"objects": n}` |
| `GET /healthz` | | `ok` |

The portal's client is `ZFSHelper` in `zfsclient.go`.

## Building

```sh
CGO_ENABLED=0 go build -mod=vendor -trimpath -o s3-zfs-helper ./cmd/s3-zfs-helper
```

Flags: `-parent` (default `storage/s3/buckets`), `-root` (default
`/storage/s3/buckets`), `-zfs` (default `/usr/sbin/zfs`), and, when not
socket-activated, `-socket PATH` with `-socket-group GID` (made 0660).

## Running it under systemd

**No mount namespace.** `zfs create` mounts the new dataset in the mount
namespace of whoever runs it. systemd's filesystem sandboxing
(`ProtectSystem=`, `ProtectHome=`, `ReadWritePaths=`, `PrivateTmp=`,
`PrivateDevices=`, `ProtectKernelTunables=`, `ProtectControlGroups=`,
`TemporaryFileSystem=`, `BindPaths=` and the like) gives the service its own
mount namespace. A dataset mounted there would be invisible to the host
and to the gateway, so the unit must not use any of those. It's hardened
instead with a capability bounding set, a device allow-list, a syscall
filter and no network.

Check this once on the host: adopt a test bucket, then confirm
`findmnt /storage/s3/buckets/<b>` on the host and in the gateway's container
(which needs `:rslave` on its bind mount) both show the dataset.

`/etc/systemd/system/s3-zfs-helper.socket`:

```ini
[Unit]
Description=s3-zfs-helper socket

[Socket]
ListenStream=/run/s3-zfs-helper.sock
SocketUser=root
# The portal's container runs as 65534. A dedicated group that the portal's
# container is given (--group-add) is tighter than nogroup, which other
# host processes may also run as.
SocketGroup=nogroup
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
ExecStart=/usr/local/sbin/s3-zfs-helper -parent storage/s3/buckets -root /storage/s3/buckets -zfs /usr/sbin/zfs
User=root
# mount/umount (zfs create, destroy): SYS_ADMIN. Setting owners, modes,
# times and xattrs on people's files: CHOWN, FOWNER, FSETID. Reading and
# writing in people's directories: DAC_OVERRIDE, DAC_READ_SEARCH.
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_CHOWN CAP_FOWNER CAP_FSETID CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH
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
```

If `zfs` turns out to need more than this bounding set on the host (zfs
2.4 normally does its work through `/dev/zfs` ioctls plus `mount(2)`),
the journal will show EPERM; add the missing capability rather than
dropping the bounding set.
