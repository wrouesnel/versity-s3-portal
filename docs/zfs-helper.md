# s3-zfs-helper

`s3-zfs-helper` keeps each of the gateway's buckets in its own ZFS dataset
for s3-key-portal, so every bucket gets its own quota, backup flag and
snapshots. It runs on the host, beside the gateway, and serves a small JSON
API on a unix socket that only the portal can reach. It uses the host's own
`zfs` command.

It's two processes, so that the kernel, not the helper's own checks, keeps
it away from everything but the buckets:

- **s3-zfs-helper**, the manager, does all the work as its own
  unprivileged user (`s3zfs`). ZFS permissions over the buckets and the
  trash are delegated to that user with `zfs allow`, and it has only the
  file capabilities it needs to carry owners, modes and xattrs over
  (`CAP_CHOWN`, `CAP_FOWNER`, `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`).
  It can't destroy, rename, snapshot or change anything else in the pool,
  can't grant itself more, and can't set `mountpoint`, `exec`, `setuid` or
  `devices`.
- **s3-zfs-mounter** does its mounting. ZFS's only privilege check is
  `CAP_SYS_ADMIN`: a process holding it bypasses `zfs allow` and controls
  every pool, and mounting needs it. So the mounter has `CAP_SYS_ADMIN` and
  nothing else, and no access to `/dev/zfs`, so it can't run a single ZFS
  command. All it can do is mount `<parent>/<bucket>` on
  `<root>/<bucket>` or `<staging>/<bucket>`, paths it works out itself, and
  unmount it again.

## What it does

- **Adopt.** versitygw refuses to create a bucket over an existing
  directory, so the portal creates the bucket through the gateway first,
  then asks the helper to adopt it while it's still empty:
  1. check the bucket directory holds nothing but the gateway's `.sgwtmp`
     directory, itself holding only directories. Then save the directory's
     owner, mode, times and xattrs (where the gateway keeps the bucket's
     owner, ACL and policy) to the state directory, synced to disk;
  2. `zfs create -u -o canmount=noauto <parent>/<bucket>`: unmounted, and
     never mounted by the host behind our back. The mounter mounts it in
     `<staging>/<bucket>`; the helper checks the new root is really a
     separate mount and puts the saved metadata on it; the mounter unmounts
     it. Nothing in the buckets tree changes during this step;
  3. check the bucket directory again, remove the gateway's empty
     temporary directories (it makes them again when it needs them), and
     `rmdir` it;
  4. the mounter mounts the dataset at `<root>/<bucket>`; the helper checks
     it's there, then sets `canmount=on`, so the host mounts it at boot at
     its inherited mountpoint, which is the same place;
  5. delete the saved metadata.

  The helper never sets a mountpoint (it isn't allowed to), so every bucket
  inherits `<root>/<bucket>` from the parent.

  If a step fails, whatever had been done is undone: the dataset is
  destroyed (including one that was created but failed to mount), and the
  directory is put back from the saved metadata. If the helper dies part
  way through, it finishes or undoes the adoption at its next start, from
  the saved metadata. A dataset that's mounted at its bucket is done;
  anything else is destroyed (it's new and empty) and the directory put
  back. Adopting a bucket that's already a mounted dataset does nothing, so
  it's safe to repeat. A dataset that exists but isn't mounted at its
  bucket is reported as a conflict, not treated as adopted.
- **Delete, to the trash.** Deleting a bucket doesn't destroy its dataset.
  Every dataset collects the host's weekly snapshots, and a destroy would
  take those with it. Only an empty bucket can be deleted: empty as the
  gateway means it, so nothing at the dataset's root but `.sgwtmp` (any
  uploads in progress there are abandoned with the bucket) and `.zfs`. An
  empty folder is a folder object and counts as content. The steps:
  1. set `readonly=on`, then check it's empty a final time, so nothing can
     be written in between (if it isn't empty, readonly is inherited again);
  2. the mounter unmounts it (first any of its snapshots ZFS mounted under
     `.zfs/snapshot`, which would hold it busy) and removes the directory,
     so the gateway no longer sees the bucket; then `zfs set canmount=off`;
  3. `zfs rename -u <parent>/<b> <trash>/<b>-<UTC yyyymmddThhmmssZ>`.

  If a step fails, the earlier ones are undone. The trashed dataset keeps
  all its snapshots, the host's included, and stays read-only and
  unmounted.
- **The trash.** Admins, through the portal, can list it, restore an
  entry, or purge one for good. A purge is `zfs destroy -r`, the host's
  snapshots included, by the admin's explicit choice. A restore is refused
  (`Exists`) while a bucket of that name exists, as a dataset or as a
  directory. Otherwise it renames the dataset back to `<parent>/<b>` (`rename -u`),
  inherits `readonly`, sets `canmount=noauto`, has the mounter mount it at
  its directory, checks it's there and sets `canmount=on`. If that fails it
  goes back to the trash as it was. The dataset's root still carries the
  gateway's xattrs (the bucket's owner, ACL and policy), so the gateway
  sees the bucket again as it was. Anything the portal keeps about the
  bucket elsewhere is the portal's to restore.
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
- `zfs set` of `readonly` or `canmount` makes the change but fails as the
  helper's user when libzfs then tries to remount the dataset, which it
  can't. So when it fails, the helper reads the property back and carries
  on if it's as asked. The kernel applies `readonly` to the live mount at
  once either way.

### The mounter

- It takes a place (`bucket` or `staging`) and a bucket name matching the
  pattern above, never a path or a dataset. The dataset is
  `<parent>/<bucket>`; the directory is `<root>/<bucket>` or
  `<staging>/<bucket>`. It never reads a dataset's mountpoint property.
- It reaches the directory from `/` one component at a time without
  following links, makes it if it's missing (0700), and mounts only over an
  empty directory that isn't already a mount, through its open fd
  (`/proc/self/fd/N`), so nothing can swap it in between. It refuses to
  mount a dataset that's mounted anywhere else, or anything on a directory
  something else is mounted on.
- It mounts with raw `mount(2)` (`mount.zfs` needs `/dev/zfs`), with
  `nosuid`, `nodev` and `noexec`, which a raw mount doesn't take from the
  dataset's properties, and data `zfsutil,mntpoint=<dir>`. Without
  `mntpoint`, ZFS can't automount snapshots under `.zfs/snapshot` for the
  sandboxed helper.
- It mounts at `<root>/` only while `<parent>` is mounted at `<root>`
  (checked in `/proc/self/mountinfo` each time), and in staging only while
  the staging directory is owned by root and 0700.
- It unmounts only `<parent>/<bucket>` from the place asked, after the
  bucket's snapshot automounts, with `UMOUNT_NOFOLLOW`, then removes the
  directory if it's empty. Busy gets `Busy` (409).
- If a mount fails, it removes the directory it made for it (one left in
  `<root>` would look like a bucket to the gateway). A dataset that doesn't
  exist gets `NotFound` (404).
- `GET /root` gives the device number of the filesystem at `<root>` as the
  host sees it (below).
- It answers only connections from root and `-allow-user` (default
  `s3zfs`), checked with `SO_PEERCRED`.

### On the host

- Make the helper's user, and delegate it exactly this:

  ```sh
  useradd --system --no-create-home --shell /usr/sbin/nologin s3zfs
  zfs allow -l -u s3zfs create,mount storage/s3/buckets
  zfs allow -l -u s3zfs create,mount storage/s3/trash
  zfs allow -d -u s3zfs destroy,rename,mount,snapshot,refquota,readonly,canmount,userprop storage/s3/buckets
  zfs allow -d -u s3zfs destroy,rename,mount,readonly,canmount storage/s3/trash
  ```

  `-l` on the parents lets it create children but do nothing to the
  parents themselves; `-d` gives it the rest on the children only. `mount`
  is needed for create, rename and destroy, but doesn't let it mount (that
  takes `CAP_SYS_ADMIN`). Never grant `mountpoint`: with it, the helper
  could point a bucket at `/etc`, and the host's boot-time `zfs mount -a`
  would mount it there as root.
- Set `setuid=off`, `devices=off` and `exec=off` on the parent dataset, so
  every bucket inherits them for its boot-time mount. The mounter passes
  them itself.
- Create the trash dataset (`-trash`, default `storage/s3/trash`) in the
  same pool as the parent, outside it, never mounted. The helper refuses
  to start if it's missing, in another pool, or inside (or containing) the
  parent.

  ```sh
  zfs set setuid=off devices=off exec=off storage/s3/buckets
  zfs create -o canmount=off -o mountpoint=none storage/s3/trash
  ```

- The staging directory (`-staging`, default `.s3-zfs-staging` beside
  `-root`) must be outside the buckets tree, owned by root and 0700: the
  mounter has no file capabilities, so it can only use the directory as
  its owner. The mounter makes it if it's missing and refuses to start
  otherwise. The helper reaches it through `CAP_DAC_READ_SEARCH`.
- The state directory (`-state-dir`, default `/var/lib/s3-zfs-helper`)
  must be owned by `s3zfs` and 0700 (`StateDirectory=` does this).
- Consider setting the zfs module parameter `zfs_snapshot_no_setuid=1`.
  ZFS mounts snapshots under `.zfs/snapshot` itself, with `suid` unless
  that's set, and never with `noexec` or `nodev`.
- Existing buckets adopted by an older helper have a local `mountpoint`
  equal to the inherited one. That's harmless and needs no change.

The portal's client is `ZFSHelper` in `zfsclient.go`.

## Building

```sh
CGO_ENABLED=0 go build -mod=vendor -trimpath -o s3-zfs-helper ./cmd/s3-zfs-helper
CGO_ENABLED=0 go build -mod=vendor -trimpath -o s3-zfs-mounter ./cmd/s3-zfs-mounter
```

or `podman build --target zfs-helper --output type=local,dest=out .` for both.

s3-zfs-helper's flags:
- `-parent`: default `storage/s3/buckets`;
- `-root`: default `/storage/s3/buckets`;
- `-trash`: default `storage/s3/trash`;
- `-staging`: must match the mounter's;
- `-state-dir`;
- `-mounter`: the mounter's socket, default `/run/s3-zfs-mounter/socket`;
- `-zfs`: default `/usr/sbin/zfs`;
- when not socket-activated, `-socket PATH`, with `-socket-group GID` to make it 0660 for that group.

s3-zfs-mounter's flags:
- `-parent`, `-root`: as above;
- `-staging`: default `/storage/s3/.s3-zfs-staging`;
- `-allow-user`: default `s3zfs`;
- when not socket-activated, `-socket PATH` (made 0600).

## Running it under systemd

Two socket-activated services. The mounter has no mount namespace: a
mount it makes in one would never reach the host or the gateway. The
helper never mounts, so it gets the full filesystem sandbox. Mounts the
mounter makes on the host propagate into the helper's namespace, and so
do the snapshot mounts ZFS makes under `.zfs/snapshot`.

**A stale namespace.** The helper's namespace pins the buckets' parent as
it was when the helper started. If the host remounts it later (a pool
export and import, `zfs mount -a`, a pool imported or unlocked after the
helper started), `<root>` inside the helper is the old, empty directory.
So before every request the helper compares the device of `<root>` as it
sees it with the mounter's `GET /root`. If they differ, it answers `Busy`
(503), finishes what's in flight and exits non-zero; the next request
starts it again, through its socket, with a fresh namespace.

After deploying, check once: adopt a test bucket, browse a snapshot of it,
then run `findmnt /storage/s3/buckets/<b>` on the host and in the
gateway's container (which needs `:rslave` on its bind mount); both should
show the dataset with `nosuid,nodev,noexec`.

Make a group for the helper's socket, and give the portal's container that
group (`--group-add s3-zfs`):

```sh
groupadd --system s3-zfs
```

`/etc/systemd/system/s3-zfs-mounter.socket`:

```ini
[Unit]
Description=s3-zfs-mounter socket

[Socket]
ListenStream=/run/s3-zfs-mounter/socket
# The socket's own mode and SO_PEERCRED do the access control.
DirectoryMode=0755
SocketUser=root
SocketGroup=s3zfs
SocketMode=0660
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
```

`/etc/systemd/system/s3-zfs-mounter.service`:

```ini
[Unit]
Description=s3-zfs-mounter: mounts S3 buckets' datasets for s3-zfs-helper
Requires=s3-zfs-mounter.socket
After=zfs-mount.service s3-zfs-mounter.socket

[Service]
ExecStart=/usr/local/sbin/s3-zfs-mounter -parent storage/s3/buckets -root /storage/s3/buckets -staging /storage/s3/.s3-zfs-staging -allow-user s3zfs
User=root
# Mounting, nothing else. No DAC capabilities: it uses only root-owned
# directories, as their owner.
CapabilityBoundingSet=CAP_SYS_ADMIN
AmbientCapabilities=
NoNewPrivileges=yes
# No devices at all, /dev/zfs above all: it can't run a ZFS command, and
# it can't make itself a /dev/zfs either.
DevicePolicy=closed
# No mount namespace (see above), so no ProtectSystem= and friends.
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service @mount
SystemCallErrorNumber=EPERM
UMask=0077
MemoryMax=128M
TasksMax=32
LimitNOFILE=1024
```

`/etc/systemd/system/s3-zfs-helper.socket`:

```ini
[Unit]
Description=s3-zfs-helper socket

[Socket]
ListenStream=/run/s3-zfs-helper/socket
# The socket's own mode does the access control. Bind-mount either the
# directory or the socket into the portal's container.
DirectoryMode=0755
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
Requires=s3-zfs-helper.socket s3-zfs-mounter.socket
After=zfs-mount.service s3-zfs-helper.socket s3-zfs-mounter.socket

[Service]
ExecStart=/usr/local/sbin/s3-zfs-helper -parent storage/s3/buckets -root /storage/s3/buckets -trash storage/s3/trash -staging /storage/s3/.s3-zfs-staging -state-dir /var/lib/s3-zfs-helper -mounter /run/s3-zfs-mounter/socket -zfs /usr/sbin/zfs
User=s3zfs
Group=s3zfs
StateDirectory=s3-zfs-helper
StateDirectoryMode=0700
# Owners, modes, times and xattrs on people's files: CHOWN, FOWNER.
# Reading and writing in people's directories: DAC_OVERRIDE,
# DAC_READ_SEARCH. No SYS_ADMIN: ZFS checks the zfs allow grants.
CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
DevicePolicy=closed
DeviceAllow=/dev/zfs rw
# With DAC_OVERRIDE it could write anywhere it can see; it sees only the
# buckets and staging as writable.
ProtectSystem=strict
ReadWritePaths=/storage/s3/buckets /storage/s3/.s3-zfs-staging
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service @chown @file-system
SystemCallErrorNumber=EPERM
UMask=0077
MemoryMax=512M
TasksMax=64
LimitNOFILE=4096
```

### Limits

- The `destroy` grant covers every snapshot of the buckets, the host's
  weekly ones included: ZFS treats snapshots as descendants. The helper
  only ever destroys `s3portal-*` snapshots and, when an admin purges a
  trash entry, everything in it. To make the host's snapshots safe from it
  anyway, the host's snapshot job can `zfs hold -r <tag>` them; the helper
  then can't destroy or release them, and purging a trash entry needs root
  to release the holds first.
- `zfs destroy -r <parent>` as the helper's user would destroy every
  bucket before being refused on the parent. It's allowed to destroy each
  bucket, so that's inherent.
- The mounter is still root with `CAP_SYS_ADMIN`. It can't touch ZFS, but
  a bug in it could mount over other paths. It's kept small, takes no
  paths, and its syscall filter allows only `@system-service` and `@mount`.
