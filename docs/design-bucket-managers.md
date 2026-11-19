# Design: buckets managed by groups, and transferring buckets

Status: built. `TestBucketManagersMock` renders its pages; `TestBucketManagersAgainstGateway`
drives it on a gateway.

A bucket belongs to one person: its owner, who alone (with admins) manages
it. A team's bucket is stuck when its owner leaves: its members keep their
access, but nobody but an admin can change it. This adds two things:

1. **Manager groups**: a group may manage a bucket, as its owner does.
2. **Transfers**: an admin gives a bucket to another person.

Group ownership proper (a bucket's files owned on disk by a group's own uid
and gid) isn't part of this.

## Manager groups

- **A new level for groups: Manages.** It's read & write in the bucket, and
  managing it as its owner does:
  - who has access: groups' levels, managing groups included;
  - its Access keys section: seeing every key reaching it, and stopping one
    reaching it;
  - storage and backups: its quota, snapshot schedule, backup flag, and
    restoring from snapshots;
  - deleting it, when it's empty.

  Only admins transfer it. The owner stays the owner: managers can't take
  away the owner's read & write, which comes from owning it, not a grant.
- **Keys**: members make keys up to read & write. Managing is never a key's:
  a key only reads and writes.
- **Shown** under "Shared with you", as "manages", with the Settings button
  the owner has. The bucket's settings say which groups manage it.
- **Group access forms** offer Manages above Read & write, for the owner,
  admins and managers.
- **Stored** as the group's level, `manage`, in the bucket's group grants.
  Its access is read & write's; only group grants take it.

## Transfers

- **Admins transfer a bucket** to someone the portal knows and who isn't
  disabled (admin page, Buckets, a bucket's actions: Transfer). It's the
  gateway's `change-bucket-owner`, to the new owner's account.
- **What changes**, as the form says before it's done:
  - the new owner has read & write and manages it, and it's listed as
    theirs;
  - the old owner keeps only what their groups give them; their keys
    reaching it are limited the same way, at once;
  - group grants, managing groups, keys, quota, snapshots and backups
    stay as they are;
  - files already there keep their owners on disk (whoever uploaded each);
    new ones are their uploaders', as always.
- **Finding buckets to transfer**: the admin page's People section marks a
  disabled person who owns buckets ("owns 3 buckets"), linking to them. A
  person's own buckets are listed by owner (Buckets, filtered).
- **The API**: `POST /api/buckets/{bucket}/owner` with `{"owner": "bob"}`,
  for automation (a migration, or someone leaving).
