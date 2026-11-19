# Design: expiring keys, and `s3-portal login`

Status: built. `TestExpiringKeysMock` renders its pages; `TestLoginAgainstGateway` drives
the command, and aws, rclone and mc with what it sets up.

Keys made today never expire. They stop working only when revoked, or
while their owner can't use what they grant. This adds expiry to every new
key, and a command-line login that gives a short-lived key without anyone
copying secrets out of a web page.

## Expiry

- **Every key has an expiry, or never expires.** `Key.Expires` is nil for
  "never". Past its expiry, the portal deletes the key from the gateway and
  its state, within a minute: a reaper runs each minute, and at startup.
  The owner's Access keys page warns of a key expiring within 7 days (or
  within a tenth of its lifetime, for short ones).
- **Admins set three lifetimes** (admin page, Key lifetimes; kept in the
  portal's state):

  | | Default | |
  | --- | --- | --- |
  | Keys made on the Keys page | 90 days | preselected in the new key's form |
  | Login keys (`s3-portal login`) | 12 hours | unless `--lifetime` asks for another |
  | Maximum, for both | 365 days | no one but an admin asks for more |

  The defaults may not exceed the maximum. Lowering the maximum doesn't
  shorten keys already made: the list shows them, to revoke if need be.
- **People pick a lifetime** for a new key, from presets up to the maximum
  (1, 7, 30, 90, 180 and 365 days, and the maximum itself if it's not one).
  Renewing a key (Edit) sets a new expiry from now, up to the maximum. Its
  ID and secret stay the same, so nothing using it changes.
- **Admins may make a key that never expires**: for themselves, for someone
  else (Issue a key), by the API, or by renewing a key as never expiring.
  The key records who did (`Key.NeverBy`), and shows it. Only admins can
  remove a key's expiry.
- **Keys made before expiry existed keep working**, and never expire: shown
  as "never expires", which admins can filter for, and renew with an expiry.
  Imported keys (`POST /api/keys` with `access_key`) default to never, as
  the server they came from didn't expire them; other API keys to the Keys
  page's default. The API takes `"lifetime": "12h" | "30d" | "never"`.

## Login keys

`s3-portal login` gets a **login key**: it reaches every bucket its owner
can, at their level, as the file browser does, and follows their access
while it lasts: a bucket shared with them later is reached too, and one
taken away isn't. `--bucket NAME[=LEVEL]` (repeatable) limits it to some
buckets instead, as a key made on the Keys page would be. Login keys are on
the owner's Access keys page, marked as such and with the computer they
were made for (their name), to revoke.

## `s3-portal login`

```
s3-portal login [PORTAL] [--default] [--lifetime 12h] [--bucket NAME[=LEVEL]]... [--name NAME] [--no-browser]
s3-portal logout [PORTAL]
s3-portal default [NAME]           # show, or set, the default portal
s3-portal status
s3-portal credentials PORTAL        # for aws's credential_process
```

`PORTAL` is a portal's URL, or the name of one logged in to before. Each
portal is remembered by name: its URL's first label (`https://s3.example.internal`
is `s3`) unless `--name` gives another. Several portals live side by side, each
with its own key and its own profile in each tool.

**The default portal**, used when `PORTAL` is left out, is explicit, never
guessed:

1. `S3_PORTAL` in the environment, if set (a name or URL);
2. else `default` in `portals.json`: the first portal logged in to becomes it,
   and only `s3-portal default NAME` (or `login PORTAL --default`) changes it;
   logging in to another portal doesn't;
3. else, with no default, the command refuses, listing the portals known.

Every command run without `PORTAL` says which it used and why, on standard
error: `Using s3 (https://s3.example.internal): the default, from
~/.config/s3-portal/portals.json (s3-portal default NAME changes it)`, or
`... from S3_PORTAL`. `s3-portal status` marks the default.

### Signing in: approved in the browser

The command can't take a password or follow single sign-on itself, and
shouldn't: the portal already does both. So signing in is a device code,
approved in a browser where the person is signed in to the portal:

1. The command asks the portal to start (`POST /api/login/start`, with the
   computer's name, the lifetime and buckets asked for). The portal answers
   a code (`HXQM-4TRW`), a URL (`https://s3.example.internal/login/cli`),
   and a secret to poll with. Both expire in 10 minutes.
2. The command opens the URL with the code filled in (or, with
   `--no-browser` or no display, as on SSH, prints it, to open anywhere).
3. In the browser, the person signs in to the portal as usual (password or
   single sign-on), and sees what's asked: the computer, the address the
   request came from, the code, what the key would reach and for how long.
   They approve it, or deny it. Approving takes the code being shown in the
   terminal too, typed or confirmed, so a link sent by someone else can't
   sign them in on someone else's computer.
4. The command polls (`POST /api/login/poll`, every 2 seconds) and, once
   approved, gets the key: its ID and secret, expiry, the S3 endpoint and
   region, and a token to revoke it with at logout. Each code gives one key,
   once.

### What it sets up

- the system's configuration directory's `s3-portal` (`~/.config/s3-portal` on Linux,
  `%AppData%\s3-portal` on Windows, `~/Library/Application Support/s3-portal` on macOS;
  `S3_PORTAL_CONFIG` overrides it): `portals.json`
  (each portal's name and URL) and `<name>.json` (its key, mode 0600).
- **aws**: a profile named for the portal, in `~/.aws/config`, with
  `credential_process = s3-portal credentials <name>`, the endpoint, region
  and path-style addressing. The aws CLI and SDKs read the key from the
  command, with its expiry, so they ask again rather than use an expired key.
- **rclone**: a remote named for the portal, using that aws profile
  (`env_auth = true`, `profile = <name>`), so it follows logins too.
- **mc**: an alias named for the portal, with the key itself (mc has no
  credential process); each login updates it.
- mc signs for `AWS_REGION` if it's set, whatever its alias: login warns
  when that isn't the portal's region.
- `--no-aws`, `--no-rclone`, `--no-mc` leave a tool alone. Only the
  sections it made are ever changed, each marked as `s3-portal`'s.

When a key expires, `credentials` says to run `s3-portal login <name>`
again (on standard error) and fails, so tools say why they can't connect.
Logging in again before then replaces the key, revoking the old one.
`logout` revokes the key and removes it; `status` shows each portal, who
it's logged in as, and until when.

### Distribution

`s3-portal` is a Go binary with no dependencies, for Linux, Windows and
macOS (amd64 and arm64). sde-s3's transfer set carries them beside its
deployer. The portal's Access keys page says how to use it.

## Not in this design

- STS (temporary credentials with session tokens): versitygw doesn't have
  it. Login keys are ordinary keys with an expiry.
- Logging in with a password typed into the command: the device code works
  from any browser, and keeps passwords out of terminals and shell history.
