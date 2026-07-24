# Authentication and Identity Operations

MaddyWeb uses one identity for both the Web application and Maddy: the
canonical full mailbox address. It does not create, verify, or store a second
Web password. Primary authentication always asks the local Maddy Submission
endpoint to verify the mailbox's current password, then requires a
Google Authenticator compatible second factor.

This document covers authentication lifecycle and secret handoff. Public
network policy and certificate installation are described separately in the
[Cloudflare public-edge runbook](public-edge.md).

## Identity and authorization model

- Every user and administrator is an enabled Maddy account with credentials
  and an IMAP mailbox.
- A normal mailbox can use only its own Mail, Compose, and Security
  workspace. The ordinary user API does not accept an account selector.
- An administrator is a real mailbox with a root-assigned `admin` role.
  There is no separate administrator login page or administrator password.
- Only root can assign or remove an administrator role. The Web interface
  cannot elevate an account.
- An administrator may select another mailbox for management, but the UI
  continuously identifies the selected target. Every send requires the
  current password of the selected sender mailbox, including an administrator
  sending as another mailbox.
- The helper derives the actor, role, and mailbox target from the opaque
  session. Browser-supplied actor names and email addresses are not trusted
  authorization claims.

Assign a role only after confirming that the target is an enabled Maddy
account:

```console
sudo /opt/maddyweb/current/bin/maddyweb auth-role \
  --config /etc/maddyweb/config.toml \
  --email administrator@example.net \
  --role admin
```

Changing a role revokes the mailbox's active sessions and pending login
challenges. Use `--role user` to remove administrator access.

## Login boundary

An unauthenticated browser can load only `/login`, the login page's local
static assets, and the narrow authentication flow. All application pages
redirect to `/login`; protected APIs and main application assets return 401.
The public Nginx edge returns 404 for `/healthz`, which remains available only
as an exact loopback health probe.

The sign-in sequence is:

1. Submit the full mailbox address and current Maddy password.
2. Maddy verifies the password through local SMTP AUTH. MaddyWeb does not
   persist it.
3. For an enrolled account, submit the current TOTP code or one unused
   recovery code.
4. For an unenrolled account, scan the locally generated QR code with Google
   Authenticator, submit one current code, and save the ten recovery codes
   before continuing.

Account existence, disabled credentials, a missing mailbox, and a wrong
password produce the same external credential error. Login limits apply to
the visitor address, mailbox, mailbox/address pair, and the whole service.
A password challenge lasts five minutes. Five failed second-factor attempts
invalidate it and require another mailbox-password check.

MaddyWeb implements [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) with a
160-bit Base32 secret, HMAC-SHA-1, six digits, and a 30-second period. It
accepts the immediately preceding or following period for clock skew, then
records the accepted counter so the same code cannot be replayed. The
`otpauth://` label and issuer follow the
[Google Authenticator key URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).
QR images are generated locally and never sent to a third-party QR service.

## Account lifecycle

### Account created in MaddyWeb

An administrator supplies the new mailbox password. After Maddy creates the
credentials and mailbox, the helper creates an active TOTP factor and ten
recovery codes in the same operation. The Web application displays the TOTP
secret, QR code, and recovery codes once. Save and deliver them through a
separate protected channel; they cannot be retrieved later.

If authentication metadata creation fails, MaddyWeb attempts to remove the
new Maddy account and reports whether rollback was verified. Do not manually
recreate an address after an uncertain result.

### Account created with the Maddy CLI

The first successful mailbox-password check synchronizes a missing metadata
record as a normal user and requires TOTP enrollment. The user cannot reach
mail or application pages until enrollment is confirmed and the recovery
codes have been acknowledged. A CLI-created mailbox never becomes an
administrator automatically.

### Existing accounts imported before public rollout

Use the offline bootstrap procedure below to give every existing account a
different active TOTP secret before enabling the public virtual host. The
bootstrap input must contain exactly one administrator record. A newly
created administrator record receives a random initial Maddy password and is
forced to change it on first login.

### Password, TOTP, and recovery changes

- A user password change verifies the current mailbox password, revokes all
  sessions and pending challenges, changes the Maddy password, and requires a
  fresh login.
- An administrator password reset marks the target for a mandatory password
  change and revokes its authentication state before changing Maddy.
- An administrator TOTP reset requires a fresh administrator step-up and
  returns the replacement factor and recovery codes once. Existing sessions,
  challenges, factors, and recovery codes are revoked.
- Recovery-code regeneration requires the mailbox password and a fresh TOTP
  value. It replaces all recovery codes, revokes sessions, and displays the
  new codes once.
- A recovery-code login consumes exactly one code and revokes every other
  session for that mailbox. Only keyed digests of recovery codes are stored.

## Session rules

The browser receives a random 256-bit opaque token only in a Secure,
HttpOnly, SameSite=Strict, path-rooted `__Host-` cookie. It is never written to
a URL, `localStorage`, or `sessionStorage`. Sessions have a 30-minute idle
limit, a 12-hour absolute limit, and a maximum of five active sessions per
mailbox. A newly issued session evicts the oldest excess session.

Administrator danger operations require mailbox password plus TOTP step-up;
that elevation lasts five minutes. Password changes, role changes, TOTP
changes, credential disable, mailbox deletion, and security recovery revoke
the affected authentication state. Logout is complete only after the helper
confirms server-side revocation; a helper failure does not falsely clear the
browser cookie.

TOTP seeds are encrypted with AES-256-GCM under a separate 32-byte root-only
master key. Authentication metadata, encrypted factors, recovery digests,
rate limits, challenges, and sessions live in
`/var/lib/maddyweb-auth/auth.sqlite3`. The directory is `root:root 0700`, and
`/var/lib/maddyweb-auth/master.key` is a root-owned single-link regular file
with mode `0600`. The Web process cannot read either file.

## Offline bootstrap and handoff

Run generation on a trusted Windows workstation from the exact reviewed
checkout. The account list supplied to the generator is non-secret metadata:
every existing enabled mailbox uses `create_account: false`, while the one
new administrator mailbox uses `role: "admin"` and
`create_account: true`. The generator requires exactly one administrator.
Use the production issuer configured for that server.

The following PowerShell example creates the output directly in a protected
directory outside the repository. Replace only the example host, issuer, and
mailbox addresses:

```powershell
$handoffDir = Join-Path $env:USERPROFILE "MaddyWeb-Private-Handoff"
$bootstrapPath = Join-Path $handoffDir "bootstrap-once.json"
$bundlePath = Join-Path $handoffDir "offline-credentials.html"

@'
{
  "server": "mail-server",
  "issuer": "MaddyWeb Example",
  "accounts": [
    {
      "email": "user@example.net",
      "role": "user",
      "create_account": false
    },
    {
      "email": "administrator@example.net",
      "role": "admin",
      "create_account": true
    }
  ]
}
'@ | uv run python scripts/generate-auth-bootstrap.py `
  --bootstrap-output $bootstrapPath `
  --bundle-output $bundlePath
```

The generator creates the directory when necessary, disables inherited ACLs,
and permits only the current Windows user and SYSTEM with FullControl. It
writes both outputs exclusively and prints only the account count and offline
bundle SHA-256. It never prints generated passwords, TOTP seeds, or recovery
codes.

Independently record both hashes and inspect the ACL before transport:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath $bootstrapPath, $bundlePath
Get-Acl -LiteralPath $handoffDir, $bootstrapPath, $bundlePath |
  Format-List Path, Owner, AreAccessRulesProtected, Access
```

Stop unless inheritance is disabled and the only access entries are the
current user and SYSTEM with FullControl. Do not put either output in the
repository, a synchronized folder, a general temporary directory, a ticket,
chat, clipboard manager, or shell transcript.

Use an existing SSH alias that has an independently verified host key and
logs in directly as root. The one-time manifest must travel from the
protected local file through SSH standard input directly to the root
`auth-bootstrap` process. Do not use `scp`, a remote temporary file, a command
argument, or an environment variable. If the alias does not execute the
remote command as root, stop; never put a sudo password in the same standard
input or automate it beside the manifest.

```powershell
$rootSshAlias = "mail-root"
Get-Content -LiteralPath $bootstrapPath -Raw |
  ssh -o BatchMode=yes `
      -o IdentitiesOnly=yes `
      -o NumberOfPasswordPrompts=0 `
      -o StrictHostKeyChecking=yes `
      -o ConnectTimeout=10 `
      -o ConnectionAttempts=1 `
      $rootSshAlias `
      "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /opt/maddyweb/current/bin/python -I -m maddyweb auth-bootstrap --config /etc/maddyweb/config.toml"
if ($LASTEXITCODE -ne 0) {
  throw "Authentication bootstrap failed; stop without retrying."
}
```

Batch mode prevents a password prompt from consuming the secret input. Stop
after one authentication failure and repair SSH separately; never retry the
secret pipeline automatically. The successful remote command prints only
record counts. It never writes the manifest or its secret values to stdout,
the journal, an audit record, or a remote file.

After the command reports `bootstrap=ok` and both reported counts match the
reviewed input, immediately delete the one-time manifest and verify that it is
gone:

```powershell
Remove-Item -LiteralPath $bootstrapPath -Force
if (Test-Path -LiteralPath $bootstrapPath) {
  throw "The one-time bootstrap manifest still exists."
}
```

Retain the offline HTML only in the protected directory or stronger offline
storage. Verify its recorded SHA-256 before opening it. It contains the
Google Authenticator QR and manual Base32 key, ten one-time recovery codes
for every account, and the initial password only for an account that the
bootstrap created. Never upload it to GitHub or a Web server.

## External Maddy CLI deletion invariant

Authentication metadata is keyed by canonical mailbox identity. If an
operator deletes a mailbox outside MaddyWeb with the Maddy CLI, the deletion
must be followed by a root metadata purge while the address is absent from
Maddy. Only then may the same address be recreated. A direct
delete-and-recreate shortcut is prohibited because old sessions or role
metadata could otherwise attach to the recreated mailbox.

After the external Maddy deletion has completed and both credentials and the
mailbox are absent, run:

```console
sudo /opt/maddyweb/current/bin/maddyweb auth-purge \
  --config /etc/maddyweb/config.toml \
  --email removed@example.net \
  --confirm-email removed@example.net
```

The command runs only as root and refuses to purge while Maddy still reports
the address. It removes the authentication record and its sessions,
challenges, TOTP factor, recovery codes, and account-linked rate state. Do not
recreate the address until `auth_purge=ok` is returned. Prefer the MaddyWeb
account deletion workflow, which coordinates mailbox and metadata removal.

## Secret-handling invariants

Mailbox passwords, TOTP codes and seeds, recovery codes, session tokens, CSRF
tokens, the authentication master key, and bootstrap material must never
appear in:

- command arguments or environment variables;
- shell history, CI output, application logs, journals, or audit fields;
- repository files, commits, issues, or pull requests;
- remote temporary files, `scp` transfers, or shared storage;
- message bodies or attachments used to deliver another factor.

The only approved bootstrap secret path is protected local output, SSH
standard input, root helper memory, and root-only authentication storage.
