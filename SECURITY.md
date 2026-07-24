# Security policy

## Security boundary

MaddyWeb is not a public Web application. The only supported Web listener is
`127.0.0.1:8787`, and the only supported privileged entry point is
`/run/maddyweb/helper.sock`. Remote operators connect through SSH local forwarding after verifying the host key;
the administration interface must not be exposed through a public listener, reverse proxy, or Docker port publishing.

The systemd units demote the Web process to the `maddyweb` user and deny it access to the Docker socket,
while allowing only loopback networking. Socket activation starts the root helper through a
`0660 root:maddyweb` socket, and the protocol uses strict length, field, and operation allow-lists. The helper
does not accept arbitrary commands, paths, container names, or shell text.

The installer generates a managed systemd path drop-in from validated configuration. The Web service's `PrivateTmp` provides
writable `/tmp` and `/var/tmp` mounts that are isolated from the host and cleaned when the service stops. When `server.temp_dir` is outside those
private mounts, the drop-in grants write access only to that exact directory. The native helper receives only read access to Maddy
configuration and write access to the data directory and the parent of each certificate deployment target. Only explicit
`webroot_roots` configuration grants the helper additional write access to the Certbot configuration root and those exact webroots,
supporting atomic updates to `archive`, `live`, and `renewal` and HTTP-01 challenges. The Docker
helper does not receive Docker socket permission, and the Web process still explicitly cannot see the Docker socket.

## Credentials and secrets

- Do not put Maddy passwords, session keys, API tokens, or private keys in CLI arguments, environment files,
  issues, CI logs, or shell history.
- The Web session key is always read from `/var/lib/maddyweb/session.key`. The installer
  atomically creates 48 random bytes as `0600 maddyweb:maddyweb`; existing files are not overwritten,
  but their type, owner, mode, and minimum length are revalidated.
- Maddy passwords travel from the UI to the local helper and enter the Maddy subprocess through stdin. Logs and
  audit records contain only the operation category and result, never passwords or message bodies.
- Private keys may be read only from allow-listed Certbot live paths in the configuration and cannot be exported through the API,
  uploaded, revoked, deleted, or issued arbitrarily.
- `/etc/maddyweb/maddyweb.env` may contain only non-secret configuration; by default it contains only the configuration file path.

During installation, `/etc/maddyweb` must be `root:maddyweb 0750`, and existing `config.toml` and
`maddyweb.env` files must be single-link, non-symlink `root:maddyweb 0640` files. The helper
does not read an EnvironmentFile. Both the Web and helper interpreters use `-I` isolated mode, preventing
`PYTHONPATH`, the user site, and the current directory from injecting modules into the root helper.

If a session key, SSH key, or Maddy credential may have leaked, first isolate the host and revoke the affected credentials,
then rotate them during a controlled outage window. Do not copy secrets into vulnerability reports.

## Production change authorization

`install.sh`, `backup.sh`, `rollback.sh`, and the Submission configuration workflow print only a
plan by default. Production `--apply` requires a one-time host-bound confirmation through `authorize-production.sh` in a real TTY.
The approval:

- Is root-owned, has mode `0600`, and resides in the dedicated `/run/maddyweb-approval` directory;
- Is bound to an action and the current `hostname`;
- Contains a random nonce and expires after ten minutes;
- Is deleted and consumed before any change occurs; retrying after failure requires new human confirmation.

An approval is not a password and cannot bypass interactive sudo authentication. The scripts reject a development
approval in production and reject reuse of an approval for another action.

The approval directory is always `root:root 0700` and must not share the helper socket parent.
`/run/maddyweb` always remains `root:maddyweb 0750`; otherwise an unprivileged Web process cannot connect to
`helper.sock`.

After validation at an external path, a release wheel is not passed directly to root pip. The installer
opens the single-link source with `O_NOFOLLOW`, copies it into root-owned 0700 staging, and recomputes SHA-256 through
the same descriptor. It verifies the copy again and installs only from that copy with
`pip --no-index --no-deps`. Dependencies are installed from `requirements.lock`, which contains complete SHA-256 hashes,
using `--require-hashes`.

Production paths used for deployment and systemd allow-lists must be normalized absolute POSIX paths;
path components cannot contain whitespace, control characters, or `%`, cannot use `.` or `..` traversal, and cannot
begin with `-`. Installation revalidates that the temporary-directory parent and native certificate-target parent already exist,
resolve canonically, and are real directories reached without symlinks. Units, the managed path drop-in,
the release symlink, and the Certbot hook belong to one installation transaction; rollback reads back old content and unit state,
and fails closed with `CRITICAL` and a nonzero status if it cannot restore them completely.

## Docker mode

Docker mode manages only an existing Maddy container; the MaddyWeb Web and helper processes remain native systemd
services. Before every SMTP send, the helper inspects the configured name
through only `unix:///var/run/docker.sock`, verifies running and paused state,
network scope, port metadata, and exact container and host listener tables,
then pins the returned full container ID. Only that validated ID may be used
for `docker --host=unix:///var/run/docker.sock exec -i <validated-id> /usr/bin/nc 127.0.0.1 1587`;
credentials are not sent if any check fails. It
never uses a Docker port publication. The container must provide the fixed
`/usr/bin/nc`, and operational checks reject every publication of container
port or host port `1587`.

`maddy.docker_submission_scope` is a closed, default-deny boundary. Its default value, `container`, rejects Docker
host networking and requires the listener to exist only in an isolated container network namespace. The explicit
`host-loopback` value is accepted only when Docker reports exact network mode `host`; it permits exactly one host
listener at IPv4 `127.0.0.1:1587`. Wildcard, IPv6, duplicate, and non-loopback listeners fail closed before or after
every change. This opt-in has the same trusted-local-user boundary as native Maddy mode: local processes can reach the
socket, but Maddy still requires the selected mailbox account's real SMTP credentials. Container network mode is
included in all transaction snapshots and rollback comparisons.

The Docker socket is equivalent to host root access, so only the root helper may access it; the Web
process explicitly cannot see it. Container name, image ID, mounts, port bindings, restart policy, and
network mode are verified before and after a change. Temporary backup containers have no network, drop capabilities,
use a read-only root filesystem, and mount the target `/data` read-only.

Managed Submission also supports a Docker local named volume, but does not accept a volume name, mount
path, or remote Docker context. Dry-run performs only fixed read-only reads inside the full container ID; the container is paused only
after approval consumption and acquisition of the transaction-wide flock. The write helper uses the existing immutable Maddy image
ID, no network, a read-only root filesystem, and minimal `DAC_OVERRIDE` and `CHOWN`; the target is always
`/data/maddy.conf`. Content hash, owner and mode, unique attachment, and container ID are read back before and after the operation;
if state cannot be classified as original or candidate, the container remains stopped and the situation is handled as an incident.

## Maddy and certificate security

Only the seven exact Maddy releases in the compatibility matrix are supported. Prereleases, development builds, unknown patch versions,
and CLI help fingerprint changes disable write capability. Version `0.8.2` does not support `verify-config` and must never receive that
invocation; listener changes require an explicit short restart through `--allow-downtime`. Maddy
`0.9.0+` uses `verify-config` and SIGUSR2 reload; LDAP writes are enabled only on
`0.9.3+`.

For `0.8.2`-`0.9.2`, every Maddy write reparses the effective configuration. `auth.ldap`,
`table.ldap`, LDAP in a composite provider, `import`, line continuation, and dynamic macros outside a validated
identity or domain context all degrade Maddy functionality to read-only. Old Docker releases allow only the two official
identity environment assignments; any macro structure that can compose a hidden `{env:...}` is also read-only.

Certificate dry-run and renewal apply only to configured certificate names. The workflow may run `nginx -t` as a read-only check,
but never writes `/etc/nginx` or reloads or restarts Nginx. Every operation safely reparses the Certbot
renewal profile and permits only a root-owned `webroot` lineage that other users cannot write,
with `installer = none` and no configured hooks. The `nginx`, `standalone`, `manual`, and DNS authenticators
are rejected before any external command runs. Direct invocations explicitly use `/dev/null` as the CLI configuration and
specify `--no-directory-hooks`. Because Certbot still merges default configuration files, the system, configuration-root, and root
XDG `cli.ini` files must all be absent, or writes degrade to read-only. After an actual renewal, the helper
deploys the certificate itself and reads the Maddy certificate back. Certbot commands and ordinary Maddy
commands use separate timeouts. The example `certificates.command_timeout_seconds` is 300,
with an accepted range of 30..900 seconds.

A webroot is allowed only below `/var/www` or `/srv/www`; the path and its ancestors must be canonical and trusted,
and group and other users cannot write them. The managed helper drop-in adds
`ReadWritePaths` only for each exact root in `certificates.webroot_roots`, making an HTTP-01 challenge
visible to host Nginx without opening adjacent paths. The default `[]` grants no webroot write access, so certificate
writes fail closed. Renewal files use a strict section/key/value allow-list; unknown keys,
`allow_subset_of_names = True`, and an active `renew_before_expiry` all make the lineage read-only. Both the version recorded in the file and the
actual Certbot runtime probed before every write must be in the `1.0.0`-`5.7.0` range. Future patch, minor, and major
versions require another audit before write access is restored.

The Web interface does not re-enable an external Certbot timer. An external unit enumerates lineages outside the allow-list
and may inherit unknown drop-ins, environment, or hooks, so the fixed argv of a single operation cannot constrain it. Until a dedicated
managed renewal service exists, the Web interface permits only status inspection or timer disable; enable always fails
closed.

Only when `certificates.enabled = true` does the installer place a
Certbot deploy hook with a managed marker at `/etc/letsencrypt/renewal-hooks/deploy/maddyweb`;
the file must remain a single-link, non-symlink `root:root 0755` file. This
root hook uses fixed current-release Python with `-I` and fixed configuration; after clearing the inherited environment, it
passes only a fixed PATH and locale and the validated `RENEWED_LINEAGE`. The lineage must match both
a name in `certificates.names` and the exact safe `certificates.live_dir/<name>` path;
the hook then reuses the existing atomic deployment, Maddy reload, and post-deployment fingerprint read-back. It never initiates
renewal or issuance, never forces renewal, and never modifies or reloads Nginx. A hook failure exits nonzero; an
unmanaged file with the same name is never overwritten or deleted, and disabling certificate management removes only a file with the correct managed marker.
For another legitimate lineage under the same canonical `live_dir` that is outside the MaddyWeb allow-list, the global
directory hook is explicitly a successful no-op; malformed, escaping, or untrusted directory paths still fail closed.

## Data recovery limitations

The backup tool creates checksums and runtime metadata, but the rollback tool only switches the MaddyWeb release
symlink and never automatically downgrades Maddy or restores a Maddy database. A newer Maddy may perform an irreversible
schema migration, and automatic restoration across versions would amplify an incident. Data restoration must use an isolated copy and
the same Maddy version or image digest recorded in the backup, and must be performed manually after operator verification.

If SMTP disconnects after DATA, the outcome may be unknown. The client reports it as uncertain and prohibits
automatic retry to avoid duplicate mail.

Loopback is not an authentication boundary: other local processes on the same VPS may also connect to
`127.0.0.1:1587`. Managed Submission therefore reuses the real authentication from default Submission,
`auth &local_authdb`, and explicitly prohibits `auth dummy`. The selected account password entered in the send form
is used only for that SMTP AUTH attempt, passes briefly through a local socket and subprocess stdin, and is never persisted or
written to the audit log.

Likewise, `127.0.0.1:8787` prevents direct remote network access but does not distinguish an SSH tunnel from other
local clients on the VPS. Version 1 omits a Web login by explicit requirement. It is therefore supported only without untrusted
local users, untrusted containers that can reach host loopback, or tenants able to execute arbitrary local requests on a
single-tenant VPS. If the host does not
meet this trust boundary, do not deploy; first add independent authentication or use a Unix-socket administration entry point with peer credentials.
Host, Origin, and CSRF checks are browser-side defense in depth and must not be mistaken for
local-client authentication.

## Security scan gates

Security tests for MaddyWeb's production Python dependencies, source, secrets, configuration, and parsers are release
gates; high or critical findings cannot be bypassed by ignore rules or reduced severity. The official Maddy
binary or image is a separate upstream component. Scans and known findings for its exact digest continue to be recorded publicly, but under
the project's security scope they do not block a MaddyWeb release or deployment. See
[MaddyWeb security gates and Maddy upstream findings](docs/security-gates.md) for the scope boundary, CI behavior, and current scan findings. The Maddy version and CLI
capability fingerprint and functional compatibility matrix remain mandatory gates.

## Reporting vulnerabilities

Use a private security advisory provided by the code hosting platform, or a private channel designated by the maintainers,
and include the affected commit, Maddy and Python versions, a minimal reproduction, and an impact description. Do not include
production domain names, message content, configuration, identity data from logs, passwords, keys, or private keys in a public issue.
