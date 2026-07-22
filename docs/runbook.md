# Operations Runbook

This runbook assumes MaddyWeb is installed at `/opt/maddyweb/current` and production configuration is at
`/etc/maddyweb/config.toml`. Before any change, confirm the current host, Maddy mode and version,
backup status, and maintenance window. All scripts default to a dry run; never execute example placeholders unchanged.

## Status and diagnostics

```console
systemctl status maddyweb.service maddyweb-helper.socket maddyweb-helper.service
journalctl -u maddyweb.service -u maddyweb-helper.service --since today
ss -H -ltn 'sport = :8787'
curl --fail --silent --show-error http://127.0.0.1:8787/healthz
```

The normal Web listener must be exactly `127.0.0.1:8787`. The helper socket must be the Unix
socket `/run/maddyweb/helper.sock` with owner and mode `root:maddyweb 0660`.

Use these commands for strict verification:

```console
sudo /opt/maddyweb/current/bin/python scripts/smoke-test.py
sudo /opt/maddyweb/current/bin/python scripts/performance-test.py \
  --requests 200 --concurrency 8 --max-p95-ms 250
```

Do not treat HTTP 200 from health as sufficient security evidence by itself. Smoke also checks the listener, socket,
exact JSON schema, supported Maddy version, and write capability. Degraded health returns
HTTP 503; common causes are an unreachable helper, changed Maddy CLI fingerprint, or unsupported Maddy version.
By default, smoke waits up to 20 seconds for Web to complete helper preflight and establish the listener; helper socket
connection remains limited to 3 seconds. Cold health on a low-performance Docker host computes the full capability fingerprint with
a separate bounded 10-second HTTP timeout. `--startup-timeout-seconds` changes only the listener and warm-up
budget; `--health-timeout-seconds` changes only the strict health response budget. Both accept
0.1..30 seconds, and neither relaxes the helper socket connection timeout.

The two-second account-page index cache is never used for health, helper write authorization, or pre-send account checks.
The cache is bypassed during account writes. If the browser cancels a request, the helper call still invalidates it when complete.
After an uncertain transport result, the cache remains quarantined until a later account read succeeds.

`MALLOC_ARENA_MAX=1` and `MALLOC_TRIM_THRESHOLD_=65536` in the Web unit are fixed
low-memory allocator tuning, not secrets or operator overrides; do not move them to
`maddyweb.env`. After an upgrade, confirm them with `systemctl cat maddyweb.service`, then remeasure
RSS, PSS, and p95 on the target host.

Inspect units with `systemctl cat maddyweb.service maddyweb-helper.service`: the Web and helper
ExecStart entries must contain `python -I -m maddyweb`; the helper must not have `EnvironmentFile=`. Both
services must contain the managed `20-maddyweb-paths.conf`. The Web drop-in may grant only the configured
exact temporary directory outside private `/tmp` and `/var/tmp`; these `PrivateTmp` mounts are
writable but isolated from the host. A native helper may expose only configuration, data, and enabled certificate paths. The Docker
helper base unit must not expose `/etc/maddy` or `/var/lib/maddy`, and must contain no configuration-
derived host path or relaxed Docker socket access. Do not edit drop-ins manually.
After changing configuration, repeat the full dry run and approved installation. If `/etc/maddyweb`, `config.toml`, or
`maddyweb.env` violates the deployment contract for owner, mode, or link count, do not blindly bypass it with chmod.
First investigate a possible unauthorized replacement, then restore from trusted configuration.

`server.request_body_timeout_seconds = 15` is the total request-body read timeout, not an ordinary keepalive
timeout; the production validator accepts only 1..120 seconds. If large attachments repeatedly time out over local SSH, first
check the link and upload size; do not remove the limit or expand it beyond the accepted range.

## Configure the management Submission endpoint

MaddyWeb requires a dedicated local Submission block for sending mail. The editor copies from a validated default
465 or 587 block its sender authorization, local routing, DKIM, and remote queue
rules, adds a marker, and changes only:

```text
submission tcp://127.0.0.1:1587
tls off
auth &local_authdb
all concurrency 2
```

The management listener reuses the real auth reference from default Submission (currently supported and required to be unique:
`&local_authdb`) and never falls back to dummy auth. The account password from the Web send form is used only for that
brief SMTP AUTH helper call and is never stored or logged. Existing 465 and 587 listeners are not modified.
The original configuration must be a single-link regular UTF-8 file
no larger than 4 MiB. Editing uses flock, TOCTOU and hash checks, a private backup, and metadata
preservation, fsync, and same-directory atomic replacement. Duplicate markers, an occupied port 1587, ambiguous default routing,
a symlink or hardlink, or unexpected content all fail closed.

### Native Maddy

Run a dry run first:

```console
HOST=$(hostname)
bash scripts/configure-submission.sh \
  --action add --environment production --host "$HOST" --mode native \
  --maddy-config /etc/maddy/maddy.conf \
  --maddy-binary /usr/bin/maddy \
  --python /opt/maddyweb/current/bin/python
```

After reviewing the output, obtain one-time approval for the matching action and reuse the same arguments:

```console
APPROVAL=$(sudo bash scripts/authorize-production.sh --action submission-add)
sudo bash scripts/configure-submission.sh <same reviewed arguments> \
  --approval-file "$APPROVAL" --apply
```

Apply on Maddy `0.8.2` also requires `--allow-downtime`; the tool performs a short restart.
On `0.9.0+`, it first runs `verify-config`, then sends SIGUSR2 and rechecks the PID, journal, and
`127.0.0.1:1587` listener. If any step fails, it restores the exact backup by candidate hash and
reloads again.

### Docker Maddy

Docker Maddy may mount `/data` from a host bind directory or local named volume.
In bind mode, the host configuration file must be the `maddy.conf` inside that directory, so
`--maddy-config` takes the host path:

```console
HOST=$(hostname)
bash scripts/configure-submission.sh \
  --action add --environment production --host "$HOST" --mode docker \
  --maddy-config /srv/maddy/data/maddy.conf \
  --docker-binary /usr/bin/docker --container maddy \
  --python /opt/maddyweb/current/bin/python
```

Then run:

```console
APPROVAL=$(sudo bash scripts/authorize-production.sh --action submission-add)
sudo bash scripts/configure-submission.sh <same reviewed arguments> \
  --approval-file "$APPROVAL" --apply
```

Named-volume mode does not accept a volume name or an internal daemon path such as `/var/lib/docker/volumes/...`.
The volume is derived only from the verified container's unique `/data` mount; the argument must be the exact
container contract path:

```console
bash scripts/configure-submission.sh \
  --action add --environment production --host "$(hostname)" --mode docker \
  --maddy-config /data/maddy.conf \
  --docker-binary /usr/bin/docker --container maddy \
  --python /opt/maddyweb/current/bin/python
```

The dry run executes only fixed, read-only commands against the verified full container ID:
`stat/readlink/sha256sum/cat`. Metadata and hashes must match before and after; it does not pause, invoke `docker run`,
or write the volume. After consuming approval, apply takes
a non-waiting root flock on `/run/lock/maddyweb-submission.lock`, then pauses the same full ID.
Atomic replacement uses a one-shot helper from that container's exact immutable image ID: no network,
read-only root filesystem, fixed script, only the target volume mounted, and only the capabilities needed to read `0600` files and preserve
the owner, `DAC_OVERRIDE` and `CHOWN`. The target is fixed at `/data/maddy.conf`; same-directory rename preserves
the original owner and mode. Special bits, group or world writability, symlinks, hardlinks, a shared volume,
or a non-local or non-default Docker daemon all fail closed.

If the helper receipt is lost or later verification or reload fails, the tool rereads the hash while paused or stopped.
A candidate hash is restored to original, an original hash is treated as never written, and an unknown hash remains paused or stopped
while reporting `CRITICAL`; it never continues with unknown configuration. On `0.9.0+`, after unpausing the same full ID,
it runs `verify-config` and sends SIGUSR2 only after success. `0.8.2` requires `--allow-downtime` and a short restart.
Even if a bad candidate makes the container exit, it restores through that ID's stopped volume, starts it, and reads it back.

Again, `0.8.2` requires `--allow-downtime`. The tool prohibits every Docker publish rule for port 1587,
verifies unchanged container ID, mounts, ports, and restart policy, and after reload or restart
checks `/proc/net/tcp` inside the container before running the fixed
`docker exec maddy /usr/bin/nc -z -w 2 127.0.0.1 1587` reachability probe. Mail
data also enters container loopback through `docker exec -i ... /usr/bin/nc`; it never passes through a host
TCP listener.

To remove the block, change `--action add` and the approval action to `remove` and
`submission-remove`, respectively. Removal accepts only exact, unmodified managed-marker content; it does not delete
similar manual configuration.

### Enable Web for the first time

For a fresh installation, first run `install.sh --apply` without `--activate`. After completing the
Submission add above, enable the services:

```console
sudo systemctl enable --now maddyweb-helper.socket maddyweb.service
sudo systemctl try-restart maddyweb-helper.service
sudo /opt/maddyweb/current/bin/python scripts/smoke-test.py
```

During an upgrade, if managed Submission already exists and is healthy, apply installation with
`--activate`, then still run the smoke gate.

## Backups

### Native backup

```console
HOST=$(hostname)
bash scripts/backup.sh \
  --environment production --host "$HOST" --mode native \
  --app-config /etc/maddyweb/config.toml \
  --maddy-binary /usr/bin/maddy \
  --maddy-config /etc/maddy/maddy.conf \
  --maddy-state /var/lib/maddy
```

After review:

```console
APPROVAL=$(sudo bash scripts/authorize-production.sh --action backup)
sudo bash scripts/backup.sh <same reviewed arguments> \
  --approval-file "$APPROVAL" --apply
```

The tool temporarily stops Web and helper. If Maddy was active, it briefly stops Maddy, archives state,
copies Maddy and MaddyWeb configuration, records the version, and restores the previous active states. The output directory
defaults to `/var/backups/maddyweb`, mode `0700`; the archive and outer SHA-256 file are `0600`.
EXIT cleanup restores and reads back each original active or inactive state for Maddy, the helper socket, helper service, and Web.
Any start, unpause, or read-back failure reports `CRITICAL` and makes the entire
backup command return nonzero. A generated archive alone does not make such a run a successful operation.

### Docker backup

For Docker backup, `--maddy-config` is the fixed path inside the container, unlike the host path used when editing
Submission:

```console
bash scripts/backup.sh \
  --environment production --host "$(hostname)" --mode docker \
  --app-config /etc/maddyweb/config.toml \
  --maddy-config /data/maddy.conf \
  --docker-binary /usr/bin/docker --container maddy
```

Before the first installation, when the MaddyWeb units and `/opt/maddyweb/current` do not exist, use the reviewed staging
configuration and system CPython 3.14:

```console
bash scripts/backup.sh \
  --environment production --host "$(hostname)" --mode docker \
  --app-config /srv/maddyweb-release/config.docker.toml \
  --maddy-config /data/maddy.conf \
  --docker-binary /usr/bin/docker --container maddy \
  --python /usr/bin/python3.14
```

The tool distinguishes a missing systemd unit, a loaded but inactive unit, and an active unit. Before first installation,
missing MaddyWeb units are not passed to `systemctl start` or `systemctl stop` and are not falsely reported as recovery failures.
Only existing units that were originally active are stopped for the snapshot and restored to their original states.

Apply uses the same `backup` approval. The tool only pauses the existing container; it does not stop or rebuild it.
A one-shot container with no network, a read-only root filesystem, and no capabilities uses
`--volumes-from maddy:ro` to archive `/data`. The EXIT trap unpauses even after failure and removes
the temporary container and staging. It compares container, image digest, mounts, ports, and restart policy before and after.

Each archive contains:

- `maddy-state.tar` and its internal SHA-256;
- `maddy.conf` and its SHA-256;
- `maddyweb.toml` and its SHA-256;
- the Maddy version; Docker mode also includes fixed container, image, mount, and port metadata;
- `MANIFEST` and the archive's outer `.sha256`.

Copy the archive and `.sha256` to controlled storage in a different host failure domain, and periodically rehearse
recovery in an isolated environment.

## Application release rollback

Rollback switches only `/opt/maddyweb/current`; it does not downgrade Maddy or restore Maddy data.
First independently verify the commit and artifact SHA-256 in the target release's `INSTALL-MANIFEST`:

```console
HOST=$(hostname)
bash scripts/rollback.sh \
  --environment production --host "$HOST" \
  --release /opt/maddyweb/releases/<40-character-commit> \
  --artifact-sha256 <original-artifact-sha256>
```

After review:

```console
APPROVAL=$(sudo bash scripts/authorize-production.sh --action rollback)
sudo bash scripts/rollback.sh <same reviewed arguments> \
  --approval-file "$APPROVAL" --apply
```

The tool atomically switches the symlink, restarts Web and helper, and runs smoke; a failure restores the original release.
To also remove managed Submission under the same approval, explicitly add
`--remove-managed-submission` and the mode, configuration, and container options. `0.8.2` again requires
`--allow-downtime`.

The combined release-rollback-and-remove entry point accepts only native or Docker bind-mounted configuration.
For a Docker named volume, first use the separate `configure-submission.sh --action remove` transaction above
with `submission-remove` approval and verify it, then run release rollback separately.
Never pass an internal daemon volume path to the rollback command as though it were a host configuration path.

After a candidate release or smoke failure, the tool reports successful restoration only if the previous symlink, unit states, and release
smoke result all read back successfully, along with optional Submission configuration, reload, port 1587 listener, and Docker identity.
Any incomplete stage reports `CRITICAL` and exits nonzero. At that point,
stop further operations and handle it as an incident; do not infer recovery from the symlink appearance alone.

### Maddy data recovery is not rollback

Never automatically overwrite live state with `maddy-state.tar`, and never give new-schema data to
an older Maddy version. Recovery requires separate approval from the incident owner:

1. verify the archive's outer SHA-256 and every internal SHA-256;
2. read the recorded Maddy version and, for Docker, verify the image digest;
3. restore a copy on an isolated host or volume with exactly the same version;
4. verify configuration, accounts, mailboxes, messages, and service startup;
5. only consider production cutover after documenting an explicit outage window, ownership and modes, and a rollback copy.

This repository deliberately provides no destructive restore automation because Maddy data migrations may be irreversible.

## Certificate operations

The certificate page permits only names in `certificates.names`. Available operations are status,
timer enable or disable, Certbot renew dry run, and renew-only-when-due. There is no arbitrary issuance,
revocation, deletion, PEM upload, or private-key export.

The example configuration sets `certificates.command_timeout_seconds` to 300 seconds; the validator accepts
30..900 seconds. This is separate from `maddy.command_timeout_seconds = 15`, ensuring that a long Certbot
dry run is not ended early by an ordinary Maddy CLI timeout or Unix helper client.

The certificate flow runs read-only `nginx -t` checks before and after renewal, but never writes, reloads, or restarts
Nginx. After successful renewal it checks that source and deployed certificate fingerprints match, then
reloads Maddy. If the certificate is not due and its fingerprint is unchanged, it explicitly reports `not_due`; that is not a failure.

When `certificates.enabled = true`, the installer manages the Certbot deploy hook
`/etc/letsencrypt/renewal-hooks/deploy/maddyweb`. After Certbot renews a lineage,
the wrapper invokes the implementation from `/opt/maddyweb/current`; it requires `RENEWED_LINEAGE` to equal
`certificates.live_dir/<name>` exactly, and `<name>` must be in the `certificates.names` allowlist.
Only after validation does it reuse the same atomic deploy and rollback flow, reload Maddy, and read back that
source and deployed fingerprints match. The hook does not renew or issue certificates, force renewal, write Nginx configuration, or
reload Nginx.

After disabling `certificates.enabled`, another approved installation removes only a hook with the MaddyWeb managed
marker. A same-named unmanaged hook is never overwritten or removed in either state. Do not manually
replace the marker or disguise another script as a managed hook.

Diagnostics:

```console
systemctl status certbot-renew.timer
journalctl -u certbot.service -u certbot-renew.service --since today
journalctl -u maddyweb-helper.service --since today
sudo tail -n 200 /var/log/letsencrypt/letsencrypt.log
sudo -u maddyweb test -r /etc/maddyweb/config.toml
```

Do not delete a live symlink outside the UI or replace a private key to repair state. First restore a verifiable
Certbot lineage and permissions, then rerun the dry run. Deploy-hook failures in name, lineage, or directory permissions,
atomic deployment, Maddy reload, or fingerprint read-back exit nonzero. Find the first failure in the Certbot
log and journal; do not delete or bypass the hook just to make renewal appear successful.

## SSH forwarding failures

```console
ssh -vv -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes \
  -N -L 127.0.0.1:8787:127.0.0.1:8787 admin@mail.example.net
```

- On a host-key error, stop and verify through an independent channel. Do not delete `known_hosts` and accept blindly.
- `Address already in use` means local port 8787 is occupied on the workstation; close the old tunnel or select
  a different local port, such as `8877:127.0.0.1:8787`.
- On `connect failed`, run smoke and status locally on the server. Do not temporarily change the listener to
  `0.0.0.0:8787`.
- The browser Host must be `127.0.0.1` or `localhost`; otherwise the allowed-host check rejects it.

## Incident stop conditions

Stop further changes and retain the journal, manifest, and backup if any of the following occurs:

- the Maddy version or CLI fingerprint is unsupported;
- `verify-config`, reload, restart, or listener read-back fails;
- Docker identity, mounts, ports, image digest, or restart policy changes;
- the helper socket mode or owner is unexpected;
- health returns 503, the SMTP outcome is unknown, or logs contain a fatal or reload error;
- a backup checksum does not match;
- the approval host, action, or expiration does not match.

A disconnect after SMTP DATA has an unknown outcome. Do not retry automatically. First check the Maddy queue,
Sent mailbox, and recipient side to determine whether the message was accepted, preventing duplicate delivery.
