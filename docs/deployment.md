# Deployment Guide

This document describes new MaddyWeb installations and upgrades. Run every command on the target Linux or WSL host;
paths must be absolute Linux paths. Complete a full rehearsal on a non-production host before proceeding to production.

## 1. Prerequisites

- Linux with systemd available; WSL must have systemd enabled.
- Exactly CPython 3.14. Both the standard build and free-threaded `3.14t` are supported, but
  the wheelhouse must provide ABI-compatible extension wheels such as `aiohttp` and `nh3`.
- Maddy must be an exact release of `0.8.2`, or `0.9.0` through `0.9.5`.
- `bash`, `systemctl`, `systemd-sysusers`, `systemd-tmpfiles`, `ss`,
  `tar`, and a SHA-256 utility. Docker mode also requires the Docker CLI at an absolute executable path.
- A wheel, release manifest, and complete offline wheelhouse produced by a trusted build environment;
  the repository-root `requirements.lock` must come from the same reviewed commit.
- An existing, recoverable Maddy backup; read the
  [compatibility matrix](compatibility.md) before upgrading.

The installer does not access the network, download Python, Maddy, images, or dependencies, or modify Nginx.

## 2. Select the Maddy mode

### Native mode

The Maddy binary, configuration, and state directory are all on the host filesystem. The example configuration is
`deploy/examples/config.native.toml`; typical paths are:

- binary: `/usr/bin/maddy`
- config: `/etc/maddy/maddy.conf`
- state: `/var/lib/maddy`

### Docker mode

Only Maddy runs in the existing container; the MaddyWeb Web process and helper remain installed under
`/opt/maddyweb/releases/<commit>` and managed by systemd. The container must meet these requirements:

- it has a fixed, safe name such as `maddy`;
- `/data` is the only writable state mount;
- `/data/maddy.conf` is valid configuration;
- an executable `/usr/bin/nc` always exists inside the container;
- port `1587` is not exposed with `-p` or `--publish`;
- when the operations script must edit Submission, `/data` is either a host bind directory or a local named volume
  referenced only by this Maddy container and without driver options. In named-volume mode,
  the configuration location is fixed at `/data/maddy.conf`; a volume name or internal Docker daemon
  path is not accepted as input.

The management Submission endpoint listens only on `127.0.0.1:1587` inside the container. The helper uses the fixed
`docker exec -i <container> /usr/bin/nc 127.0.0.1 1587` command to transport SMTP inside the container network
namespace. It does not depend on the container network mode and never maps the host port.

The Docker-mode example is `docker/config.toml`. It is not a Compose file and does not create,
replace, or upgrade the Maddy container.

## 3. Configuration

Copy the template for the selected mode and review every absolute path. After production installation, the main file is
`/etc/maddyweb/config.toml`, which must be `root:maddyweb 0640`; unknown tables or keys,
missing keys, non-loopback addresses, and out-of-range values are rejected.

The following network fields must remain in place:

```toml
[server]
listen = "127.0.0.1:8787"
allowed_hosts = ["127.0.0.1", "localhost"]
request_body_timeout_seconds = 15

[maddy]
helper_socket = "/run/maddyweb/helper.sock"
submission_host = "127.0.0.1"
submission_port = 1587
command_timeout_seconds = 15
```

`server.request_body_timeout_seconds` limits the time to read the complete HTTP request body, preventing slow or
stalled uploads from occupying scarce workers indefinitely; the production validator accepts 1..120 seconds, fixed at 15 in the template.

The production validator applies conservative syntax to every deployment path: it must be a normalized absolute Linux path,
must not be `/`, and no path component may contain whitespace, control characters, or `%`, or include `.` or `..`
traversal or begin with `-`. Do not rely on symlinks, repeated `/`, a trailing `/`, or shell or
systemd escaping to express these paths.

The parent of `server.temp_dir` must already exist as a real directory that resolves canonically without traversing a symlink.
If the leaf does not exist, the installer creates it as `maddyweb:maddyweb 0700`; if it exists, it must
match that type, owner, and mode exactly. When certificate management is enabled in native mode,
the parents of `deployed_cert_path` and `deployed_key_path` must also already exist and meet the same
real, canonical, no-symlink-traversal requirements; the installer does not guess or create the certificate target tree.

Certificate commands use a separate, longer timeout so an ordinary short Maddy CLI timeout cannot truncate a Certbot
dry run:

```toml
[certificates]
command_timeout_seconds = 300
```

The deployment validator accepts certificate timeouts from 30..900 seconds. When management is not needed, set
`enabled = false` and `names = []`. When enabled, `names` is the allowlist of the only operable certificate names;
never map arbitrary user input to file paths.

Validate independently first:

```console
python3.14 scripts/validate-config.py \
  --config /absolute/config.toml \
  --expected-maddy-mode native
```

For Docker mode, also add `--expected-container maddy`.

## 4. Read-only preflight

Native mode:

```console
bash scripts/preflight.sh \
  --mode native \
  --app-config /absolute/config.native.toml \
  --maddy-binary /usr/bin/maddy \
  --maddy-config /etc/maddy/maddy.conf \
  --maddy-state /var/lib/maddy \
  --python /usr/bin/python3.14
```

On WSL with systemd, replace `--mode native` with `--mode wsl`. Docker mode:

```console
bash scripts/preflight.sh \
  --mode container \
  --app-config /absolute/config.docker.toml \
  --container maddy \
  --docker-binary /usr/bin/docker \
  --maddy-config /data/maddy.conf \
  --python /usr/bin/python3.14
```

The read-only preflight checks the interpreter build and GIL state, exact Maddy version, CLI profile, configuration,
container state and network mode, and whether port 8787 has a non-loopback listener. For
`0.9.0+` it runs `verify-config`; for `0.8.2` it validates only the pinned help profile
and never calls the nonexistent `verify-config` command.

## 5. Release artifact

The production artifact manifest must be UTF-8 JSON containing exactly these four fields:

```json
{
  "format": "maddyweb-release-v1",
  "commit": "0123456789abcdef0123456789abcdef01234567",
  "artifact": "maddyweb-1.0.0-py3-none-any.whl",
  "sha256": "<64 lowercase hexadecimal characters>"
}
```

When generating a source archive from a Git commit, explicitly use a safe umask and build the wheel from the unpacked
archive. Do not package directly from a Windows or DrvFS working tree because it can conceal Git
executable bits or introduce a group-writable mode on Linux:

```console
git -c tar.umask=0022 archive --format=tar.gz \
  --prefix="maddyweb-$COMMIT/" -o "$SOURCE_ARCHIVE" "$COMMIT"
```

After unpacking, confirm that `scripts/*.sh` are `0755`, other source files are `0644`, and no file is
group- or other-writable. The CI deployment contract tests also verify that these operations scripts in the Git tree
are all mode `100755`.

`commit` must be a full, 40-character lowercase Git object ID; the artifact must be a single-link
regular file in the explicit wheelhouse, and its filename and SHA-256 must agree with the manifest and
`--sha256` argument. `requirements.lock` must also be a regular, non-symlink file;
it pins exact runtime dependency versions and the SHA-256 of every acceptable wheel or source distribution.

The wheelhouse must contain every transitive dependency wheel required by the lock. Installation first runs
`pip --no-index --find-links ... --only-binary=:all: --require-hashes -r requirements.lock`, then runs
`pip --no-index --no-deps` for the independently SHA-256-verified MaddyWeb wheel. Thus an unhashed
extra file in the wheelhouse is not selected; a missing wheel, version drift, or hash mismatch fails
without fetching from the network. The installed release retains a read-only copy named `REQUIREMENTS.lock` and
records its SHA-256 in `INSTALL-MANIFEST`.

Production apply does not pass the initially verified external wheel path directly to pip. After approval is consumed,
the installer creates root-owned `0700` staging and opens the single-link artifact with `O_NOFOLLOW`,
copying and computing SHA-256 through the same file descriptor. It verifies the copy again and runs
`pip --no-deps` only against that staged copy. This closes the window between verification and pip opening the original
path, preventing TOCTOU replacement.

Before transport to production, an independent trusted step must verify the commit, signature or provenance, and SHA-256. Do not
build dependencies ad hoc from a package index on the production host.

## 6. Install: dry run first

The following variables only shorten the examples; replace each path with its verified real value:

```console
HOST=$(hostname)
WHEELHOUSE=/srv/maddyweb-release/wheelhouse
WHEEL=$WHEELHOUSE/maddyweb-1.0.0-py3-none-any.whl
MANIFEST=/srv/maddyweb-release/release.json
SHA256=<artifact-sha256>
```

Native dry run:

```console
bash scripts/install.sh \
  --environment production --host "$HOST" \
  --artifact "$WHEEL" --artifact-manifest "$MANIFEST" --sha256 "$SHA256" \
  --wheelhouse "$WHEELHOUSE" \
  --maddy-mode native \
  --maddy-binary /usr/bin/maddy \
  --maddy-config /etc/maddy/maddy.conf \
  --maddy-state /var/lib/maddy \
  --config-template /absolute/config.native.toml \
  --python /usr/bin/python3.14
```

Docker dry run:

```console
bash scripts/install.sh \
  --environment production --host "$HOST" \
  --artifact "$WHEEL" --artifact-manifest "$MANIFEST" --sha256 "$SHA256" \
  --wheelhouse "$WHEELHOUSE" \
  --maddy-mode docker \
  --docker-binary /usr/bin/docker --container maddy \
  --maddy-config /data/maddy.conf \
  --config-template /absolute/config.docker.toml \
  --python /usr/bin/python3.14
```

Save and manually review the reported host, mode, container, commit, artifact, release
directory, and activation state. Without `--apply`, the command does not write the filesystem, systemd, or container.

## 7. One-time production authorization and apply

Generate install approval in the same real interactive terminal. The script invokes sudo and requires
the exact phrase `AUTHORIZE install ON <hostname>`:

```console
APPROVAL=$(sudo bash scripts/authorize-production.sh --action install)
```

Then add the same dry-run arguments unchanged:

```console
sudo bash scripts/install.sh <same reviewed arguments> \
  --approval-file "$APPROVAL" --apply
```

Do not create or copy an approval manually. It must be root-owned, mode `0600`, bound to the current host and
action, expire in ten minutes, and be consumed before any write. If apply fails, repeat the complete
dry run before obtaining a new approval.

Approval lives in the separate `/run/maddyweb-approval` directory (`root:root 0700`). Do not move it
back under the helper socket parent; `/run/maddyweb` must remain `root:maddyweb 0750`
so the Web user can connect to the socket.

The installer:

1. creates the `maddyweb` system user and runtime, state, and temporary directories;
2. atomically creates or strictly verifies the session key;
3. creates an offline virtual environment under `/opt/maddyweb/releases/<commit>`;
4. writes the release and install manifests;
5. installs the Web service, helper service, and socket unit;
6. atomically switches `/opt/maddyweb/current`;
7. with `--activate`, enables the helper socket and Web service and runs the strict smoke gate. If any unit
   installation, daemon reload, restart, or smoke step fails, it restores the previous release symlink,
   all three unit files, and their original enabled and active states. A failed fresh install stops and disables the new units.

The installer also generates these managed systemd path drop-ins from validated configuration:
`/etc/systemd/system/maddyweb.service.d/20-maddyweb-paths.conf` and
`/etc/systemd/system/maddyweb-helper.service.d/20-maddyweb-paths.conf`.
With `ProtectSystem=strict`, the Web service's managed path drop-in works with
`PrivateTmp`, which provides writable `/tmp` and `/var/tmp` mounts isolated from the host. Only a
`server.temp_dir` outside those private mounts receives exact write access. The native helper drop-in makes
`maddy.config_path` read-only,
`maddy.data_dir` writable, and the exact parents of deployed certificate and key files writable when enabled.
With an explicit webroot, configuration roots needed for Certbot's atomic `archive`, `live`, and `renewal` updates
also become writable. Configuration accepts only `/etc/letsencrypt`, or the dedicated
`/var/lib/maddyweb/certbot` and `/srv/maddyweb/certbot` namespaces. Docker and native
helpers grant optional write access only to exact roots explicitly listed in `certificates.webroot_roots`;
each must be under `/var/www` or `/srv/www`, and the empty default leaves certificate writes read-only. The Docker
helper derives no other host path from configuration and receives no Docker socket permission. The base helper unit
also does not expose
the native-only `/etc/maddy`
or `/var/lib/maddy`; only the managed native drop-in for the configured paths may grant access.

When `certificates.enabled = true`, the installer transactionally installs
`/etc/letsencrypt/renewal-hooks/deploy/maddyweb`, whose wrapper always calls the implementation in the current release.
`/etc/letsencrypt` must be canonical, not a symlink, root-owned, and not group- or other-writable.
The installer may create missing `renewal-hooks/deploy` parents with safe modes.
The hook must remain a single-link, non-symlink `root:root 0755` file. An existing same-named file may be
upgraded only with the MaddyWeb managed marker; an unmanaged file makes enabled installation fail without overwrite.
When certificate management is disabled, only a managed hook is removed; a same-named unmanaged file remains.

Web-initiated dry runs and renewals do not execute the directory hook, but use `/dev/null` as the explicit
Certbot CLI configuration and pass `--no-directory-hooks`. The automatically searched system
and root XDG `cli.ini` files must also be absent. The helper then reuses the same deployment and fingerprint read-back.
The renewal profile is revalidated before and after execution; only a safe profile that cannot modify Nginx is accepted:
a `webroot` lineage. Web can inspect or disable an external timer, but cannot re-enable it until a dedicated managed
renewal service exists, so it cannot execute out-of-allowlist lineages or inherit unit drop-ins.
Renewal files and the running Certbot are restricted to audited versions `1.0.0` through `5.7.0`; unknown keys or
later versions hide the dry-run and renew buttons, and the helper write interface independently rejects the operation.

Transaction recovery reads back every symlink and enabled or active state. Any recovery-stage failure reports
`CRITICAL`, preserves the root-only unit backup, and exits nonzero; it never describes partial recovery as success.
Previous units, managed drop-ins, the managed Certbot hook, and empty parent directories created during installation
are restored or removed exactly in the transaction. Do not manually modify these targets while installation is running.

An existing `/etc/maddyweb` is never silently re-permissioned and accepted. The installer requires that directory to be exactly
`root:maddyweb 0750`, and existing `config.toml` and `maddyweb.env` files to be
single-link, non-symlink `root:maddyweb 0640`; any mismatch stops installation. The helper unit
does not read an EnvironmentFile. Both Web and helper use `python -I -m maddyweb`, preventing
`PYTHONPATH`, the user site, or current directory from affecting root-helper imports.

The Web unit always contains `MALLOC_ARENA_MAX=1` and
`MALLOC_TRIM_THRESHOLD_=65536` to limit glibc allocator caching in the single-process, low-memory service.
The benchmark environment measured about 43.1 MiB RSS, 40.8 MiB PSS, and p95 4.7 ms
for 400 health requests at concurrency 8. Actual values vary with libc, Python, kernel, and workload; remeasure on the target host.
Both allocator settings are tested unit tuning and deliberately absent from optional `env.example`, preventing
accidental removal while an operator cleans the environment file.

For account indexes without APPENDLIMIT, Web uses a short, two-second process-local cache measured from read completion,
and coalesces simultaneous successful or failed page reads with a shared task. Every account write bumps
a generation and clears the cache before invocation and again when the helper call finishes. Even if the HTTP request is cancelled,
the background call completes invalidation. A stale read crossing a generation may neither refill nor return; an uncertain transport
result quarantines the cache until a later serialized account read succeeds. The health storage probe does not use the page cache.
The helper's pre-send account check and each write's version, configuration, and CLI fingerprint check never use it either.

A cold health check in Docker mode must probe the full Maddy CLI fingerprint, so its duration includes `docker exec` startup
cost. The smoke test therefore limits listener, helper socket, and health separately to 20, 3, and 10
seconds. The performance gate remains independent; do not substitute the health timeout budget for p95 acceptance.

The installer does not modify the management Submission block in Maddy configuration; that step needs separate approval. See the
[operations runbook](runbook.md). For a fresh install, omit `--activate`, configure and validate Submission,
then enable Web and helper. For an upgrade with a healthy Submission endpoint, add `--activate` after review
to apply. The installer never checks, edits, or reloads Nginx.

## 8. Verification and SSH

Run the strict smoke gate on the server:

```console
sudo /opt/maddyweb/current/bin/python scripts/smoke-test.py
sudo /opt/maddyweb/current/bin/python scripts/performance-test.py \
  --requests 200 --concurrency 8 --max-p95-ms 250
```

The smoke test verifies that the only listener is `127.0.0.1:8787`, and checks the helper socket type, mode, connectivity,
the exact health fields, and a supported Maddy version. The performance gate reads only the same loopback
health endpoint and reports p50, p95, p99, throughput, and error count.

Verify the host key from the administrator workstation before opening a tunnel:

```console
ssh -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes \
  -N -L 127.0.0.1:8787:127.0.0.1:8787 admin@mail.example.net
```

Open only `http://127.0.0.1:8787/` in the browser. The entry point disappears when SSH disconnects. Do not create
a public listener, Nginx proxy, or Docker publish rule as a persistent substitute.
