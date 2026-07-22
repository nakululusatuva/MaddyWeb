# Compatibility matrix

MaddyWeb uses an exact version allow-list and does not treat an unknown release inside a version range as safe.
Supported releases are `0.8.2`, `0.9.0`, `0.9.1`, `0.9.2`, `0.9.3`,
`0.9.4`, and `0.9.5`. Prereleases, development builds, `0.8.3`, future `0.9.x` releases, and `1.x`
releases fail closed until their digest, CLI profile, and real integration tests are added.

## Maddy feature differences

| Release | `verify-config` | Endpoint reload | LDAP write safety | Explicit CLI lifecycle | Deployment requirement |
| --- | --- | --- | --- | --- | --- |
| 0.8.2 | No; invocation prohibited | Short restart | No | No | Listener changes require `--allow-downtime` |
| 0.9.0 | Yes | SIGUSR2 | No | No | Verify PID, logs, and listeners after reload |
| 0.9.1 | Yes | SIGUSR2 | No | No | Same as above |
| 0.9.2 | Yes | SIGUSR2 | No | No | Same as above |
| 0.9.3 | Yes | SIGUSR2 | Yes | No | Same as above |
| 0.9.4 | Yes | SIGUSR2 | Yes | Yes | Same as above |
| 0.9.5 | Yes | SIGUSR2 | Yes | Yes | Same as above |

Support for `0.8.2`-`0.9.2` requires a static, decidable authentication configuration. The Web service reparses it before every write.
If it finds `auth.ldap`, `table.ldap`, an LDAP composite provider, `import`, a line continuation,
unclassified macro syntax, or a structure that can compose an environment placeholder, only diagnostics and independent certificate functionality remain.
Exact adapters cover the two official Docker assignments, `MADDY_HOSTNAME` and `MADDY_DOMAIN`, and validated domain uses;
other dynamic authentication configurations are not admitted by guesswork.

All seven releases provide account, credential, APPENDLIMIT, mailbox,
message, and certificate-file management capabilities verified against locked CLI profiles. TLS reload is a baseline capability, but endpoint changes on `0.8.2`
cannot rely on USR2, so the deployment tool explicitly uses the restart path.

### Special rules for 0.8.2

The `0.8.2` top-level CLI does not have `verify-config`. The old release can route an unknown command into an implicit
server run, so merely trying the subcommand to see whether it exists is unsafe. Code and scripts run only
`--help` and management-subcommand help, confirming these groups and action/option profiles:

- `creds`: list/create/remove/password
- `imap-acct`: list/create/remove/appendlimit
- `imap-mboxes`: list/create/remove/rename
- `imap-msgs`: add/flags/remove/copy/move/list/dump

If top-level help unexpectedly contains `verify-config`, omits a group, produces oversized output, or enters the legacy run error path,
write capability is disabled immediately.

### Derivation from default Submission

The management endpoint is not an independently guessed routing block. The editor requires exactly one supported default
Submission block on port 465 or 587 and copies its sender authorization, local routing,
DKIM, and remote queue rules, changing only the following:

- The listener becomes `tcp://127.0.0.1:1587`;
- `tls off`, because the connection remains on loopback within one host;
- The single `auth &local_authdb` is preserved exactly, so local processes must still complete real SMTP AUTH;
- `all concurrency 2`, limiting local concurrency.

Markers surround this copy in every supported version. Before and after adding or removing it, the workflow reads back structure, hash, and metadata,
listeners, container identity, and logs. Any unexpected content prevents ambiguous edits.

## Docker image lock

`tests/integration/maddy-image-lock.json` stores the complete reference for each release:
`ghcr.io/foxcpp/maddy@sha256:<digest>`. The matrix defaults to `AllowImagePull=false`;
it can pull only those exact digests and only after an operator explicitly permits it. Tag drift is not allowed.

The WSL/container fixture provides:

- An internal network with no published ports;
- A separate random container, volume, account, and messages for each release;
- Fixed local SQLite configuration and a temporary self-signed certificate valid for one day;
- No production credentials, production network routes, or SSH;
- An EXIT trap that removes containers, volumes, networks, and temporary certificates.

A separate Docker named-volume Submission transaction test uses the locked `0.8.2` image to cover read-only planning while running,
preservation of a non-root `0600` owner and mode, atomic replacement while paused or stopped, and stale
hashes, exclusive attachment, the fixed local Docker context, `--allow-downtime`, and concurrent flock behavior,
plus restoration of the original hash after a listener fault and read-back of running and unpaused state.

Run the matrix with:

```powershell
./tests/integration/maddy-wsl-matrix.ps1 `
  -Distro Ubuntu `
  -Mode Container `
  -ReportPath "$env:TEMP/maddyweb-matrix.json"
```

If the locked images are not already present locally, add `-AllowImagePull` only after separate authorization. Artifact mode
accepts only a fixed binary, configuration, and SHA-256 file for each release, and supports WSL runners without Docker.

The matrix runs a real Maddy binary rather than a mock for every release: version probe and complete CLI help
fingerprint, `verify-config` only on `0.9.0+`, and account create/list/password/remove,
APPENDLIMIT, rejection of SMTP AUTH with a wrong password, and local delivery through the container loopback Submission endpoint with the correct password,
mailbox creation, message add/list/dump/move/remove, certificate PEM parsing,
private-key mode, deployment fingerprint read-back, and exact rollback after fault injection.

## Python 3.14 and free-threading

CI covers four interpreter states:

| Build | Startup argument | Expected GIL |
| --- | --- | --- |
| CPython 3.14 | Default | Enabled |
| CPython 3.14t | `-X gil=1` | enabled |
| CPython 3.14t | Default | Disabled |
| CPython 3.14t | `-X gil=0` | disabled |

`scripts/check-python314t.py` verifies the interpreter build, runtime GIL state, and
distribution wheel tags for extensions including `aiohttp` and `nh3`. A free-threaded environment requires
`cp314t`-compatible wheels; the presence of only `abi3` or standard `cp314` wheels does not constitute a validated
free-threaded deployment.

The minimum gate for a version or dependency upgrade is to update the exact allow-list and digests, review upstream
CLI and data-migration differences, complete the profiles, and run all four Python CI states and the real seven-version Maddy
matrix, then verify a backup against an isolated restoration copy. Changing only a version string does not constitute support.
