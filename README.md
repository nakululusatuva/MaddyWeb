# MaddyWeb

MaddyWeb is a lightweight browser mail client and administration console for
[Maddy Mail Server](https://maddy.email/). It provides a three-pane mailbox,
account and certificate administration, TOTP, Passkeys, folders, filing rules,
and live new-mail alerts without exposing Maddy's data store directly.

[![MaddyWeb authenticated three-pane mail workspace](docs/assets/maddyweb-overview.png)](docs/assets/maddyweb-overview.png)

<p align="center"><em>Mail, folders, message actions, and administration in one private workspace.</em></p>

## Features

- Read, compose, reply, forward, move, archive, and delete mail.
- All Mail, custom IMAP folders, page-level sender and subject filtering, bulk
  actions, and nested filing rules.
- Unified mailbox identity with required TOTP enrollment, recovery codes, and
  optional discoverable Passkey sign-in.
- User session management and five-minute re-verification for sensitive changes.
- Administrator tools for accounts, mailboxes, certificates, and renewal status.
- Native and existing Docker-based Maddy installations.
- A static, dependency-free frontend with sandboxed sanitized HTML messages.

## Requirements

- Linux with systemd.
- CPython 3.14 or free-threaded CPython 3.14t.
- Maddy `0.8.2` or `0.9.0` through `0.9.5`.
- An existing Maddy installation and a verified backup.
- Docker CLI access only when managing an existing Docker Maddy container.

MaddyWeb itself runs natively in a Python virtual environment. It is not
installed inside the Maddy container.

## Network access

MaddyWeb listens on **`127.0.0.1:8787`** by default and rejects non-loopback
addresses. Supported remote access uses either the reviewed Cloudflare/Nginx
edge or an SSH tunnel:

```console
ssh -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes \
  -N -L 127.0.0.1:8787:127.0.0.1:8787 admin@mail.example.net
```

Do not publish port `8787`, bind it to `0.0.0.0`, or place it behind an
unreviewed public proxy. See the [public-edge guide](docs/public-edge.md) for
Internet-facing deployments.

## Development

```console
uv sync --python 3.14 --extra dev --extra browser
uv run pytest -q
uv run ruff check .
uv run python -m maddyweb --help
```

The example configurations reference real Maddy and system paths; they are not
standalone demos. Production installation requires a prepared configuration,
wheel, and offline wheelhouse. Start with the
[deployment guide](docs/deployment.md).

## Configuration

- Native Maddy: [`deploy/examples/config.native.toml`](deploy/examples/config.native.toml)
- Docker management: [`docker/config.toml`](docker/config.toml)
- WSL testing: [`deploy/examples/config.wsl.toml`](deploy/examples/config.wsl.toml)

An unsupported Maddy version, CLI fingerprint, helper state, or deployment
topology disables write operations instead of guessing compatibility.

## Security boundary

- The Web process runs without privileges and cannot access the Docker socket.
- Fixed privileged operations pass through a restricted root helper over a
  local Unix socket.
- Mailbox credentials establish the Web identity and TOTP enrollment is
  required; registered Passkeys provide discoverable passwordless sign-in.
- Message HTML is sanitized and displayed in a sandboxed iframe with a separate
  restrictive CSP.
- Sessions expire after 72 hours of inactivity and after 30 days absolutely;
  sensitive operations require verification completed within five minutes.

Read [SECURITY.md](SECURITY.md) for the complete trust model and disclosure
process.

## Documentation

- [Deployment guide](docs/deployment.md)
- [Operations runbook](docs/runbook.md)
- [Authentication and identity](docs/authentication.md)
- [Cloudflare public edge](docs/public-edge.md)
- [Mail organization and filing rules](docs/mail-organization.md)
- [Compatibility matrix](docs/compatibility.md)
- [Security gates](docs/security-gates.md)
