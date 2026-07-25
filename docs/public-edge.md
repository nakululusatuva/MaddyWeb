# Cloudflare Public Edge

This runbook exposes MaddyWeb through Cloudflare while the application remains
bound to `127.0.0.1:8787`. It covers only these reviewed hostnames:

- `maddy.standalone.example.test` on `mail_standalone`;
- `maddy.custom.example.test` on `mail_custom`.

The templates pin the 15 IPv4 and 7 IPv6 prefixes published by Cloudflare at
[ips-v4](https://www.cloudflare.com/ips-v4) and
[ips-v6](https://www.cloudflare.com/ips-v6), verified on 2026-07-25.
Cloudflare recommends allowing those proxy ranges at the origin and blocking
other sources. Review its
[origin guidance](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/)
before every range update.

## Security boundary

The reviewed layout has these invariants:

- MaddyWeb continues to listen only on `127.0.0.1:8787`.
- Only Cloudflare proxy peers can reach the named HTTP and HTTPS virtual hosts.
- The original TCP peer is checked independently from `CF-Connecting-IP`.
- Nginx overwrites `Host`, `X-Forwarded-*`, `Forwarded`, and Cloudflare client
  headers before proxying. The application never trusts arbitrary proxy input.
- `/healthz` is unavailable through the public edge.
- Password, TOTP, recovery, and both enrollment steps share a small
  visitor-address rate-limit zone. CSRF bootstrap and message submission have
  separate visitor-address limits.
- The default request body limit is 128 KiB. Only the three exact message-send
  endpoints accept 32 MiB, and those locations stream to the authenticated
  application without Nginx request buffering.
- TLS accepts only TLS 1.2 and TLS 1.3.
- HTTPS sends a domain-scoped one-year HSTS policy without
  `includeSubDomains`.
- The Web certificate has its own lineage, service, and timer. Existing mail
  certificate lineages, hooks, and timers are not replaced or disabled.

Keep Cloudflare proxying enabled for the two `maddy` records and select
Full (strict) origin TLS. Do not proxy SMTP, IMAP, Submission, MX, or mail
autoconfiguration records. A host firewall may restrict only origin TCP ports
80 and 443 to the pinned Cloudflare ranges; it must not block public mail
ports.

During initial HTTP-01 issuance, Cloudflare must not redirect
`/.well-known/acme-challenge/*` from HTTP to HTTPS. Temporarily disable an
account-wide "Always Use HTTPS" redirect or add a narrowly scoped exception
for that path, then remove the exception after the final TLS virtual host is
active. The origin bootstrap intentionally has no HTTPS listener.

Cloudflare ranges change infrequently but are not permanent. A range change is
a reviewed configuration update: compare both official lists, update both
network files and their tests, validate Nginx, deploy atomically, and only then
remove an obsolete range.

## Application configuration

Keep loopback hosts for local smoke checks and add exactly the public hostname
for the selected server:

```toml
[server]
listen = "127.0.0.1:8787"
allowed_hosts = ["127.0.0.1", "localhost", "maddy.standalone.example.test"]

[security]
auth_state_dir = "/var/lib/maddyweb-auth"
session_cookie_name = "__Host-maddyweb-session"
csrf_cookie_name = "__Host-maddyweb-csrf"
public_origin = "https://maddy.standalone.example.test"
totp_issuer = "MaddyWeb Standalone"
```

Use `maddy.custom.example.test` in both fields on `mail_custom`. Do not configure both
production hostnames on one server. The production checker requires the
allowed host set to be exactly `127.0.0.1`, `localhost`, and the selected
public hostname. It also requires the cookie names and authentication state
directory shown above. Validate and restart MaddyWeb before enabling the final
TLS virtual host, then confirm that port 8787 remains loopback-only.

The complete reviewed host profiles are
`deploy/examples/config.standalone.toml` and
`deploy/examples/config.custom.toml`. Use the matching file as the explicit
replacement configuration; do not reconstruct a production profile by
editing a development example during deployment.

## Preserve existing certificate automation

Before any edge change, record existing mail certificate state:

```console
systemctl list-unit-files 'certbot*' --no-pager
systemctl list-timers 'certbot*' --all --no-pager
find /etc/letsencrypt/renewal-hooks -type f -print0 \
  | sort -z | xargs -0 -r sha256sum
find /etc/letsencrypt/renewal -maxdepth 1 -type f -print0 \
  | sort -z | xargs -0 -r sha256sum
```

Store the output outside `/etc/letsencrypt`. The public-edge procedure does
not disable, mask, replace, or edit an existing mail timer or hook. The
dedicated Web services use an exact `--cert-name` and
`--no-directory-hooks`. The Web renewal file must use `webroot`, have no
installer, and contain no `pre_hook`, `post_hook`, `renew_hook`, or
`deploy_hook`.

Certbot 5.5 writes a `certonly --webroot` lineage without an `installer`
option when no installer was selected. Older renewal files can instead contain
the exact legacy value `installer = None`. These two forms are equivalent and
are the only accepted no-installer forms. Do not edit a newly generated file
just to add the legacy option. Any other value, spelling, or duplicate
`installer` option fails the public-edge check.

Use a separate Certbot state tree at `/var/lib/maddyweb-web-cert`, including
independent `config`, `work`, and `logs` directories. Never use
`/etc/letsencrypt`, `/var/lib/letsencrypt`, or `/var/log/letsencrypt` for the
Web lineage, even if an existing mail certificate currently covers the same
name. This keeps Web renewal and reload behavior independent from Maddy's
certificate deployment hook.

## Standalone managed include

`mail_standalone` runs a standalone root-owned Nginx master outside
`nginx.service`. Its PID is read from `/run/nginx.pid`, its executable is
`/usr/bin/nginx`, and its command is `nginx -c /etc/nginx/nginx.conf`. Keep
`nginx.service` inactive; do not enable, start, or use it to reload this
master.

The current core configuration does not include `/etc/nginx/conf.d/*.conf`.
Adding that include inside its existing `http` block is a deployment
prerequisite. Record the original file checksum and metadata, then make one
reviewed atomic edit which adds exactly this block while preserving every
other byte where practical:

```nginx
# BEGIN MADDYWEB PUBLIC EDGE
include /etc/nginx/conf.d/*.conf;
# END MADDYWEB PUBLIC EDGE
```

Do not replace `/etc/nginx/nginx.conf`. The checker requires both boundary
markers and the exact include, validates the root-owned live master against
the PID file and command line, and rejects `nginx.service` ownership drift.

Because this is a shared Nginx installation, the Standalone fragment does not
claim `default_server` and cannot change routing for existing sites. Its exact
`maddy.standalone.example.test` servers still close every direct non-Cloudflare request.
The pre-existing shared default server remains outside MaddyWeb ownership.

Create the managed paths and install the HTTP prelude, server-local trusted
proxy list, and temporary bootstrap include:

```console
sudo install -d -o root -g root -m 0755 /etc/nginx/maddyweb
sudo install -d -o root -g root -m 0755 /var/www/maddyweb-web-acme
sudo install -d -o root -g root -m 0700 /var/lib/maddyweb-web-cert
sudo install -d -o root -g root -m 0700 \
  /var/lib/maddyweb-web-cert/config \
  /var/lib/maddyweb-web-cert/work \
  /var/lib/maddyweb-web-cert/logs
sudo install -o root -g root -m 0644 \
  /opt/maddyweb/current/public-edge/nginx/cloudflare-realip.conf \
  /etc/nginx/maddyweb/cloudflare-realip.conf
sudo install -o root -g root -m 0644 \
  /opt/maddyweb/current/public-edge/nginx/cloudflare-http.conf \
  /etc/nginx/conf.d/00-maddyweb-cloudflare-http.conf
sudo install -o root -g root -m 0644 \
  /opt/maddyweb/current/public-edge/nginx/maddy.standalone.example.test.bootstrap.conf \
  /etc/nginx/conf.d/maddy.standalone.example.test.conf
sudo /usr/bin/nginx -t -c /etc/nginx/nginx.conf
sudo /usr/bin/nginx -s reload
```

The bootstrap include exposes only the ACME HTTP-01 path and returns 404 for
everything else. Set an actual ACME account address before issuing:

```console
ACME_EMAIL=operator@example.com
sudo /usr/bin/certbot --config /dev/null certonly \
  --non-interactive --agree-tos --email "$ACME_EMAIL" \
  --webroot --webroot-path /var/www/maddyweb-web-acme \
  --cert-name maddy.standalone.example.test --domain maddy.standalone.example.test \
  --no-directory-hooks \
  --config-dir /var/lib/maddyweb-web-cert/config \
  --work-dir /var/lib/maddyweb-web-cert/work \
  --logs-dir /var/lib/maddyweb-web-cert/logs
```

Inspect
`/var/lib/maddyweb-web-cert/config/renewal/maddy.standalone.example.test.conf`
against the certificate constraints above. Then atomically replace the
bootstrap include with the final `maddy.standalone.example.test.conf`, run
`/usr/bin/nginx -t -c /etc/nginx/nginx.conf`, and signal the existing master
with `/usr/bin/nginx -s reload`. Do not change any other virtual host.

Install only the dedicated Web unit and timer:

```console
sudo install -o root -g root -m 0644 \
  /opt/maddyweb/current/public-edge/systemd/maddyweb-web-cert-standalone.service \
  /etc/systemd/system/maddyweb-web-cert-standalone.service
sudo install -o root -g root -m 0644 \
  /opt/maddyweb/current/public-edge/systemd/maddyweb-web-cert-standalone.timer \
  /etc/systemd/system/maddyweb-web-cert-standalone.timer
sudo systemctl daemon-reload
sudo systemctl enable --now maddyweb-web-cert-standalone.timer
```

## Custom custom Nginx service

`mail_custom` owns Nginx through its existing custom service and
`/etc/custom-acme/nginx.conf`. Do not enable, start, reload, or edit the system
`nginx.service`. First confirm the existing custom unit invokes Nginx with the
exact custom configuration:

```console
systemctl cat custom-acme-webroot.service
sudo /usr/bin/nginx -t -c /etc/custom-acme/nginx.conf
```

Install managed files under the custom configuration tree:

```console
sudo install -d -o root -g root -m 0755 /etc/custom-acme/maddyweb
sudo install -d -o root -g root -m 0755 /var/www/maddyweb-web-acme
sudo install -d -o root -g root -m 0700 /var/lib/maddyweb-web-cert
sudo install -d -o root -g root -m 0700 \
  /var/lib/maddyweb-web-cert/config \
  /var/lib/maddyweb-web-cert/work \
  /var/lib/maddyweb-web-cert/logs
sudo install -o root -g root -m 0644 \
  /opt/maddyweb/current/public-edge/nginx/cloudflare-http.conf \
  /etc/custom-acme/maddyweb/cloudflare-http.conf
sudo install -o root -g root -m 0644 \
  /opt/maddyweb/current/public-edge/nginx/cloudflare-realip.conf \
  /etc/custom-acme/maddyweb/cloudflare-realip.conf
sudo install -o root -g root -m 0644 \
  /opt/maddyweb/current/public-edge/nginx/maddy.custom.example.test.bootstrap.conf \
  /etc/custom-acme/maddyweb/maddy.custom.example.test.conf
sudo install -o root -g root -m 0644 \
  /opt/maddyweb/current/public-edge/nginx/custom-maddyweb-http.inc \
  /etc/custom-acme/maddyweb/maddyweb-http.inc
```

Add exactly this line inside the existing `http` block in
`/etc/custom-acme/nginx.conf`, preserving every other byte where practical:

```nginx
include /etc/custom-acme/maddyweb/maddyweb-http.inc;
```

Test the custom configuration and reload only its owning service:

```console
sudo /usr/bin/nginx -t -c /etc/custom-acme/nginx.conf
sudo systemctl reload custom-acme-webroot.service
```

Use Custom's existing `/opt/certbot/bin/certbot`; `/usr/bin/certbot` is not the
selected runtime on this host. Issue the dedicated lineage:

```console
ACME_EMAIL=operator@example.com
sudo /opt/certbot/bin/certbot --config /dev/null certonly \
  --non-interactive --agree-tos --email "$ACME_EMAIL" \
  --webroot --webroot-path /var/www/maddyweb-web-acme \
  --cert-name maddy.custom.example.test --domain maddy.custom.example.test \
  --no-directory-hooks \
  --config-dir /var/lib/maddyweb-web-cert/config \
  --work-dir /var/lib/maddyweb-web-cert/work \
  --logs-dir /var/lib/maddyweb-web-cert/logs
```

Inspect
`/var/lib/maddyweb-web-cert/config/renewal/maddy.custom.example.test.conf`, atomically
replace the bootstrap include with `maddy.custom.example.test.conf`, test with the custom
`-c` argument, and reload only `custom-acme-webroot.service`. The existing
`mail.custom.example.test` server remains the port 80 `default_server`; MaddyWeb must not
claim that HTTP default. The final Custom fragment owns only the port 443
default-deny server. Stop if the existing custom configuration begins to claim
an HTTPS `default_server`; resolve that collision explicitly instead of
deleting an unrelated server.

Install only the Custom Web certificate unit and timer:

```console
sudo install -o root -g root -m 0644 \
  /opt/maddyweb/current/public-edge/systemd/maddyweb-web-cert-custom.service \
  /etc/systemd/system/maddyweb-web-cert-custom.service
sudo install -o root -g root -m 0644 \
  /opt/maddyweb/current/public-edge/systemd/maddyweb-web-cert-custom.timer \
  /etc/systemd/system/maddyweb-web-cert-custom.timer
sudo systemctl daemon-reload
sudo systemctl enable --now maddyweb-web-cert-custom.timer
```

## Verification

Run the repository-owned read-only checker as root:

```console
sudo bash /opt/maddyweb/current/public-edge/check-public-edge.sh --profile standalone
sudo bash /opt/maddyweb/current/public-edge/check-public-edge.sh --profile custom
```

The installer copies these assets into the immutable commit-named application
release. The checker compares the installed includes and units byte-for-byte
with that current release. Do not install or verify public-edge assets from a
working tree or a different release. Run only the profile for the current host.

The checker is read-only. It invokes the validator from the immutable
`/opt/maddyweb/current` release, then independently verifies the exact
profile-specific listen address, allowed hosts, public origin, TOTP issuer,
authentication state directory, and `__Host-` cookie names. It resolves the
Certbot live links into the dedicated
`/var/lib/maddyweb-web-cert/config/archive/<domain>` directory, requires the
private key to be root-owned mode `0600` with one hard link, requires the
certificate and key to use the same archive generation, verifies their public
keys match, and rejects a certificate whose sole DNS SAN is not the selected
hostname or which expires within 24 hours.

The checker also probes the loopback login and health routes through the exact
trusted proxy headers, requires a direct-origin HTTPS request to be closed by
Nginx, and requests the public `/healthz` path through normal DNS. The public
response must be 404 and carry the reviewed HSTS header. Therefore the host
running the checker needs outbound DNS and HTTPS access. After it passes,
verify:

Nginx `return 444` deliberately closes the connection without an HTTP
response. Depending on the curl TLS backend and close behavior, curl reports
this as either exit 52 (empty reply) or exit 56 (receive failure). The checker
accepts only those two results and separately requires HTTP status `000`; any
received HTTP response still fails the direct-origin denial check.

- the Cloudflare public URL redirects HTTP to HTTPS;
- the HTTPS response includes exactly
  `Strict-Transport-Security: max-age=31536000`;
- the public `/healthz` returns 404;
- a direct-origin request with the public Host is closed rather than proxied;
- login returns 429 after a deliberately bounded test burst;
- the application listener is exactly `127.0.0.1:8787`;
- existing SMTP, IMAP, mail TLS, mail certificate timers, and mail deployment
  hooks match the pre-change snapshot.

Confirm in the Cloudflare dashboard that SSL/TLS mode is Full (strict).
Confirm that no Transform Rule or edge header rule removes or replaces the
origin HSTS header. These two zone settings cannot be proven by the origin
checker; a successful HTTPS probe does not distinguish Full (strict) from
weaker Cloudflare modes. They remain explicit deployment gates.

Do not send an unbounded login burst. A local direct-origin probe is expected
to fail because loopback is not a Cloudflare proxy range:

```console
curl --fail --resolve maddy.standalone.example.test:443:127.0.0.1 \
  https://maddy.standalone.example.test/
```

## Rollback

Never expose an older release that does not carry the required-authentication
attestation. First replace only the selected application virtual host with the
withdrawn asset retained in the current immutable release. It keeps the ACME
challenge reachable but returns 503 for every application request.

Standalone:

```console
sudo install -o root -g root -m 0644 \
  /opt/maddyweb/current/public-edge/nginx/maddy.standalone.example.test.withdrawn.conf \
  /etc/nginx/conf.d/maddy.standalone.example.test.conf
sudo /usr/bin/nginx -t -c /etc/nginx/nginx.conf
sudo /usr/bin/nginx -s reload
curl --output /dev/null --write-out '%{http_code}\n' \
  'https://maddy.standalone.example.test/?maddyweb-withdrawal=operator-check'
```

Custom:

```console
sudo install -o root -g root -m 0644 \
  /opt/maddyweb/current/public-edge/nginx/maddy.custom.example.test.withdrawn.conf \
  /etc/custom-acme/maddyweb/maddy.custom.example.test.conf
sudo /usr/bin/nginx -t -c /etc/custom-acme/nginx.conf
sudo systemctl reload custom-acme-webroot.service
curl --output /dev/null --write-out '%{http_code}\n' \
  'https://maddy.custom.example.test/?maddyweb-withdrawal=operator-check'
```

The public result must be 503. Then run the root dry run and approved rollback
with both `--restore-previous-config` and
`--acknowledge-public-edge-withdrawn`. The rollback independently compares the
installed file with the immutable withdrawn asset, tests the host-specific
Nginx configuration, and probes the public 503 twice. It does not install or
reload Nginx. Leave the withdrawn edge in place after rollback; do not proxy
an unauthenticated predecessor.

Disable only the selected `maddyweb-web-cert-*.timer`, restore the prior
managed MaddyWeb include or remove its single Custom include line, validate the
correct Nginx configuration, and reload its established owner. On Standalone,
remove the exact bounded `conf.d` include only after its managed files are no
longer needed, run `/usr/bin/nginx -t -c /etc/nginx/nginx.conf`, and signal
the root-owned master with `/usr/bin/nginx -s reload`. On Custom, test the
custom configuration and reload `custom-acme-webroot.service`. Do not restore
an entire Nginx configuration tree, enable the Standalone `nginx.service`,
disable a mail timer, remove a mail hook, or delete a certificate lineage
automatically.

Keep MaddyWeb on loopback throughout rollback. Remove the public host and
origin from MaddyWeb configuration only after the public virtual host is no
longer reachable. Compare mail certificate timers, hooks, and renewal files
with the saved pre-change snapshot before declaring rollback complete.
