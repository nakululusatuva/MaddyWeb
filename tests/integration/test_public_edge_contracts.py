from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EDGE = ROOT / "deploy/public-edge"
NGINX = EDGE / "nginx"
SYSTEMD = EDGE / "systemd"

CLOUDFLARE_IPV4 = {
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
}
CLOUDFLARE_IPV6 = {
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
}
CLOUDFLARE_NETWORKS = CLOUDFLARE_IPV4 | CLOUDFLARE_IPV6


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_cloudflare_ranges_are_exactly_pinned_in_both_contexts() -> None:
    http = _read(NGINX / "cloudflare-http.conf")
    realip = _read(NGINX / "cloudflare-realip.conf")

    geo_networks = set(re.findall(r"^\s*([0-9a-f:.]+/\d+)\s+1;\s*$", http, re.MULTILINE))
    trusted_networks = set(
        re.findall(r"^\s*set_real_ip_from\s+([0-9a-f:.]+/\d+);\s*$", realip, re.MULTILINE)
    )

    assert geo_networks == CLOUDFLARE_NETWORKS
    assert trusted_networks == CLOUDFLARE_NETWORKS
    assert len(CLOUDFLARE_IPV4) == 15
    assert len(CLOUDFLARE_IPV6) == 7
    for source in (http, realip):
        assert "https://www.cloudflare.com/ips-v4" in source
        assert "https://www.cloudflare.com/ips-v6" in source
        assert "2026-07-25" in source


def test_cloudflare_peer_and_login_limit_use_independent_addresses() -> None:
    http = _read(NGINX / "cloudflare-http.conf")
    realip = _read(NGINX / "cloudflare-realip.conf")

    assert "geo $realip_remote_addr $maddyweb_cloudflare_peer" in http
    assert "limit_req_zone $binary_remote_addr zone=maddyweb_auth_login:1m rate=5r/m;" in http
    assert "limit_req_zone $binary_remote_addr zone=maddyweb_auth_csrf:1m rate=30r/m;" in http
    assert "limit_req_zone $binary_remote_addr zone=maddyweb_send:1m rate=10r/m;" in http
    assert "real_ip_header CF-Connecting-IP;" in realip
    assert "real_ip_recursive off;" in realip


def test_public_vhosts_pin_host_headers_health_rate_limit_and_tls() -> None:
    profiles = {
        "maddy.standalone.example.test": (
            NGINX / "maddy.standalone.example.test.conf",
            "/etc/nginx/maddyweb/cloudflare-realip.conf",
        ),
        "maddy.custom.example.test": (
            NGINX / "maddy.custom.example.test.conf",
            "/etc/custom-acme/maddyweb/cloudflare-realip.conf",
        ),
    }
    for domain, (path, realip_path) in profiles.items():
        source = _read(path)
        assert f"server_name {domain};" in source
        assert f"include {realip_path};" in source
        assert "if ($maddyweb_cloudflare_peer = 0)" in source
        assert "return 444;" in source
        assert "location = /healthz {" in source
        assert re.search(r"location = /healthz \{\s*return 404;\s*\}", source)
        assert "location = /api/v1/auth/password {" in source
        assert "location = /api/v1/auth/totp {" in source
        assert "location = /api/v1/auth/recovery {" in source
        assert "location = /api/v1/auth/enrollment {" in source
        assert "location = /api/v1/auth/enrollment/confirm {" in source
        assert source.count("limit_req zone=maddyweb_auth_login burst=5 nodelay;") == 8
        for path in (
            "/api/v1/auth/password/change",
            "/api/v1/auth/recovery-codes/regenerate",
            "/api/v1/auth/step-up",
        ):
            assert f"location = {path} {{" in source
        assert "location = /api/v1/auth/csrf {" in source
        assert source.count("limit_req zone=maddyweb_auth_csrf burst=10 nodelay;") == 1
        assert "proxy_pass http://127.0.0.1:8787;" in source
        assert f"proxy_set_header Host {domain};" in source
        assert 'proxy_set_header X-Forwarded-Host "";' in source
        assert "proxy_set_header X-Forwarded-Proto https;" in source
        assert 'proxy_set_header X-Forwarded-Port "";' in source
        assert 'proxy_set_header X-Forwarded-For "";' in source
        assert "proxy_set_header X-Real-IP $remote_addr;" in source
        assert 'proxy_set_header Forwarded "";' in source
        assert 'proxy_set_header CF-Connecting-IP "";' in source
        assert 'proxy_set_header True-Client-IP "";' in source
        assert "proxy_set_header Host $host" not in source
        assert "ssl_protocols TLSv1.2 TLSv1.3;" in source
        assert 'add_header Strict-Transport-Security "max-age=31536000" always;' in source
        assert "includeSubDomains" not in source
        assert "TLSv1.1" not in source
        assert "TLSv1 " not in source
        assert source.count("client_max_body_size 128k;") == 1
        assert source.count("client_max_body_size 32m;") == 3
        assert source.count("proxy_request_buffering off;") == 3
        assert source.count("limit_req zone=maddyweb_send burst=2 nodelay;") == 3
        for send_path in (
            "/api/v1/send",
            "/api/v1/me/send",
            "/api/v1/admin/send",
        ):
            assert f"location = {send_path} {{" in source
        assert (
            f"ssl_certificate /var/lib/maddyweb-web-cert/config/live/{domain}/fullchain.pem;"
        ) in source
        assert (
            f"ssl_certificate_key /var/lib/maddyweb-web-cert/config/live/{domain}/privkey.pem;"
        ) in source
        assert "/etc/letsencrypt/live/" not in source


def test_bootstrap_vhosts_expose_only_acme_over_http() -> None:
    for domain in ("maddy.standalone.example.test", "maddy.custom.example.test"):
        source = _read(NGINX / f"{domain}.bootstrap.conf")
        assert f"server_name {domain};" in source
        assert "listen 80;" in source
        assert "listen 443" not in source
        assert "proxy_pass" not in source
        assert "location ^~ /.well-known/acme-challenge/" in source
        assert re.search(r"location / \{\s*return 404;\s*\}", source)
        assert "if ($maddyweb_cloudflare_peer = 0)" in source


def test_withdrawn_vhosts_keep_acme_but_never_proxy_application() -> None:
    profiles = {
        "maddy.standalone.example.test": "/etc/nginx/maddyweb/cloudflare-realip.conf",
        "maddy.custom.example.test": "/etc/custom-acme/maddyweb/cloudflare-realip.conf",
    }
    for domain, realip_path in profiles.items():
        source = _read(NGINX / f"{domain}.withdrawn.conf")
        assert f"server_name {domain};" in source
        assert f"include {realip_path};" in source
        assert "if ($maddyweb_cloudflare_peer = 0)" in source
        assert "location ^~ /.well-known/acme-challenge/" in source
        assert "root /var/www/maddyweb-web-acme;" in source
        assert source.count("return 503;") == 2
        assert "proxy_pass" not in source
        assert "127.0.0.1:8787" not in source

    custom = _read(NGINX / "maddy.custom.example.test.withdrawn.conf")
    assert "listen 80 default_server;" not in custom
    assert "listen [::]:80 default_server;" not in custom
    assert "listen 443 ssl default_server;" in custom
    assert "mail.custom.example.test server remains the HTTP default server" in custom


def test_host_specific_nginx_ownership_is_not_interchangeable() -> None:
    standalone = _read(NGINX / "maddy.standalone.example.test.conf")
    custom = _read(NGINX / "maddy.custom.example.test.conf")
    wrapper = _read(NGINX / "custom-maddyweb-http.inc")
    guide = _read(ROOT / "docs/public-edge.md")
    compact_guide = " ".join(guide.split())

    assert "/etc/custom-acme" not in standalone
    assert "default_server" not in standalone
    assert "does not replace nginx.conf" in standalone
    assert "listen 80 default_server;" not in custom
    assert "listen [::]:80 default_server;" not in custom
    assert "mail.custom.example.test server remains the HTTP default server" in custom
    assert "listen 443 ssl default_server;" in custom
    assert "ssl_reject_handshake on;" in custom
    assert wrapper.splitlines()[-2:] == [
        "include /etc/custom-acme/maddyweb/cloudflare-http.conf;",
        "include /etc/custom-acme/maddyweb/maddy.custom.example.test.conf;",
    ]
    assert "Do not replace `/etc/nginx/nginx.conf`." in compact_guide
    assert "# BEGIN MADDYWEB PUBLIC EDGE" in compact_guide
    assert "Keep `nginx.service` inactive" in compact_guide
    assert "Do not enable, start, reload, or edit the system" in compact_guide
    assert "`nginx.service`" in compact_guide
    assert (
        "The existing `mail.custom.example.test` server remains the port 80 `default_server`" in compact_guide
    )
    assert "owns only the port 443 default-deny server" in compact_guide


def test_web_certificate_units_are_scoped_and_do_not_run_mail_hooks() -> None:
    profiles = {
        "standalone": ("maddy.standalone.example.test", "/usr/bin/certbot"),
        "custom": ("maddy.custom.example.test", "/opt/certbot/bin/certbot"),
    }
    for profile, (domain, certbot_binary) in profiles.items():
        service = _read(SYSTEMD / f"maddyweb-web-cert-{profile}.service")
        timer = _read(SYSTEMD / f"maddyweb-web-cert-{profile}.timer")

        assert f"--cert-name {domain}" in service
        assert f"ExecStart={certbot_binary} --config /dev/null renew" in service
        assert "--no-directory-hooks" in service
        assert f"/var/lib/maddyweb-web-cert/config/renewal/{domain}.conf" in service
        assert "ProtectSystem=strict" in service
        assert "NoNewPrivileges=yes" in service
        assert "LimitCORE=0" in service
        assert "ReadWritePaths=/var/lib/maddyweb-web-cert" in service
        assert "--config-dir /var/lib/maddyweb-web-cert/config" in service
        assert "--work-dir /var/lib/maddyweb-web-cert/work" in service
        assert "--logs-dir /var/lib/maddyweb-web-cert/logs" in service
        assert "/etc/letsencrypt" not in service
        assert "/var/lib/letsencrypt" not in service
        assert "/var/log/letsencrypt" not in service
        assert "ReadWritePaths=/var/www/maddyweb-web-acme" in service
        assert "certbot.timer" not in service
        assert "certbot-renew.timer" not in service
        assert f"Unit=maddyweb-web-cert-{profile}.service" in timer
        assert "Persistent=true" in timer
        assert "RandomizedDelaySec=30min" in timer
        assert "Documentation=file:/opt/maddyweb/current/public-edge/public-edge.md" in service
        assert "Documentation=file:/opt/maddyweb/current/public-edge/public-edge.md" in timer

    standalone_service = _read(SYSTEMD / "maddyweb-web-cert-standalone.service")
    assert "After=network-online.target\n" in standalone_service
    assert "After=network-online.target nginx.service" not in standalone_service
    assert "ExecStartPre=/usr/bin/nginx -t -c /etc/nginx/nginx.conf" in standalone_service
    assert "ExecStartPost=/usr/bin/nginx -t -c /etc/nginx/nginx.conf" in standalone_service
    assert "ExecStartPost=/usr/bin/nginx -s reload" in standalone_service
    assert "systemctl reload nginx.service" not in standalone_service

    custom_service = _read(SYSTEMD / "maddyweb-web-cert-custom.service")
    assert "After=network-online.target custom-acme-webroot.service" in custom_service
    assert "Wants=network-online.target custom-acme-webroot.service" in custom_service
    assert "ExecStartPre=/usr/bin/nginx -t -c /etc/custom-acme/nginx.conf" in custom_service
    assert "ExecStartPost=/usr/bin/nginx -t -c /etc/custom-acme/nginx.conf" in custom_service
    assert "ExecStartPost=/usr/bin/systemctl reload custom-acme-webroot.service" in custom_service
    assert "/usr/bin/certbot" not in custom_service
    assert "custom-acme.service" not in custom_service
    assert "nginx.service" not in custom_service


def test_public_edge_checker_is_read_only_and_profile_bound() -> None:
    checker = _read(EDGE / "check-public-edge.sh")

    assert "--profile standalone|custom" in checker
    assert 'totp_issuer="MaddyWeb Standalone"' in checker
    assert 'totp_issuer="MaddyWeb Custom"' in checker
    assert "/etc/nginx/nginx.conf" in checker
    assert "/etc/custom-acme/nginx.conf" in checker
    assert "nginx_test=(/usr/bin/nginx -t -c /etc/custom-acme/nginx.conf)" in checker
    assert 'nginx_binary="/usr/bin/nginx"' in checker
    assert 'certbot_binary="/usr/bin/certbot"' in checker
    assert 'certbot_binary="/opt/certbot/bin/certbot"' in checker
    assert 'nginx_service="custom-acme-webroot.service"' in checker
    assert "system nginx.service must remain disabled" in checker
    assert "pre_hook|post_hook|renew_hook|deploy_hook" in checker
    assert 'certificate_root="/var/lib/maddyweb-web-cert"' in checker
    assert "require_root_private_directory" in checker
    assert "require_root_secret_file" in checker
    assert "127\\.0\\.0\\.1:8787" in checker
    assert checker.count("cmp -s --") >= 6
    assert "drifted from the reviewed asset" in checker
    assert 'require_root_private_file "$source_vhost"' in checker
    assert 'require_root_executable "$nginx_binary"' in checker
    assert 'require_root_executable "$certbot_binary"' in checker
    assert "systemctl is-active --quiet maddyweb.service" in checker
    assert not re.search(
        r"\bsystemctl\s+(?:enable|disable|mask|unmask|start|stop|reload|restart)\b",
        checker,
    )
    assert not re.search(r"\b(?:rm|mv|cp|install)\s", checker)
    assert "certbot renew" not in checker


def test_public_edge_checker_validates_exact_application_profile() -> None:
    checker = _read(EDGE / "check-public-edge.sh")

    assert 'require_root_private_file "/etc/maddyweb/config.toml"' in checker
    assert "[[ -L /opt/maddyweb/current ]]" in checker
    assert r"^/opt/maddyweb/releases/[0-9a-f]{40}$" in checker
    assert "-I -m maddyweb validate-config \\\n    --config /etc/maddyweb/config.toml" in checker
    assert 'server.get("listen") != "127.0.0.1:8787"' in checker
    assert 'expected_hosts = {"127.0.0.1", "localhost", domain}' in checker
    assert '"auth_state_dir": "/var/lib/maddyweb-auth"' in checker
    assert '"session_cookie_name": "__Host-maddyweb-session"' in checker
    assert '"csrf_cookie_name": "__Host-maddyweb-csrf"' in checker
    assert '"public_origin": f"https://{domain}"' in checker
    assert '"totp_issuer": issuer' in checker
    assert "other production hostname is present" in checker


def test_public_edge_checker_validates_isolated_certificate_and_key() -> None:
    checker = _read(EDGE / "check-public-edge.sh")

    assert 'certificate_live="$certificate_root/config/live/$domain"' in checker
    assert 'certificate_archive="$certificate_root/config/archive/$domain"' in checker
    assert "resolve_live_lineage_file fullchain" in checker
    assert "resolve_live_lineage_file privkey" in checker
    assert 'link_prefix="../../archive/$domain/"' in checker
    assert '[[ "$target_name" == "$link_name" ]]' in checker
    assert '[[ "$target_parent" == "$certificate_archive" ]]' in checker
    assert '[[ "$identity" == "0:600:1" ]]' in checker
    assert "live certificate and private key use different archive generations" in checker
    assert 'openssl x509 -in "$certificate_target" -noout -checkend 86400' in checker
    assert '[[ "$san_value" == "DNS:$domain" ]]' in checker
    assert 'openssl pkey -in "$private_key_target" -pubout -outform DER' in checker
    assert "/etc/letsencrypt" not in checker


def test_public_edge_checker_probes_login_health_and_direct_origin_denial() -> None:
    checker = _read(EDGE / "check-public-edge.sh")

    assert "http://127.0.0.1:8787/login" in checker
    assert "http://127.0.0.1:8787/healthz" in checker
    assert '--header "Host: $domain"' in checker
    assert "--header 'X-Forwarded-Proto: https'" in checker
    assert "--header 'X-Real-IP: 127.0.0.1'" in checker
    health_probe = checker.split("loopback_health_status=$(", maxsplit=1)[1].split(
        ") || die", maxsplit=1
    )[0]
    assert "--header 'Host: 127.0.0.1'" in health_probe
    assert "Host: $domain" not in health_probe
    assert "X-Forwarded-Proto" not in health_probe
    assert "X-Real-IP" not in health_probe
    assert '--resolve "$domain:443:127.0.0.1"' in checker
    assert '[[ "$direct_origin_exit" == "52" ]]' in checker
    assert '"https://$domain/healthz"' in checker
    assert '[[ "$public_health_status" == "404" ]]' in checker
    assert "strict-transport-security:" in checker
    assert "Full (strict)" not in checker


def test_standalone_checker_validates_standalone_nginx_master() -> None:
    checker = _read(EDGE / "check-public-edge.sh")

    assert 'nginx_pid_file="/run/nginx.pid"' in checker
    assert "/usr/bin/nginx -t -c /etc/nginx/nginx.conf" in checker
    assert "nginx.service must remain inactive for the standalone Standalone master" in checker
    assert "standalone nginx pid file is invalid" in checker
    assert "stat -c '%u' -- \"/proc/$nginx_master_pid\"" in checker
    assert 'realpath -e -- "/proc/$nginx_master_pid/exe"' in checker
    assert "tr '\\0' ' ' <\"/proc/$nginx_master_pid/cmdline\"" in checker
    assert "nginx: master process nginx -c /etc/nginx/nginx.conf" in checker
    assert "standalone nginx master changed during validation" in checker
    assert "# BEGIN MADDYWEB PUBLIC EDGE" in checker
    assert "include /etc/nginx/conf.d/*.conf;" in checker
    assert "# END MADDYWEB PUBLIC EDGE" in checker
    assert "directive_line == begin_line + 1" in checker
    assert "end_line == directive_line + 1" in checker
    assert "managed include is not one exact contiguous block" in checker


def test_custom_checker_validates_actual_service_owner_and_hup_reload() -> None:
    checker = _read(EDGE / "check-public-edge.sh")

    assert "custom-acme-webroot.service does not use the expected nginx command" in checker
    assert "custom-acme-webroot.service does not reload its master with HUP" in checker
    assert 'systemctl show "$nginx_service" --property=ExecStart --value' in checker
    assert "/usr/bin/nginx -c /etc/custom-acme/nginx.conf -g daemon off;" in checker
    assert 'systemctl show "$nginx_service" --property=ExecReload --value' in checker
    assert "-s[[:space:]]+HUP|-HUP" in checker


def test_public_edge_documentation_preserves_mail_automation() -> None:
    guide = _read(ROOT / "docs/public-edge.md")
    compact_guide = " ".join(guide.split())

    assert (
        "does not disable, mask, replace, or edit an existing mail timer or hook" in compact_guide
    )
    assert "Use a separate Certbot state tree" in compact_guide
    assert (
        "Never use `/etc/letsencrypt`, `/var/lib/letsencrypt`, or "
        "`/var/log/letsencrypt` for the Web lineage"
    ) in compact_guide
    assert "Do not change any other virtual host." in compact_guide
    assert "reload only `custom-acme-webroot.service`" in compact_guide
    assert "`/opt/certbot/bin/certbot`" in compact_guide
    assert "signal the existing master with `/usr/bin/nginx -s reload`" in compact_guide
    assert "Do not send an unbounded login burst." in compact_guide
    assert "MaddyWeb continues to listen only on `127.0.0.1:8787`." in compact_guide
    assert "private key to be root-owned mode `0600` with one hard link" in compact_guide
    assert "sole DNS SAN is not the selected hostname" in compact_guide
    assert "The public response must be 404" in compact_guide
    assert "cannot be proven by the origin checker" in compact_guide
    assert "does not distinguish Full (strict) from weaker Cloudflare modes" in compact_guide
    assert (
        "sudo bash /opt/maddyweb/current/public-edge/check-public-edge.sh --profile standalone"
    ) in compact_guide
    assert "Do not install or verify public-edge assets from a working tree" in compact_guide


def test_installer_retains_public_edge_assets_in_immutable_release() -> None:
    install = _read(ROOT / "scripts/install.sh")
    guide = _read(ROOT / "docs/deployment.md")

    assert 'readonly PUBLIC_EDGE_ROOT="$REPO_ROOT/deploy/public-edge"' in install
    assert 'readonly PUBLIC_EDGE_DOCUMENTATION="$REPO_ROOT/docs/public-edge.md"' in install
    assert '"$staging/public-edge/nginx"' in install
    assert '"$staging/public-edge/systemd"' in install
    assert '"$staging/public-edge/check-public-edge.sh"' in install
    assert '"$staging/public-edge/public-edge.md"' in install
    for name in (
        "cloudflare-http.conf",
        "cloudflare-realip.conf",
        "maddy.custom.example.test.bootstrap.conf",
        "maddy.custom.example.test.conf",
        "maddy.custom.example.test.withdrawn.conf",
        "maddy.standalone.example.test.bootstrap.conf",
        "maddy.standalone.example.test.conf",
        "maddy.standalone.example.test.withdrawn.conf",
        "custom-maddyweb-http.inc",
        "maddyweb-web-cert-custom.service",
        "maddyweb-web-cert-custom.timer",
        "maddyweb-web-cert-standalone.service",
        "maddyweb-web-cert-standalone.timer",
    ):
        assert name in install
    assert "immutable commit-named release" in guide
