#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ASSET_DIR="$SCRIPT_DIR/nginx"
UNIT_ASSET_DIR="$SCRIPT_DIR/systemd"
RENEWAL_POLICY_CHECKER="$SCRIPT_DIR/validate-renewal-profile.py"

log() {
    printf '[maddyweb-public-edge] %s\n' "$*" >&2
}

die() {
    log "ERROR: $*"
    exit 1
}

usage() {
    cat <<'EOF'
Usage:
  bash check-public-edge.sh --profile standalone|custom

Performs read-only validation of the selected public edge, dedicated Web
certificate renewal profile, systemd timer, and loopback MaddyWeb listener.
EOF
}

profile=""
while (($#)); do
    case "$1" in
        --profile)
            (($# >= 2)) || die "--profile requires a value"
            profile=$2
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

case "$profile" in
    standalone)
        domain="maddy.standalone.example.test"
        other_domain="maddy.custom.example.test"
        totp_issuer="MaddyWeb Standalone"
        nginx_config="/etc/nginx/nginx.conf"
        nginx_http_include="/etc/nginx/conf.d/00-maddyweb-cloudflare-http.conf"
        nginx_realip_include="/etc/nginx/maddyweb/cloudflare-realip.conf"
        nginx_vhost="/etc/nginx/conf.d/maddy.standalone.example.test.conf"
        nginx_service="nginx.service"
        nginx_binary="/usr/bin/nginx"
        nginx_pid_file="/run/nginx.pid"
        certbot_binary="/usr/bin/certbot"
        service_unit="maddyweb-web-cert-standalone.service"
        timer_unit="maddyweb-web-cert-standalone.timer"
        source_vhost="$ASSET_DIR/maddy.standalone.example.test.conf"
        nginx_test=(/usr/bin/nginx -t -c /etc/nginx/nginx.conf)
        ;;
    custom)
        domain="maddy.custom.example.test"
        other_domain="maddy.standalone.example.test"
        totp_issuer="MaddyWeb Custom"
        nginx_config="/etc/custom-acme/nginx.conf"
        nginx_http_include="/etc/custom-acme/maddyweb/cloudflare-http.conf"
        nginx_realip_include="/etc/custom-acme/maddyweb/cloudflare-realip.conf"
        nginx_vhost="/etc/custom-acme/maddyweb/maddy.custom.example.test.conf"
        nginx_service="custom-acme-webroot.service"
        nginx_binary="/usr/bin/nginx"
        nginx_pid_file=""
        certbot_binary="/opt/certbot/bin/certbot"
        service_unit="maddyweb-web-cert-custom.service"
        timer_unit="maddyweb-web-cert-custom.timer"
        source_vhost="$ASSET_DIR/maddy.custom.example.test.conf"
        nginx_test=(/usr/bin/nginx -t -c /etc/custom-acme/nginx.conf)
        ;;
    *)
        die "--profile must be standalone or custom"
        ;;
esac

for command in awk basename cmp curl dirname getent grep openssl readlink realpath sed sha256sum stat systemctl ss timeout tr; do
    command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

require_root_private_file() {
    local path=${1:?path is required}
    [[ -f "$path" && ! -L "$path" ]] || die "required regular file is missing: $path"
    local owner mode links
    owner=$(stat -c '%u' -- "$path") || die "cannot inspect owner: $path"
    mode=$(stat -c '%a' -- "$path") || die "cannot inspect mode: $path"
    links=$(stat -c '%h' -- "$path") || die "cannot inspect links: $path"
    [[ "$owner" == "0" && "$links" == "1" ]] || die "file identity is unsafe: $path"
    (( (8#$mode & 8#022) == 0 )) || die "file is group or world writable: $path"
}

require_root_private_directory() {
    local path=${1:?path is required}
    [[ -d "$path" && ! -L "$path" ]] || die "required real directory is missing: $path"
    local owner mode
    owner=$(stat -c '%u' -- "$path") || die "cannot inspect owner: $path"
    mode=$(stat -c '%a' -- "$path") || die "cannot inspect mode: $path"
    [[ "$owner" == "0" ]] || die "directory owner is unsafe: $path"
    (( (8#$mode & 8#022) == 0 )) || die "directory is group or world writable: $path"
}

require_root_secret_file() {
    local path=${1:?path is required}
    [[ -f "$path" && ! -L "$path" ]] || die "required secret file is missing: $path"
    local identity
    identity=$(stat -c '%u:%a:%h' -- "$path") || die "cannot inspect secret file: $path"
    [[ "$identity" == "0:600:1" ]] || die "secret file must be root-owned mode 0600 with one link: $path"
}

require_root_executable() {
    local path=${1:?executable path is required}
    local target owner mode
    target=$(realpath -e -- "$path") || die "cannot resolve executable: $path"
    [[ -f "$target" && -x "$target" && ! -L "$target" ]] \
        || die "required executable is missing: $path"
    owner=$(stat -c '%u' -- "$target") || die "cannot inspect executable owner: $path"
    mode=$(stat -c '%a' -- "$target") || die "cannot inspect executable mode: $path"
    [[ "$owner" == "0" ]] || die "executable owner is unsafe: $path"
    (( (8#$mode & 8#022) == 0 )) || die "executable is group or world writable: $path"
}

resolve_live_lineage_file() {
    local kind=${1:?lineage file kind is required}
    local live_path="$certificate_live/$kind.pem"
    [[ -L "$live_path" ]] || die "live lineage file is not a symbolic link: $live_path"
    [[ "$(stat -c '%u:%h' -- "$live_path")" == "0:1" ]] \
        || die "live lineage link identity is unsafe: $live_path"

    local link_value link_prefix link_name target target_parent target_name
    link_value=$(readlink -- "$live_path") || die "cannot read live lineage link: $live_path"
    link_prefix="../../archive/$domain/"
    [[ "$link_value" == "$link_prefix"* ]] \
        || die "live lineage link does not point directly into its dedicated archive: $live_path"
    link_name=${link_value#"$link_prefix"}
    [[ "$link_name" =~ ^${kind}[1-9][0-9]*\.pem$ ]] \
        || die "live lineage link target name is invalid: $live_path"
    target=$(realpath -e -- "$live_path") || die "cannot resolve live lineage file: $live_path"
    target_parent=$(dirname -- "$target")
    target_name=$(basename -- "$target")
    [[ "$target_parent" == "$certificate_archive" ]] \
        || die "live lineage file escapes its dedicated archive: $live_path"
    [[ "$target_name" == "$link_name" ]] \
        || die "live lineage link traverses another symbolic link: $live_path"
    printf '%s\n' "$target"
}

require_root_private_file "$nginx_config"
require_root_private_file "$nginx_http_include"
require_root_private_file "$nginx_realip_include"
require_root_private_file "$nginx_vhost"
require_root_private_file "/etc/systemd/system/$service_unit"
require_root_private_file "/etc/systemd/system/$timer_unit"
require_root_private_file "/etc/maddyweb/config.toml"
require_root_private_file "$ASSET_DIR/cloudflare-http.conf"
require_root_private_file "$ASSET_DIR/cloudflare-realip.conf"
require_root_private_file "$source_vhost"
require_root_private_file "$RENEWAL_POLICY_CHECKER"
require_root_private_file "$UNIT_ASSET_DIR/$service_unit"
require_root_private_file "$UNIT_ASSET_DIR/$timer_unit"
require_root_executable "$nginx_binary"
require_root_executable "$certbot_binary"

require_root_private_directory /opt/maddyweb
require_root_private_directory /opt/maddyweb/releases
[[ -L /opt/maddyweb/current ]] || die "current MaddyWeb release link is missing or unsafe"
[[ "$(stat -c '%u:%h' -- /opt/maddyweb/current)" == "0:1" ]] \
    || die "current MaddyWeb release link identity is unsafe"
current_release=$(realpath -e -- /opt/maddyweb/current) \
    || die "cannot resolve the current MaddyWeb release"
[[ "$current_release" =~ ^/opt/maddyweb/releases/[0-9a-f]{40}$ ]] \
    || die "current MaddyWeb release target is outside the immutable release tree"
require_root_private_directory "$current_release"
installed_python="$current_release/bin/python"
[[ -x "$installed_python" ]] || die "installed MaddyWeb Python is missing"
"$installed_python" -I -m maddyweb validate-config \
    --config /etc/maddyweb/config.toml >/dev/null \
    || die "installed MaddyWeb rejected the production configuration"
"$installed_python" -I - \
    /etc/maddyweb/config.toml "$domain" "$other_domain" "$totp_issuer" <<'PY' \
    || die "production configuration does not match the selected public-edge profile"
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

config_path, domain, other_domain, issuer = sys.argv[1:]
config = tomllib.loads(Path(config_path).read_text(encoding="utf-8"))
server = config.get("server", {})
security = config.get("security", {})
hosts = server.get("allowed_hosts")
expected_hosts = {"127.0.0.1", "localhost", domain}
if server.get("listen") != "127.0.0.1:8787":
    raise SystemExit("server.listen mismatch")
if not isinstance(hosts, list) or set(hosts) != expected_hosts or len(hosts) != len(expected_hosts):
    raise SystemExit("server.allowed_hosts mismatch")
if other_domain in hosts:
    raise SystemExit("other production hostname is present")
expected_security = {
    "auth_state_dir": "/var/lib/maddyweb-auth",
    "session_cookie_name": "__Host-maddyweb-session",
    "csrf_cookie_name": "__Host-maddyweb-csrf",
    "public_origin": f"https://{domain}",
    "totp_issuer": issuer,
}
for name, expected in expected_security.items():
    if security.get(name) != expected:
        raise SystemExit(f"security.{name} mismatch")
PY

cmp -s -- "$ASSET_DIR/cloudflare-http.conf" "$nginx_http_include" \
    || die "installed Cloudflare HTTP include drifted from the reviewed asset"
cmp -s -- "$ASSET_DIR/cloudflare-realip.conf" "$nginx_realip_include" \
    || die "installed Cloudflare trusted proxy include drifted from the reviewed asset"
cmp -s -- "$source_vhost" "$nginx_vhost" \
    || die "installed public virtual host drifted from the reviewed asset"
cmp -s -- "$UNIT_ASSET_DIR/$service_unit" "/etc/systemd/system/$service_unit" \
    || die "installed Web certificate service drifted from the reviewed asset"
cmp -s -- "$UNIT_ASSET_DIR/$timer_unit" "/etc/systemd/system/$timer_unit" \
    || die "installed Web certificate timer drifted from the reviewed asset"

if [[ "$profile" == "standalone" ]]; then
    awk '
        $0 == "# BEGIN MADDYWEB PUBLIC EDGE" {
            begin_count += 1
            begin_line = NR
        }
        $0 == "include /etc/nginx/conf.d/*.conf;" {
            directive_count += 1
            directive_line = NR
        }
        $0 == "# END MADDYWEB PUBLIC EDGE" {
            end_count += 1
            end_line = NR
        }
        END {
            valid = begin_count == 1 && directive_count == 1 && end_count == 1
            valid = valid && directive_line == begin_line + 1
            valid = valid && end_line == directive_line + 1
            exit !valid
        }
    ' "$nginx_config" \
        || die "standalone nginx managed include is not one exact contiguous block"
    if systemctl is-active --quiet "$nginx_service"; then
        die "nginx.service must remain inactive for the standalone Standalone master"
    fi
    require_root_private_file "$nginx_pid_file"
    nginx_master_pid=$(<"$nginx_pid_file")
    [[ "$nginx_master_pid" =~ ^[1-9][0-9]*$ ]] \
        || die "standalone nginx pid file is invalid"
    [[ -d "/proc/$nginx_master_pid" ]] \
        || die "standalone nginx master is not running"
    [[ "$(stat -c '%u' -- "/proc/$nginx_master_pid")" == "0" ]] \
        || die "standalone nginx master is not root-owned"
    nginx_master_executable=$(realpath -e -- "/proc/$nginx_master_pid/exe") \
        || die "cannot resolve standalone nginx master executable"
    expected_nginx_executable=$(realpath -e -- "$nginx_binary") \
        || die "cannot resolve expected nginx executable"
    [[ "$nginx_master_executable" == "$expected_nginx_executable" ]] \
        || die "standalone nginx master executable drifted"
    nginx_master_command=$(
        tr '\0' ' ' <"/proc/$nginx_master_pid/cmdline" \
            | sed -E 's/[[:space:]]+$//'
    ) || die "cannot inspect standalone nginx master command line"
    case "$nginx_master_command" in
        "nginx -c /etc/nginx/nginx.conf" \
        | "/usr/bin/nginx -c /etc/nginx/nginx.conf" \
        | "nginx: master process nginx -c /etc/nginx/nginx.conf" \
        | "nginx: master process /usr/bin/nginx -c /etc/nginx/nginx.conf")
            ;;
        *)
            die "standalone nginx master command line drifted"
            ;;
    esac
    [[ "$(<"$nginx_pid_file")" == "$nginx_master_pid" ]] \
        || die "standalone nginx master changed during validation"
else
    require_root_private_file "/etc/custom-acme/maddyweb/maddyweb-http.inc"
    require_root_private_file "$ASSET_DIR/custom-maddyweb-http.inc"
    cmp -s -- "$ASSET_DIR/custom-maddyweb-http.inc" \
        "/etc/custom-acme/maddyweb/maddyweb-http.inc" \
        || die "installed custom MaddyWeb include wrapper drifted from the reviewed asset"
    grep -Fq 'include /etc/custom-acme/maddyweb/maddyweb-http.inc;' "$nginx_config" \
        || die "custom custom nginx does not include the managed MaddyWeb fragment"
    if systemctl is-enabled --quiet nginx.service 2>/dev/null; then
        die "system nginx.service must remain disabled on the custom profile"
    fi
    nginx_exec_start=$(
        systemctl show "$nginx_service" --property=ExecStart --value
    ) || die "cannot inspect custom-acme-webroot.service start command"
    [[ "$nginx_exec_start" == *"/usr/bin/nginx -c /etc/custom-acme/nginx.conf -g daemon off;"* ]] \
        || die "custom-acme-webroot.service does not use the expected nginx command"
    nginx_exec_reload=$(
        systemctl show "$nginx_service" --property=ExecReload --value
    ) || die "cannot inspect custom-acme-webroot.service reload command"
    [[ "$nginx_exec_reload" =~ (^|[[:space:]])(-s[[:space:]]+HUP|-HUP)([[:space:]]|$) ]] \
        || die "custom-acme-webroot.service does not reload its master with HUP"
fi

"${nginx_test[@]}" >/dev/null 2>&1 || die "nginx configuration test failed"
if [[ "$profile" == "custom" ]]; then
    systemctl is-active --quiet "$nginx_service" || die "$nginx_service is not active"
fi
systemctl is-active --quiet maddyweb.service || die "maddyweb.service is not active"
systemctl is-enabled --quiet "$timer_unit" || die "$timer_unit is not enabled"
systemctl is-active --quiet "$timer_unit" || die "$timer_unit is not active"

certificate_root="/var/lib/maddyweb-web-cert"
require_root_private_directory "$certificate_root"
[[ "$(realpath -e -- "$certificate_root")" == "$certificate_root" ]] \
    || die "dedicated Web certificate root traverses a symbolic link"
require_root_private_directory "$certificate_root/config"
require_root_private_directory "$certificate_root/work"
require_root_private_directory "$certificate_root/logs"
certificate_live="$certificate_root/config/live/$domain"
certificate_archive="$certificate_root/config/archive/$domain"
require_root_private_directory "$certificate_root/config/live"
require_root_private_directory "$certificate_root/config/archive"
require_root_private_directory "$certificate_live"
require_root_private_directory "$certificate_archive"
require_root_private_file "$certificate_root/config/renewal/$domain.conf"
renewal_file="$certificate_root/config/renewal/$domain.conf"
"$installed_python" -I "$RENEWAL_POLICY_CHECKER" "$renewal_file" >/dev/null \
    || die "Web certificate lineage violates the webroot-only plugin policy"
grep -Fq "archive_dir = $certificate_root/config/archive/$domain" "$renewal_file" \
    || die "Web certificate archive path drifted"
grep -Fq "cert = $certificate_root/config/live/$domain/cert.pem" "$renewal_file" \
    || die "Web certificate live path drifted"
grep -Fq '/var/www/maddyweb-web-acme' "$renewal_file" \
    || die "Web certificate webroot drifted"

certificate_target=$(resolve_live_lineage_file fullchain)
private_key_target=$(resolve_live_lineage_file privkey)
require_root_private_file "$certificate_target"
require_root_secret_file "$private_key_target"
certificate_generation=${certificate_target##*fullchain}
certificate_generation=${certificate_generation%.pem}
private_key_generation=${private_key_target##*privkey}
private_key_generation=${private_key_generation%.pem}
[[ "$certificate_generation" == "$private_key_generation" ]] \
    || die "live certificate and private key use different archive generations"

openssl x509 -in "$certificate_target" -noout -checkend 86400 >/dev/null 2>&1 \
    || die "Web certificate is invalid, expired, or expires within 24 hours"
san_output=$(openssl x509 -in "$certificate_target" -noout -ext subjectAltName 2>/dev/null) \
    || die "cannot inspect Web certificate subject alternative names"
san_value=$(printf '%s\n' "$san_output" | sed '1d' | tr -d '[:space:]')
[[ "$san_value" == "DNS:$domain" ]] \
    || die "Web certificate subject alternative names are not exactly $domain"
certificate_public_key=$(
    openssl x509 -in "$certificate_target" -noout -pubkey 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null \
        | sha256sum
) || die "cannot derive the Web certificate public key"
private_public_key=$(
    openssl pkey -in "$private_key_target" -pubout -outform DER 2>/dev/null \
        | sha256sum
) || die "cannot derive the Web private key public key"
[[ "${certificate_public_key%% *}" == "${private_public_key%% *}" ]] \
    || die "Web certificate and private key do not match"

if ! ss -H -ltn 'sport = :8787' \
    | grep -Eq '^[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+127\.0\.0\.1:8787([[:space:]]|$)'; then
    die "MaddyWeb is not listening on loopback 127.0.0.1:8787"
fi
if ss -H -ltn 'sport = :8787' \
    | grep -Ev '127\.0\.0\.1:8787([[:space:]]|$)' \
    | grep -q .; then
    die "MaddyWeb port 8787 has a non-loopback listener"
fi

loopback_login_status=$(
    curl --noproxy '*' --silent --show-error --output /dev/null \
        --write-out '%{http_code}' --connect-timeout 3 --max-time 5 \
        --header "Host: $domain" \
        --header 'X-Forwarded-Proto: https' \
        --header 'X-Real-IP: 127.0.0.1' \
        http://127.0.0.1:8787/login
) || die "loopback MaddyWeb login probe failed"
[[ "$loopback_login_status" == "200" ]] \
    || die "loopback MaddyWeb login returned HTTP $loopback_login_status"
loopback_health_status=$(
    curl --noproxy '*' --silent --show-error --output /dev/null \
        --write-out '%{http_code}' --connect-timeout 3 --max-time 5 \
        --header 'Host: 127.0.0.1' \
        http://127.0.0.1:8787/healthz
) || die "loopback MaddyWeb health probe failed"
[[ "$loopback_health_status" == "200" ]] \
    || die "loopback MaddyWeb health returned HTTP $loopback_health_status"

direct_origin_exit=0
direct_origin_status=$(
    curl --noproxy '*' --silent --output /dev/null \
        --write-out '%{http_code}' \
        --connect-timeout 3 --max-time 5 \
        --resolve "$domain:443:127.0.0.1" "https://$domain/"
) || direct_origin_exit=$?
if (( direct_origin_exit == 0 )); then
    die "direct-origin HTTPS unexpectedly returned an HTTP response"
fi
[[ "$direct_origin_status" == "000" ]] \
    || die "direct-origin HTTPS unexpectedly returned HTTP $direct_origin_status"
case "$direct_origin_exit" in
    52|56)
        ;;
    *)
        die "direct-origin HTTPS denial probe failed unexpectedly (curl $direct_origin_exit)"
        ;;
esac

getent ahosts "$domain" >/dev/null 2>&1 \
    || die "public hostname does not resolve: $domain"
for modern_tls in 1.2 1.3; do
    modern_status=$(
        curl --noproxy '*' --silent --show-error --output /dev/null \
            --write-out '%{http_code}' \
            "--tlsv$modern_tls" --tls-max "$modern_tls" \
            --connect-timeout 5 --max-time 15 "https://$domain/login"
    ) || die "public edge does not complete TLS $modern_tls"
    [[ "$modern_status" == "200" ]] \
        || die "public edge TLS $modern_tls login returned HTTP $modern_status"
done
for legacy_tls in tls1 tls1_1; do
    legacy_output=""
    legacy_exit=0
    legacy_output=$(
        timeout 15 openssl s_client \
            -connect "$domain:443" \
            -servername "$domain" \
            "-$legacy_tls" \
            -cipher 'DEFAULT:@SECLEVEL=0' \
            </dev/null 2>&1
    ) || legacy_exit=$?
    (( legacy_exit != 0 )) \
        || die "public edge still accepts deprecated $legacy_tls"
    (( legacy_exit != 124 )) \
        || die "deprecated $legacy_tls verification timed out"
    grep -Eiq 'alert protocol version|SSL alert number 70' <<<"$legacy_output" \
        || die "deprecated $legacy_tls verification was inconclusive"
done
public_health_headers=$(
    curl --noproxy '*' --silent --show-error --dump-header - --output /dev/null \
        --connect-timeout 5 --max-time 15 "https://$domain/healthz"
) || die "public health-denial probe failed"
public_health_status=$(
    printf '%s\n' "$public_health_headers" \
        | awk 'toupper($1) ~ /^HTTP\// { status=$2 } END { print status }'
)
[[ "$public_health_status" == "404" ]] \
    || die "public health endpoint returned HTTP ${public_health_status:-unknown}, expected 404"
printf '%s\n' "$public_health_headers" \
    | grep -Eiq '^strict-transport-security:[[:space:]]*max-age=31536000[[:space:]]*$' \
    || die "public HTTPS response is missing the reviewed HSTS policy"

log "read-only public-edge check passed for $domain"
