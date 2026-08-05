#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly PREFIX="/opt/maddyweb"
readonly RELEASE_ROOT="$PREFIX/releases"
readonly CURRENT_LINK="$PREFIX/current"
readonly CONFIG_HISTORY_ROOT="/var/lib/maddyweb-config-history"
readonly CERTBOT_DEPLOY_HOOK="/etc/letsencrypt/renewal-hooks/deploy/maddyweb"
readonly CERTBOT_HOOK_MARKER="# Managed by MaddyWeb install.sh; do not edit."

usage() {
    cat <<'EOF'
Usage: rollback.sh --environment development|production --host HOST \
  --release /opt/maddyweb/releases/<40-char-commit> --artifact-sha256 HEX \
  [--app-config /etc/maddyweb/config.toml] [--approval-file PATH] [--apply]

Configuration-schema rollback:
  --restore-previous-config
  --acknowledge-public-edge-withdrawn

Optional managed-listener rollback (performed under the same approval):
  --remove-managed-submission --maddy-mode native|docker \
  --maddy-config /absolute/host/maddy.conf [mode-specific Maddy options]
  Docker host networking also requires:
  --docker-submission-scope host-loopback

By default this rolls back only the MaddyWeb release symlink. A configuration
can be restored only from the root-only history bound to the current installed
release and its recorded predecessor. An unauthenticated target additionally
requires a verified public 503 withdrawal and the explicit acknowledgement.
This never downgrades Maddy or restores Maddy state automatically. Without
--apply this is a read-only plan.
EOF
}

assert_root_private_file() {
    local path=${1:?file path is required}
    [[ -f "$path" && ! -L "$path" ]] || die "required file is missing or unsafe: $path"
    [[ "$(stat -c '%u:%g:%a:%h' -- "$path")" == "0:0:600:1" ]] \
        || die "file must be single-link root:root 0600: $path"
}

assert_config_history_root() {
    [[ -d "$CONFIG_HISTORY_ROOT" && ! -L "$CONFIG_HISTORY_ROOT" ]] \
        || die "configuration history root must be a real directory"
    [[ "$(realpath -e -- "$CONFIG_HISTORY_ROOT")" == "$CONFIG_HISTORY_ROOT" ]] \
        || die "configuration history root must be canonical"
    [[ "$(stat -c '%u:%g:%a' -- "$CONFIG_HISTORY_ROOT")" == "0:0:700" ]] \
        || die "configuration history root must be root:root 0700"
}

load_config_history() {
    assert_config_history_root
    [[ -d "$config_history_path" && ! -L "$config_history_path" ]] \
        || die "configuration rollback history is missing for the current release"
    [[ "$(realpath -e -- "$config_history_path")" == "$config_history_path" ]] \
        || die "configuration rollback history path must be canonical"
    [[ "$(stat -c '%u:%g:%a' -- "$config_history_path")" == "0:0:700" ]] \
        || die "configuration rollback history directory must be root:root 0700"

    local manifest="$config_history_path/MANIFEST"
    local previous_config="$config_history_path/previous-config.toml"
    local entry name
    local -a entries=()
    mapfile -d '' -t entries < <(
        find "$config_history_path" -xdev -mindepth 1 -maxdepth 1 -print0
    )
    [[ "${#entries[@]}" -eq 2 ]] \
        || die "configuration rollback history must contain exactly two files"
    for entry in "${entries[@]}"; do
        name=$(basename -- "$entry")
        case "$name" in
            MANIFEST|previous-config.toml) ;;
            *) die "configuration rollback history contains an unexpected entry" ;;
        esac
    done
    assert_root_private_file "$manifest"
    assert_root_private_file "$previous_config"

    local format="" installed_release="" previous_release=""
    local installed_hash="" previous_hash="" key value
    local seen_format=false seen_installed=false seen_previous=false
    local seen_installed_hash=false seen_previous_hash=false
    local line_count=0
    while IFS='=' read -r key value; do
        ((line_count += 1))
        case "$key" in
            format)
                [[ "$seen_format" == false ]] || die "duplicate configuration history field: format"
                format=$value
                seen_format=true
                ;;
            installed_release)
                [[ "$seen_installed" == false ]] \
                    || die "duplicate configuration history field: installed_release"
                installed_release=$value
                seen_installed=true
                ;;
            previous_release)
                [[ "$seen_previous" == false ]] \
                    || die "duplicate configuration history field: previous_release"
                previous_release=$value
                seen_previous=true
                ;;
            installed_config_sha256)
                [[ "$seen_installed_hash" == false ]] \
                    || die "duplicate configuration history field: installed_config_sha256"
                installed_hash=$value
                seen_installed_hash=true
                ;;
            previous_config_sha256)
                [[ "$seen_previous_hash" == false ]] \
                    || die "duplicate configuration history field: previous_config_sha256"
                previous_hash=$value
                seen_previous_hash=true
                ;;
            *)
                die "unknown configuration history field: $key"
                ;;
        esac
    done < "$manifest"

    [[ "$line_count" -eq 5 && "$format" == "maddyweb-config-rollback-v1" ]] \
        || die "configuration rollback history manifest format is invalid"
    [[ "$installed_release" == "$current" ]] \
        || die "configuration history is not bound to the current release"
    [[ "$previous_release" == "$release" ]] \
        || die "configuration history is not bound to the requested predecessor"
    [[ "$installed_hash" =~ ^[0-9a-f]{64}$ && "$previous_hash" =~ ^[0-9a-f]{64}$ ]] \
        || die "configuration history contains an invalid checksum"
    [[ "$(sha256_file "$app_config")" == "$installed_hash" ]] \
        || die "live configuration no longer matches its installed release"
    [[ "$(sha256_file "$previous_config")" == "$previous_hash" ]] \
        || die "recorded predecessor configuration checksum does not match"

    installed_config_sha256=$installed_hash
    previous_config_sha256=$previous_hash
    effective_app_config="$previous_config"
}

target_authentication_capability() {
    local manifest_profile runtime_profile
    manifest_profile=$(
        awk -F= '$1 == "authentication_profile" {print $2}' \
            "$release/INSTALL-MANIFEST"
    ) || manifest_profile=""
    runtime_profile=$(
        "$release/bin/python" -I -m maddyweb.release_attestation 2>/dev/null
    ) || runtime_profile=""
    if [[ "$manifest_profile" == required-unified-mailbox-v1 \
        && "$runtime_profile" == required-unified-mailbox-v1 ]]; then
        printf 'authenticated\n'
    else
        printf 'unauthenticated\n'
    fi
}

assert_root_managed_file() {
    local path=${1:?managed file path is required}
    [[ -f "$path" && ! -L "$path" ]] || die "managed file is missing or unsafe: $path"
    local owner mode links
    owner=$(stat -c '%u' -- "$path") || die "cannot inspect managed file owner: $path"
    mode=$(stat -c '%a' -- "$path") || die "cannot inspect managed file mode: $path"
    links=$(stat -c '%h' -- "$path") || die "cannot inspect managed file links: $path"
    [[ "$owner" == 0 && "$links" == 1 ]] \
        || die "managed file identity is unsafe: $path"
    (( (8#$mode & 8#022) == 0 )) \
        || die "managed file is group or world writable: $path"
}

select_public_edge_withdrawal() {
    current_public_origin=$(
        "$current/bin/python" -I - "$app_config" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as handle:
    config = tomllib.load(handle)
print(config.get("security", {}).get("public_origin", ""))
PY
    ) || die "cannot read the current public origin"
    case "$current_public_origin" in
        https://maddy.standalone.example.test)
            public_domain="maddy.standalone.example.test"
            withdrawn_source="$current/public-edge/nginx/maddy.standalone.example.test.withdrawn.conf"
            installed_public_vhost="/etc/nginx/conf.d/maddy.standalone.example.test.conf"
            nginx_test=(/usr/bin/nginx -t -c /etc/nginx/nginx.conf)
            ;;
        https://maddy.custom.example.test)
            public_domain="maddy.custom.example.test"
            withdrawn_source="$current/public-edge/nginx/maddy.custom.example.test.withdrawn.conf"
            installed_public_vhost="/etc/custom-acme/maddyweb/maddy.custom.example.test.conf"
            nginx_test=(/usr/bin/nginx -t -c /etc/custom-acme/nginx.conf)
            ;;
        *)
            die "unauthenticated rollback requires one supported public-edge profile"
            ;;
    esac
}

verify_public_edge_withdrawal() {
    assert_root_managed_file "$withdrawn_source"
    assert_root_managed_file "$installed_public_vhost"
    cmp -s -- "$withdrawn_source" "$installed_public_vhost" \
        || die "public edge is not the exact reviewed 503 withdrawal asset"
    "${nginx_test[@]}" >/dev/null 2>&1 \
        || die "withdrawn public-edge Nginx configuration test failed"
    local nonce status
    nonce="$(date +%s)-$$-${RANDOM}"
    status=$(
        curl --noproxy '*' --silent --show-error --output /dev/null \
            --write-out '%{http_code}' --connect-timeout 5 --max-time 15 \
            --header 'Cache-Control: no-cache' \
            "https://$public_domain/?maddyweb-withdrawal=$nonce"
    ) || die "public withdrawal probe failed"
    [[ "$status" == 503 ]] \
        || die "public edge returned HTTP $status instead of the required 503"
}

environment=""
target_host=""
release=""
expected_sha256=""
approval_file=""
app_config="/etc/maddyweb/config.toml"
restore_previous_config=false
acknowledge_public_edge_withdrawn=false
remove_submission=false
maddy_mode=""
maddy_config=""
maddy_binary=""
docker_binary="$(command -v docker || true)"
container=""
docker_submission_scope="container"
submission_backup_dir="/var/backups/maddyweb/submission"
allow_downtime=false
apply=false

while (($#)); do
    case "$1" in
        --environment) (($# >= 2)) || die "--environment requires a value"; environment=$2; shift 2 ;;
        --host) (($# >= 2)) || die "--host requires a value"; target_host=$2; shift 2 ;;
        --release) (($# >= 2)) || die "--release requires a value"; release=$2; shift 2 ;;
        --artifact-sha256) (($# >= 2)) || die "--artifact-sha256 requires a value"; expected_sha256=${2,,}; shift 2 ;;
        --app-config) (($# >= 2)) || die "--app-config requires a value"; app_config=$2; shift 2 ;;
        --approval-file) (($# >= 2)) || die "--approval-file requires a value"; approval_file=$2; shift 2 ;;
        --restore-previous-config) restore_previous_config=true; shift ;;
        --acknowledge-public-edge-withdrawn) acknowledge_public_edge_withdrawn=true; shift ;;
        --remove-managed-submission) remove_submission=true; shift ;;
        --maddy-mode) (($# >= 2)) || die "--maddy-mode requires a value"; maddy_mode=$2; shift 2 ;;
        --maddy-config) (($# >= 2)) || die "--maddy-config requires a value"; maddy_config=$2; shift 2 ;;
        --maddy-binary) (($# >= 2)) || die "--maddy-binary requires a value"; maddy_binary=$2; shift 2 ;;
        --docker-binary) (($# >= 2)) || die "--docker-binary requires a value"; docker_binary=$2; shift 2 ;;
        --container) (($# >= 2)) || die "--container requires a value"; container=$2; shift 2 ;;
        --docker-submission-scope) (($# >= 2)) || die "--docker-submission-scope requires a value"; docker_submission_scope=$2; shift 2 ;;
        --submission-backup-dir) (($# >= 2)) || die "--submission-backup-dir requires a value"; submission_backup_dir=$2; shift 2 ;;
        --allow-downtime) allow_downtime=true; shift ;;
        --apply) apply=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$environment" in development|production) ;; *) die "--environment must be development or production" ;; esac
case "$docker_submission_scope" in
    container|host-loopback) ;;
    *) die "--docker-submission-scope must be container or host-loopback" ;;
esac
[[ -n "$target_host" && "$target_host" == "$(hostname)" ]] || die "--host must exactly match $(hostname)"
[[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || die "--artifact-sha256 must be 64 lowercase hexadecimal characters"
require_command realpath
require_command find
require_directory "$release" "rollback release"
require_path_below "$release" "$RELEASE_ROOT"
[[ "$(realpath -e -- "$release")" == "$release" ]] \
    || die "rollback release path must be canonical and traverse no symbolic link"
release_commit=$(basename -- "$release")
[[ "$release_commit" =~ ^[0-9a-f]{40}$ ]] || die "rollback release directory must be a full lowercase commit"
[[ -x "$release/bin/python" ]] || die "rollback release has no executable Python"
require_regular_file "$app_config" "MaddyWeb config"
assert_private_file_mode "$app_config"
[[ "$(realpath -e -- "$app_config")" == "$app_config" ]] \
    || die "MaddyWeb config path must be canonical and traverse no symbolic link"
if [[ "$environment" == production ]]; then
    [[ "$app_config" == /etc/maddyweb/config.toml ]] \
        || die "production requires --app-config exactly /etc/maddyweb/config.toml"
    expected_web_gid=$(id -g maddyweb) || die "cannot resolve maddyweb group"
    [[ "$(stat -c '%u:%g:%a:%h' -- "$app_config")" == "0:${expected_web_gid}:640:1" ]] \
        || die "production MaddyWeb config must be single-link root-owned mode 0640 with the maddyweb group"
fi
[[ -L "$CURRENT_LINK" ]] || die "current release link is missing or unsafe"
[[ "$(stat -c '%u:%h' -- "$CURRENT_LINK")" == "0:1" ]] \
    || die "current release link identity is unsafe"
current=$(readlink -f -- "$CURRENT_LINK")
require_path_below "$current" "$RELEASE_ROOT"
[[ "$current" =~ ^${RELEASE_ROOT}/[0-9a-f]{40}$ ]] \
    || die "current release target is not a full lowercase commit"
[[ "$current" != "$release" ]] || die "requested release is already current"
[[ -x "$current/bin/python" ]] || die "current release has no executable Python"
require_regular_file "$release/INSTALL-MANIFEST" "release manifest"
manifest_sha=$(awk -F= '$1 == "sha256" {print $2}' "$release/INSTALL-MANIFEST")
manifest_commit=$(awk -F= '$1 == "commit" {print $2}' "$release/INSTALL-MANIFEST")
[[ "$manifest_sha" == "$expected_sha256" ]] || die "release manifest checksum does not match explicit artifact checksum"
[[ "$manifest_commit" == "$release_commit" ]] || die "release manifest commit does not match its directory"
"$release/bin/python" -m maddyweb --help >/dev/null || die "rollback release cannot import maddyweb"

target_authentication=$(target_authentication_capability) \
    || die "cannot determine rollback target authentication capability"
case "$target_authentication" in
    authenticated|unauthenticated) ;;
    *) die "rollback target returned an invalid authentication capability" ;;
esac

target_filter_capability=unsupported
if "$release/bin/python" -I -c \
    'import maddyweb.filter_bridge, maddyweb.filter_client' >/dev/null 2>&1; then
    target_filter_help=$(
        "$release/bin/python" -I -m maddyweb filter-bridge --help 2>/dev/null
    ) || target_filter_help=""
    if [[ "$target_filter_help" == *--listen* \
        && "$target_filter_help" == *--token-file* \
        && "$target_filter_help" != *--config* ]]; then
        target_filter_capability=supported
    fi
fi
current_filter_profile=$(
    "$current/bin/python" -I - "$app_config" <<'PY'
from __future__ import annotations

import json
import sys
from maddyweb.config import load_config

config = load_config(sys.argv[1])
print(json.dumps({
    "mode": config.maddy.mode,
    "config": str(config.maddy.config_path),
    "container": config.maddy.container or "",
}, sort_keys=True, separators=(",", ":")))
PY
) || die "cannot inspect the current filter deployment profile"
current_filter_mode=$("$current/bin/python" -c \
    'import json,sys; print(json.loads(sys.argv[1])["mode"])' "$current_filter_profile")
current_filter_config=$("$current/bin/python" -c \
    'import json,sys; print(json.loads(sys.argv[1])["config"])' "$current_filter_profile")
current_filter_container=$("$current/bin/python" -c \
    'import json,sys; print(json.loads(sys.argv[1])["container"])' "$current_filter_profile")

managed_filter_marker_present() {
    if [[ "$current_filter_mode" == native ]]; then
        [[ -f "$current_filter_config" && ! -L "$current_filter_config" ]] \
            || die "current native Maddy config is missing or unsafe"
        grep -Fq '# BEGIN MADDYWEB MANAGED IMAP FILTER v1' "$current_filter_config"
    else
        [[ -n "$docker_binary" && -x "$docker_binary" ]] \
            || die "Docker is required to inspect the current managed filter"
        [[ "$current_filter_container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] \
            || die "current Maddy container name is invalid"
        [[ "$current_filter_config" == /data/maddy.conf ]] \
            || die "current Docker Maddy config path is unsupported"
        "$docker_binary" exec "$current_filter_container" /bin/busybox grep -Fq \
            '# BEGIN MADDYWEB MANAGED IMAP FILTER v1' /data/maddy.conf
    fi
}

if [[ "$target_filter_capability" == unsupported ]]; then
    if managed_filter_marker_present; then
        die "rollback target lacks the managed delivery filter; run configure-filter.sh --action remove first"
    fi
    if command -v systemctl >/dev/null 2>&1 \
        && { systemctl is-active --quiet maddyweb-filter.service \
            || systemctl is-enabled --quiet maddyweb-filter.service; }; then
        die "rollback target lacks the managed delivery filter; disable it through configure-filter.sh --action remove first"
    fi
fi

effective_app_config="$app_config"
installed_config_sha256=$(sha256_file "$app_config")
previous_config_sha256=""
config_history_path=""
if [[ "$restore_previous_config" == true ]]; then
    [[ "$app_config" == /etc/maddyweb/config.toml ]] \
        || die "--restore-previous-config requires /etc/maddyweb/config.toml"
    require_root
    config_history_path="$CONFIG_HISTORY_ROOT/$(basename -- "$current")"
    load_config_history
fi

public_domain=""
current_public_origin=""
withdrawn_source=""
installed_public_vhost=""
nginx_test=()
if [[ "$target_authentication" == unauthenticated ]]; then
    [[ "$restore_previous_config" == true ]] \
        || die "an unauthenticated rollback target requires --restore-previous-config"
    [[ "$acknowledge_public_edge_withdrawn" == true ]] \
        || die "an unauthenticated rollback target requires --acknowledge-public-edge-withdrawn"
    require_command cmp
    require_command curl
    select_public_edge_withdrawal
    verify_public_edge_withdrawal
elif [[ "$acknowledge_public_edge_withdrawn" == true ]]; then
    die "--acknowledge-public-edge-withdrawn is valid only for an unauthenticated target"
fi

"$release/bin/python" -I -c \
    'import sys; from maddyweb.config import load_config; load_config(sys.argv[1])' \
    "$effective_app_config" \
    || die "rollback release cannot load the effective MaddyWeb configuration"

if [[ -f "$CERTBOT_DEPLOY_HOOK" && ! -L "$CERTBOT_DEPLOY_HOOK" ]]; then
    hook_lines=()
    mapfile -t -n 2 hook_lines < "$CERTBOT_DEPLOY_HOOK" || true
    hook_second_line=${hook_lines[1]-}
    if [[ "$hook_second_line" == "$CERTBOT_HOOK_MARKER" ]]; then
        [[ "$(stat -c '%u:%g:%a:%h' -- "$CERTBOT_DEPLOY_HOOK")" == "0:0:755:1" ]] \
            || die "managed Certbot deploy hook metadata is unsafe"
        certbot_driver="$release/libexec/certbot-deploy-hook.py"
        [[ -f "$certbot_driver" && ! -L "$certbot_driver" ]] \
            || die "rollback release lacks the managed Certbot deploy-hook driver"
        driver_metadata=$(stat -c '%u:%a:%h' -- "$certbot_driver") \
            || die "cannot inspect rollback release Certbot deploy-hook driver"
        IFS=: read -r driver_owner driver_mode driver_links <<< "$driver_metadata"
        [[ "$driver_owner" == 0 && "$driver_links" == 1 ]] \
            || die "rollback release Certbot deploy-hook driver ownership is unsafe"
        (( (8#$driver_mode & 8#022) == 0 )) \
            || die "rollback release Certbot deploy-hook driver permissions are unsafe"
    fi
fi

submission_version=""
container_before=""
container_id=""
if [[ "$remove_submission" == true ]]; then
    case "$maddy_mode" in native|docker) ;; *) die "managed removal requires --maddy-mode native or docker" ;; esac
    require_absolute_path "$submission_backup_dir" "submission backup directory"
    if [[ "$maddy_mode" == native ]]; then
        [[ "$docker_submission_scope" == container ]] \
            || die "--docker-submission-scope is valid only in docker mode"
        require_regular_file "$maddy_config" "host Maddy config"
        "$release/bin/python" "$SCRIPT_DIR/manage-submission.py" \
            --action check-remove --config "$maddy_config" >/dev/null
        [[ -n "$maddy_binary" && -z "$container" ]] || die "native managed removal requires --maddy-binary and no container"
        submission_version=$(assert_supported_maddy "$maddy_binary")
        "$release/bin/python" "$SCRIPT_DIR/validate-config.py" \
            --config "$effective_app_config" --expected-host 127.0.0.1 --expected-port 8787 \
            --expected-maddy-mode native --expected-maddy-binary "$maddy_binary" \
            --expected-maddy-config "$maddy_config" >/dev/null
    else
        [[ "$container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || die "Docker managed removal requires a safe container"
        require_absolute_path "$docker_binary" "Docker binary"
        container_before=$("$release/bin/python" "$SCRIPT_DIR/check-maddy-container.py" \
            --docker "$docker_binary" --container "$container" --host-config "$maddy_config")
        container_id=$("$release/bin/python" -c \
            'import json,sys; print(json.loads(sys.argv[1])["id"])' \
            "$container_before")
        [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] \
            || die "container inspection returned an invalid container ID"
        rollback_config_kind=$("$release/bin/python" -c \
            'import json,sys; print(json.loads(sys.argv[1])["config_kind"])' \
            "$container_before")
        network_mode=$("$release/bin/python" -c \
            'import json,sys; print(json.loads(sys.argv[1])["network_mode"])' \
            "$container_before")
        if [[ "$docker_submission_scope" == host-loopback ]]; then
            [[ "$network_mode" == host ]] \
                || die "host-loopback scope requires Docker host networking"
        else
            [[ "$network_mode" != host && "$network_mode" != container:* ]] \
                || die "container scope requires an isolated Docker network namespace"
        fi
        [[ "$rollback_config_kind" == bind ]] \
            || die "combined rollback only supports a host-bind Maddy config; remove named-volume Submission separately"
        require_regular_file "$maddy_config" "host Maddy config"
        "$release/bin/python" "$SCRIPT_DIR/manage-submission.py" \
            --action check-remove --config "$maddy_config" >/dev/null
        version_output=$("$docker_binary" exec "$container_id" /bin/maddy version 2>&1) || die "container Maddy version failed"
        submission_version=$(extract_maddy_version "$version_output")
        version_in_supported_range "$submission_version" || die "unsupported container Maddy version"
        "$release/bin/python" "$SCRIPT_DIR/validate-config.py" \
            --config "$effective_app_config" --expected-host 127.0.0.1 --expected-port 8787 \
            --expected-maddy-mode docker --expected-container "$container" \
            --expected-maddy-config /data/maddy.conf --expected-maddy-data /data \
            >/dev/null
        configured_submission_scope=$("$release/bin/python" - "$effective_app_config" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as handle:
    config = tomllib.load(handle)
print(config["maddy"].get("docker_submission_scope", "container"))
PY
) || die "cannot read Docker Submission scope from validated config"
        [[ "$configured_submission_scope" == "$docker_submission_scope" ]] \
            || die "--docker-submission-scope must match maddy.docker_submission_scope"
    fi
    if [[ "$submission_version" == 0.8.2 && "$apply" == true && "$allow_downtime" != true ]]; then
        die "Maddy 0.8.2 managed removal requires --allow-downtime for a short restart"
    fi
elif [[ -n "$maddy_mode$maddy_config$maddy_binary$container" \
    || "$docker_submission_scope" != container ]]; then
    die "managed Maddy options require --remove-managed-submission"
fi

printf 'environment=%s\nhost=%s\nfrom=%s\nto=%s\ncommit=%s\nartifact_sha256=%s\ntarget_authentication=%s\ntarget_filter=%s\nrestore_previous_config=%s\ninstalled_config_sha256=%s\nprevious_config_sha256=%s\npublic_withdrawal=%s\nremove_managed_submission=%s\ndocker_submission_scope=%s\nnetwork_mode=%s\n' \
    "$environment" "$target_host" "$current" "$release" "$release_commit" \
    "$expected_sha256" "$target_authentication" "$target_filter_capability" \
    "$restore_previous_config" \
    "$installed_config_sha256" "${previous_config_sha256:-none}" \
    "${public_domain:-none}" "$remove_submission" "$docker_submission_scope" \
    "${network_mode:-native}"

if [[ "$apply" != true ]]; then
    log "dry-run complete; pass --apply only after reviewing the plan"
    exit 0
fi
require_root
if [[ "$environment" == "production" ]]; then
    [[ -n "$approval_file" ]] || die "production --apply requires --approval-file"
    consume_production_approval "$approval_file" rollback
elif [[ -n "$approval_file" ]]; then
    die "approval files are accepted only for production"
fi
require_command systemctl
require_command sync
require_command flock
require_command install

filter_was_active=false
if systemctl is-active --quiet maddyweb-filter.service; then
    filter_was_active=true
fi
if [[ "$target_filter_capability" == unsupported ]]; then
    if managed_filter_marker_present \
        || [[ "$filter_was_active" == true ]] \
        || systemctl is-enabled --quiet maddyweb-filter.service; then
        die "managed delivery filter state changed or was not removed before incompatible rollback"
    fi
fi

[[ "$(stat -c '%u:%g:%a' -- "$MADDYWEB_APPROVAL_ROOT")" == "0:0:700" ]] \
    || die "approval runtime directory must be root:root 0700"
deployment_lock="$MADDYWEB_APPROVAL_ROOT/deployment.lock"
exec {deployment_lock_fd}>> "$deployment_lock"
[[ "$(stat -c '%u:%g:%a:%h' -- "$deployment_lock")" == "0:0:600:1" ]] \
    || die "deployment lock must be single-link root:root 0600"
flock -n "$deployment_lock_fd" || die "another MaddyWeb deployment transaction is active"

if [[ -e "$CONFIG_HISTORY_ROOT" || -L "$CONFIG_HISTORY_ROOT" ]]; then
    assert_config_history_root
else
    install -d -o root -g root -m 0700 -- "$CONFIG_HISTORY_ROOT"
    assert_config_history_root
fi
if [[ "$restore_previous_config" == true ]]; then
    load_config_history
fi
if [[ "$target_authentication" == unauthenticated ]]; then
    verify_public_edge_withdrawal
fi

submission_backup=""
submission_candidate_hash=""
submission_edit_started=false
native_pid_before=""
rollback_transaction_active=false
config_transaction_dir=""
config_backup=""
config_candidate=""
config_temporary="/etc/maddyweb/.config.toml.rollback-$$"
config_recovery_temporary="/etc/maddyweb/.config.toml.rollback-recovery-$$"
config_edit_started=false
expected_web_gid=$(id -g maddyweb) || die "cannot resolve maddyweb group"

assert_live_config() {
    local expected_hash=${1:?expected configuration checksum is required}
    [[ -f "$app_config" && ! -L "$app_config" ]] || return 1
    [[ "$(stat -c '%u:%g:%a:%h' -- "$app_config" 2>/dev/null)" \
        == "0:${expected_web_gid}:640:1" ]] || return 1
    [[ "$(sha256_file "$app_config" 2>/dev/null)" == "$expected_hash" ]]
}

quiesce_maddyweb_units() {
    local unit status=0
    local -a units=(maddyweb.service maddyweb-helper.socket maddyweb-helper.service)
    if [[ "$filter_was_active" == true ]]; then
        units=(maddyweb-filter.service "${units[@]}")
    fi
    for unit in "${units[@]}"; do
        systemctl stop "$unit" || status=1
    done
    for unit in "${units[@]}"; do
        if systemctl is-active --quiet "$unit"; then status=1; fi
    done
    return "$status"
}

atomic_install_config() {
    local source=${1:?configuration source is required}
    local expected_hash=${2:?configuration checksum is required}
    local temporary=${3:?configuration temporary path is required}
    [[ ! -e "$temporary" && ! -L "$temporary" ]] || return 1
    install -o root -g maddyweb -m 0640 -- "$source" "$temporary" \
        && mv -fT -- "$temporary" "$app_config" \
        && sync -f "$(dirname -- "$app_config")" \
        && assert_live_config "$expected_hash"
}

cleanup_config_transaction() {
    local status=0
    rm -f -- "$config_temporary" "$config_recovery_temporary" || status=1
    if [[ -n "$config_transaction_dir" ]]; then
        rm -f -- "$config_transaction_dir/current-config.toml" \
            "$config_transaction_dir/previous-config.toml" || status=1
        rmdir -- "$config_transaction_dir" || status=1
    fi
    return "$status"
}

prepare_config_transaction() {
    [[ "$restore_previous_config" == true ]] || return 0
    assert_live_config "$installed_config_sha256" \
        || return 1
    config_transaction_dir=$(
        mktemp -d --tmpdir="$MADDYWEB_APPROVAL_ROOT" .rollback-config.XXXXXXXX
    ) || return 1
    case "$config_transaction_dir" in
        "$MADDYWEB_APPROVAL_ROOT"/.rollback-config.*) ;;
        *) return 1 ;;
    esac
    [[ "$(stat -c '%u:%g:%a' -- "$config_transaction_dir")" == "0:0:700" ]] \
        || return 1
    config_backup="$config_transaction_dir/current-config.toml"
    config_candidate="$config_transaction_dir/previous-config.toml"
    install -o root -g root -m 0600 -- "$app_config" "$config_backup" \
        || return 1
    install -o root -g root -m 0600 -- "$effective_app_config" "$config_candidate" \
        || return 1
    [[ -f "$config_backup" && ! -L "$config_backup" \
        && "$(stat -c '%u:%g:%a:%h' -- "$config_backup")" == "0:0:600:1" ]] \
        || return 1
    [[ -f "$config_candidate" && ! -L "$config_candidate" \
        && "$(stat -c '%u:%g:%a:%h' -- "$config_candidate")" == "0:0:600:1" ]] \
        || return 1
    [[ "$(sha256_file "$config_backup")" == "$installed_config_sha256" ]] \
        || return 1
    [[ "$(sha256_file "$config_candidate")" == "$previous_config_sha256" ]] \
        || return 1
}

switch_link() {
    local target=${1:?target is required}
    local link="$PREFIX/.current-rollback-$$"
    if ! ln -s -- "$target" "$link" || ! mv -Tf -- "$link" "$CURRENT_LINK"; then
        if [[ -L "$link" ]]; then rm -f -- "$link" || true; fi
        return 1
    fi
}

container_snapshot_matches() {
    local after=${1:?container snapshot is required}
    "$release/bin/python" -c 'import json,sys
before, after = map(json.loads, sys.argv[1:])
keys=("id","mounts_sha256","ports_sha256","restart_policy_sha256",
      "network_mode","config_source")
raise SystemExit(any(before.get(k) != after.get(k) for k in keys))' \
        "$container_before" "$after"
}

managed_listener_gate() {
    local expected=${1:?expected listener state is required}
    local listeners
    listeners=$(ss -H -ltn 'sport = :1587' 2>/dev/null | awk '{print $4}')
    if [[ "$maddy_mode" == native \
        || "$docker_submission_scope" == host-loopback ]]; then
        if [[ "$expected" == present ]]; then
            [[ "$listeners" == "127.0.0.1:1587" ]]
        else
            [[ -z "$listeners" ]]
        fi
    else
        [[ -z "$listeners" ]]
    fi
    if [[ "$maddy_mode" == docker ]]; then
        local table listener_summary
        table=$(
            "$docker_binary" exec "$container_id" \
                /bin/cat /proc/net/tcp /proc/net/tcp6 2>/dev/null
        ) || return 1
        listener_summary=$(
            printf '%s\n' "$table" \
                | awk '$2 ~ /:0633$/ && $4 == "0A" {
                    count += 1
                    if ($2 == "0100007F:0633") exact += 1
                }
                END {print count + 0 ":" exact + 0}'
        )
        if [[ "$expected" == present ]]; then
            [[ "$listener_summary" == 1:1 ]] || return 1
            "$docker_binary" exec "$container_id" /usr/bin/nc -z -w 2 127.0.0.1 1587 \
                >/dev/null 2>&1
        else
            [[ "$listener_summary" == 0:0 ]]
        fi
    fi
}

verify_submission_config() {
    if [[ "$submission_version" == 0.8.2 ]]; then return 0; fi
    if [[ "$maddy_mode" == native ]]; then
        "$maddy_binary" -config "$maddy_config" verify-config >/dev/null 2>&1
    else
        "$docker_binary" exec "$container_id" /bin/maddy -config /data/maddy.conf \
            verify-config >/dev/null 2>&1
    fi
}

reload_submission_config() {
    if [[ "$maddy_mode" == native ]]; then
        if [[ "$submission_version" == 0.8.2 ]]; then
            systemctl restart maddy.service
        else
            systemctl kill --kill-who=main --signal=SIGUSR2 maddy.service
        fi
    elif [[ "$submission_version" == 0.8.2 ]]; then
        "$docker_binary" restart --time 10 "$container_id" >/dev/null
    else
        "$docker_binary" kill --signal=SIGUSR2 "$container_id" >/dev/null
    fi
}

maddy_state_gate() {
    if [[ "$maddy_mode" == native ]]; then
        local pid
        systemctl is-active --quiet maddy.service || return 1
        pid=$(systemctl show --property MainPID --value maddy.service) || return 1
        [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
        if [[ "$submission_version" != 0.8.2 && "$pid" != "$native_pid_before" ]]; then
            return 1
        fi
    else
        local after="" health version_output
        for _ in {1..50}; do
            after=$("$release/bin/python" "$SCRIPT_DIR/check-maddy-container.py" \
                --docker "$docker_binary" --container "$container_id" \
                --host-config "$maddy_config" 2>/dev/null) && break
            sleep 0.2
        done
        [[ -n "$after" ]] || return 1
        container_snapshot_matches "$after" || return 1
        health=$("$release/bin/python" -c \
            'import json,sys; print(json.loads(sys.argv[1]).get("health") or "none")' \
            "$after") || return 1
        [[ "$health" == none || "$health" == healthy ]] || return 1
        version_output=$("$docker_binary" exec "$container_id" /bin/maddy version 2>&1) \
            || return 1
        [[ "$(extract_maddy_version "$version_output")" == "$submission_version" ]]
    fi
}

restore_submission() {
    local status=0 restored=false reloaded=false
    if [[ "$submission_edit_started" != true ]]; then return 0; fi
    [[ -n "$submission_backup" && -n "$submission_candidate_hash" ]] || return 1
    if "$release/bin/python" "$SCRIPT_DIR/manage-submission.py" --action restore \
        --config "$maddy_config" --backup "$submission_backup" \
        --expected-current-sha256 "$submission_candidate_hash" >/dev/null; then
        restored=true
    else
        status=1
    fi
    if [[ "$restored" == true ]]; then
        if verify_submission_config; then
            if reload_submission_config; then
                reloaded=true
            else
                status=1
            fi
        else
            status=1
        fi
    fi
    if [[ "$reloaded" == true ]]; then
        maddy_state_gate || status=1
        managed_listener_gate present || status=1
    fi
    return "$status"
}

restore_previous_release_state() {
    local status=0 quiesced=false restored_link=false restored_config=true restored_current
    rollback_transaction_active=false
    log "restoring the exact pre-rollback release, configuration, and managed Submission state"
    if quiesce_maddyweb_units; then quiesced=true; else status=1; fi
    if switch_link "$current"; then restored_link=true; else status=1; fi
    if [[ "$config_edit_started" == true ]]; then
        restored_config=false
        rm -f -- "$config_temporary" "$config_recovery_temporary" || status=1
        if [[ "$quiesced" == true ]] \
            && atomic_install_config \
                "$config_backup" "$installed_config_sha256" "$config_recovery_temporary"; then
            restored_config=true
        else
            status=1
        fi
    fi
    if [[ "$remove_submission" == true ]]; then restore_submission || status=1; fi
    if (( status == 0 )) && [[ "$quiesced" == true \
        && "$restored_link" == true && "$restored_config" == true ]]; then
        if [[ "$filter_was_active" == true ]]; then
            systemctl restart maddyweb-filter.service || status=1
            systemctl is-active --quiet maddyweb-filter.service || status=1
        fi
        systemctl restart maddyweb-helper.socket maddyweb.service || status=1
        systemctl try-restart maddyweb-helper.service || status=1
        restored_current=$(readlink -f -- "$CURRENT_LINK" 2>/dev/null) || status=1
        [[ "${restored_current:-}" == "$current" ]] || status=1
        systemctl is-active --quiet maddyweb-helper.socket maddyweb.service || status=1
        "$current/bin/python" "$SCRIPT_DIR/smoke-test.py" || status=1
    else
        status=1
    fi
    cleanup_config_transaction || status=1
    if (( status != 0 )); then
        log "CRITICAL: rollback candidate failed and restoration of the previous state was incomplete"
    fi
    return "$status"
}

abort_rollback_transaction() {
    local reason=${1:-rollback candidate failed}
    rollback_transaction_active=false
    trap - EXIT INT TERM
    if restore_previous_release_state; then
        die "$reason; exact previous release, configuration, and managed Submission state were restored"
    fi
    die "$reason and restoration of the previous state was incomplete"
}

on_rollback_exit() {
    local status=$?
    trap - EXIT INT TERM
    if [[ "$rollback_transaction_active" == true ]]; then
        (( status != 0 )) || status=1
        restore_previous_release_state \
            || log "CRITICAL: unexpected rollback exit left restoration incomplete"
    fi
    exit "$status"
}

if [[ "$remove_submission" == true ]]; then
    require_command ss
    if [[ "$maddy_mode" == native ]]; then
        systemctl is-active --quiet maddy.service || die "maddy.service is not active"
        native_pid_before=$(systemctl show --property MainPID --value maddy.service)
        [[ "$native_pid_before" =~ ^[1-9][0-9]*$ ]] || die "maddy.service MainPID is invalid"
    else
        container_after_approval=$("$release/bin/python" "$SCRIPT_DIR/check-maddy-container.py" \
            --docker "$docker_binary" --container "$container" --host-config "$maddy_config")
        container_snapshot_matches "$container_after_approval" \
            || die "Maddy container identity changed after the reviewed rollback plan"
    fi
    managed_listener_gate present \
        || die "managed Submission is not active on exactly its loopback endpoint"
fi

rollback_transaction_active=true
trap on_rollback_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

prepare_config_transaction \
    || abort_rollback_transaction "cannot prepare the root-only configuration transaction"

if [[ "$remove_submission" == true ]]; then
    install -d -o root -g root -m 0700 -- "$submission_backup_dir"
    submission_edit_started=true
    edit_report=$("$release/bin/python" "$SCRIPT_DIR/manage-submission.py" --action remove \
        --config "$maddy_config" --backup-dir "$submission_backup_dir")
    submission_backup=$("$release/bin/python" -c 'import json,sys; print(json.loads(sys.argv[1])["backup"])' "$edit_report")
    submission_candidate_hash=$("$release/bin/python" -c 'import json,sys; print(json.loads(sys.argv[1])["after_sha256"])' "$edit_report")
    require_regular_file "$submission_backup" "Maddy configuration backup"
    [[ "$submission_candidate_hash" =~ ^[0-9a-f]{64}$ ]] \
        || abort_rollback_transaction "managed Submission editor returned an invalid candidate hash"
    if ! verify_submission_config \
        || ! reload_submission_config \
        || ! maddy_state_gate \
        || ! managed_listener_gate absent; then
        abort_rollback_transaction "managed Submission removal failed its verification gate"
    fi
fi

if [[ "$target_authentication" == unauthenticated ]]; then
    verify_public_edge_withdrawal
fi
if [[ "$restore_previous_config" == true ]]; then
    quiesce_maddyweb_units \
        || abort_rollback_transaction "cannot quiesce MaddyWeb for configuration restoration"
    assert_live_config "$installed_config_sha256" \
        || abort_rollback_transaction "live configuration changed before restoration"
    [[ "$(sha256_file "$config_candidate")" == "$previous_config_sha256" ]] \
        || abort_rollback_transaction "staged predecessor configuration changed"
    config_edit_started=true
    atomic_install_config \
        "$config_candidate" "$previous_config_sha256" "$config_temporary" \
        || abort_rollback_transaction "predecessor configuration restoration failed"
fi

switch_link "$release" || abort_rollback_transaction "rollback release switch failed"
if [[ "$filter_was_active" == true ]] \
    && { ! systemctl restart maddyweb-filter.service \
        || ! systemctl is-active --quiet maddyweb-filter.service; }; then
    abort_rollback_transaction "rollback delivery filter activation failed"
fi
if ! systemctl restart maddyweb-helper.socket maddyweb.service \
    || ! systemctl try-restart maddyweb-helper.service \
    || ! systemctl is-active --quiet maddyweb-helper.socket maddyweb.service \
    || ! "$release/bin/python" "$SCRIPT_DIR/smoke-test.py"; then
    abort_rollback_transaction "rollback candidate activation or smoke gate failed"
fi
previous_release_record="$CONFIG_HISTORY_ROOT/previous-release"
if [[ -e "$previous_release_record" || -L "$previous_release_record" ]]; then
    [[ -f "$previous_release_record" && ! -L "$previous_release_record" \
        && "$(stat -c '%u:%g:%a:%h' -- "$previous_release_record")" == "0:0:600:1" ]] \
        || abort_rollback_transaction "previous-release metadata target is unsafe"
fi
previous_release_temp=$(
    mktemp --tmpdir="$CONFIG_HISTORY_ROOT" .previous-release.XXXXXXXX
) || abort_rollback_transaction "previous-release metadata staging failed"
if ! printf '%s\n' "$current" > "$previous_release_temp" \
    || ! chmod 0600 -- "$previous_release_temp" \
    || ! mv -fT -- "$previous_release_temp" "$previous_release_record" \
    || ! sync -f "$CONFIG_HISTORY_ROOT" \
    || [[ "$(stat -c '%u:%g:%a:%h' -- "$previous_release_record" 2>/dev/null)" \
        != "0:0:600:1" ]] \
    || [[ "$(<"$previous_release_record")" != "$current" ]]; then
    rm -f -- "$previous_release_temp" || true
    abort_rollback_transaction "previous-release metadata update failed"
fi
rollback_transaction_active=false
trap - EXIT INT TERM
if ! cleanup_config_transaction; then
    die "rollback completed but its root-only runtime configuration backup could not be removed"
fi
log "rollback completed: $release"
