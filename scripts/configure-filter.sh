#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    cat <<'EOF'
Usage: configure-filter.sh --action add|remove \
  --environment development|production --host HOST \
  [--app-config /etc/maddyweb/config.toml] [--python /opt/maddyweb/current/bin/python] \
  [--docker-binary /usr/bin/docker] [--approval-file PATH] [--apply]

Adds or removes only MaddyWeb's marked storage.imapsql imap_filter block.
Production apply requires a fresh approval for filter-add or filter-remove.
EOF
}

action=""
environment=""
target_host=""
app_config="/etc/maddyweb/config.toml"
python_binary="/opt/maddyweb/current/bin/python"
docker_binary="$(command -v docker || true)"
approval_file=""
apply=false

while (($#)); do
    case "$1" in
        --action) (($# >= 2)) || die "--action requires a value"; action=$2; shift 2 ;;
        --environment) (($# >= 2)) || die "--environment requires a value"; environment=$2; shift 2 ;;
        --host) (($# >= 2)) || die "--host requires a value"; target_host=$2; shift 2 ;;
        --app-config) (($# >= 2)) || die "--app-config requires a value"; app_config=$2; shift 2 ;;
        --python) (($# >= 2)) || die "--python requires a value"; python_binary=$2; shift 2 ;;
        --docker-binary) (($# >= 2)) || die "--docker-binary requires a value"; docker_binary=$2; shift 2 ;;
        --approval-file) (($# >= 2)) || die "--approval-file requires a value"; approval_file=$2; shift 2 ;;
        --apply) apply=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$action" in add|remove) ;; *) die "--action must be add or remove" ;; esac
case "$environment" in development|production) ;; *) die "--environment must be development or production" ;; esac
[[ -n "$target_host" && "$target_host" == "$(hostname)" ]] \
    || die "--host must exactly match $(hostname)"
require_absolute_path "$app_config" "application config"
require_absolute_path "$python_binary" "Python binary"
require_regular_file "$app_config" "application config"
[[ -x "$python_binary" ]] || die "Python binary is not executable"
require_regular_file "$SCRIPT_DIR/manage-imap-filter.py" "managed IMAP filter editor"
require_regular_file "$SCRIPT_DIR/../deploy/maddyweb-filter-docker" "Docker filter client"

profile=$(
    "$python_binary" -I - "$app_config" <<'PY'
from __future__ import annotations

import json
import sys
from maddyweb.config import load_config

config = load_config(sys.argv[1])
print(json.dumps({
    "mode": config.maddy.mode,
    "binary": str(config.maddy.binary),
    "config_path": str(config.maddy.config_path),
    "container": config.maddy.container or "",
    "service_user": config.maddy.service_user,
}, sort_keys=True, separators=(",", ":")))
PY
) || die "cannot load the effective MaddyWeb configuration"
maddy_mode=$("$python_binary" -c 'import json,sys; print(json.loads(sys.argv[1])["mode"])' "$profile")
maddy_binary=$("$python_binary" -c 'import json,sys; print(json.loads(sys.argv[1])["binary"])' "$profile")
maddy_config=$("$python_binary" -c 'import json,sys; print(json.loads(sys.argv[1])["config_path"])' "$profile")
container=$("$python_binary" -c 'import json,sys; print(json.loads(sys.argv[1])["container"])' "$profile")
service_user=$("$python_binary" -c 'import json,sys; print(json.loads(sys.argv[1])["service_user"])' "$profile")
case "$maddy_mode" in native|docker) ;; *) die "configured Maddy mode is invalid" ;; esac

deployment_lock_fd=""
if [[ "$apply" == true ]]; then
    require_root
    require_command flock
    require_command install
    if [[ -e "$MADDYWEB_APPROVAL_ROOT" || -L "$MADDYWEB_APPROVAL_ROOT" ]]; then
        [[ -d "$MADDYWEB_APPROVAL_ROOT" && ! -L "$MADDYWEB_APPROVAL_ROOT" ]] \
            || die "approval runtime directory must be a real directory"
    else
        install -d -o root -g root -m 0700 -- "$MADDYWEB_APPROVAL_ROOT"
    fi
    [[ "$(stat -c '%u:%g:%a' -- "$MADDYWEB_APPROVAL_ROOT")" == "0:0:700" ]] \
        || die "approval runtime directory must be root:root 0700"
    deployment_lock="$MADDYWEB_APPROVAL_ROOT/deployment.lock"
    exec {deployment_lock_fd}>> "$deployment_lock"
    [[ "$(stat -c '%u:%g:%a:%h' -- "$deployment_lock")" == "0:0:600:1" ]] \
        || die "deployment lock must be single-link root:root 0600"
    flock -n "$deployment_lock_fd" \
        || die "another MaddyWeb deployment transaction is active"
fi

work=$(mktemp -d)
chmod 0700 "$work"
source_config="$work/maddy.conf.original"
candidate_config="$work/maddy.conf.candidate"
live_config="$work/maddy.conf.live"
recovery_config="$work/maddy.conf.recovery"
token_source="$work/bridge.token"
endpoint_source="$work/client.endpoint"
env_source="$work/maddyweb-filter.env"
inspect_file="$work/container-inspect.json"
existing_client_token="$work/existing-client.token"
config_replaced=false
restoring_config=false
service_started=false
native_membership_added=false
filter_was_active=false
filter_config_present=true
maddy_restart_expected=false
maddy_restart_identity_before=""

cleanup() {
    local status=$?
    trap - EXIT INT TERM ERR
    set +e
    if (( status != 0 )) && [[ "$config_replaced" == true ]] \
        && declare -F restore_config >/dev/null; then
        restore_config || log "CRITICAL: managed filter config restoration failed"
    fi
    if (( status != 0 )) && [[ "$service_started" == true \
        && "$filter_was_active" == false ]]; then
        systemctl disable --now maddyweb-filter.service >/dev/null 2>&1 || true
    fi
    if (( status != 0 )) && [[ "$native_membership_added" == true ]]; then
        if ! gpasswd -d "$service_user" maddyweb-filter-client >/dev/null 2>&1; then
            log "CRITICAL: native client reader group membership restoration failed"
        elif [[ "$config_replaced" == false ]] \
            && ! systemctl restart maddy.service >/dev/null 2>&1; then
            log "CRITICAL: Maddy could not be restarted after reader group restoration"
        fi
    fi
    rm -f -- "$source_config" "$candidate_config" "$live_config" "$recovery_config" \
        "$token_source" \
        "$endpoint_source" "$env_source" "$inspect_file" "$existing_client_token"
    rmdir -- "$work" 2>/dev/null || true
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

container_id=""
network_mode="native"
filter_host="127.0.0.1"
maddy_version=""
config_uid=""
config_gid=""
config_mode=""

if [[ "$maddy_mode" == native ]]; then
    require_regular_file "$maddy_binary" "Maddy binary"
    require_regular_file "$maddy_config" "Maddy config"
    id "$service_user" >/dev/null 2>&1 || die "configured Maddy service user does not exist"
    maddy_version=$(assert_supported_maddy "$maddy_binary")
    config_identity=$(stat -c '%u:%g:%a:%h' -- "$maddy_config")
    IFS=: read -r config_uid config_gid config_mode config_links <<< "$config_identity"
    [[ "$config_links" == 1 ]] || die "Maddy config must have one hard link"
    install -m 0600 -- "$maddy_config" "$source_config"
else
    [[ -n "$docker_binary" ]] || die "Docker binary is required in Docker mode"
    require_absolute_path "$docker_binary" "Docker binary"
    [[ -x "$docker_binary" ]] || die "Docker binary is not executable"
    [[ -n "$container" ]] || die "configured Maddy container is missing"
    [[ "$maddy_config" == /data/maddy.conf ]] \
        || die "Docker filter lifecycle requires config_path exactly /data/maddy.conf"
    "$docker_binary" inspect "$container" > "$inspect_file" \
        || die "cannot inspect Maddy container"
    docker_profile=$(
        "$python_binary" -I - "$inspect_file" <<'PY'
from __future__ import annotations

import ipaddress
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    records = json.load(handle)
if not isinstance(records, list) or len(records) != 1:
    raise SystemExit(2)
record = records[0]
state = record.get("State") or {}
host = record.get("HostConfig") or {}
network = record.get("NetworkSettings") or {}
if state.get("Running") is not True or state.get("Paused") is True:
    raise SystemExit(2)
mode = host.get("NetworkMode")
if host.get("PidMode") not in {None, ""}:
    raise SystemExit(2)
if mode == "host":
    endpoint = "127.0.0.1"
else:
    networks = network.get("Networks") or {}
    gateways = {value.get("Gateway") for value in networks.values() if isinstance(value, dict)}
    gateways.discard(None)
    gateways.discard("")
    if len(gateways) != 1:
        raise SystemExit(2)
    endpoint = gateways.pop()
    address = ipaddress.ip_address(endpoint)
    allowed = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    if not isinstance(address, ipaddress.IPv4Address) or not any(
        address in network for network in allowed
    ):
        raise SystemExit(2)
print(json.dumps({"id": record.get("Id"), "mode": mode, "endpoint": endpoint}, separators=(",", ":")))
PY
    ) || die "Maddy container networking or PID isolation is unsupported"
    container_id=$("$python_binary" -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "$docker_profile")
    network_mode=$("$python_binary" -c 'import json,sys; print(json.loads(sys.argv[1])["mode"])' "$docker_profile")
    filter_host=$("$python_binary" -c 'import json,sys; print(json.loads(sys.argv[1])["endpoint"])' "$docker_profile")
    [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || die "Maddy container identity is invalid"
    version_output=$($docker_binary exec "$container_id" /bin/maddy version 2>&1) \
        || die "cannot read container Maddy version"
    maddy_version=$(extract_maddy_version "$version_output")
    version_in_supported_range "$maddy_version" || die "unsupported container Maddy version"
    config_identity=$($docker_binary exec "$container_id" /bin/busybox stat -c '%u:%g:%a:%h' /data/maddy.conf) \
        || die "cannot inspect container Maddy config"
    IFS=: read -r config_uid config_gid config_mode config_links <<< "$config_identity"
    [[ "$config_links" == 1 ]] || die "container Maddy config must have one hard link"
    $docker_binary cp "$container_id:/data/maddy.conf" "$source_config" >/dev/null \
        || die "cannot snapshot container Maddy config"
    chmod 0600 "$source_config"
fi

if [[ "$action" == add ]]; then
    "$python_binary" "$SCRIPT_DIR/manage-imap-filter.py" --action render-add \
        --config "$source_config" --mode "$maddy_mode" > "$candidate_config" \
        || die "Maddy config is not eligible for the managed filter"
else
    if "$python_binary" "$SCRIPT_DIR/manage-imap-filter.py" --action render-remove \
        --config "$source_config" --mode "$maddy_mode" > "$candidate_config" \
        2>/dev/null; then
        filter_config_present=true
    elif "$python_binary" "$SCRIPT_DIR/manage-imap-filter.py" --action check-add \
        --config "$source_config" --mode "$maddy_mode" >/dev/null 2>&1; then
        install -m 0600 -- "$source_config" "$candidate_config"
        filter_config_present=false
    else
        die "managed Maddy filter is modified or conflicts with another filter"
    fi
fi
chmod 0600 "$candidate_config"
[[ -s "$candidate_config" ]] || die "managed filter editor returned an empty config"
printf '%s:18787\n' "$filter_host" > "$endpoint_source"
printf 'MADDYWEB_FILTER_LISTEN=%s:18787\n' "$filter_host" > "$env_source"

printf 'environment=%s\nhost=%s\naction=%s\nmode=%s\nmaddy=%s\nnetwork_mode=%s\nfilter_listen=%s:18787\nconfig=%s\n' \
    "$environment" "$target_host" "$action" "$maddy_mode" "$maddy_version" \
    "$network_mode" "$filter_host" "$maddy_config"
if [[ "$apply" != true ]]; then
    log "dry-run complete; pass --apply only after reviewing the plan"
    exit 0
fi

require_root
require_command systemctl
require_command ss
require_command sync
if [[ "$maddy_mode" == native ]]; then
    require_command getent
    require_command usermod
    require_command gpasswd
fi
if [[ "$environment" == production ]]; then
    [[ -n "$approval_file" ]] || die "production --apply requires --approval-file"
    consume_production_approval "$approval_file" "filter-$action"
elif [[ -n "$approval_file" ]]; then
    die "approval files are accepted only for production"
fi
if systemctl is-active --quiet maddyweb-filter.service; then
    filter_was_active=true
else
    filter_was_active=false
fi

backup_dir=/var/backups/maddyweb/filter
install -d -o root -g root -m 0700 -- "$backup_dir"
backup=$(mktemp --tmpdir="$backup_dir" \
    "maddy.conf.$(date -u +%Y%m%dT%H%M%SZ).$action.XXXXXXXX.bak")
install -o root -g root -m 0600 -- "$source_config" "$backup"
cmp -s -- "$source_config" "$backup" || die "Maddy config backup failed read-back"
[[ "$(sha256_file "$source_config")" == "$(sha256_file "$backup")" ]] \
    || die "Maddy config backup checksum failed read-back"

assert_existing_host_file() {
    local path=${1:?path is required} expected=${2:?metadata is required}
    if [[ ! -e "$path" && ! -L "$path" ]]; then return 0; fi
    [[ -f "$path" && ! -L "$path" ]] \
        || die "managed file is not a regular non-symlink: $path"
    [[ "$(stat -c '%u:%g:%a:%h' -- "$path")" == "$expected" ]] \
        || die "managed file metadata is unsafe: $path"
}

assert_existing_host_directory() {
    local path=${1:?path is required} expected=${2:?metadata is required}
    if [[ ! -e "$path" && ! -L "$path" ]]; then return 0; fi
    [[ -d "$path" && ! -L "$path" ]] \
        || die "managed directory is not a real directory: $path"
    [[ "$(stat -c '%u:%g:%a' -- "$path")" == "$expected" ]] \
        || die "managed directory metadata is unsafe: $path"
}

assert_existing_docker_file() {
    local path=${1:?path is required} expected_mode=${2:?mode is required}
    if ! "$docker_binary" exec "$container_id" /bin/busybox test -e "$path" \
        && ! "$docker_binary" exec "$container_id" /bin/busybox test -L "$path"; then
        return 0
    fi
    if ! "$docker_binary" exec "$container_id" /bin/busybox test -f "$path" \
        || "$docker_binary" exec "$container_id" /bin/busybox test -L "$path"; then
        die "container managed file is not a regular non-symlink: $path"
    fi
    [[ "$("$docker_binary" exec "$container_id" /bin/busybox stat -c '%u:%g:%a:%h' "$path")" \
        == "0:0:${expected_mode}:1" ]] \
        || die "container managed file metadata is unsafe: $path"
}

assert_existing_docker_directory() {
    local path=${1:?path is required}
    if ! "$docker_binary" exec "$container_id" /bin/busybox test -e "$path" \
        && ! "$docker_binary" exec "$container_id" /bin/busybox test -L "$path"; then
        return 0
    fi
    if ! "$docker_binary" exec "$container_id" /bin/busybox test -d "$path" \
        || "$docker_binary" exec "$container_id" /bin/busybox test -L "$path"; then
        die "container managed directory is not a real directory: $path"
    fi
    [[ "$("$docker_binary" exec "$container_id" /bin/busybox stat -c '%u:%g:%a' "$path")" \
        == "0:0:700" ]] \
        || die "container managed directory metadata is unsafe: $path"
}

validate_token_file() {
    local path=${1:?token path is required}
    "$python_binary" -I - "$path" <<'PY'
from pathlib import Path
import re
import sys

payload = Path(sys.argv[1]).read_bytes()
raise SystemExit(0 if re.fullmatch(rb"[0-9a-f]{64}\n", payload) else 2)
PY
}

install_host_file_atomic() {
    local source=${1:?source is required} target=${2:?target is required}
    local owner=${3:?owner is required} group=${4:?group is required} mode=${5:?mode is required}
    local directory temporary
    directory=$(dirname -- "$target")
    temporary="$directory/.maddyweb-filter.$(basename -- "$target").$$"
    [[ ! -e "$temporary" && ! -L "$temporary" ]] \
        || die "managed file staging path already exists: $temporary"
    install -o "$owner" -g "$group" -m "$mode" -- "$source" "$temporary"
    mv -fT -- "$temporary" "$target"
    sync -f "$directory"
    cmp -s -- "$source" "$target" || die "managed file failed read-back: $target"
}

read_live_config() {
    rm -f -- "$live_config" || return 1
    if [[ "$maddy_mode" == native ]]; then
        install -m 0600 -- "$maddy_config" "$live_config" || return 1
    else
        "$docker_binary" cp "$container_id:/data/maddy.conf" "$live_config" \
            >/dev/null || return 1
        chmod 0600 "$live_config" || return 1
    fi
}

verify_live_config() {
    local expected_source=${1:?expected config source is required}
    local expected_hash actual_hash live_identity
    expected_hash=$(sha256_file "$expected_source") || return 1
    read_live_config || return 1
    actual_hash=$(sha256_file "$live_config") || return 1
    [[ "$actual_hash" == "$expected_hash" ]] || return 1
    cmp -s -- "$expected_source" "$live_config" || return 1
    if [[ "$maddy_mode" == native ]]; then
        live_identity=$(stat -c '%u:%g:%a:%h' -- "$maddy_config") || return 1
    else
        live_identity=$(
            "$docker_binary" exec "$container_id" /bin/busybox \
                stat -c '%u:%g:%a:%h' /data/maddy.conf 2>/dev/null
        ) || {
            [[ "$restoring_config" == true ]] \
                && [[ "$("$docker_binary" inspect --format '{{.State.Running}}' \
                    "$container_id" 2>/dev/null || true)" == false ]] \
                && return 0
            return 1
        }
    fi
    [[ "$live_identity" == "${config_uid}:${config_gid}:${config_mode}:1" ]]
}

native_listener_snapshot() {
    local pid=${1:?Maddy PID is required}
    ss -H -ltnp \
        | awk -v marker="pid=$pid," 'index($0, marker) {print $4}' \
        | LC_ALL=C sort -u
}

docker_listener_snapshot() {
    "$docker_binary" exec "$container_id" /bin/busybox netstat -ltnp 2>/dev/null \
        | awk '$6 == "LISTEN" && $7 ~ /^[0-9]+\// {print $4}' \
        | LC_ALL=C sort -u
}

native_pid_before=""
initial_maddy_listeners=""
if [[ "$maddy_mode" == native ]]; then
    systemctl is-active --quiet maddy.service || die "maddy.service is not active"
    native_pid_before=$(systemctl show --property MainPID --value maddy.service)
    [[ "$native_pid_before" =~ ^[1-9][0-9]*$ ]] || die "maddy.service MainPID is invalid"
    initial_maddy_listeners=$(native_listener_snapshot "$native_pid_before")
else
    initial_maddy_listeners=$(docker_listener_snapshot)
fi
[[ -n "$initial_maddy_listeners" ]] || die "Maddy has no observable TCP listeners"

filter_gid=$(id -g maddyweb-filter) || die "maddyweb-filter group is missing"
assert_existing_host_directory /var/lib/maddyweb-filter "0:${filter_gid}:750"
assert_existing_host_directory /var/lib/maddyweb-filter/snapshots "0:${filter_gid}:750"
assert_existing_host_file \
    /var/lib/maddyweb-filter/bridge.token "0:${filter_gid}:640:1"
assert_existing_host_file \
    /etc/maddyweb/maddyweb-filter.env "0:${filter_gid}:640:1"
if [[ -e /var/lib/maddyweb-filter/bridge.token ]]; then
    validate_token_file /var/lib/maddyweb-filter/bridge.token \
        || die "existing bridge token content is invalid"
fi
if [[ "$maddy_mode" == native ]]; then
    [[ "$(id -u "$service_user")" != 0 ]] \
        || die "native Maddy service user must not be root"
    client_group_record=$(getent group maddyweb-filter-client) \
        || die "maddyweb-filter-client group is missing"
    IFS=: read -r client_group _password client_gid client_members \
        <<< "$client_group_record"
    [[ "$client_group" == maddyweb-filter-client && "$client_gid" =~ ^[0-9]+$ ]] \
        || die "maddyweb-filter-client group record is invalid"
    [[ "$(id -gn "$service_user")" != maddyweb-filter-client ]] \
        || die "native client reader group must not be the Maddy primary group"
    case "$client_members" in
        ""|"$service_user") ;;
        *) die "native client reader group has an unexpected member" ;;
    esac
    assert_existing_host_directory /etc/maddyweb-filter "0:${client_gid}:750"
    assert_existing_host_file \
        /etc/maddyweb-filter/client.token "0:${client_gid}:640:1"
    assert_existing_host_file \
        /etc/maddyweb-filter/client.endpoint "0:${client_gid}:640:1"
    if [[ -e /etc/maddyweb-filter/client.token ]]; then
        validate_token_file /etc/maddyweb-filter/client.token \
            || die "existing native client token content is invalid"
    fi
else
    assert_existing_docker_directory /data/maddyweb-filter
    assert_existing_docker_file /data/maddyweb-filter/client.token 400
    assert_existing_docker_file /data/maddyweb-filter/client.endpoint 400
    assert_existing_docker_file /data/maddyweb-filter/maddyweb-filter-client 555
    if "$docker_binary" exec "$container_id" /bin/busybox test -e \
        /data/maddyweb-filter/client.token; then
        "$docker_binary" cp \
            "$container_id:/data/maddyweb-filter/client.token" "$existing_client_token" \
            >/dev/null
        validate_token_file "$existing_client_token" \
            || die "existing container client token content is invalid"
        rm -f -- "$existing_client_token"
    fi
fi

restart_maddy() {
    maddy_restart_expected=true
    if [[ "$maddy_mode" == native ]]; then
        maddy_restart_identity_before=$(
            systemctl show --property MainPID --value maddy.service 2>/dev/null
        ) || return 1
        [[ "$maddy_restart_identity_before" =~ ^[0-9]+$ ]] || return 1
        systemctl restart maddy.service
    else
        maddy_restart_identity_before=$(
            "$docker_binary" inspect --format '{{.State.StartedAt}}' \
                "$container_id" 2>/dev/null
        ) || return 1
        [[ -n "$maddy_restart_identity_before" ]] || return 1
        "$docker_binary" restart --time 10 "$container_id" >/dev/null
    fi
}

verify_candidate() {
    local path=$1
    [[ "$maddy_version" == 0.8.2 ]] && return 0
    if [[ "$maddy_mode" == native ]]; then
        "$maddy_binary" -config "$path" verify-config >/dev/null
    else
        "$docker_binary" exec --workdir /data "$container_id" \
            /bin/maddy -config "$path" verify-config >/dev/null
    fi
}

maddy_state_gate() {
    local expected_source=${1:?expected config source is required}
    local pid listeners state started_at version_output observed_version
    for _ in {1..50}; do
        if [[ "$maddy_mode" == native ]]; then
            if systemctl is-active --quiet maddy.service; then
                pid=$(systemctl show --property MainPID --value maddy.service 2>/dev/null || true)
                if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
                    if [[ "$maddy_restart_expected" == true \
                        && "$pid" != "$maddy_restart_identity_before" ]] \
                        || [[ "$maddy_restart_expected" == false \
                            && "$pid" == "$native_pid_before" ]]; then
                        version_output=$($maddy_binary version 2>&1 || true)
                        observed_version=$(extract_maddy_version "$version_output" 2>/dev/null || true)
                        listeners=$(native_listener_snapshot "$pid" 2>/dev/null || true)
                        if [[ "$observed_version" == "$maddy_version" \
                            && "$listeners" == "$initial_maddy_listeners" ]] \
                            && verify_live_config "$expected_source" \
                            && verify_candidate "$maddy_config"; then
                            maddy_restart_expected=false
                            return 0
                        fi
                    fi
                fi
            fi
        else
            if "$docker_binary" inspect "$container_id" > "$inspect_file" 2>/dev/null; then
                state=$(
                    "$python_binary" -I - "$inspect_file" "$container_id" <<'PY'
from __future__ import annotations

import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        records = json.load(handle)
except (TypeError, ValueError):
    raise SystemExit(2)
if not isinstance(records, list) or len(records) != 1:
    raise SystemExit(2)
record = records[0]
state = record.get("State") or {}
health = (state.get("Health") or {}).get("Status", "none")
valid = (
    record.get("Id") == sys.argv[2]
    and state.get("Running") is True
    and state.get("Paused") is not True
    and state.get("Restarting") is not True
    and health in {"none", "healthy"}
)
print("ready" if valid else "not-ready")
PY
                ) || state=not-ready
            else
                state=not-ready
            fi
            if [[ "$state" == ready ]]; then
                started_at=$(
                    "$docker_binary" inspect --format '{{.State.StartedAt}}' \
                        "$container_id" 2>/dev/null || true
                )
                version_output=$(
                    "$docker_binary" exec "$container_id" /bin/maddy version 2>&1 || true
                )
                observed_version=$(extract_maddy_version "$version_output" 2>/dev/null || true)
                listeners=$(docker_listener_snapshot 2>/dev/null || true)
                if [[ "$maddy_restart_expected" == false \
                    || "$started_at" != "$maddy_restart_identity_before" ]] \
                    && [[ -n "$started_at" \
                    && "$observed_version" == "$maddy_version" \
                    && "$listeners" == "$initial_maddy_listeners" ]] \
                    && verify_live_config "$expected_source" \
                    && verify_candidate /data/maddy.conf; then
                    maddy_restart_expected=false
                    return 0
                fi
            fi
        fi
        sleep 0.2
    done
    return 1
}

wait_for_filter_listener() {
    local listeners
    for _ in {1..50}; do
        systemctl is-active --quiet maddyweb-filter.service || return 1
        listeners=$(
            ss -H -ltn 'sport = :18787' \
                | awk '{print $4}' \
                | LC_ALL=C sort -u
        )
        if [[ "$listeners" == "$filter_host:18787" ]]; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

install_native_config() {
    local source=$1 temporary
    temporary="$(dirname -- "$maddy_config")/.maddy.conf.filter-$$"
    install -o "$config_uid" -g "$config_gid" -m "$config_mode" -- \
        "$source" "$temporary" || return 1
    mv -fT -- "$temporary" "$maddy_config" || return 1
    sync -f "$(dirname -- "$maddy_config")" || return 1
}

install_docker_config() {
    local source=$1 temporary="/data/.maddy.conf.filter-$$"
    if [[ "$("$docker_binary" inspect --format '{{.State.Running}}' \
        "$container_id" 2>/dev/null || true)" != true ]]; then
        [[ "$restoring_config" == true && "$config_uid" == 0 && "$config_gid" == 0 ]] \
            || return 1
        install -o root -g root -m "$config_mode" -- "$source" "$recovery_config" \
            || return 1
        "$docker_binary" cp "$recovery_config" "$container_id:/data/maddy.conf" \
            >/dev/null || return 1
        return 0
    fi
    "$docker_binary" cp "$source" "$container_id:$temporary" >/dev/null || return 1
    "$docker_binary" exec "$container_id" /bin/busybox \
        chown "$config_uid:$config_gid" "$temporary" || return 1
    "$docker_binary" exec "$container_id" /bin/busybox \
        chmod "$config_mode" "$temporary" || return 1
    "$docker_binary" exec "$container_id" /bin/busybox \
        mv -f "$temporary" /data/maddy.conf || return 1
    "$docker_binary" exec "$container_id" /bin/busybox sync || return 1
}

replace_config() {
    config_replaced=true
    if [[ "$maddy_mode" == native ]]; then
        install_native_config "$1" || return 1
    else
        install_docker_config "$1" || return 1
    fi
    verify_live_config "$1"
}

restore_config() {
    [[ "$config_replaced" == true ]] || return 0
    restoring_config=true
    if replace_config "$source_config" \
        && restart_maddy \
        && maddy_state_gate "$source_config" \
        && verify_live_config "$source_config"; then
        restoring_config=false
        config_replaced=false
        return 0
    fi
    restoring_config=false
    return 1
}

if [[ "$action" == add ]]; then
    install -d -o root -g maddyweb-filter -m 0750 -- \
        /var/lib/maddyweb-filter /var/lib/maddyweb-filter/snapshots
    if [[ -e /var/lib/maddyweb-filter/bridge.token ]]; then
        cp -- /var/lib/maddyweb-filter/bridge.token "$token_source"
    else
        "$python_binary" -I - "$token_source" <<'PY'
import secrets
import sys
from pathlib import Path
Path(sys.argv[1]).write_text(secrets.token_hex(32) + "\n", encoding="ascii")
PY
        chmod 0600 "$token_source"
        validate_token_file "$token_source" || die "generated bridge token is invalid"
        install_host_file_atomic "$token_source" \
            /var/lib/maddyweb-filter/bridge.token root maddyweb-filter 0640
    fi
    validate_token_file "$token_source" || die "bridge token content is invalid"
    if [[ "$maddy_mode" == native ]]; then
        if [[ -z "$client_members" ]]; then
            usermod -a -G maddyweb-filter-client "$service_user"
            native_membership_added=true
        fi
        refreshed_group=$(getent group maddyweb-filter-client) \
            || die "cannot read native client reader group after enrollment"
        IFS=: read -r refreshed_name _password refreshed_gid refreshed_members \
            <<< "$refreshed_group"
        [[ "$refreshed_name" == maddyweb-filter-client \
            && "$refreshed_gid" == "$client_gid" \
            && "$refreshed_members" == "$service_user" ]] \
            || die "native client reader group is not exclusive to the Maddy service identity"
        case " $(id -G "$service_user") " in
            *" $client_gid "*) ;;
            *) die "native Maddy service identity did not acquire the client reader group" ;;
        esac
        install -d -o root -g maddyweb-filter-client -m 0750 -- /etc/maddyweb-filter
        install_host_file_atomic "$token_source" \
            /etc/maddyweb-filter/client.token root maddyweb-filter-client 0640
        install_host_file_atomic "$endpoint_source" \
            /etc/maddyweb-filter/client.endpoint root maddyweb-filter-client 0640
        verify_candidate "$candidate_config"
    else
        "$docker_binary" exec "$container_id" /bin/busybox mkdir -p /data/maddyweb-filter
        "$docker_binary" exec "$container_id" /bin/busybox chown 0:0 /data/maddyweb-filter
        "$docker_binary" exec "$container_id" /bin/busybox chmod 0700 /data/maddyweb-filter
        for pair in \
            "$SCRIPT_DIR/../deploy/maddyweb-filter-docker:maddyweb-filter-client:0555" \
            "$token_source:client.token:0400" \
            "$endpoint_source:client.endpoint:0400"; do
            IFS=: read -r local_source target_name target_mode <<< "$pair"
            temporary="/data/maddyweb-filter/.${target_name}.tmp-$$"
            "$docker_binary" cp "$local_source" "$container_id:$temporary" >/dev/null
            "$docker_binary" exec "$container_id" /bin/busybox chown 0:0 "$temporary"
            "$docker_binary" exec "$container_id" /bin/busybox chmod "$target_mode" "$temporary"
            "$docker_binary" exec "$container_id" /bin/busybox mv -f \
                "$temporary" "/data/maddyweb-filter/$target_name"
        done
        docker_candidate="/data/.maddy.conf.filter-verify-$$"
        "$docker_binary" cp "$candidate_config" "$container_id:$docker_candidate" >/dev/null
        verify_candidate "$docker_candidate"
        "$docker_binary" exec "$container_id" /bin/busybox rm -f "$docker_candidate"
    fi
    install_host_file_atomic "$env_source" \
        /etc/maddyweb/maddyweb-filter.env root maddyweb-filter 0640
    systemctl daemon-reload
    systemctl enable maddyweb-filter.service
    if [[ "$filter_was_active" == false ]]; then service_started=true; fi
    systemctl restart maddyweb-filter.service
    systemctl is-active --quiet maddyweb-filter.service
    wait_for_filter_listener \
        || die "delivery filter is not listening on exactly its reviewed private endpoint"
    replace_config "$candidate_config"
    restart_maddy
    maddy_state_gate "$candidate_config"
else
    if [[ "$filter_config_present" == true ]]; then
        if [[ "$maddy_mode" == native ]]; then
            verify_candidate "$candidate_config"
        else
            docker_candidate="/data/.maddy.conf.filter-verify-$$"
            "$docker_binary" cp "$candidate_config" "$container_id:$docker_candidate" >/dev/null
            verify_candidate "$docker_candidate"
            "$docker_binary" exec "$container_id" /bin/busybox rm -f "$docker_candidate"
        fi
        replace_config "$candidate_config"
        restart_maddy
        maddy_state_gate "$candidate_config"
        config_replaced=false
    else
        maddy_state_gate "$source_config"
    fi
    systemctl disable --now maddyweb-filter.service
    if [[ "$maddy_mode" == native ]]; then
        rm -f -- /etc/maddyweb-filter/client.token /etc/maddyweb-filter/client.endpoint
        if [[ "$client_members" == "$service_user" ]]; then
            gpasswd -d "$service_user" maddyweb-filter-client >/dev/null
            refreshed_group=$(getent group maddyweb-filter-client) \
                || die "cannot read native client reader group after removal"
            IFS=: read -r _name _password _gid refreshed_members <<< "$refreshed_group"
            [[ -z "$refreshed_members" ]] \
                || die "native client reader group membership removal failed"
        fi
    else
        for target in client.token client.endpoint maddyweb-filter-client; do
            "$docker_binary" exec "$container_id" /bin/busybox rm -f \
                "/data/maddyweb-filter/$target"
        done
    fi
    rm -f -- /var/lib/maddyweb-filter/bridge.token /etc/maddyweb/maddyweb-filter.env
fi

config_replaced=false
log "managed delivery filter $action completed"
