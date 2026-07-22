#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/backup-unit-state.sh
source "$SCRIPT_DIR/lib/backup-unit-state.sh"

usage() {
    cat <<'EOF'
Usage: backup.sh --environment development|production --host HOST \
  --mode native|docker --app-config /etc/maddyweb/config.toml \
  --maddy-config PATH [mode options] [--apply]

Native: --maddy-binary /usr/bin/maddy --maddy-state /var/lib/maddy
Docker: --docker-binary /usr/bin/docker --container SAFE_NAME

Common: [--python /opt/maddyweb/current/bin/python]
        [--destination /var/backups/maddyweb] [--approval-file PATH]

The default is a read-only plan. Native Maddy is stopped briefly. Docker Maddy
is paused (never stopped or recreated), then its /data mount is attached
read-only to a disposable, networkless snapshot container. Trap cleanup always
unpauses the target and restores previously active MaddyWeb units.
EOF
}

environment=""
target_host=""
mode=""
app_config=""
maddy_binary=""
maddy_config=""
maddy_state=""
docker_binary="$(command -v docker || true)"
container=""
python_binary="/opt/maddyweb/current/bin/python"
destination="/var/backups/maddyweb"
approval_file=""
apply=false

while (($#)); do
    case "$1" in
        --environment) (($# >= 2)) || die "--environment requires a value"; environment=$2; shift 2 ;;
        --host) (($# >= 2)) || die "--host requires a value"; target_host=$2; shift 2 ;;
        --mode) (($# >= 2)) || die "--mode requires a value"; mode=$2; shift 2 ;;
        --app-config) (($# >= 2)) || die "--app-config requires a value"; app_config=$2; shift 2 ;;
        --maddy-binary) (($# >= 2)) || die "--maddy-binary requires a value"; maddy_binary=$2; shift 2 ;;
        --maddy-config) (($# >= 2)) || die "--maddy-config requires a value"; maddy_config=$2; shift 2 ;;
        --maddy-state) (($# >= 2)) || die "--maddy-state requires a value"; maddy_state=$2; shift 2 ;;
        --docker-binary) (($# >= 2)) || die "--docker-binary requires a value"; docker_binary=$2; shift 2 ;;
        --container) (($# >= 2)) || die "--container requires a value"; container=$2; shift 2 ;;
        --python) (($# >= 2)) || die "--python requires a value"; python_binary=$2; shift 2 ;;
        --destination) (($# >= 2)) || die "--destination requires a value"; destination=$2; shift 2 ;;
        --approval-file) (($# >= 2)) || die "--approval-file requires a value"; approval_file=$2; shift 2 ;;
        --apply) apply=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$environment" in development|production) ;; *) die "--environment must be development or production" ;; esac
case "$mode" in native|docker) ;; *) die "--mode must be native or docker" ;; esac
[[ -n "$target_host" && "$target_host" == "$(hostname)" ]] || die "--host must exactly match $(hostname)"
[[ -n "$app_config" && -n "$maddy_config" ]] || die "--app-config and --maddy-config are required"
require_absolute_path "$destination" "backup destination"
[[ "$destination" != *,* ]] || die "backup destination must not contain a comma"

if [[ "$mode" == native ]]; then
    [[ -n "$maddy_binary" && -n "$maddy_state" && -z "$container" ]] || die "native mode requires binary/state and no container"
    "$SCRIPT_DIR/preflight.sh" --mode native --app-config "$app_config" \
        --maddy-binary "$maddy_binary" --maddy-config "$maddy_config" \
        --maddy-state "$maddy_state" --python "$python_binary"
else
    [[ -z "$maddy_binary" && -z "$maddy_state" ]] || die "Docker mode rejects native binary/state paths"
    [[ "$container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || die "Docker mode requires a safe container name"
    [[ "$maddy_config" == /data/maddy.conf ]] || die "Docker Maddy config must be /data/maddy.conf"
    "$SCRIPT_DIR/preflight.sh" --mode container --app-config "$app_config" \
        --container "$container" --docker-binary "$docker_binary" \
        --maddy-config "$maddy_config" --python "$python_binary"
    container_before=$("$python_binary" "$SCRIPT_DIR/inspect-maddy-container.py" \
        --docker "$docker_binary" --container "$container")
    docker_version_output=$("$docker_binary" exec "$container" /bin/maddy version 2>&1) \
        || die "cannot record container Maddy version"
fi

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
safe_host=${target_host//[^A-Za-z0-9._-]/_}
archive="$destination/maddyweb-${safe_host}-${timestamp}.tar"
printf 'environment=%s\nhost=%s\nmode=%s\ncontainer=%s\ndestination=%s\narchive=%s\n' \
    "$environment" "$target_host" "$mode" "$container" "$destination" "$archive"

if [[ "$apply" != true ]]; then
    log "dry-run complete; no service/container/filesystem state changed"
    exit 0
fi
require_root
if [[ "$environment" == production ]]; then
    [[ -n "$approval_file" ]] || die "production --apply requires --approval-file"
    consume_production_approval "$approval_file" backup
elif [[ -n "$approval_file" ]]; then
    die "approval files are accepted only for production"
fi

require_command install
require_command systemctl
require_command tar
install -d -o root -g root -m 0700 -- "$destination"
require_directory "$destination" "backup destination"
destination_mode=$(stat -c '%a' -- "$destination")
(( (8#$destination_mode & 8#077) == 0 )) || die "backup destination must not grant group/other access"
[[ ! -e "$archive" && ! -e "$archive.sha256" ]] || die "backup output already exists"

staging=$(mktemp -d --tmpdir="$destination" .maddyweb-backup.XXXXXXXX)
require_path_below "$staging" "$destination"
maddy_was_active=false
source_quiesced=false
snapshot_helper=""

restore_native_maddy_active_state() {
    local result=0
    if [[ "$maddy_was_active" == true ]]; then
        systemctl start maddy.service || result=1
        systemctl is-active --quiet maddy.service || result=1
    elif systemctl is-active --quiet maddy.service; then
        systemctl stop maddy.service >/dev/null 2>&1 || result=1
        if systemctl is-active --quiet maddy.service; then result=1; fi
    fi
    return "$result"
}

restore_docker_running_state() {
    local result=0 paused
    paused=$(
        "$docker_binary" inspect --format '{{.State.Paused}}' "$container" 2>/dev/null
    ) || result=1
    if [[ "${paused:-}" == true ]]; then
        "$docker_binary" unpause "$container" >/dev/null || result=1
    elif [[ "${paused:-}" != false ]]; then
        result=1
    fi
    "$python_binary" "$SCRIPT_DIR/inspect-maddy-container.py" \
        --docker "$docker_binary" --container "$container" >/dev/null 2>&1 || result=1
    return "$result"
}

cleanup() {
    local status=$? restore_status=0 cleanup_status=0
    trap - EXIT INT TERM
    set +e
    if [[ -n "$snapshot_helper" ]] \
        && "$docker_binary" container inspect "$snapshot_helper" >/dev/null 2>&1; then
        "$docker_binary" rm --force "$snapshot_helper" >/dev/null 2>&1 || cleanup_status=1
        if "$docker_binary" container inspect "$snapshot_helper" >/dev/null 2>&1; then
            cleanup_status=1
        fi
    fi
    if [[ "$source_quiesced" == true ]]; then
        if [[ "$mode" == docker ]]; then
            restore_docker_running_state || restore_status=1
        else
            restore_native_maddy_active_state || restore_status=1
        fi
    fi
    restore_maddyweb_unit_states || restore_status=1
    if [[ "$staging" == "$destination"/.maddyweb-backup.* && -d "$staging" && ! -L "$staging" ]]; then
        rm -rf -- "$staging" || cleanup_status=1
    fi
    if (( restore_status != 0 )); then
        log "CRITICAL: backup completed or failed, but pre-backup service/container state was not fully restored"
        status=1
    fi
    if (( cleanup_status != 0 )); then
        log "CRITICAL: backup cleanup left snapshot or staging material behind"
        status=1
    fi
    exit "$status"
}

capture_maddyweb_unit_states \
    || die "cannot capture exact MaddyWeb systemd unit presence/active state"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

stop_active_maddyweb_units \
    || die "cannot quiesce the active MaddyWeb systemd units"

if [[ "$mode" == native ]]; then
    systemctl is-active --quiet maddy.service && maddy_was_active=true
    # Mark restoration necessary before the first mutating command so a
    # signal delivered immediately after stop cannot strand Maddy offline.
    source_quiesced=true
    if [[ "$maddy_was_active" == true ]]; then systemctl stop maddy.service; fi
    systemctl is-active --quiet maddy.service && die "Maddy did not quiesce"
    tar --create --file "$staging/maddy-state.tar" --acls --xattrs --numeric-owner --one-file-system \
        --directory "$(dirname -- "$maddy_state")" "$(basename -- "$maddy_state")"
    install -o root -g root -m 0600 -- "$maddy_config" "$staging/maddy.conf"
    "$maddy_binary" version > "$staging/maddy-version.txt"
    restore_native_maddy_active_state
    source_quiesced=false
else
    # Set the cleanup intent before pause; cleanup safely handles both a
    # completed pause and a pause command that failed without changing state.
    source_quiesced=true
    "$docker_binary" pause "$container" >/dev/null
    "$docker_binary" cp "$container:/data/maddy.conf" "$staging/maddy.conf"
    [[ -f "$staging/maddy.conf" && ! -L "$staging/maddy.conf" ]] || die "exported Maddy config is not a regular file"
    chmod 0600 "$staging/maddy.conf"
    image_id=$("$python_binary" -c 'import json,sys; print(json.loads(sys.argv[1])["image_id"])' "$container_before")
    nonce=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
    [[ "$nonce" =~ ^[0-9a-f]{16}$ ]] || die "failed to generate snapshot helper name"
    snapshot_helper="maddyweb-backup-$nonce"
    "$docker_binary" run --rm --name "$snapshot_helper" --network none --read-only \
        --user 0:0 --cap-drop ALL --security-opt no-new-privileges \
        --volumes-from "$container:ro" \
        --mount "type=bind,source=$staging,target=/backup" \
        --entrypoint /bin/tar "$image_id" -C /data -cpf /backup/maddy-state.tar .
    snapshot_helper=""
    printf '%s\n' "$container_before" > "$staging/container-inspect.json"
    printf '%s\n' "$docker_version_output" > "$staging/maddy-version.txt"
    restore_docker_running_state
    container_after=$("$python_binary" "$SCRIPT_DIR/inspect-maddy-container.py" \
        --docker "$docker_binary" --container "$container")
    "$python_binary" -c 'import json,sys
before, after = map(json.loads, sys.argv[1:])
keys = ("container_id", "image_id", "image_digest", "mounts_sha256", "ports_sha256", "restart_policy_sha256")
raise SystemExit(any(before.get(key) != after.get(key) for key in keys))' \
        "$container_before" "$container_after" || die "Maddy container identity changed during backup"
    source_quiesced=false
fi

install -o root -g root -m 0600 -- "$app_config" "$staging/maddyweb.toml"
printf 'format=maddyweb-backup-v1\nhost=%s\ncreated=%s\nmode=%s\ncontainer=%s\n' \
    "$target_host" "$timestamp" "$mode" "$container" > "$staging/MANIFEST"
(
    cd -- "$staging"
    sha256_file maddy-state.tar > maddy-state.tar.sha256
    sha256_file maddy.conf > maddy.conf.sha256
    sha256_file maddyweb.toml > maddyweb.toml.sha256
)
tar --create --file "$archive.tmp.$$" --directory "$staging" .
chmod 0600 -- "$archive.tmp.$$"
mv -- "$archive.tmp.$$" "$archive"
sha256_file "$archive" > "$archive.sha256.tmp.$$"
chmod 0600 -- "$archive.sha256.tmp.$$"
mv -- "$archive.sha256.tmp.$$" "$archive.sha256"

log "backup created: $archive"
log "Maddy state restoration remains a manual disaster-recovery procedure"
