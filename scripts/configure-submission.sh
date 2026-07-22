#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    cat <<'EOF'
Usage: configure-submission.sh --action add|remove \
  --environment development|production --host HOST --mode native|docker \
  --maddy-config /absolute/config/path [mode options] [--apply]

Native options:
  --maddy-binary /absolute/maddy

Docker options:
  --docker-binary /absolute/docker --container maddy
  For a bind mount, --maddy-config is the host maddy.conf. For a named volume,
  it must be exactly /data/maddy.conf; the volume name is never caller-supplied.

Common options:
  --python /absolute/python3.14
  --backup-dir /var/backups/maddyweb/submission
  --approval-file /run/maddyweb-approval/approval-...
  --allow-downtime       Required to mutate Maddy 0.8.2 (short restart)

The default is a read-only plan. The editor only appends/removes its exact
marker block, preserves metadata atomically, and creates a private backup.
Docker mode never publishes port 1587. No Nginx file or unit is touched.
EOF
}

action=""
environment=""
target_host=""
mode=""
maddy_config=""
maddy_binary=""
docker_binary="$(command -v docker || true)"
container=""
python_binary="/opt/maddyweb/current/bin/python"
backup_dir="/var/backups/maddyweb/submission"
approval_file=""
allow_downtime=false
apply=false

while (($#)); do
    case "$1" in
        --action) (($# >= 2)) || die "--action requires a value"; action=$2; shift 2 ;;
        --environment) (($# >= 2)) || die "--environment requires a value"; environment=$2; shift 2 ;;
        --host) (($# >= 2)) || die "--host requires a value"; target_host=$2; shift 2 ;;
        --mode) (($# >= 2)) || die "--mode requires a value"; mode=$2; shift 2 ;;
        --maddy-config) (($# >= 2)) || die "--maddy-config requires a value"; maddy_config=$2; shift 2 ;;
        --maddy-binary) (($# >= 2)) || die "--maddy-binary requires a value"; maddy_binary=$2; shift 2 ;;
        --docker-binary) (($# >= 2)) || die "--docker-binary requires a value"; docker_binary=$2; shift 2 ;;
        --container) (($# >= 2)) || die "--container requires a value"; container=$2; shift 2 ;;
        --python) (($# >= 2)) || die "--python requires a value"; python_binary=$2; shift 2 ;;
        --backup-dir) (($# >= 2)) || die "--backup-dir requires a value"; backup_dir=$2; shift 2 ;;
        --approval-file) (($# >= 2)) || die "--approval-file requires a value"; approval_file=$2; shift 2 ;;
        --allow-downtime) allow_downtime=true; shift ;;
        --apply) apply=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$action" in add|remove) ;; *) die "--action must be add or remove" ;; esac
case "$environment" in development|production) ;; *) die "--environment must be development or production" ;; esac
case "$mode" in native|docker) ;; *) die "--mode must be native or docker" ;; esac
[[ -n "$target_host" && "$target_host" == "$(hostname)" ]] || die "--host must exactly match $(hostname)"
require_absolute_path "$python_binary" "Python binary"
[[ -x "$python_binary" ]] || die "Python is not executable"
"$python_binary" -c 'import sys; raise SystemExit(sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14))' \
    || die "CPython 3.14 is required"
require_absolute_path "$backup_dir" "backup directory"
require_command ss

if [[ "$mode" == "native" ]]; then
    require_regular_file "$maddy_config" "Maddy config"
    assert_private_file_mode "$maddy_config"
    [[ -n "$maddy_binary" ]] || die "native mode requires --maddy-binary"
    maddy_version=$(assert_supported_maddy "$maddy_binary")
    [[ -z "$container" ]] || die "--container is invalid in native mode"
    if [[ "$maddy_version" == "0.8.2" ]]; then
        help_fingerprint=$(assert_maddy_082_help_profile "$maddy_binary")
    else
        "$maddy_binary" -config "$maddy_config" verify-config >/dev/null 2>&1 || die "current Maddy config does not verify"
        help_fingerprint=not-applicable
    fi
else
    [[ "$container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || die "docker container name is unsafe"
    [[ -n "$docker_binary" ]] || die "docker mode requires --docker-binary"
    require_absolute_path "$docker_binary" "Docker binary"
    [[ -x "$docker_binary" ]] || die "Docker binary is not executable"
    container_before=$("$python_binary" "$SCRIPT_DIR/check-maddy-container.py" \
        --docker "$docker_binary" --container "$container" --host-config "$maddy_config")
    config_kind=$("$python_binary" -c \
        'import json,sys; print(json.loads(sys.argv[1])["config_kind"])' "$container_before")
    container_id=$("$python_binary" -c \
        'import json,sys; print(json.loads(sys.argv[1])["id"])' "$container_before")
    [[ "$config_kind" == bind || "$config_kind" == volume ]] \
        || die "container inspection returned an invalid configuration kind"
    [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] \
        || die "container inspection returned an invalid container ID"
    if [[ "$config_kind" == bind ]]; then
        require_regular_file "$maddy_config" "Maddy config"
        assert_private_file_mode "$maddy_config"
    fi
    version_output=$("$docker_binary" exec "$container_id" /bin/maddy version 2>&1) || die "container Maddy version failed"
    maddy_version=$(extract_maddy_version "$version_output")
    version_in_supported_range "$maddy_version" || die "unsupported Maddy version: $maddy_version"
    if [[ "$maddy_version" == "0.8.2" ]]; then
        help_fingerprint=$(assert_maddy_082_help_profile "$docker_binary" exec "$container_id" /bin/maddy)
    else
        "$docker_binary" exec "$container_id" /bin/maddy -config /data/maddy.conf verify-config >/dev/null 2>&1 \
            || die "current container Maddy config does not verify"
        help_fingerprint=not-applicable
    fi
fi

if [[ "$maddy_version" == "0.8.2" && "$apply" == true && "$allow_downtime" != true ]]; then
    die "Maddy 0.8.2 endpoint changes require --allow-downtime and a short restart"
fi

staging_dir=""
planned_config="$maddy_config"
planned_hash=""
cleanup_staging() {
    if [[ -n "$staging_dir" && -d "$staging_dir" ]]; then
        rm -f -- "$staging_dir"/*.conf
        rmdir -- "$staging_dir"
    fi
}
if [[ "$mode" == docker && "$config_kind" == volume ]]; then
    require_command mktemp
    staging_dir=$(mktemp -d /tmp/maddyweb-submission.XXXXXXXX)
    chmod 0700 -- "$staging_dir"
    trap cleanup_staging EXIT
    planned_config="$staging_dir/planned.conf"
    plan_report=$("$python_binary" "$SCRIPT_DIR/docker-volume-config.py" \
        --docker "$docker_binary" --container "$container_id" \
        --expected-container-id "$container_id" --state running \
        --action export --output "$planned_config")
    planned_hash=$("$python_binary" -c \
        'import json,sys; print(json.loads(sys.argv[1])["sha256"])' "$plan_report")
    [[ "$planned_hash" =~ ^[0-9a-f]{64}$ ]] || die "named-volume plan hash is invalid"
fi

"$python_binary" "$SCRIPT_DIR/manage-submission.py" \
    --action "check-$action" --config "$planned_config" >/dev/null

host_listener_count=$(ss -H -ltn 'sport = :1587' 2>/dev/null | wc -l)
if [[ "$mode" == "native" ]]; then
    if [[ "$action" == "add" && "$host_listener_count" -ne 0 ]]; then
        die "host port 1587 is already occupied"
    fi
    if [[ "$action" == "remove" ]] && ! ss -H -ltn 'sport = :1587' 2>/dev/null | awk '{print $4}' | grep -qx '127.0.0.1:1587'; then
        die "managed native listener is not active on exactly 127.0.0.1:1587"
    fi
else
    # Host publication is prohibited in Docker mode; the inspection above also
    # checks configured/runtime Docker port bindings.
    [[ "$host_listener_count" -eq 0 ]] || die "Docker mode must not publish host port 1587"
fi

printf 'environment=%s\nhost=%s\nmode=%s\nconfig_kind=%s\naction=%s\nmaddy=%s\nconfig=%s\nbackup_dir=%s\nlegacy_help_fingerprint=%s\ndowntime_required=%s\n' \
    "$environment" "$target_host" "$mode" "${config_kind:-native}" "$action" "$maddy_version" "$maddy_config" "$backup_dir" "$help_fingerprint" \
    "$([[ "$maddy_version" == "0.8.2" ]] && printf true || printf false)"

if [[ "$apply" != true ]]; then
    log "dry-run complete; no configuration, service, container, or Nginx state changed"
    exit 0
fi
require_root
if [[ "$environment" == "production" ]]; then
    [[ -n "$approval_file" ]] || die "production --apply requires --approval-file"
    consume_production_approval "$approval_file" "submission-$action"
elif [[ -n "$approval_file" ]]; then
    die "approval files are accepted only for production"
fi
require_command flock
submission_lock=/run/lock/maddyweb-submission.lock
if [[ -e "$submission_lock" || -L "$submission_lock" ]]; then
    [[ -d "$submission_lock" && ! -L "$submission_lock" ]] \
        || die "Submission transaction lock must be a real directory"
    [[ "$(stat -c '%u:%g:%a' "$submission_lock")" == "0:0:700" ]] \
        || die "Submission transaction lock metadata is unsafe"
else
    install -d -o root -g root -m 0700 -- "$submission_lock"
fi
# Open and lock the verified directory itself, avoiding symlink-following file
# redirection.  The descriptor remains held through health gates and any EXIT
# rollback; a concurrent apply fails immediately rather than waiting.
exec {submission_lock_fd}<"$submission_lock"
flock -n "$submission_lock_fd" \
    || die "another MaddyWeb Submission transaction is already active"
install -d -o root -g root -m 0700 -- "$backup_dir"

if [[ "$mode" == "native" ]]; then
    require_command systemctl
    require_command journalctl
    systemctl is-active --quiet maddy.service || die "maddy.service is not active"
    native_pid_before=$(systemctl show --property MainPID --value maddy.service)
    [[ "$native_pid_before" =~ ^[1-9][0-9]*$ ]] || die "maddy.service MainPID is invalid"
    journal_cursor=$(journalctl --unit maddy.service --lines 0 --show-cursor --no-pager 2>/dev/null | awk '/^-- cursor: / {print $3}')
    [[ -n "$journal_cursor" ]] || die "cannot establish a Maddy journal cursor"
else
    docker_since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
fi

backup_path=""
candidate_hash=""
original_hash=""
rollback_needed=false
edit_attempted=false
container_stopped=false
editor_config="$maddy_config"

container_snapshot_matches() {
    local after=$1
    "$python_binary" -c 'import json, sys
before, after = map(json.loads, sys.argv[1:])
keys = ("id", "mounts_sha256", "ports_sha256", "restart_policy_sha256",
        "config_kind", "config_source", "volume_name", "volume_sha256")
raise SystemExit(any(before.get(key) != after.get(key) for key in keys))' \
        "$container_before" "$after"
}

named_volume_snapshot() {
    "$python_binary" "$SCRIPT_DIR/check-maddy-container.py" \
        --docker "$docker_binary" --container "$container_id" --host-config "$maddy_config"
}

pause_named_volume() {
    [[ "$mode" == docker && "${config_kind:-}" == volume ]] || return 0
    local before_pause current_state running_state paused_state current_id
    current_state=$("$docker_binary" inspect --format \
        '{{.Id}} {{.State.Running}} {{.State.Paused}}' "$container_id")
    current_id=${current_state%% *}
    [[ "$current_id" == "$container_id" ]] || die "selected Maddy container ID changed"
    running_state=$(printf '%s\n' "$current_state" | awk '{print $2}')
    paused_state=${current_state##* }
    if [[ "$running_state" != true ]]; then
        [[ "$paused_state" == false ]] || die "stopped container reported an invalid paused state"
        container_stopped=true
        return 0
    fi
    container_stopped=false
    if [[ "$paused_state" == true ]]; then
        return 0
    fi
    before_pause=$(named_volume_snapshot)
    container_snapshot_matches "$before_pause" || die "container identity changed before pause"
    "$docker_binary" pause "$container_id" >/dev/null
    paused_state=$("$docker_binary" inspect --format '{{.State.Paused}}' "$container_id")
    [[ "$paused_state" == true ]] || die "selected Maddy container did not enter paused state"
}

unpause_named_volume() {
    [[ "$mode" == docker && "${config_kind:-}" == volume ]] || return 0
    local after_unpause current_state running_state paused_state current_id
    current_state=$("$docker_binary" inspect --format \
        '{{.Id}} {{.State.Running}} {{.State.Paused}}' "$container_id")
    current_id=${current_state%% *}
    [[ "$current_id" == "$container_id" ]] || die "selected Maddy container ID changed"
    running_state=$(printf '%s\n' "$current_state" | awk '{print $2}')
    paused_state=${current_state##* }
    [[ "$running_state" == true ]] || die "selected Maddy container is stopped"
    if [[ "$paused_state" == true ]]; then
        "$docker_binary" unpause "$container_id" >/dev/null
    fi
    container_stopped=false
    after_unpause=$(named_volume_snapshot)
    container_snapshot_matches "$after_unpause" || die "container identity changed while unpausing"
    paused_state=$("$docker_binary" inspect --format '{{.State.Paused}}' "$container_id")
    [[ "$paused_state" == false ]] || die "selected Maddy container remained paused"
}

ensure_named_volume_unpaused() {
    [[ "$mode" == docker && "${config_kind:-}" == volume ]] || return 0
    local state current_id running_state paused_state after
    state=$("$docker_binary" inspect --format \
        '{{.Id}} {{.State.Running}} {{.State.Paused}}' "$container_id" 2>/dev/null) \
        || return 1
    current_id=${state%% *}
    [[ "$current_id" == "$container_id" ]] || return 1
    running_state=$(printf '%s\n' "$state" | awk '{print $2}')
    paused_state=${state##* }
    if [[ "$running_state" == true && "$paused_state" == true ]]; then
        "$docker_binary" unpause "$container_id" >/dev/null || return 1
    elif [[ "$running_state" != true ]]; then
        "$docker_binary" start "$container_id" >/dev/null || return 1
    fi
    container_stopped=false
    after=$(named_volume_snapshot) || return 1
    container_snapshot_matches "$after"
}

reload_or_restart() {
    if [[ "$mode" == "native" ]]; then
        if [[ "$maddy_version" == "0.8.2" ]]; then
            systemctl restart maddy.service
        else
            systemctl kill --kill-who=main --signal=SIGUSR2 maddy.service
        fi
    else
        local started_from_stopped=false
        if [[ "${config_kind:-}" == volume && "$container_stopped" == true ]]; then
            "$docker_binary" start "$container_id" >/dev/null
            container_stopped=false
            started_from_stopped=true
        else
            unpause_named_volume
        fi
        if [[ "$started_from_stopped" == true ]]; then return 0; fi
        if [[ "$maddy_version" == "0.8.2" ]]; then
            "$docker_binary" restart --time 10 "$container_id" >/dev/null
        else
            "$docker_binary" kill --signal=SIGUSR2 "$container_id" >/dev/null
        fi
    fi
}

config_verify() {
    if [[ "$maddy_version" == "0.8.2" ]]; then
        return 0
    fi
    if [[ "$mode" == "native" ]]; then
        "$maddy_binary" -config "$maddy_config" verify-config >/dev/null 2>&1
    elif [[ "${config_kind:-}" == volume ]]; then
        # A fresh helper lacks the selected container's exact environment and
        # auxiliary mounts.  Unpause the unchanged main process, then validate
        # through the reviewed full container ID before signalling reload.
        if [[ "$container_stopped" == true ]]; then return 0; fi
        unpause_named_volume
        "$docker_binary" exec "$container_id" /bin/maddy \
            -config /data/maddy.conf verify-config >/dev/null 2>&1
    else
        "$docker_binary" exec "$container_id" /bin/maddy -config /data/maddy.conf verify-config >/dev/null 2>&1
    fi
}

managed_listener_gate() {
    local expected=$1
    if [[ "$mode" == "native" ]]; then
        local listeners
        listeners=$(ss -H -ltn 'sport = :1587' 2>/dev/null | awk '{print $4}')
        if [[ "$expected" == present ]]; then
            [[ "$listeners" == "127.0.0.1:1587" ]]
        else
            [[ -z "$listeners" ]]
        fi
    else
        local table found=false
        table=$("$docker_binary" exec "$container_id" /bin/cat /proc/net/tcp 2>/dev/null) || return 1
        if printf '%s\n' "$table" | awk '$2 == "0100007F:0633" && $4 == "0A" {found=1} END {exit !found}'; then
            found=true
        fi
        if [[ "$expected" == present ]]; then
            [[ "$found" == true ]] || return 1
            "$docker_binary" exec "$container_id" /usr/bin/nc -z -w 2 127.0.0.1 1587 \
                >/dev/null 2>&1
        else
            [[ "$found" == false ]]
        fi
    fi
}

health_and_log_gate() {
    if [[ "$mode" == "native" ]]; then
        systemctl is-active --quiet maddy.service || return 1
        local current_pid logs
        current_pid=$(systemctl show --property MainPID --value maddy.service)
        [[ "$current_pid" =~ ^[1-9][0-9]*$ ]] || return 1
        if [[ "$maddy_version" != "0.8.2" && "$current_pid" != "$native_pid_before" ]]; then return 1; fi
        logs=$(journalctl --unit maddy.service --after-cursor "$journal_cursor" --no-pager --output cat 2>&1) || return 1
    else
        local after health logs
        for _ in {1..50}; do
            after=$("$python_binary" "$SCRIPT_DIR/check-maddy-container.py" \
                --docker "$docker_binary" --container "$container_id" --host-config "$maddy_config" 2>/dev/null) && break
            sleep 0.2
        done
        [[ -n "${after:-}" ]] || return 1
        container_snapshot_matches "$after" || return 1
        health=$("$python_binary" -c 'import json,sys; print(json.loads(sys.argv[1]).get("health") or "none")' "$after")
        [[ "$health" == none || "$health" == healthy ]] || return 1
        logs=$("$docker_binary" logs --since "$docker_since" "$container_id" 2>&1) || return 1
        version_output=$("$docker_binary" exec "$container_id" /bin/maddy version 2>&1) || return 1
        [[ "$(extract_maddy_version "$version_output")" == "$maddy_version" ]] || return 1
    fi
    ! printf '%s\n' "$logs" | grep -Eiq 'app\.Run failed|reload[^[:alnum:]]*(failed|error)|"level":"(error|fatal)"|(^|[^[:alpha:]])fatal([^[:alpha:]]|$)'
}

rollback_candidate() {
    log "restoring the exact pre-change Maddy configuration"
    local status=0 restored=false reloaded=false expected_listener
    local restored_pid restored_snapshot restored_health restored_version_output restored_version
    local rollback_view rollback_report current_hash rollback_state
    if [[ "$mode" == docker && "${config_kind:-}" == volume ]]; then
        if pause_named_volume; then
            if [[ "$container_stopped" == true ]]; then
                rollback_state=stopped
            else
                rollback_state=paused
            fi
            rollback_view="$staging_dir/rollback-current.conf"
            rm -f -- "$rollback_view"
            if rollback_report=$("$python_binary" "$SCRIPT_DIR/docker-volume-config.py" \
                --docker "$docker_binary" --container "$container_id" \
                --expected-container-id "$container_id" --state "$rollback_state" \
                --action export --output "$rollback_view"); then
                current_hash=$("$python_binary" -c \
                    'import json,sys; print(json.loads(sys.argv[1])["sha256"])' \
                    "$rollback_report") || status=1
                if [[ "${current_hash:-}" == "$candidate_hash" ]]; then
                    if "$python_binary" "$SCRIPT_DIR/docker-volume-config.py" \
                        --docker "$docker_binary" --container "$container_id" \
                        --expected-container-id "$container_id" --state "$rollback_state" \
                        --action replace --candidate "$backup_path" \
                        --expected-current-sha256 "$candidate_hash" \
                        --expected-candidate-sha256 "$original_hash" >/dev/null; then
                        restored=true
                    else
                        status=1
                    fi
                elif [[ "${current_hash:-}" == "$original_hash" ]]; then
                    # The helper failed before its atomic rename.  Read-back
                    # proves there is nothing to restore.
                    restored=true
                else
                    status=1
                fi
            else
                status=1
            fi
        else
            status=1
        fi
    elif "$python_binary" "$SCRIPT_DIR/manage-submission.py" \
        --action restore --config "$maddy_config" --backup "$backup_path" \
        --expected-current-sha256 "$candidate_hash" >/dev/null; then
        restored=true
    else
        status=1
    fi
    if [[ "$restored" == true ]]; then
        if config_verify; then
            if reload_or_restart; then
                reloaded=true
            else
                status=1
            fi
        else
            status=1
        fi
    fi
    if [[ "$reloaded" == true ]]; then
        if [[ "$mode" == "native" ]]; then
            systemctl is-active --quiet maddy.service || status=1
            restored_pid=$(systemctl show --property MainPID --value maddy.service) || status=1
            [[ "${restored_pid:-}" =~ ^[1-9][0-9]*$ ]] || status=1
            if [[ "$maddy_version" != "0.8.2" \
                && "${restored_pid:-}" != "$native_pid_before" ]]; then
                status=1
            fi
        else
            restored_snapshot=$("$python_binary" "$SCRIPT_DIR/check-maddy-container.py" \
                --docker "$docker_binary" --container "$container_id" \
                --host-config "$maddy_config" 2>/dev/null) || status=1
            if [[ -n "${restored_snapshot:-}" ]]; then
                container_snapshot_matches "$restored_snapshot" || status=1
                restored_health=$("$python_binary" -c \
                    'import json,sys; print(json.loads(sys.argv[1]).get("health") or "none")' \
                    "$restored_snapshot") || status=1
                [[ "${restored_health:-}" == none || "${restored_health:-}" == healthy ]] \
                    || status=1
            fi
            restored_version_output=$(
                "$docker_binary" exec "$container_id" /bin/maddy version 2>&1
            ) || status=1
            if [[ -n "${restored_version_output:-}" ]]; then
                restored_version=$(extract_maddy_version "$restored_version_output") || status=1
                [[ "${restored_version:-}" == "$maddy_version" ]] || status=1
            fi
        fi
        if [[ "$action" == "add" ]]; then
            expected_listener=absent
        else
            expected_listener=present
        fi
        managed_listener_gate "$expected_listener" || status=1
    fi
    return "$status"
}

on_error() {
    local status=$?
    local restoration_failed=false
    trap - ERR EXIT INT TERM
    if [[ "$rollback_needed" == true ]]; then
        (( status != 0 )) || status=1
        if ! rollback_candidate; then
            restoration_failed=true
            log "CRITICAL: automatic configuration restoration failed; leave the named-volume container paused if possible"
        fi
    elif [[ "$edit_attempted" == true ]]; then
        (( status != 0 )) || status=1
        log "CRITICAL: Submission editor exited before a restorable backup/hash was confirmed"
    fi
    if [[ "$restoration_failed" != true ]] && ! ensure_named_volume_unpaused; then
        (( status != 0 )) || status=1
        log "CRITICAL: selected Maddy container could not be safely unpaused and revalidated"
    fi
    cleanup_staging || {
        (( status != 0 )) || status=1
        log "CRITICAL: private Submission staging cleanup failed"
    }
    exit "$status"
}
trap on_error EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$mode" == docker && "${config_kind:-}" == volume ]]; then
    pause_named_volume
    editor_config="$staging_dir/apply.conf"
    apply_report=$("$python_binary" "$SCRIPT_DIR/docker-volume-config.py" \
        --docker "$docker_binary" --container "$container_id" \
        --expected-container-id "$container_id" --state paused \
        --action export --output "$editor_config")
    apply_hash=$("$python_binary" -c \
        'import json,sys; print(json.loads(sys.argv[1])["sha256"])' "$apply_report")
    [[ "$apply_hash" == "$planned_hash" ]] \
        || die "named-volume configuration changed after the reviewed dry-run"
else
    edit_attempted=true
fi

edit_report=$("$python_binary" "$SCRIPT_DIR/manage-submission.py" \
    --action "$action" --config "$editor_config" --backup-dir "$backup_dir")
backup_path=$("$python_binary" -c 'import json,sys; print(json.loads(sys.argv[1])["backup"])' "$edit_report")
candidate_hash=$("$python_binary" -c 'import json,sys; print(json.loads(sys.argv[1])["after_sha256"])' "$edit_report")
original_hash=$("$python_binary" -c 'import json,sys; print(json.loads(sys.argv[1])["before_sha256"])' "$edit_report")
require_regular_file "$backup_path" "Maddy configuration backup"
[[ "$candidate_hash" =~ ^[0-9a-f]{64}$ ]] || die "editor returned an invalid candidate hash"
[[ "$original_hash" =~ ^[0-9a-f]{64}$ ]] || die "editor returned an invalid original hash"

if [[ "$mode" == docker && "${config_kind:-}" == volume ]]; then
    # The helper may complete its atomic rename but lose its acknowledgement.
    # Arm three-state recovery before invoking it, then distinguish original,
    # candidate, and unknown content by a fresh paused export.
    edit_attempted=true
    rollback_needed=true
    "$python_binary" "$SCRIPT_DIR/docker-volume-config.py" \
        --docker "$docker_binary" --container "$container_id" \
        --expected-container-id "$container_id" --state paused \
        --action replace --candidate "$editor_config" \
        --expected-current-sha256 "$original_hash" \
        --expected-candidate-sha256 "$candidate_hash" >/dev/null
else
    rollback_needed=true
fi

config_verify
reload_or_restart
health_and_log_gate
if [[ "$action" == "add" ]]; then
    managed_listener_gate present
else
    managed_listener_gate absent
fi
rollback_needed=false
edit_attempted=false
ensure_named_volume_unpaused
cleanup_staging
trap - EXIT INT TERM

log "managed Submission action completed: $action"
log "backup retained at $backup_path"
log "Nginx was not inspected or modified"
