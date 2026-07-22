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
readonly CERTBOT_DEPLOY_HOOK="/etc/letsencrypt/renewal-hooks/deploy/maddyweb"
readonly CERTBOT_HOOK_MARKER="# Managed by MaddyWeb install.sh; do not edit."

usage() {
    cat <<'EOF'
Usage: rollback.sh --environment development|production --host HOST \
  --release /opt/maddyweb/releases/<40-char-commit> --artifact-sha256 HEX \
  [--approval-file PATH] [--apply]

Optional managed-listener rollback (performed under the same approval):
  --remove-managed-submission --maddy-mode native|docker \
  --maddy-config /absolute/host/maddy.conf [mode-specific Maddy options]

Rolls back only the MaddyWeb release symlink. It never downgrades Maddy or
restores Maddy state automatically because newer Maddy releases may migrate
their database irreversibly. Without --apply this is a read-only plan.
EOF
}

environment=""
target_host=""
release=""
expected_sha256=""
approval_file=""
remove_submission=false
maddy_mode=""
maddy_config=""
maddy_binary=""
docker_binary="$(command -v docker || true)"
container=""
submission_backup_dir="/var/backups/maddyweb/submission"
allow_downtime=false
apply=false

while (($#)); do
    case "$1" in
        --environment) (($# >= 2)) || die "--environment requires a value"; environment=$2; shift 2 ;;
        --host) (($# >= 2)) || die "--host requires a value"; target_host=$2; shift 2 ;;
        --release) (($# >= 2)) || die "--release requires a value"; release=$2; shift 2 ;;
        --artifact-sha256) (($# >= 2)) || die "--artifact-sha256 requires a value"; expected_sha256=${2,,}; shift 2 ;;
        --approval-file) (($# >= 2)) || die "--approval-file requires a value"; approval_file=$2; shift 2 ;;
        --remove-managed-submission) remove_submission=true; shift ;;
        --maddy-mode) (($# >= 2)) || die "--maddy-mode requires a value"; maddy_mode=$2; shift 2 ;;
        --maddy-config) (($# >= 2)) || die "--maddy-config requires a value"; maddy_config=$2; shift 2 ;;
        --maddy-binary) (($# >= 2)) || die "--maddy-binary requires a value"; maddy_binary=$2; shift 2 ;;
        --docker-binary) (($# >= 2)) || die "--docker-binary requires a value"; docker_binary=$2; shift 2 ;;
        --container) (($# >= 2)) || die "--container requires a value"; container=$2; shift 2 ;;
        --submission-backup-dir) (($# >= 2)) || die "--submission-backup-dir requires a value"; submission_backup_dir=$2; shift 2 ;;
        --allow-downtime) allow_downtime=true; shift ;;
        --apply) apply=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$environment" in development|production) ;; *) die "--environment must be development or production" ;; esac
[[ -n "$target_host" && "$target_host" == "$(hostname)" ]] || die "--host must exactly match $(hostname)"
[[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || die "--artifact-sha256 must be 64 lowercase hexadecimal characters"
require_directory "$release" "rollback release"
require_path_below "$release" "$RELEASE_ROOT"
release_commit=$(basename -- "$release")
[[ "$release_commit" =~ ^[0-9a-f]{40}$ ]] || die "rollback release directory must be a full lowercase commit"
[[ -x "$release/bin/python" ]] || die "rollback release has no executable Python"
require_regular_file "$release/INSTALL-MANIFEST" "release manifest"
manifest_sha=$(awk -F= '$1 == "sha256" {print $2}' "$release/INSTALL-MANIFEST")
manifest_commit=$(awk -F= '$1 == "commit" {print $2}' "$release/INSTALL-MANIFEST")
[[ "$manifest_sha" == "$expected_sha256" ]] || die "release manifest checksum does not match explicit artifact checksum"
[[ "$manifest_commit" == "$release_commit" ]] || die "release manifest commit does not match its directory"
"$release/bin/python" -m maddyweb --help >/dev/null || die "rollback release cannot import maddyweb"

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
if [[ "$remove_submission" == true ]]; then
    case "$maddy_mode" in native|docker) ;; *) die "managed removal requires --maddy-mode native or docker" ;; esac
    require_absolute_path "$submission_backup_dir" "submission backup directory"
    if [[ "$maddy_mode" == native ]]; then
        require_regular_file "$maddy_config" "host Maddy config"
        "$release/bin/python" "$SCRIPT_DIR/manage-submission.py" \
            --action check-remove --config "$maddy_config" >/dev/null
        [[ -n "$maddy_binary" && -z "$container" ]] || die "native managed removal requires --maddy-binary and no container"
        submission_version=$(assert_supported_maddy "$maddy_binary")
    else
        [[ "$container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || die "Docker managed removal requires a safe container"
        require_absolute_path "$docker_binary" "Docker binary"
        container_before=$("$release/bin/python" "$SCRIPT_DIR/check-maddy-container.py" \
            --docker "$docker_binary" --container "$container" --host-config "$maddy_config")
        rollback_config_kind=$("$release/bin/python" -c \
            'import json,sys; print(json.loads(sys.argv[1])["config_kind"])' \
            "$container_before")
        [[ "$rollback_config_kind" == bind ]] \
            || die "combined rollback only supports a host-bind Maddy config; remove named-volume Submission separately"
        require_regular_file "$maddy_config" "host Maddy config"
        "$release/bin/python" "$SCRIPT_DIR/manage-submission.py" \
            --action check-remove --config "$maddy_config" >/dev/null
        version_output=$("$docker_binary" exec "$container" /bin/maddy version 2>&1) || die "container Maddy version failed"
        submission_version=$(extract_maddy_version "$version_output")
        version_in_supported_range "$submission_version" || die "unsupported container Maddy version"
    fi
    if [[ "$submission_version" == 0.8.2 && "$apply" == true && "$allow_downtime" != true ]]; then
        die "Maddy 0.8.2 managed removal requires --allow-downtime for a short restart"
    fi
elif [[ -n "$maddy_mode$maddy_config$maddy_binary$container" ]]; then
    die "managed Maddy options require --remove-managed-submission"
fi

[[ -L "$CURRENT_LINK" ]] || die "current release link is missing or unsafe"
current=$(readlink -f -- "$CURRENT_LINK")
require_path_below "$current" "$RELEASE_ROOT"
[[ "$current" != "$release" ]] || die "requested release is already current"
printf 'environment=%s\nhost=%s\nfrom=%s\nto=%s\ncommit=%s\nartifact_sha256=%s\nremove_managed_submission=%s\n' \
    "$environment" "$target_host" "$current" "$release" "$release_commit" "$expected_sha256" "$remove_submission"

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

submission_backup=""
submission_candidate_hash=""
submission_edit_started=false
native_pid_before=""
rollback_transaction_active=false

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
keys=("id","mounts_sha256","ports_sha256","restart_policy_sha256","config_source")
raise SystemExit(any(before.get(k) != after.get(k) for k in keys))' \
        "$container_before" "$after"
}

managed_listener_gate() {
    local expected=${1:?expected listener state is required}
    if [[ "$maddy_mode" == native ]]; then
        local listeners
        listeners=$(ss -H -ltn 'sport = :1587' 2>/dev/null | awk '{print $4}')
        if [[ "$expected" == present ]]; then
            [[ "$listeners" == "127.0.0.1:1587" ]]
        else
            [[ -z "$listeners" ]]
        fi
    else
        local table found=false
        table=$("$docker_binary" exec "$container" /bin/cat /proc/net/tcp 2>/dev/null) \
            || return 1
        if printf '%s\n' "$table" \
            | awk '$2 == "0100007F:0633" && $4 == "0A" {found=1} END {exit !found}'; then
            found=true
        fi
        if [[ "$expected" == present ]]; then
            [[ "$found" == true ]] || return 1
            "$docker_binary" exec "$container" /usr/bin/nc -z -w 2 127.0.0.1 1587 \
                >/dev/null 2>&1
        else
            [[ "$found" == false ]]
        fi
    fi
}

verify_submission_config() {
    if [[ "$submission_version" == 0.8.2 ]]; then return 0; fi
    if [[ "$maddy_mode" == native ]]; then
        "$maddy_binary" -config "$maddy_config" verify-config >/dev/null 2>&1
    else
        "$docker_binary" exec "$container" /bin/maddy -config /data/maddy.conf \
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
        "$docker_binary" restart --time 10 "$container" >/dev/null
    else
        "$docker_binary" kill --signal=SIGUSR2 "$container" >/dev/null
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
                --docker "$docker_binary" --container "$container" \
                --host-config "$maddy_config" 2>/dev/null) && break
            sleep 0.2
        done
        [[ -n "$after" ]] || return 1
        container_snapshot_matches "$after" || return 1
        health=$("$release/bin/python" -c \
            'import json,sys; print(json.loads(sys.argv[1]).get("health") or "none")' \
            "$after") || return 1
        [[ "$health" == none || "$health" == healthy ]] || return 1
        version_output=$("$docker_binary" exec "$container" /bin/maddy version 2>&1) \
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
    local status=0 restored_link=false restored_current
    rollback_transaction_active=false
    log "restoring the exact pre-rollback release and managed Submission state"
    if switch_link "$current"; then restored_link=true; else status=1; fi
    if [[ "$remove_submission" == true ]]; then restore_submission || status=1; fi
    if [[ "$restored_link" == true ]]; then
        systemctl restart maddyweb-helper.socket maddyweb.service || status=1
        systemctl try-restart maddyweb-helper.service || status=1
        restored_current=$(readlink -f -- "$CURRENT_LINK" 2>/dev/null) || status=1
        [[ "${restored_current:-}" == "$current" ]] || status=1
        systemctl is-active --quiet maddyweb-helper.socket maddyweb.service || status=1
        "$current/bin/python" "$SCRIPT_DIR/smoke-test.py" || status=1
    fi
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
        die "$reason; exact previous release and managed Submission state were restored"
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
        container_before=$("$release/bin/python" "$SCRIPT_DIR/check-maddy-container.py" \
            --docker "$docker_binary" --container "$container" --host-config "$maddy_config")
    fi
    managed_listener_gate present \
        || die "managed Submission is not active on exactly its loopback endpoint"
fi

rollback_transaction_active=true
trap on_rollback_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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

switch_link "$release" || abort_rollback_transaction "rollback release switch failed"
if ! systemctl restart maddyweb-helper.socket maddyweb.service \
    || ! systemctl try-restart maddyweb-helper.service \
    || ! systemctl is-active --quiet maddyweb-helper.socket maddyweb.service \
    || ! "$release/bin/python" "$SCRIPT_DIR/smoke-test.py"; then
    abort_rollback_transaction "rollback candidate activation or smoke gate failed"
fi
previous_release_temp="/var/lib/maddyweb/.previous-release-rollback-$$"
if ! printf '%s\n' "$current" > "$previous_release_temp" \
    || ! chmod 0600 -- "$previous_release_temp" \
    || ! mv -fT -- "$previous_release_temp" /var/lib/maddyweb/previous-release; then
    rm -f -- "$previous_release_temp" || true
    abort_rollback_transaction "previous-release metadata update failed"
fi
rollback_transaction_active=false
trap - EXIT INT TERM
log "rollback completed: $release"
