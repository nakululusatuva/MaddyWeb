#!/usr/bin/env bash

# Exact systemd state tracking for backup.sh. This file is sourced after
# lib/common.sh and intentionally performs no action by itself.

readonly -a MADDYWEB_BACKUP_UNITS=(
    maddyweb.service
    maddyweb-helper.socket
    maddyweb-helper.service
)
readonly -a MADDYWEB_BACKUP_RESTORE_ORDER=(
    maddyweb-helper.socket
    maddyweb-helper.service
    maddyweb.service
)
declare -A MADDYWEB_BACKUP_UNIT_PRESENT=()
declare -A MADDYWEB_BACKUP_UNIT_ACTIVE=()

systemd_unit_property() {
    local unit=${1:?unit is required}
    local property=${2:?property is required}
    local value
    value=$(systemctl show --property="$property" --value "$unit" 2>/dev/null) \
        || return 1
    [[ -n "$value" && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
    printf '%s\n' "$value"
}

capture_maddyweb_unit_states() {
    local unit load_state active_state
    for unit in "${MADDYWEB_BACKUP_UNITS[@]}"; do
        load_state=$(systemd_unit_property "$unit" LoadState) || return 1
        active_state=$(systemd_unit_property "$unit" ActiveState) || return 1
        if [[ "$load_state" == not-found ]]; then
            [[ "$active_state" == inactive ]] || return 1
            MADDYWEB_BACKUP_UNIT_PRESENT[$unit]=false
            MADDYWEB_BACKUP_UNIT_ACTIVE[$unit]=false
            continue
        fi
        MADDYWEB_BACKUP_UNIT_PRESENT[$unit]=true
        case "$active_state" in
            active) MADDYWEB_BACKUP_UNIT_ACTIVE[$unit]=true ;;
            inactive|failed) MADDYWEB_BACKUP_UNIT_ACTIVE[$unit]=false ;;
            *) return 1 ;;
        esac
    done
}

stop_active_maddyweb_units() {
    local unit active_state
    for unit in "${MADDYWEB_BACKUP_UNITS[@]}"; do
        if [[ "${MADDYWEB_BACKUP_UNIT_PRESENT[$unit]}" == true \
            && "${MADDYWEB_BACKUP_UNIT_ACTIVE[$unit]}" == true ]]; then
            systemctl stop "$unit" || return 1
            active_state=$(systemd_unit_property "$unit" ActiveState) || return 1
            [[ "$active_state" == inactive ]] || return 1
        fi
    done
}

restore_maddyweb_unit_states() {
    local status=0 unit load_state active_state

    # Restore originally active units first. Starting Web can socket-activate
    # the helper, so originally inactive units are normalized in a second pass.
    for unit in "${MADDYWEB_BACKUP_RESTORE_ORDER[@]}"; do
        if [[ "${MADDYWEB_BACKUP_UNIT_PRESENT[$unit]}" == true \
            && "${MADDYWEB_BACKUP_UNIT_ACTIVE[$unit]}" == true ]]; then
            active_state=$(systemd_unit_property "$unit" ActiveState) || {
                status=1
                continue
            }
            if [[ "$active_state" != active ]]; then
                systemctl start "$unit" || status=1
            fi
        fi
    done

    for unit in "${MADDYWEB_BACKUP_RESTORE_ORDER[@]}"; do
        if [[ "${MADDYWEB_BACKUP_UNIT_PRESENT[$unit]}" == true \
            && "${MADDYWEB_BACKUP_UNIT_ACTIVE[$unit]}" == false ]]; then
            active_state=$(systemd_unit_property "$unit" ActiveState) || {
                status=1
                continue
            }
            if [[ "$active_state" == active ]]; then
                systemctl stop "$unit" || status=1
            fi
        fi
    done

    # Read back exact presence and active/inactive classification. A unit that
    # did not exist before a first-install backup is a successful unchanged
    # state, not a cleanup error, and is never passed to start/stop.
    for unit in "${MADDYWEB_BACKUP_UNITS[@]}"; do
        load_state=$(systemd_unit_property "$unit" LoadState) || {
            status=1
            continue
        }
        active_state=$(systemd_unit_property "$unit" ActiveState) || {
            status=1
            continue
        }
        if [[ "${MADDYWEB_BACKUP_UNIT_PRESENT[$unit]}" == false ]]; then
            [[ "$load_state" == not-found && "$active_state" == inactive ]] || status=1
        elif [[ "$load_state" == not-found ]]; then
            status=1
        elif [[ "${MADDYWEB_BACKUP_UNIT_ACTIVE[$unit]}" == true ]]; then
            [[ "$active_state" == active ]] || status=1
        else
            [[ "$active_state" != active ]] || status=1
        fi
    done
    return "$status"
}
