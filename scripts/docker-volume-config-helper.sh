#!/bin/sh
# Fixed helper executed in a disposable, networkless container created from
# the selected Maddy container's immutable image ID.  It never runs inside the
# mutable Maddy container and the target path is deliberately not configurable.
set -eu
umask 077

config=/data/maddy.conf
maximum=4194304

fail() {
    printf 'MaddyWeb named-volume helper failed: %s\n' "$1" >&2
    exit 1
}

validate_hash() {
    case "$1" in
        *[!0-9a-f]*|'') return 1 ;;
    esac
    [ "${#1}" -eq 64 ]
}

snapshot_metadata() {
    [ -f "$config" ] || fail 'configuration is not a regular file'
    [ ! -L "$config" ] || fail 'configuration must not be a symlink'
    metadata=$(stat -c '%a:%u:%g:%s:%h' -- "$config") \
        || fail 'cannot stat configuration'
    old_ifs=$IFS
    IFS=:
    # Deliberate field split on the fixed numeric stat format above.
    # shellcheck disable=SC2086
    set -- $metadata
    IFS=$old_ifs
    [ "$#" -eq 5 ] || fail 'configuration metadata is invalid'
    mode=$1
    uid=$2
    gid=$3
    size=$4
    links=$5
    case "$mode:$uid:$gid:$size:$links" in
        *[!0-9:]*) fail 'configuration metadata is unsafe' ;;
    esac
    mode_value=$((0$mode))
    [ $((mode_value & 07000)) -eq 0 ] \
        || fail 'configuration mode must not contain special bits'
    [ $((mode_value & 022)) -eq 0 ] \
        || fail 'configuration mode must not be group/world writable'
    [ "$links" -eq 1 ] || fail 'configuration must have exactly one link'
    [ "$size" -gt 0 ] && [ "$size" -le "$maximum" ] \
        || fail 'configuration size is outside the safe range'
    hash=$(sha256sum -- "$config") || fail 'cannot hash configuration'
    hash=${hash%% *}
    validate_hash "$hash" || fail 'configuration hash is invalid'
}

action=${1:-}
case "$action" in
    export)
        [ "$#" -eq 1 ] || fail 'export takes no additional arguments'
        snapshot_metadata
        printf 'MADDYWEB_CONFIG_V1 %s %s %s %s %s\n' \
            "$mode" "$uid" "$gid" "$size" "$hash"
        cat -- "$config" || fail 'cannot export configuration'
        ;;
    replace)
        [ "$#" -eq 4 ] || fail 'replace requires fixed hash arguments'
        expected_current=$2
        expected_candidate=$3
        nonce=$4
        validate_hash "$expected_current" || fail 'expected current hash is invalid'
        validate_hash "$expected_candidate" || fail 'expected candidate hash is invalid'
        case "$nonce" in
            *[!0-9a-f]*|'') fail 'temporary nonce is invalid' ;;
        esac
        [ "${#nonce}" -eq 32 ] || fail 'temporary nonce length is invalid'
        candidate=/input/maddy.conf
        [ -f "$candidate" ] && [ ! -L "$candidate" ] \
            || fail 'candidate is not a regular file'
        candidate_size=$(stat -c '%s' -- "$candidate") \
            || fail 'cannot stat candidate'
        case "$candidate_size" in *[!0-9]*|'') fail 'candidate size is invalid' ;; esac
        [ "$candidate_size" -gt 0 ] && [ "$candidate_size" -le "$maximum" ] \
            || fail 'candidate size is outside the safe range'
        candidate_hash=$(sha256sum -- "$candidate") || fail 'cannot hash candidate'
        candidate_hash=${candidate_hash%% *}
        [ "$candidate_hash" = "$expected_candidate" ] \
            || fail 'candidate hash differs from the reviewed content'

        snapshot_metadata
        [ "$hash" = "$expected_current" ] \
            || fail 'configuration changed before replacement'
        original_mode=$mode
        original_uid=$uid
        original_gid=$gid
        temporary="/data/.maddy.conf.maddyweb-$nonce"
        [ ! -e "$temporary" ] && [ ! -L "$temporary" ] \
            || fail 'private temporary path already exists'
        trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
        cp -- "$candidate" "$temporary" || fail 'cannot stage candidate in target directory'
        chmod "$mode" -- "$temporary" || fail 'cannot preserve configuration mode'
        chown "$uid:$gid" -- "$temporary" || fail 'cannot preserve configuration owner'
        staged_hash=$(sha256sum -- "$temporary") || fail 'cannot hash staged candidate'
        staged_hash=${staged_hash%% *}
        [ "$staged_hash" = "$expected_candidate" ] || fail 'staged candidate hash mismatch'
        sync "$temporary" || fail 'cannot sync staged candidate'

        # Close the content TOCTOU window immediately before the same-directory
        # rename.  The selected container is paused and exclusive attachment is
        # checked by the host orchestrator before this helper starts.
        current_hash=$(sha256sum -- "$config") || fail 'cannot re-hash configuration'
        current_hash=${current_hash%% *}
        [ "$current_hash" = "$expected_current" ] \
            || fail 'configuration changed during replacement'
        mv -f -- "$temporary" "$config" || fail 'atomic configuration rename failed'
        trap - EXIT HUP INT TERM
        sync /data || fail 'cannot sync target volume'

        snapshot_metadata
        [ "$hash" = "$expected_candidate" ] || fail 'replacement read-back hash mismatch'
        [ "$mode:$uid:$gid" = "$original_mode:$original_uid:$original_gid" ] \
            || fail 'replacement ownership or mode read-back failed'
        printf 'MADDYWEB_REPLACED_V1 %s\n' "$hash"
        ;;
    *)
        fail 'action must be export or replace'
        ;;
esac
