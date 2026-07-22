#!/usr/bin/env bash

# Shared safety primitives. This file is sourced by the operational scripts;
# it intentionally performs no action by itself.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly MADDYWEB_SUPPORTED_MADDY_RELEASES="0.8.2,0.9.0,0.9.1,0.9.2,0.9.3,0.9.4,0.9.5"
readonly MADDYWEB_MADDY_082_HELP_SHA256="e60d7cdaae4721367e291f78faf0b75a0689d1fceafea1a904f6707b43e9f708"
readonly MADDYWEB_APPROVAL_ROOT="/run/maddyweb-approval"

log() {
    printf '[maddyweb] %s\n' "$*" >&2
}

die() {
    log "ERROR: $*"
    exit 1
}

require_command() {
    command -v -- "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "this operation must run as root"
}

require_absolute_path() {
    local value=${1:?path is required}
    local label=${2:-path}
    [[ "$value" == /* ]] || die "$label must be absolute: $value"
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "$label contains a newline"
    [[ "$value" != "/" ]] || die "$label must not be the filesystem root"
}

require_regular_file() {
    local value=${1:?file is required}
    local label=${2:-file}
    require_absolute_path "$value" "$label"
    [[ -f "$value" ]] || die "$label is not a regular file: $value"
    [[ ! -L "$value" ]] || die "$label must not be a symbolic link: $value"
}

require_directory() {
    local value=${1:?directory is required}
    local label=${2:-directory}
    require_absolute_path "$value" "$label"
    [[ -d "$value" ]] || die "$label is not a directory: $value"
    [[ ! -L "$value" ]] || die "$label must not be a symbolic link: $value"
}

require_path_below() {
    local value=${1:?path is required}
    local root=${2:?root is required}
    require_absolute_path "$value"
    require_absolute_path "$root" "allowed root"
    case "$value" in
        "$root"/*) ;;
        *) die "path escapes the allowed root $root: $value" ;;
    esac
}

sha256_file() {
    local value=${1:?file is required}
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$value" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$value" | awk '{print $1}'
    else
        die "sha256sum or shasum is required"
    fi
}

extract_maddy_version() {
    local output=${1:?version output is required}
    local first_line first_token version
    first_line=${output%%$'\n'*}
    read -r first_token _ <<< "$first_line"
    version=${first_token#v}
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "unable to parse Maddy version output"
    printf '%s\n' "$version"
}

version_in_supported_range() {
    local version=${1:?version is required}
    case "$version" in
        0.8.2|0.9.0|0.9.1|0.9.2|0.9.3|0.9.4|0.9.5) return 0 ;;
        *) return 1 ;;
    esac
}

assert_supported_maddy() {
    local binary=${1:?Maddy binary is required}
    require_absolute_path "$binary" "Maddy binary"
    [[ -f "$binary" && -x "$binary" ]] || die "Maddy binary is not executable: $binary"
    local output version
    output=$("$binary" version 2>&1) || die "Maddy version command failed"
    version=$(extract_maddy_version "$output")
    version_in_supported_range "$version" \
        || die "unsupported Maddy version $version; supported official releases are $MADDYWEB_SUPPORTED_MADDY_RELEASES"
    printf '%s\n' "$version"
}

assert_maddy_082_help_profile() {
    (($# >= 1)) || die "Maddy command prefix is required"
    local -a command_prefix=("$@")
    local combined="" output signature token
    local -a signatures=(
        '--help|creds,imap-acct,imap-mboxes,imap-msgs'
        'creds --help|list,create,remove,password'
        'imap-acct --help|list,create,remove,appendlimit'
        'imap-acct appendlimit --help|--value,USERNAME'
        'imap-mboxes --help|list,create,remove,rename'
        'imap-msgs --help|add,add-flags,rem-flags,set-flags,remove,copy,move,list,dump'
        'imap-msgs list --help|--uid,--full,USERNAME,MAILBOX'
        'imap-msgs remove --help|--uid,--yes,SEQSET'
    )
    for signature in "${signatures[@]}"; do
        local argv_text=${signature%%|*}
        local required=${signature#*|}
        local -a argv
        IFS=' ' read -r -a argv <<< "$argv_text"
        output=$("${command_prefix[@]}" "${argv[@]}" 2>&1) || die "Maddy 0.8.2 help signature failed: $argv_text"
        (( ${#output} <= 524288 )) || die "Maddy help output exceeded 512 KiB"
        [[ "$output" != *'app.Run failed'* ]] || die "Maddy help unexpectedly entered the legacy run path"
        if [[ "$argv_text" == "--help" && "$output" == *verify-config* ]]; then
            die "Maddy 0.8.2 unexpectedly advertises verify-config"
        fi
        local -a required_tokens
        IFS=',' read -r -a required_tokens <<< "$required"
        for token in "${required_tokens[@]}"; do
            [[ "$output" == *"$token"* ]] || die "Maddy help '$argv_text' is missing required token: $token"
        done
        combined+="$argv_text"$'\x1e'"$output"$'\x1f'
    done
    local fingerprint
    fingerprint=$(printf '%s' "$combined" | sha256_file /dev/stdin) \
        || die "cannot calculate the Maddy 0.8.2 help fingerprint"
    [[ "$fingerprint" == "$MADDYWEB_MADDY_082_HELP_SHA256" ]] \
        || die "Maddy 0.8.2 help fingerprint does not match the verified release"
    printf '%s\n' "$fingerprint"
}

assert_private_file_mode() {
    local value=${1:?file is required}
    local mode
    mode=$(stat -c '%a' -- "$value") || die "cannot inspect permissions: $value"
    (( (8#$mode & 8#022) == 0 )) || die "file is group/world writable: $value (mode $mode)"
}

consume_production_approval() {
    local approval=${1:?approval file is required}
    local expected_action=${2:?expected action is required}
    require_root
    require_regular_file "$approval" "production approval"
    require_path_below "$approval" "$MADDYWEB_APPROVAL_ROOT"

    local owner mode
    owner=$(stat -c '%u' -- "$approval") || die "cannot inspect approval owner"
    mode=$(stat -c '%a' -- "$approval") || die "cannot inspect approval permissions"
    [[ "$owner" == "0" ]] || die "approval must be owned by root"
    [[ "$mode" == "600" ]] || die "approval mode must be exactly 0600"

    local format="" action="" host="" expires="" nonce="" key value
    local line_count=0
    while IFS='=' read -r key value; do
        ((line_count += 1))
        case "$key" in
            format) [[ -z "$format" ]] || die "duplicate approval field: format"; format=$value ;;
            action) [[ -z "$action" ]] || die "duplicate approval field: action"; action=$value ;;
            host) [[ -z "$host" ]] || die "duplicate approval field: host"; host=$value ;;
            expires) [[ -z "$expires" ]] || die "duplicate approval field: expires"; expires=$value ;;
            nonce) [[ -z "$nonce" ]] || die "duplicate approval field: nonce"; nonce=$value ;;
            *) die "unknown approval field: $key" ;;
        esac
    done < "$approval"

    [[ "$line_count" -eq 5 && "$format" == "maddyweb-production-approval-v1" ]] || die "invalid approval format"
    [[ "$action" == "$expected_action" ]] || die "approval is for '$action', expected '$expected_action'"
    [[ "$host" == "$(hostname)" ]] || die "approval was issued for a different host"
    [[ "$expires" =~ ^[0-9]+$ ]] || die "invalid approval expiry"
    [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || die "invalid approval nonce"

    local now
    now=$(date +%s)
    (( expires >= now )) || die "production approval has expired"
    (( expires <= now + 900 )) || die "production approval expiry is unreasonably far in the future"

    # Consume before any mutation. A failed operation requires a new human
    # approval, which prevents accidental retries from becoming implicit.
    rm -f -- "$approval"
    [[ ! -e "$approval" ]] || die "failed to consume production approval"
    log "consumed one-time production approval for '$expected_action'"
}
