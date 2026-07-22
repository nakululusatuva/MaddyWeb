#!/bin/bash -p
# Managed by MaddyWeb install.sh; do not edit.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export LC_ALL=C

readonly PRODUCTION_PYTHON="/opt/maddyweb/current/bin/python"
readonly PRODUCTION_DRIVER="/opt/maddyweb/current/libexec/certbot-deploy-hook.py"
readonly PRODUCTION_CONFIG="/etc/maddyweb/config.toml"
readonly FIXED_PATH="/usr/sbin:/usr/bin:/sbin:/bin"

die() {
    printf 'maddyweb Certbot deploy hook: %s\n' "$*" >&2
    exit 1
}

validate_lineage_text() {
    local value=${1-} leaf
    [[ -n "$value" && ${#value} -le 4096 ]] \
        || die "RENEWED_LINEAGE is missing or too long"
    [[ "$value" == /* ]] || die "RENEWED_LINEAGE must be absolute"
    [[ "$value" != *[[:cntrl:][:space:]%]* ]] \
        || die "RENEWED_LINEAGE contains a forbidden character"
    [[ "$value" != *\\* && "$value" != *//* && "$value" != */ ]] \
        || die "RENEWED_LINEAGE is not a canonical POSIX path"
    [[ "$value" != */./* && "$value" != */../* \
        && "$value" != */. && "$value" != */.. ]] \
        || die "RENEWED_LINEAGE contains path traversal"
    leaf=${value##*/}
    [[ "$leaf" != -* && "$leaf" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$ ]] \
        || die "RENEWED_LINEAGE has an invalid certificate name"
}

(($# == 0)) || die "arguments are not accepted"
[[ ${RENEWED_LINEAGE+x} == x ]] || die "RENEWED_LINEAGE is required"
readonly lineage=$RENEWED_LINEAGE
validate_lineage_text "$lineage"

if ((EUID == 0)); then
    [[ -z "${MADDYWEB_CERTBOT_HOOK_FIXTURE+x}${MADDYWEB_CERTBOT_HOOK_PYTHON+x}${MADDYWEB_CERTBOT_HOOK_DRIVER+x}${MADDYWEB_CERTBOT_HOOK_CONFIG+x}" ]] \
        || die "fixture overrides are forbidden for the root production hook"
    [[ -x "$PRODUCTION_PYTHON" ]] || die "fixed MaddyWeb Python is unavailable"
    [[ -f "$PRODUCTION_DRIVER" && ! -L "$PRODUCTION_DRIVER" ]] \
        || die "fixed deploy-hook driver is unavailable or unsafe"
    driver_metadata=$(/usr/bin/stat -c '%u:%a:%h' -- "$PRODUCTION_DRIVER") \
        || die "fixed deploy-hook driver metadata is unavailable"
    IFS=: read -r driver_owner driver_mode driver_links <<< "$driver_metadata"
    [[ "$driver_owner" == 0 && "$driver_links" == 1 ]] \
        || die "fixed deploy-hook driver ownership is unsafe"
    (( (8#$driver_mode & 0022) == 0 )) \
        || die "fixed deploy-hook driver permissions are unsafe"
    exec /usr/bin/env -i \
        "PATH=$FIXED_PATH" "LANG=C" "LC_ALL=C" "RENEWED_LINEAGE=$lineage" \
        "$PRODUCTION_PYTHON" -I "$PRODUCTION_DRIVER" \
        --config "$PRODUCTION_CONFIG"
fi

[[ ${MADDYWEB_CERTBOT_HOOK_FIXTURE-} == 1 ]] \
    || die "the production hook must run as root"
fixture_python=${MADDYWEB_CERTBOT_HOOK_PYTHON-}
fixture_driver=${MADDYWEB_CERTBOT_HOOK_DRIVER-}
fixture_config=${MADDYWEB_CERTBOT_HOOK_CONFIG-}
[[ "$fixture_python" == /* && -x "$fixture_python" ]] \
    || die "fixture Python must be an absolute executable path"
[[ "$fixture_driver" == /* && -f "$fixture_driver" && ! -L "$fixture_driver" ]] \
    || die "fixture driver must be an absolute regular non-symlink file"
[[ "$fixture_config" == /* && -f "$fixture_config" && ! -L "$fixture_config" ]] \
    || die "fixture config must be an absolute regular non-symlink file"
exec /usr/bin/env -i \
    "PATH=$FIXED_PATH" "LANG=C" "LC_ALL=C" "RENEWED_LINEAGE=$lineage" \
    "$fixture_python" -I "$fixture_driver" --fixture --config "$fixture_config"
