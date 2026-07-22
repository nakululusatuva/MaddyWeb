#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

die() {
    printf 'WSL matrix case failed: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 6 ]] || die "expected binary, checksum, config, version, repository, and Python"
source_binary=$1
expected_sha256=${2,,}
source_config=$3
expected_version=$4
repository=$5
python_binary=$6

case "$expected_version" in
    0.8.2|0.9.0|0.9.1|0.9.2|0.9.3|0.9.4|0.9.5) ;;
    *) die "unsupported matrix version: $expected_version" ;;
esac
[[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || die "invalid SHA-256"
[[ -f "$source_binary" && ! -L "$source_binary" ]] || die "binary artifact is missing or a symlink"
[[ -f "$source_config" && ! -L "$source_config" ]] || die "version config is missing or a symlink"
[[ -d "$repository/src/maddyweb" ]] || die "repository path is invalid"
command -v -- "$python_binary" >/dev/null 2>&1 || die "Python command not found: $python_binary"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

actual_sha256=$(sha256sum -- "$source_binary" | awk '{print $1}')
[[ "$actual_sha256" == "$expected_sha256" ]] || die "artifact checksum mismatch"

case_root=$(mktemp -d "${TMPDIR:-/tmp}/maddyweb-wsl-${expected_version}.XXXXXXXX")
cleanup() {
    local status=$?
    if [[ "$case_root" == "${TMPDIR:-/tmp}"/maddyweb-wsl-* && -d "$case_root" && ! -L "$case_root" ]]; then
        rm -rf -- "$case_root"
    fi
    exit "$status"
}
trap cleanup EXIT

install -m 0755 -- "$source_binary" "$case_root/maddy"
install -m 0600 -- "$source_config" "$case_root/maddy.conf"
first_token=$("$case_root/maddy" version | awk 'NR == 1 {print $1}')
[[ "${first_token#v}" == "$expected_version" ]] || die "binary version token does not match artifact directory"

PYTHONPATH="$repository/src" "$python_binary" \
    "$repository/tests/integration/wsl_matrix_case.py" \
    --binary "$case_root/maddy" \
    --config "$case_root/maddy.conf" \
    --expected-version "$expected_version"
