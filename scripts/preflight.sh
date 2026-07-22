#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    cat <<'EOF'
Native/WSL:
  preflight.sh --mode native|wsl --app-config /absolute/config.toml \
    --maddy-binary /absolute/maddy --maddy-config /absolute/maddy.conf \
    --maddy-state /absolute/state-dir [--python /absolute/python3.14]

Container:
  preflight.sh --mode container --app-config /absolute/config.toml \
    --container maddy --maddy-config /data/maddy.conf \
    [--docker-binary /absolute/docker] [--python /absolute/python3.14]

Read-only checks only. Paths are never guessed. Maddy versions outside
0.8.2-0.9.5 are rejected rather than treated as write-compatible.
EOF
}

mode=""
app_config=""
maddy_binary=""
maddy_config=""
maddy_state=""
container=""
docker_binary="$(command -v docker || true)"
python_binary="$(command -v python3 || true)"

while (($#)); do
    case "$1" in
        --mode) (($# >= 2)) || die "--mode requires a value"; mode=$2; shift 2 ;;
        --app-config) (($# >= 2)) || die "--app-config requires a value"; app_config=$2; shift 2 ;;
        --maddy-binary) (($# >= 2)) || die "--maddy-binary requires a value"; maddy_binary=$2; shift 2 ;;
        --maddy-config) (($# >= 2)) || die "--maddy-config requires a value"; maddy_config=$2; shift 2 ;;
        --maddy-state) (($# >= 2)) || die "--maddy-state requires a value"; maddy_state=$2; shift 2 ;;
        --container) (($# >= 2)) || die "--container requires a value"; container=$2; shift 2 ;;
        --docker-binary) (($# >= 2)) || die "--docker-binary requires a value"; docker_binary=$2; shift 2 ;;
        --python) (($# >= 2)) || die "--python requires a value"; python_binary=$2; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$mode" in native|wsl|container) ;; *) die "--mode must be native, wsl, or container" ;; esac
[[ -n "$app_config" && -n "$python_binary" ]] || die "--app-config and --python are required"

require_regular_file "$app_config" "MaddyWeb config"
require_absolute_path "$python_binary" "Python binary"
[[ -x "$python_binary" ]] || die "Python binary is not executable: $python_binary"
assert_private_file_mode "$app_config"

python_diagnostics=$("$python_binary" -c 'import sys, sysconfig
if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14):
    raise SystemExit(1)
gil_disabled = int(bool(sysconfig.get_config_var("Py_GIL_DISABLED")))
is_gil_enabled = getattr(sys, "_is_gil_enabled", None)
if is_gil_enabled is None:
    raise SystemExit(1)
print(".".join(map(str, sys.version_info[:3])), gil_disabled, int(is_gil_enabled()))' \
) || die "CPython 3.14 (standard or free-threaded) is required"
read -r python_version py_gil_disabled gil_enabled <<< "$python_diagnostics"

if [[ "$mode" == "container" ]]; then
    [[ "$container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || die "container name is unsafe"
    [[ -n "$maddy_config" ]] || die "--maddy-config is required in container mode"
    require_absolute_path "$maddy_config" "in-container Maddy config"
    [[ -n "$docker_binary" ]] || die "--docker-binary is required in container mode"
    require_absolute_path "$docker_binary" "Docker binary"
    [[ -x "$docker_binary" ]] || die "Docker binary is not executable"
    running=$("$docker_binary" inspect --format '{{.State.Running}}' "$container" 2>/dev/null) || die "cannot inspect container: $container"
    [[ "$running" == "true" ]] || die "Maddy container is not running"
    published_ports=$("$docker_binary" port "$container" 2>/dev/null) \
        || die "cannot inspect container port publications"
    if printf '%s\n' "$published_ports" | grep -Eq '(^|[[:space:]])1587/(tcp|udp)[[:space:]]|:1587$'; then
        die "Docker must not publish MaddyWeb's managed port 1587"
    fi
    "$docker_binary" exec "$container" /usr/bin/test -x /usr/bin/nc >/dev/null 2>&1 \
        || die "container must provide fixed /usr/bin/nc for local SMTP transport"
    version_output=$("$docker_binary" exec "$container" /bin/maddy version 2>&1) || die "container maddy version failed"
    maddy_version=$(extract_maddy_version "$version_output")
    version_in_supported_range "$maddy_version" || die "unsupported Maddy version $maddy_version"
    if [[ "$maddy_version" == "0.8.2" ]]; then
        legacy_help_fingerprint=$(assert_maddy_082_help_profile "$docker_binary" exec "$container" /bin/maddy)
        config_validation=isolated-container-running
    else
        "$docker_binary" exec "$container" /bin/maddy -config "$maddy_config" verify-config >/dev/null 2>&1 || die "container maddy verify-config failed"
        legacy_help_fingerprint=not-applicable
        config_validation=verify-config
    fi
    expected_maddy_mode=docker
else
    [[ -n "$maddy_binary" && -n "$maddy_config" && -n "$maddy_state" ]] || die "native/WSL mode requires all explicit Maddy paths"
    require_regular_file "$maddy_config" "Maddy config"
    require_directory "$maddy_state" "Maddy state"
    assert_private_file_mode "$maddy_config"
    maddy_version=$(assert_supported_maddy "$maddy_binary")
    if [[ "$maddy_version" == "0.8.2" ]]; then
        legacy_help_fingerprint=$(assert_maddy_082_help_profile "$maddy_binary")
        config_validation=help-profile-only
    else
        "$maddy_binary" -config "$maddy_config" verify-config >/dev/null 2>&1 || die "maddy verify-config failed"
        legacy_help_fingerprint=not-applicable
        config_validation=verify-config
    fi
    expected_maddy_mode=native
fi

validate_args=(--config "$app_config" --expected-host 127.0.0.1 --expected-port 8787 --expected-maddy-mode "$expected_maddy_mode")
if [[ "$expected_maddy_mode" == docker ]]; then
    validate_args+=(
        --expected-container "$container"
        --expected-maddy-config "$maddy_config"
        --expected-maddy-data /data
    )
else
    validate_args+=(
        --expected-maddy-binary "$maddy_binary"
        --expected-maddy-config "$maddy_config"
        --expected-maddy-data "$maddy_state"
    )
fi
"$python_binary" "$SCRIPT_DIR/validate-config.py" "${validate_args[@]}"

if [[ "$expected_maddy_mode" == native ]]; then
    require_command realpath
    [[ "$(realpath -e -- "$maddy_config")" == "$maddy_config" ]] \
        || die "native Maddy config path must not traverse a symbolic link"
    [[ "$(realpath -e -- "$maddy_state")" == "$maddy_state" ]] \
        || die "native Maddy state path must not traverse a symbolic link"
    certificate_parents=$("$python_binary" -c 'import pathlib, sys, tomllib
with open(sys.argv[1], "rb") as handle:
    config = tomllib.load(handle)
if config["certificates"]["enabled"]:
    values = {
        str(pathlib.PurePosixPath(config["certificates"][name]).parent)
        for name in ("deployed_cert_path", "deployed_key_path")
    }
    print("\n".join(sorted(values)))' "$app_config") \
        || die "cannot derive native certificate target parents"
    if [[ -n "$certificate_parents" ]]; then
        while IFS= read -r certificate_parent; do
            require_directory "$certificate_parent" "native certificate target parent"
            [[ "$(realpath -e -- "$certificate_parent")" == "$certificate_parent" ]] \
                || die "native certificate target parent must not traverse a symbolic link"
        done <<< "$certificate_parents"
    fi
fi

if command -v ss >/dev/null 2>&1; then
    if ss -H -ltn 'sport = :8787' 2>/dev/null | awk '{print $4}' | grep -Ev '^(127\.0\.0\.1|\[::1\]):8787$' | grep -q .; then
        die "port 8787 has a non-loopback listener"
    fi
fi

if [[ "$mode" == "wsl" ]]; then
    grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null || die "--mode wsl was selected outside WSL"
fi

if [[ "$mode" == "native" ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl show-environment >/dev/null 2>&1 || die "systemd is installed but not operational"
fi

printf 'preflight=ok\nmode=%s\npython=%s\npy_gil_disabled=%s\ngil_enabled=%s\nmaddy=%s\nconfig_validation=%s\nlegacy_help_fingerprint=%s\n' \
    "$mode" "$python_version" "$py_gil_disabled" "$gil_enabled" "$maddy_version" "$config_validation" "$legacy_help_fingerprint"
