#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly PREFIX="/opt/maddyweb"
readonly RELEASE_ROOT="$PREFIX/releases"
readonly CURRENT_LINK="$PREFIX/current"
readonly SYSTEMD_ROOT="/etc/systemd/system"
readonly CONFIG_ROOT="/etc/maddyweb"
readonly DEPENDENCY_LOCK="$REPO_ROOT/requirements.lock"
readonly CERTBOT_ROOT="/etc/letsencrypt"
readonly CERTBOT_RENEWAL_HOOKS="$CERTBOT_ROOT/renewal-hooks"
readonly CERTBOT_DEPLOY_HOOKS="$CERTBOT_RENEWAL_HOOKS/deploy"
readonly CERTBOT_DEPLOY_HOOK="$CERTBOT_DEPLOY_HOOKS/maddyweb"
readonly CERTBOT_HOOK_MARKER="# Managed by MaddyWeb install.sh; do not edit."

assert_config_root_metadata() {
    [[ -d "$CONFIG_ROOT" && ! -L "$CONFIG_ROOT" ]] \
        || die "$CONFIG_ROOT must be a real directory"
    local expected_gid metadata
    expected_gid=$(id -g maddyweb) || die "cannot resolve maddyweb group"
    metadata=$(stat -c '%u:%g:%a' -- "$CONFIG_ROOT") \
        || die "cannot inspect $CONFIG_ROOT"
    [[ "$metadata" == "0:${expected_gid}:750" ]] \
        || die "$CONFIG_ROOT must be root:maddyweb 0750"
}

assert_managed_config_file() {
    local path=${1:?managed config path is required}
    [[ -f "$path" && ! -L "$path" ]] || die "$path must be a regular non-symlink file"
    local expected_gid metadata
    expected_gid=$(id -g maddyweb) || die "cannot resolve maddyweb group"
    metadata=$(stat -c '%u:%g:%a:%h' -- "$path") || die "cannot inspect $path"
    [[ "$metadata" == "0:${expected_gid}:640:1" ]] \
        || die "$path must be single-link root:maddyweb 0640"
}

secure_root_directory() {
    local path=${1:?directory path is required}
    local metadata owner group mode
    [[ -d "$path" && ! -L "$path" ]] || return 1
    metadata=$(stat -c '%u:%g:%a' -- "$path" 2>/dev/null) || return 1
    IFS=: read -r owner group mode <<< "$metadata"
    [[ "$owner" == 0 && "$group" == 0 ]] || return 1
    (( (8#$mode & 8#022) == 0 )) || return 1
    [[ "$(realpath -e -- "$path")" == "$path" ]] \
        || return 1
}

assert_secure_root_directory() {
    local path=${1:?directory path is required} label=${2:-directory}
    secure_root_directory "$path" \
        || die "$label must be canonical, real, root:root, and not group/other writable"
}

certbot_hook_is_managed() {
    local path=${1:?hook path is required} first_line second_line
    [[ -f "$path" && ! -L "$path" ]] || return 1
    [[ "$(stat -c '%u:%g:%a:%h' -- "$path" 2>/dev/null)" == "0:0:755:1" ]] \
        || return 1
    {
        IFS= read -r first_line
        IFS= read -r second_line
    } < "$path" || return 1
    [[ "$second_line" == "$CERTBOT_HOOK_MARKER" ]]
}

usage() {
    cat <<'EOF'
Usage: install.sh --environment development|production --host HOST \
  --artifact /absolute/maddyweb.whl --artifact-manifest /absolute/release.json \
  --sha256 HEX --wheelhouse /absolute/wheelhouse \
  --maddy-mode native|docker --maddy-config /absolute/maddy.conf [mode options]

Options:
  Native: --maddy-binary /absolute/maddy --maddy-state /absolute/state-dir
  Docker: --docker-binary /absolute/docker --container SAFE_NAME
  --config-template PATH   Defaults to the matching native/docker example
  --python PATH            Default: resolved python3
  --approval-file PATH     Required for a production --apply
  --apply                  Mutate this host; without this, print the plan only
  --activate               Enable/restart units after installation; requires --apply

Production changes require an explicit host, a checksum-pinned local artifact,
and a fresh one-time approval. Dependencies are installed only from wheelhouse;
this script performs no network access and never accepts a password.
EOF
}

environment=""
target_host=""
artifact=""
artifact_manifest=""
expected_sha256=""
wheelhouse=""
maddy_mode=""
maddy_binary=""
maddy_config=""
maddy_state=""
docker_binary="$(command -v docker || true)"
container=""
config_template=""
python_binary="$(command -v python3 || true)"
approval_file=""
apply=false
activate=false

while (($#)); do
    case "$1" in
        --environment) (($# >= 2)) || die "--environment requires a value"; environment=$2; shift 2 ;;
        --host) (($# >= 2)) || die "--host requires a value"; target_host=$2; shift 2 ;;
        --artifact) (($# >= 2)) || die "--artifact requires a value"; artifact=$2; shift 2 ;;
        --artifact-manifest) (($# >= 2)) || die "--artifact-manifest requires a value"; artifact_manifest=$2; shift 2 ;;
        --sha256) (($# >= 2)) || die "--sha256 requires a value"; expected_sha256=${2,,}; shift 2 ;;
        --wheelhouse) (($# >= 2)) || die "--wheelhouse requires a value"; wheelhouse=$2; shift 2 ;;
        --maddy-mode) (($# >= 2)) || die "--maddy-mode requires a value"; maddy_mode=$2; shift 2 ;;
        --maddy-binary) (($# >= 2)) || die "--maddy-binary requires a value"; maddy_binary=$2; shift 2 ;;
        --maddy-config) (($# >= 2)) || die "--maddy-config requires a value"; maddy_config=$2; shift 2 ;;
        --maddy-state) (($# >= 2)) || die "--maddy-state requires a value"; maddy_state=$2; shift 2 ;;
        --docker-binary) (($# >= 2)) || die "--docker-binary requires a value"; docker_binary=$2; shift 2 ;;
        --container) (($# >= 2)) || die "--container requires a value"; container=$2; shift 2 ;;
        --config-template) (($# >= 2)) || die "--config-template requires a value"; config_template=$2; shift 2 ;;
        --python) (($# >= 2)) || die "--python requires a value"; python_binary=$2; shift 2 ;;
        --approval-file) (($# >= 2)) || die "--approval-file requires a value"; approval_file=$2; shift 2 ;;
        --apply) apply=true; shift ;;
        --activate) activate=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$environment" in development|production) ;; *) die "--environment must be development or production" ;; esac
case "$maddy_mode" in native|docker) ;; *) die "--maddy-mode must be native or docker" ;; esac
[[ -n "$target_host" ]] || die "--host is required"
[[ "$target_host" == "$(hostname)" ]] || die "--host does not match this host: $(hostname)"
[[ -n "$artifact" && -n "$artifact_manifest" && -n "$wheelhouse" && -n "$maddy_config" && -n "$python_binary" ]] || die "artifact, manifest, wheelhouse, Maddy config, and Python are required"
[[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || die "--sha256 must be exactly 64 lowercase hexadecimal characters"
[[ "$artifact" == *.whl ]] || die "--artifact must be a Python wheel"
require_regular_file "$artifact" "application artifact"
require_regular_file "$artifact_manifest" "artifact manifest"
require_regular_file "$DEPENDENCY_LOCK" "dependency lock"
require_directory "$wheelhouse" "offline wheelhouse"
require_path_below "$artifact" "$wheelhouse"
require_absolute_path "$python_binary" "Python binary"
[[ -x "$python_binary" ]] || die "Python binary is not executable"
artifact_report=$("$python_binary" "$SCRIPT_DIR/verify-release-artifact.py" \
    --artifact "$artifact" --manifest "$artifact_manifest" --expected-sha256 "$expected_sha256")
release_commit=$("$python_binary" -c 'import json,sys; print(json.loads(sys.argv[1])["commit"])' "$artifact_report")
[[ "$release_commit" =~ ^[0-9a-f]{40}$ ]] || die "artifact manifest returned an invalid commit"
dependency_lock_sha256=$(sha256_file "$DEPENDENCY_LOCK")
[[ "$dependency_lock_sha256" =~ ^[0-9a-f]{64}$ ]] || die "dependency lock checksum is invalid"

if [[ -z "$config_template" ]]; then
    if [[ "$maddy_mode" == native ]]; then
        config_template="$REPO_ROOT/deploy/examples/config.native.toml"
    else
        config_template="$REPO_ROOT/docker/config.toml"
    fi
fi
require_regular_file "$config_template" "config template"

run_preflight() {
    local app_config=${1:?application config is required}
    if [[ "$maddy_mode" == native ]]; then
        "$SCRIPT_DIR/preflight.sh" \
            --mode native --app-config "$app_config" \
            --maddy-binary "$maddy_binary" --maddy-config "$maddy_config" \
            --maddy-state "$maddy_state" --python "$python_binary"
    else
        "$SCRIPT_DIR/preflight.sh" \
            --mode container --app-config "$app_config" \
            --container "$container" --docker-binary "$docker_binary" \
            --maddy-config "$maddy_config" --python "$python_binary"
    fi
}

if [[ "$maddy_mode" == native ]]; then
    [[ -n "$maddy_binary" && -n "$maddy_state" ]] || die "native mode requires --maddy-binary and --maddy-state"
    [[ -z "$container" ]] || die "--container is invalid in native mode"
else
    [[ -z "$maddy_binary" && -z "$maddy_state" ]] || die "Docker mode does not accept native binary/state paths"
    [[ "$container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || die "Docker mode requires a safe --container"
    [[ -n "$docker_binary" ]] || die "Docker mode requires --docker-binary"
fi

preflight_config="$config_template"
if [[ -e "$CONFIG_ROOT/config.toml" || -L "$CONFIG_ROOT/config.toml" ]]; then
    assert_config_root_metadata
    assert_managed_config_file "$CONFIG_ROOT/config.toml"
    preflight_config="$CONFIG_ROOT/config.toml"
fi
run_preflight "$preflight_config"

artifact_name=$(basename -- "$artifact")
release_name=$release_commit
release_path="$RELEASE_ROOT/$release_name"

printf 'environment=%s\nhost=%s\nmaddy_mode=%s\ncontainer=%s\nartifact=%s\ncommit=%s\nrelease=%s\nactivate=%s\n' \
    "$environment" "$target_host" "$maddy_mode" "$container" "$artifact" "$release_commit" "$release_path" "$activate"

if [[ "$apply" != true ]]; then
    log "dry-run complete; pass --apply only after reviewing the plan"
    exit 0
fi
require_root
[[ ! -e "$release_path" ]] || die "release already exists: $release_path"
if [[ "$environment" == "production" ]]; then
    [[ -n "$approval_file" ]] || die "production --apply requires --approval-file"
    consume_production_approval "$approval_file" install
elif [[ -n "$approval_file" ]]; then
    die "approval files are accepted only for production"
fi

require_command install
require_command cmp
require_command realpath
require_command systemd-sysusers
require_command systemd-tmpfiles
require_command systemctl

install -d -o root -g root -m 0755 -- "$PREFIX" "$RELEASE_ROOT"
systemd-sysusers "$REPO_ROOT/deploy/systemd/maddyweb.sysusers"
systemd-tmpfiles --create "$REPO_ROOT/deploy/systemd/maddyweb.tmpfiles"
if [[ -e "$CONFIG_ROOT" || -L "$CONFIG_ROOT" ]]; then
    assert_config_root_metadata
else
    install -d -o root -g maddyweb -m 0750 -- "$CONFIG_ROOT"
fi
assert_config_root_metadata

if [[ ! -e "$CONFIG_ROOT/config.toml" && ! -L "$CONFIG_ROOT/config.toml" ]]; then
    install -o root -g maddyweb -m 0640 -- "$config_template" "$CONFIG_ROOT/config.toml"
fi
assert_managed_config_file "$CONFIG_ROOT/config.toml"
config_validation=(--config "$CONFIG_ROOT/config.toml" --expected-maddy-mode "$maddy_mode")
if [[ "$maddy_mode" == docker ]]; then
    config_validation+=(
        --expected-container "$container"
        --expected-maddy-config "$maddy_config"
        --expected-maddy-data /data
    )
else
    config_validation+=(
        --expected-maddy-binary "$maddy_binary"
        --expected-maddy-config "$maddy_config"
        --expected-maddy-data "$maddy_state"
    )
fi
"$python_binary" "$SCRIPT_DIR/validate-config.py" "${config_validation[@]}"
run_preflight "$CONFIG_ROOT/config.toml"
if [[ "$maddy_mode" == native ]]; then
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
    print("\n".join(sorted(values)))' "$CONFIG_ROOT/config.toml") \
        || die "cannot derive native certificate target parents"
    if [[ -n "$certificate_parents" ]]; then
        while IFS= read -r certificate_parent; do
            require_directory "$certificate_parent" "native certificate target parent"
            [[ "$(realpath -e -- "$certificate_parent")" == "$certificate_parent" ]] \
                || die "native certificate target parent must not traverse a symbolic link"
        done <<< "$certificate_parents"
    fi
fi
if [[ -e /var/lib/maddyweb/session.key || -L /var/lib/maddyweb/session.key ]]; then
    "$python_binary" "$SCRIPT_DIR/create-session-key.py" --config "$CONFIG_ROOT/config.toml" --check-existing
else
    "$python_binary" "$SCRIPT_DIR/create-session-key.py" --config "$CONFIG_ROOT/config.toml"
fi
if [[ ! -e "$CONFIG_ROOT/maddyweb.env" && ! -L "$CONFIG_ROOT/maddyweb.env" ]]; then
    install -o root -g maddyweb -m 0640 -- "$REPO_ROOT/deploy/systemd/maddyweb.env.example" "$CONFIG_ROOT/maddyweb.env"
fi
assert_managed_config_file "$CONFIG_ROOT/maddyweb.env"

staging="$RELEASE_ROOT/.staging-${release_name}-$$"
[[ ! -e "$staging" ]] || die "staging path already exists"
install -d -o root -g root -m 0700 -- "$staging" "$staging/input"
artifact_copy="$staging/input/$artifact_name"
"$python_binary" "$SCRIPT_DIR/verify-release-artifact.py" \
    --artifact "$artifact" --manifest "$artifact_manifest" \
    --expected-sha256 "$expected_sha256" --copy-to "$artifact_copy" >/dev/null
[[ "$(sha256_file "$artifact_copy")" == "$expected_sha256" ]] \
    || die "staged artifact checksum changed after secure copy"
install -o root -g root -m 0444 -- "$DEPENDENCY_LOCK" "$staging/REQUIREMENTS.lock"
[[ "$(sha256_file "$staging/REQUIREMENTS.lock")" == "$dependency_lock_sha256" ]] \
    || die "staged dependency lock checksum changed"
install -o root -g root -m 0444 -- "$artifact_manifest" "$staging/RELEASE-MANIFEST.json"
staged_artifact_report=$("$python_binary" "$SCRIPT_DIR/verify-release-artifact.py" \
    --artifact "$artifact_copy" --manifest "$staging/RELEASE-MANIFEST.json" \
    --expected-sha256 "$expected_sha256")
staged_commit=$("$python_binary" -c \
    'import json,sys; print(json.loads(sys.argv[1])["commit"])' "$staged_artifact_report")
[[ "$staged_commit" == "$release_commit" ]] \
    || die "staged release manifest commit changed after initial verification"
"$python_binary" -m venv "$staging"
"$staging/bin/python" -m pip install \
    --no-index --find-links "$wheelhouse" --only-binary=:all: --require-hashes \
    --requirement "$staging/REQUIREMENTS.lock"
"$staging/bin/python" -m pip install --no-index --no-deps -- "$artifact_copy"
"$staging/bin/python" -I -m maddyweb --help >/dev/null
"$staging/bin/python" -I "$SCRIPT_DIR/render-systemd-sandbox.py" \
    --config "$CONFIG_ROOT/config.toml" --output-dir "$staging"
install -d -o root -g root -m 0755 -- "$staging/libexec"
install -o root -g root -m 0444 -- \
    "$SCRIPT_DIR/certbot-deploy-hook.py" "$staging/libexec/certbot-deploy-hook.py"
install -o root -g root -m 0555 -- \
    "$SCRIPT_DIR/certbot-deploy-hook.sh" "$staging/CERTBOT-DEPLOY-HOOK"
web_temp_dir=$("$staging/bin/python" -I -c \
    'import sys; from maddyweb.config import load_config; print(load_config(sys.argv[1]).server.temp_dir)' \
    "$CONFIG_ROOT/config.toml")
certificates_enabled=$("$staging/bin/python" -I -c \
    'import sys; from maddyweb.config import load_config; print(int(load_config(sys.argv[1]).certificates.enabled))' \
    "$CONFIG_ROOT/config.toml")
[[ "$certificates_enabled" == 0 || "$certificates_enabled" == 1 ]] \
    || die "certificate enablement state is invalid"
require_absolute_path "$web_temp_dir" "server.temp_dir"
web_temp_parent=$(dirname -- "$web_temp_dir")
require_directory "$web_temp_parent" "server.temp_dir parent"
[[ "$(realpath -e -- "$web_temp_parent")" == "$web_temp_parent" ]] \
    || die "server.temp_dir parent must not traverse a symbolic link"
expected_web_uid=$(id -u maddyweb) || die "cannot resolve maddyweb uid"
expected_web_gid=$(id -g maddyweb) || die "cannot resolve maddyweb gid"
if [[ -e "$web_temp_dir" || -L "$web_temp_dir" ]]; then
    [[ -d "$web_temp_dir" && ! -L "$web_temp_dir" ]] \
        || die "server.temp_dir must be a real directory"
    [[ "$(stat -c '%u:%g:%a' -- "$web_temp_dir")" \
        == "${expected_web_uid}:${expected_web_gid}:700" ]] \
        || die "existing server.temp_dir must be maddyweb:maddyweb 0700"
else
    install -d -o maddyweb -g maddyweb -m 0700 -- "$web_temp_dir"
fi
[[ "$(realpath -e -- "$web_temp_dir")" == "$web_temp_dir" ]] \
    || die "server.temp_dir must not traverse a symbolic link"
printf 'format=maddyweb-install-v1\ncommit=%s\nartifact=%s\nsha256=%s\ndependencies_sha256=%s\nmaddy_mode=%s\ncontainer=%s\ninstalled_at=%s\n' \
    "$release_commit" "$artifact_name" "$expected_sha256" "$dependency_lock_sha256" \
    "$maddy_mode" "$container" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$staging/INSTALL-MANIFEST"
chmod -R u=rwX,go=rX -- "$staging"
mv -- "$staging" "$release_path"

previous=""
if [[ -L "$CURRENT_LINK" ]]; then
    previous=$(readlink -f -- "$CURRENT_LINK")
    require_path_below "$previous" "$RELEASE_ROOT"
elif [[ -e "$CURRENT_LINK" ]]; then
    die "$CURRENT_LINK exists but is not a symbolic link"
fi

unit_names=(maddyweb-helper.socket maddyweb-helper.service maddyweb.service)
declare -A unit_existed=()
declare -A unit_enabled=()
declare -A unit_active=()
dropin_keys=(web-paths helper-paths)
declare -A dropin_target=(
    [web-paths]="$SYSTEMD_ROOT/maddyweb.service.d/20-maddyweb-paths.conf"
    [helper-paths]="$SYSTEMD_ROOT/maddyweb-helper.service.d/20-maddyweb-paths.conf"
)
declare -A dropin_source=(
    [web-paths]="$release_path/SYSTEMD-WEB-PATHS.conf"
    [helper-paths]="$release_path/SYSTEMD-HELPER-PATHS.conf"
)
declare -A dropin_existed=()
declare -A dropin_parent_existed=()
approval_root_metadata=$(stat -c '%u:%g:%a' -- "$MADDYWEB_APPROVAL_ROOT") \
    || die "cannot inspect approval runtime directory"
[[ "$approval_root_metadata" == "0:0:700" ]] \
    || die "approval runtime directory must be root:root 0700"
unit_backup=$(mktemp -d --tmpdir="$MADDYWEB_APPROVAL_ROOT" .install-unit-backup.XXXXXXXX)
require_path_below "$unit_backup" "$MADDYWEB_APPROVAL_ROOT"
[[ "$(stat -c '%u:%g:%a' -- "$unit_backup")" == "0:0:700" ]] \
    || die "unit backup directory metadata is unsafe"

for unit in "${unit_names[@]}"; do
    unit_path="$SYSTEMD_ROOT/$unit"
    if [[ -e "$unit_path" || -L "$unit_path" ]]; then
        [[ -f "$unit_path" && ! -L "$unit_path" ]] \
            || die "existing unit must be a regular non-symlink file: $unit"
        [[ "$(stat -c '%u:%g:%a:%h' -- "$unit_path")" == "0:0:644:1" ]] \
            || die "existing unit must be single-link root:root 0644: $unit"
        install -o root -g root -m 0600 -- "$unit_path" "$unit_backup/$unit"
        unit_existed[$unit]=true
    else
        unit_existed[$unit]=false
    fi
    if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        unit_enabled[$unit]=true
    else
        unit_enabled[$unit]=false
    fi
    if systemctl is-active --quiet "$unit"; then
        unit_active[$unit]=true
    else
        unit_active[$unit]=false
    fi
done

for key in "${dropin_keys[@]}"; do
    target=${dropin_target[$key]}
    parent=$(dirname -- "$target")
    if [[ -e "$parent" || -L "$parent" ]]; then
        [[ -d "$parent" && ! -L "$parent" ]] \
            || die "systemd drop-in parent must be a real directory: $parent"
        [[ "$(stat -c '%u:%g:%a' -- "$parent")" == "0:0:755" ]] \
            || die "systemd drop-in parent must be root:root 0755: $parent"
        dropin_parent_existed[$key]=true
    else
        dropin_parent_existed[$key]=false
    fi
    if [[ -e "$target" || -L "$target" ]]; then
        [[ -f "$target" && ! -L "$target" ]] \
            || die "managed systemd drop-in must be a regular non-symlink file: $target"
        [[ "$(stat -c '%u:%g:%a:%h' -- "$target")" == "0:0:644:1" ]] \
            || die "managed systemd drop-in must be single-link root:root 0644: $target"
        IFS= read -r first_line < "$target" || die "cannot read managed systemd drop-in"
        [[ "$first_line" == "# Managed by MaddyWeb install.sh; do not edit." ]] \
            || die "refusing to overwrite an unmanaged systemd drop-in: $target"
        install -o root -g root -m 0600 -- "$target" "$unit_backup/DROPIN-$key.conf"
        dropin_existed[$key]=true
    else
        dropin_existed[$key]=false
    fi
done

[[ "$(stat -c '%u:%g:%a:%h' -- "$release_path/CERTBOT-DEPLOY-HOOK")" == "0:0:755:1" ]] \
    || die "staged Certbot deploy-hook wrapper metadata is unsafe"
[[ "$(stat -c '%u:%g:%a:%h' -- "$release_path/libexec/certbot-deploy-hook.py")" == "0:0:644:1" ]] \
    || die "staged Certbot deploy-hook driver metadata is unsafe"

certbot_hook_action=none
certbot_root_available=false
certbot_renewal_parent_existed=false
certbot_deploy_parent_existed=false
certbot_hook_existed=false
certbot_hook_mutation_started=false
certbot_renewal_created=false
certbot_deploy_created=false
if [[ "$certificates_enabled" == 1 ]]; then
    [[ -e "$CERTBOT_ROOT" || -L "$CERTBOT_ROOT" ]] \
        || die "$CERTBOT_ROOT must already exist before enabling certificate automation"
    certbot_hook_action=install
fi
if [[ -e "$CERTBOT_ROOT" || -L "$CERTBOT_ROOT" ]]; then
    assert_secure_root_directory "$CERTBOT_ROOT" "Certbot configuration root"
    certbot_root_available=true
fi
if [[ "$certbot_root_available" == true ]]; then
    if [[ -e "$CERTBOT_RENEWAL_HOOKS" || -L "$CERTBOT_RENEWAL_HOOKS" ]]; then
        assert_secure_root_directory "$CERTBOT_RENEWAL_HOOKS" "Certbot renewal-hooks directory"
        certbot_renewal_parent_existed=true
    fi
    if [[ "$certbot_renewal_parent_existed" == true \
        && ( -e "$CERTBOT_DEPLOY_HOOKS" || -L "$CERTBOT_DEPLOY_HOOKS" ) ]]; then
        assert_secure_root_directory "$CERTBOT_DEPLOY_HOOKS" "Certbot deploy-hooks directory"
        certbot_deploy_parent_existed=true
    fi
    if [[ "$certbot_deploy_parent_existed" == true \
        && ( -e "$CERTBOT_DEPLOY_HOOK" || -L "$CERTBOT_DEPLOY_HOOK" ) ]]; then
        if certbot_hook_is_managed "$CERTBOT_DEPLOY_HOOK"; then
            install -o root -g root -m 0600 -- \
                "$CERTBOT_DEPLOY_HOOK" "$unit_backup/CERTBOT-DEPLOY-HOOK"
            certbot_hook_existed=true
            if [[ "$certificates_enabled" == 0 ]]; then
                certbot_hook_action=remove
            fi
        elif [[ "$certificates_enabled" == 1 ]]; then
            die "refusing to overwrite an unmanaged Certbot deploy hook: $CERTBOT_DEPLOY_HOOK"
        else
            log "leaving unmanaged Certbot deploy hook unchanged: $CERTBOT_DEPLOY_HOOK"
        fi
    fi
fi

install_transaction_active=false

restore_install_transaction() {
    local status=0 unit unit_path key target parent recovery_link failed_link restored_current
    install_transaction_active=false
    log "restoring pre-install release, units, Certbot hook, enablement, and active state"
    for unit in "${unit_names[@]}"; do
        systemctl stop "$unit" >/dev/null 2>&1 || true
        systemctl disable "$unit" >/dev/null 2>&1 || true
    done
    if [[ -n "$previous" ]]; then
        recovery_link="$PREFIX/.current-recovery-$$"
        if ! ln -s -- "$previous" "$recovery_link" \
            || ! mv -Tf -- "$recovery_link" "$CURRENT_LINK"; then
            status=1
            if [[ -L "$recovery_link" ]]; then
                rm -f -- "$recovery_link" || status=1
            fi
        fi
    elif [[ -L "$CURRENT_LINK" ]]; then
        failed_link="$PREFIX/.failed-current-$release_commit"
        if [[ -e "$failed_link" || -L "$failed_link" ]] \
            || ! mv -- "$CURRENT_LINK" "$failed_link"; then
            status=1
        fi
    fi
    if [[ "$certbot_hook_mutation_started" == true ]]; then
        if [[ "$certbot_hook_existed" == true ]]; then
            if secure_root_directory "$CERTBOT_DEPLOY_HOOKS"; then
                install -o root -g root -m 0755 -- \
                    "$unit_backup/CERTBOT-DEPLOY-HOOK" "$CERTBOT_DEPLOY_HOOK" \
                    || status=1
                cmp -s -- "$unit_backup/CERTBOT-DEPLOY-HOOK" "$CERTBOT_DEPLOY_HOOK" \
                    || status=1
                certbot_hook_is_managed "$CERTBOT_DEPLOY_HOOK" || status=1
            else
                status=1
            fi
        elif [[ -e "$CERTBOT_DEPLOY_HOOK" || -L "$CERTBOT_DEPLOY_HOOK" ]]; then
            if certbot_hook_is_managed "$CERTBOT_DEPLOY_HOOK" \
                && cmp -s -- "$release_path/CERTBOT-DEPLOY-HOOK" "$CERTBOT_DEPLOY_HOOK"; then
                rm -f -- "$CERTBOT_DEPLOY_HOOK" || status=1
            else
                status=1
            fi
        fi
        if [[ "$certbot_deploy_created" == true ]]; then
            if [[ -d "$CERTBOT_DEPLOY_HOOKS" && ! -L "$CERTBOT_DEPLOY_HOOKS" ]]; then
                rmdir -- "$CERTBOT_DEPLOY_HOOKS" || status=1
            elif [[ -e "$CERTBOT_DEPLOY_HOOKS" || -L "$CERTBOT_DEPLOY_HOOKS" ]]; then
                status=1
            fi
        fi
        if [[ "$certbot_renewal_created" == true ]]; then
            if [[ -d "$CERTBOT_RENEWAL_HOOKS" && ! -L "$CERTBOT_RENEWAL_HOOKS" ]]; then
                rmdir -- "$CERTBOT_RENEWAL_HOOKS" || status=1
            elif [[ -e "$CERTBOT_RENEWAL_HOOKS" || -L "$CERTBOT_RENEWAL_HOOKS" ]]; then
                status=1
            fi
        fi
    fi
    for unit in "${unit_names[@]}"; do
        unit_path="$SYSTEMD_ROOT/$unit"
        if [[ "${unit_existed[$unit]}" == true ]]; then
            install -o root -g root -m 0644 -- "$unit_backup/$unit" "$unit_path" \
                || status=1
            cmp -s -- "$unit_backup/$unit" "$unit_path" || status=1
            [[ "$(stat -c '%u:%g:%a:%h' -- "$unit_path" 2>/dev/null)" == "0:0:644:1" ]] \
                || status=1
        elif [[ -e "$unit_path" && ! -L "$unit_path" ]]; then
            rm -f -- "$unit_path" || status=1
        elif [[ -L "$unit_path" ]]; then
            status=1
        fi
    done
    for key in "${dropin_keys[@]}"; do
        target=${dropin_target[$key]}
        parent=$(dirname -- "$target")
        if [[ "${dropin_existed[$key]}" == true ]]; then
            install -d -o root -g root -m 0755 -- "$parent" || status=1
            install -o root -g root -m 0644 -- \
                "$unit_backup/DROPIN-$key.conf" "$target" || status=1
            cmp -s -- "$unit_backup/DROPIN-$key.conf" "$target" || status=1
            [[ "$(stat -c '%u:%g:%a:%h' -- "$target" 2>/dev/null)" == "0:0:644:1" ]] \
                || status=1
        elif [[ -e "$target" && ! -L "$target" ]]; then
            rm -f -- "$target" || status=1
        elif [[ -L "$target" ]]; then
            status=1
        fi
        if [[ "${dropin_parent_existed[$key]}" == false && -d "$parent" && ! -L "$parent" ]]; then
            rmdir -- "$parent" || status=1
        fi
    done
    systemctl daemon-reload || status=1
    for unit in "${unit_names[@]}"; do
        if [[ "${unit_enabled[$unit]}" == true ]]; then
            systemctl enable "$unit" >/dev/null || status=1
        elif [[ "${unit_existed[$unit]}" == true ]]; then
            systemctl disable "$unit" >/dev/null || status=1
        fi
    done
    for unit in "${unit_names[@]}"; do
        if [[ "${unit_active[$unit]}" == true ]]; then
            systemctl start "$unit" || status=1
        fi
    done
    # Starting Web can socket-activate the helper; restore originally inactive
    # units after all required active units have reached their start job.
    for unit in "${unit_names[@]}"; do
        if [[ "${unit_active[$unit]}" == false ]]; then
            systemctl stop "$unit" >/dev/null 2>&1 || true
        fi
    done
    for unit in "${unit_names[@]}"; do
        if [[ "${unit_active[$unit]}" == true ]]; then
            systemctl is-active --quiet "$unit" || status=1
        elif systemctl is-active --quiet "$unit"; then
            status=1
        fi
        if [[ "${unit_enabled[$unit]}" == true ]]; then
            systemctl is-enabled --quiet "$unit" || status=1
        elif systemctl is-enabled --quiet "$unit" 2>/dev/null; then
            status=1
        fi
    done
    if [[ -n "$previous" ]]; then
        restored_current=$(readlink -f -- "$CURRENT_LINK" 2>/dev/null) || status=1
        [[ "${restored_current:-}" == "$previous" ]] || status=1
    elif [[ -L "$CURRENT_LINK" ]]; then
        status=1
    fi
    if (( status != 0 )); then
        log "CRITICAL: install rollback was incomplete; unit backup retained at $unit_backup"
    fi
    return "$status"
}

abort_install_transaction() {
    local reason=${1:-installation failed}
    install_transaction_active=false
    trap - EXIT INT TERM
    if restore_install_transaction; then
        die "$reason; exact prior release and unit state was restored"
    fi
    die "$reason and transactional restoration was incomplete"
}

on_install_transaction_exit() {
    local status=$?
    trap - EXIT INT TERM
    if [[ "$install_transaction_active" == true ]]; then
        (( status != 0 )) || status=1
        if restore_install_transaction; then
            log "installation exited unexpectedly; exact prior release and unit state was restored"
        else
            log "CRITICAL: installation exited unexpectedly and restoration was incomplete"
        fi
    fi
    exit "$status"
}

install_transaction_active=true
trap on_install_transaction_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! install -o root -g root -m 0644 -- \
    "$REPO_ROOT/deploy/systemd/maddyweb.service" "$SYSTEMD_ROOT/maddyweb.service" \
    || ! install -o root -g root -m 0644 -- \
    "$REPO_ROOT/deploy/systemd/maddyweb-helper.service" "$SYSTEMD_ROOT/maddyweb-helper.service" \
    || ! install -o root -g root -m 0644 -- \
    "$REPO_ROOT/deploy/systemd/maddyweb-helper.socket" "$SYSTEMD_ROOT/maddyweb-helper.socket" \
    || ! install -d -o root -g root -m 0755 -- \
    "$(dirname -- "${dropin_target[web-paths]}")" \
    || ! install -d -o root -g root -m 0755 -- \
    "$(dirname -- "${dropin_target[helper-paths]}")" \
    || ! install -o root -g root -m 0644 -- \
    "${dropin_source[web-paths]}" "${dropin_target[web-paths]}" \
    || ! install -o root -g root -m 0644 -- \
    "${dropin_source[helper-paths]}" "${dropin_target[helper-paths]}"; then
    abort_install_transaction "unit installation failed"
fi

temporary_link="$PREFIX/.current-${release_name}-$$"
if ! ln -s -- "$release_path" "$temporary_link" \
    || ! mv -Tf -- "$temporary_link" "$CURRENT_LINK"; then
    if [[ -L "$temporary_link" ]]; then rm -f -- "$temporary_link" || true; fi
    abort_install_transaction "release switch failed"
fi

if [[ "$certbot_hook_action" == install ]]; then
    if [[ "$certbot_hook_existed" == true ]] \
        && ! certbot_hook_is_managed "$CERTBOT_DEPLOY_HOOK"; then
        abort_install_transaction "managed Certbot deploy hook changed before activation"
    fi
    certbot_hook_mutation_started=true
    if [[ "$certbot_renewal_parent_existed" == false ]]; then
        if install -d -o root -g root -m 0755 -- "$CERTBOT_RENEWAL_HOOKS"; then
            certbot_renewal_created=true
        else
            if secure_root_directory "$CERTBOT_RENEWAL_HOOKS" \
                && [[ "$(stat -c '%u:%g:%a' -- "$CERTBOT_RENEWAL_HOOKS")" == "0:0:755" ]]; then
                certbot_renewal_created=true
            fi
            abort_install_transaction "Certbot renewal-hooks directory creation failed"
        fi
    fi
    if ! secure_root_directory "$CERTBOT_RENEWAL_HOOKS" \
        || [[ "$certbot_renewal_created" == true \
            && "$(stat -c '%u:%g:%a' -- "$CERTBOT_RENEWAL_HOOKS")" != "0:0:755" ]]; then
        abort_install_transaction "Certbot renewal-hooks directory failed its metadata gate"
    fi
    if [[ "$certbot_deploy_parent_existed" == false ]]; then
        if install -d -o root -g root -m 0755 -- "$CERTBOT_DEPLOY_HOOKS"; then
            certbot_deploy_created=true
        else
            if secure_root_directory "$CERTBOT_DEPLOY_HOOKS" \
                && [[ "$(stat -c '%u:%g:%a' -- "$CERTBOT_DEPLOY_HOOKS")" == "0:0:755" ]]; then
                certbot_deploy_created=true
            fi
            abort_install_transaction "Certbot deploy-hooks directory creation failed"
        fi
    fi
    if ! secure_root_directory "$CERTBOT_DEPLOY_HOOKS" \
        || [[ "$certbot_deploy_created" == true \
            && "$(stat -c '%u:%g:%a' -- "$CERTBOT_DEPLOY_HOOKS")" != "0:0:755" ]]; then
        abort_install_transaction "Certbot deploy-hooks directory failed its metadata gate"
    fi
    if [[ "$certbot_hook_existed" == false \
        && ( -e "$CERTBOT_DEPLOY_HOOK" || -L "$CERTBOT_DEPLOY_HOOK" ) ]]; then
        abort_install_transaction "Certbot deploy-hook target appeared during activation"
    fi
    if ! install -o root -g root -m 0755 -- \
        "$release_path/CERTBOT-DEPLOY-HOOK" "$CERTBOT_DEPLOY_HOOK" \
        || ! certbot_hook_is_managed "$CERTBOT_DEPLOY_HOOK" \
        || ! cmp -s -- "$release_path/CERTBOT-DEPLOY-HOOK" "$CERTBOT_DEPLOY_HOOK"; then
        abort_install_transaction "Certbot deploy-hook installation failed its readback gate"
    fi
elif [[ "$certbot_hook_action" == remove ]]; then
    certbot_hook_is_managed "$CERTBOT_DEPLOY_HOOK" \
        || abort_install_transaction "managed Certbot deploy hook changed before removal"
    certbot_hook_mutation_started=true
    if ! rm -f -- "$CERTBOT_DEPLOY_HOOK" \
        || [[ -e "$CERTBOT_DEPLOY_HOOK" || -L "$CERTBOT_DEPLOY_HOOK" ]]; then
        abort_install_transaction "managed Certbot deploy-hook removal failed its readback gate"
    fi
fi

systemctl daemon-reload || abort_install_transaction "systemd daemon reload failed"
if [[ "$activate" == true ]]; then
    if ! systemctl enable maddyweb-helper.socket maddyweb.service \
        || ! systemctl restart maddyweb-helper.socket maddyweb.service \
        || ! systemctl try-restart maddyweb-helper.service \
        || ! systemctl is-active --quiet maddyweb-helper.socket maddyweb.service \
        || ! "$release_path/bin/python" "$SCRIPT_DIR/smoke-test.py"; then
        abort_install_transaction "installation activation or smoke gate failed"
    fi
fi

if [[ -n "$previous" ]]; then
    previous_release_temp="/var/lib/maddyweb/.previous-release-$$"
    if ! printf '%s\n' "$previous" > "$previous_release_temp" \
        || ! chmod 0600 -- "$previous_release_temp" \
        || ! mv -fT -- "$previous_release_temp" /var/lib/maddyweb/previous-release; then
        rm -f -- "$previous_release_temp" || true
        abort_install_transaction "previous-release metadata update failed"
    fi
fi
install_transaction_active=false
trap - EXIT INT TERM

unit_backup_cleanup_status=0
for unit in "${unit_names[@]}"; do
    rm -f -- "$unit_backup/$unit" || unit_backup_cleanup_status=1
done
for key in "${dropin_keys[@]}"; do
    rm -f -- "$unit_backup/DROPIN-$key.conf" || unit_backup_cleanup_status=1
done
rm -f -- "$unit_backup/CERTBOT-DEPLOY-HOOK" || unit_backup_cleanup_status=1
if ! rmdir -- "$unit_backup"; then unit_backup_cleanup_status=1; fi
if (( unit_backup_cleanup_status != 0 )); then
    log "WARNING: installation succeeded but the root-only transaction backup could not be removed: $unit_backup"
fi

log "installed $release_path"
log "Nginx was not inspected or modified"
