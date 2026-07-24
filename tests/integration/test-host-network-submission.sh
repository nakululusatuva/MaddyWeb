#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

die() {
    printf 'host-network Submission integration failed: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 2 ]] || die "expected repository and Python executable"
repository=$1
python_binary=$2
[[ -d "$repository/scripts" && -d "$repository/src/maddyweb" ]] \
    || die "repository is invalid"
if [[ "$python_binary" != /* ]]; then
    python_binary=$(command -v -- "$python_binary") \
        || die "Python executable is unavailable"
fi
[[ "$python_binary" == /* ]] || die "Python executable did not resolve absolutely"
[[ -x "$python_binary" ]] || die "Python executable is invalid"
[[ "$(id -u)" -eq 0 ]] || die "integration test requires root inside disposable WSL"

docker_binary=/usr/bin/docker
[[ -x "$docker_binary" ]] || die "fixed Docker executable is unavailable"
command -v ss >/dev/null 2>&1 || die "ss is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

image=$("$python_binary" -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["images"]["0.8.2"])' \
    "$repository/tests/integration/maddy-image-lock.json")
[[ "$image" =~ ^ghcr\.io/foxcpp/maddy@sha256:[0-9a-f]{64}$ ]] \
    || die "locked Maddy 0.8.2 image is invalid"
"$docker_binary" image inspect "$image" >/dev/null

nonce=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
[[ "$nonce" =~ ^[0-9a-f]{16}$ ]] || die "failed to create a fixture nonce"
container="maddyweb-host-network-$nonce"
label="io.maddyweb.host-network-test=$nonce"
work=$(mktemp -d /tmp/maddyweb-host-network.XXXXXXXX)
data="$work/data"
release="$work/release"
entrypoint="$work/entrypoint.sh"
app_config="$work/config.toml"
backup_dir="$work/backups"
container_created=false

install -d -m 0700 -- "$work/bin"
printf '%s\n' '#!/bin/sh' 'exec uname -n' > "$work/bin/hostname"
chmod 0755 -- "$work/bin/hostname"
PATH="$work/bin:$PATH"
export PATH

public_listener_snapshot() {
    local port
    for port in 25 143 465 587 993; do
        ss -H -ltn "sport = :$port" 2>/dev/null \
            | awk -v port="$port" '{print port "\t" $4}'
    done | LC_ALL=C sort
}

assert_public_listeners_unchanged() {
    [[ "$(public_listener_snapshot)" == "$public_listeners_before" ]] \
        || die "fixture changed a public mail listener"
}

submission_listener_summary() {
    local container_id=$1
    "$docker_binary" exec "$container_id" \
        /bin/cat /proc/net/tcp /proc/net/tcp6 2>/dev/null \
        | awk '$2 ~ /:0633$/ && $4 == "0A" {
            count += 1
            if ($2 == "0100007F:0633") exact += 1
        }
        END {print count + 0 ":" exact + 0}'
}

assert_exact_submission_listener() {
    local container_id=$1
    local host_listeners
    host_listeners=$(ss -H -ltn 'sport = :1587' 2>/dev/null | awk '{print $4}')
    [[ "$host_listeners" == "127.0.0.1:1587" ]] \
        || die "host listener is not exactly one IPv4 loopback socket"
    [[ "$(submission_listener_summary "$container_id")" == "1:1" ]] \
        || die "container socket tables contain a wildcard, IPv6, or duplicate listener"
}

assert_submission_listener_absent() {
    local container_id=$1
    [[ -z "$(ss -H -ltn 'sport = :1587' 2>/dev/null)" ]] \
        || die "host port 1587 is unexpectedly occupied"
    [[ "$(submission_listener_summary "$container_id")" == "0:0" ]] \
        || die "container socket tables retain a port 1587 listener"
}

cleanup() {
    local status=$?
    set +e
    if (( status != 0 )) && [[ "$container_created" == true ]]; then
        "$docker_binary" logs "$container" >&2
    fi
    if [[ "$container_created" == true ]]; then
        "$docker_binary" rm --force --volumes "$container" >/dev/null 2>&1
    fi
    if [[ "$work" == /tmp/maddyweb-host-network.* \
        && -d "$work" && ! -L "$work" ]]; then
        rm -rf -- "$work"
    fi
    exit "$status"
}
trap cleanup EXIT

install -d -m 0700 -- "$data" "$release" "$backup_dir"
cp -a -- "$repository/scripts/." "$release/"
chmod -R go-w -- "$release"
chmod 0755 -- "$release"/*.sh "$release"/*.py
install -m 0600 \
    "$repository/tests/integration/fixtures/maddy-host-network.conf" \
    "$data/maddy.conf"
install -m 0755 \
    "$repository/tests/integration/fixtures/maddy-host-network-entrypoint.sh" \
    "$entrypoint"
install -m 0600 "$repository/docker/config.toml" "$app_config"
sed -i \
    -e "s/^container = .*/container = \"$container\"/" \
    -e 's/^docker_submission_scope = "container"$/docker_submission_scope = "host-loopback"/' \
    "$app_config"

safe_source_port=$("$python_binary" -c 'import socket
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
if not 20000 <= port <= 60999 or port == 1587:
    raise SystemExit(1)
print(port)')
[[ "$safe_source_port" =~ ^[0-9]+$ ]] || die "safe source port is invalid"
[[ -z "$(ss -H -ltn "sport = :$safe_source_port" 2>/dev/null)" ]] \
    || die "randomized safe source port became occupied"
[[ -z "$(ss -H -ltn 'sport = :1587' 2>/dev/null)" ]] \
    || die "host port 1587 is occupied before the fixture"
public_listeners_before=$(public_listener_snapshot)

"$docker_binary" run --detach \
    --name "$container" \
    --label "$label" \
    --network host \
    --user 0:0 \
    --workdir /data \
    --env "MADDYWEB_SAFE_SOURCE_PORT=$safe_source_port" \
    --mount "type=bind,source=$data,target=/data" \
    --mount "type=bind,source=$entrypoint,target=/fixture/entrypoint.sh,readonly" \
    --entrypoint /fixture/entrypoint.sh \
    "$image" >/dev/null
container_created=true

container_id=$("$docker_binary" inspect --format '{{.Id}}' "$container")
[[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || die "container ID is invalid"
for _ in {1..50}; do
    if [[ "$("$docker_binary" inspect --format '{{.State.Running}}' "$container")" == true ]] \
        && [[ -n "$(ss -H -ltn "sport = :$safe_source_port" 2>/dev/null)" ]]; then
        break
    fi
    sleep 0.2
done
[[ "$("$docker_binary" inspect --format \
    '{{.State.Running}} {{.State.Paused}} {{.HostConfig.NetworkMode}}' \
    "$container")" == "true false host" ]] \
    || die "locked Maddy host-network fixture did not remain healthy"
[[ "$(ss -H -ltn "sport = :$safe_source_port" 2>/dev/null | awk '{print $4}')" \
    == "127.0.0.1:$safe_source_port" ]] \
    || die "safe source listener is not exact IPv4 loopback"
assert_submission_listener_absent "$container_id"
assert_public_listeners_unchanged

# This is the deployment preflight branch used when /data is a bind-mounted
# directory but the caller knows only the fixed in-container config path.
container_config_report=$("$python_binary" "$release/check-maddy-container.py" \
    --docker "$docker_binary" --container "$container" \
    --container-config /data/maddy.conf)
"$python_binary" -c 'import json,pathlib,sys
report = json.loads(sys.argv[1])
assert report["id"] == sys.argv[2]
assert report["network_mode"] == "host"
assert report["config_kind"] == "bind"
assert pathlib.Path(report["config_source"]).resolve() == pathlib.Path(sys.argv[3]).resolve()' \
    "$container_config_report" "$container_id" "$data/maddy.conf"
if "$python_binary" "$release/check-maddy-container.py" \
    --docker "$docker_binary" --container "$container" \
    --container-config /data/not-maddy.conf >/dev/null 2>&1; then
    die "checker accepted a wrong in-container bind config path"
fi

preflight_report=$("$release/preflight.sh" \
    --mode container \
    --app-config "$app_config" \
    --container "$container" \
    --maddy-config /data/maddy.conf \
    --docker-binary "$docker_binary" \
    --python "$python_binary")
printf '%s\n' "$preflight_report" | grep -qx 'preflight=ok' \
    || die "bind-mounted container preflight did not pass"
printf '%s\n' "$preflight_report" | grep -qx 'network_mode=host' \
    || die "bind-mounted container preflight lost host network mode"
printf '%s\n' "$preflight_report" | grep -qx 'docker_submission_scope=host-loopback' \
    || die "bind-mounted container preflight lost explicit Submission scope"

original_hash=$(sha256sum "$data/maddy.conf" | awk '{print $1}')
original_metadata=$(stat -c '%a %u:%g %h' "$data/maddy.conf")
original_container=$("$python_binary" "$release/check-maddy-container.py" \
    --docker "$docker_binary" --container "$container" \
    --host-config "$data/maddy.conf")
original_mounts=$("$docker_binary" inspect --format '{{json .Mounts}}' "$container")
original_state=$("$docker_binary" inspect --format \
    '{{.Id}} {{.State.Running}} {{.State.Paused}} {{.RestartCount}} {{.HostConfig.RestartPolicy.Name}} {{.HostConfig.NetworkMode}}' \
    "$container")

common_args=(
    --environment development
    --host "$(hostname)"
    --mode docker
    --maddy-config "$data/maddy.conf"
    --docker-binary "$docker_binary"
    --container "$container"
    --docker-submission-scope host-loopback
    --python "$python_binary"
    --app-config "$app_config"
    --backup-dir "$backup_dir"
    --allow-downtime
    --apply
)
"$release/configure-submission.sh" --action add "${common_args[@]}"

grep -qx '# BEGIN MADDYWEB MANAGED SUBMISSION v1' "$data/maddy.conf" \
    || die "successful add did not persist the managed marker"
[[ "$(grep -c '^submission tcp://127.0.0.1:1587 {$' "$data/maddy.conf")" -eq 1 ]] \
    || die "successful add did not create exactly one managed endpoint"
assert_exact_submission_listener "$container_id"
assert_public_listeners_unchanged

PYTHONPATH="$repository/src" "$python_binary" \
    "$repository/tests/integration/host_network_submission_case.py" \
    --container "$container"
assert_exact_submission_listener "$container_id"
assert_public_listeners_unchanged

"$release/configure-submission.sh" --action remove "${common_args[@]}"
assert_submission_listener_absent "$container_id"
assert_public_listeners_unchanged
[[ "$(sha256sum "$data/maddy.conf" | awk '{print $1}')" == "$original_hash" ]] \
    || die "successful remove did not restore exact original config bytes"
[[ "$(stat -c '%a %u:%g %h' "$data/maddy.conf")" == "$original_metadata" ]] \
    || die "successful add/remove changed config metadata"

final_container=$("$python_binary" "$release/check-maddy-container.py" \
    --docker "$docker_binary" --container "$container" \
    --host-config "$data/maddy.conf")
final_mounts=$("$docker_binary" inspect --format '{{json .Mounts}}' "$container")
# Docker does not define Mounts array ordering across restarts. Compare the
# complete records as an order-independent collection after checking the
# remaining identity digests directly.
"$python_binary" -c 'import json,sys
before, after = map(json.loads, sys.argv[1:3])
keys = (
    "id",
    "network_mode",
    "ports_sha256",
    "restart_policy_sha256",
    "config_kind",
    "config_source",
)
changed = {
    key: (before[key], after[key])
    for key in keys
    if before[key] != after[key]
}
mounts_before, mounts_after = map(json.loads, sys.argv[3:5])
sort_key = lambda record: json.dumps(record, sort_keys=True, separators=(",", ":"))
if sorted(mounts_before, key=sort_key) != sorted(mounts_after, key=sort_key):
    changed["mount_records"] = (mounts_before, mounts_after)
if changed:
    print(changed, file=sys.stderr)
raise SystemExit(changed != {})' \
    "$original_container" "$final_container" "$original_mounts" "$final_mounts"
[[ "$("$docker_binary" inspect --format \
    '{{.Id}} {{.State.Running}} {{.State.Paused}} {{.RestartCount}} {{.HostConfig.RestartPolicy.Name}} {{.HostConfig.NetworkMode}}' \
    "$container")" == "$original_state" ]] \
    || die "successful add/remove changed container identity or state"
[[ "$(ss -H -ltn "sport = :$safe_source_port" 2>/dev/null | awk '{print $4}')" \
    == "127.0.0.1:$safe_source_port" ]] \
    || die "safe source listener did not survive the transaction"

printf 'host-network Submission integration passed\n'
