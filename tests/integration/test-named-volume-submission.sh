#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

die() {
    printf 'named-volume Submission integration failed: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 2 ]] || die "expected repository and Python executable"
repository=$1
python_binary=$2
[[ -d "$repository/scripts" ]] || die "repository is invalid"
[[ -x "$python_binary" ]] || die "Python executable is invalid"
[[ "$(id -u)" -eq 0 ]] || die "integration test requires root inside disposable WSL"
docker_binary=$(command -v docker)
[[ "$docker_binary" == /* ]] || die "Docker executable must be absolute"

image=$("$python_binary" -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["images"]["0.8.2"])' \
    "$repository/tests/integration/maddy-image-lock.json")
[[ "$image" =~ ^ghcr\.io/foxcpp/maddy@sha256:[0-9a-f]{64}$ ]] \
    || die "locked Maddy 0.8.2 image is invalid"
docker image inspect "$image" >/dev/null

nonce=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
container="maddyweb-named-volume-$nonce"
second="maddyweb-named-volume-second-$nonce"
volume="maddyweb-named-volume-$nonce"
label="io.maddyweb.named-volume-test=$nonce"
work=$(mktemp -d /tmp/maddyweb-named-volume.XXXXXXXX)
release="$work/release"
mkdir -m 0700 -- "$release"
mkdir -m 0700 -- "$work/bin"
printf '%s\n' '#!/bin/sh' 'exec uname -n' > "$work/bin/hostname"
chmod 0755 -- "$work/bin/hostname"
PATH="$work/bin:$PATH"
export PATH
cp -a -- "$repository/scripts/." "$release/"
chmod -R go-w -- "$release"
chmod 0755 -- "$release"/*.sh "$release"/*.py
fixture="$repository/tests/integration/fixtures/maddy-default-submission.conf"
volume_created=false

cleanup() {
    local status=$?
    set +e
    if [[ "$volume_created" == true ]]; then
        # The randomized target volume is the cleanup boundary.  Never delete
        # helpers from another concurrent test/transaction by global label.
        docker container ls --all --quiet --no-trunc --filter "volume=$volume" \
            | xargs -r docker rm --force >/dev/null 2>&1
        docker volume rm --force "$volume" >/dev/null 2>&1
    fi
    if [[ "$work" == /tmp/maddyweb-named-volume.* && -d "$work" && ! -L "$work" ]]; then
        rm -rf -- "$work"
    fi
    exit "$status"
}
trap cleanup EXIT

docker volume create --label "$label" "$volume" >/dev/null
volume_created=true
docker run --rm --network none --read-only \
    --mount "type=volume,source=$volume,target=/data" \
    --mount "type=bind,source=$fixture,target=/input/maddy.conf,readonly" \
    --entrypoint /bin/sh "$image" -c \
    'cp /input/maddy.conf /data/maddy.conf && chown 1234:1234 /data/maddy.conf && chmod 0600 /data/maddy.conf && sync /data' \
    >/dev/null
docker run --detach --name "$container" --label "$label" --network none \
    --mount "type=volume,source=$volume,target=/data" \
    --entrypoint /bin/sleep "$image" 600 >/dev/null
container_id=$(docker inspect --format '{{.Id}}' "$container")
[[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || die "container ID is invalid"

check_report=$("$python_binary" "$release/check-maddy-container.py" \
    --docker "$docker_binary" --container "$container" --host-config /data/maddy.conf)
"$python_binary" -c \
    'import json,sys; r=json.loads(sys.argv[1]); assert r["config_kind"] == "volume"; assert r["id"] == sys.argv[2]' \
    "$check_report" "$container_id"

# A running dry-run export uses only fixed read-only docker exec calls.  It
# must not leave or create a disposable helper container.
snapshot="$work/original.conf"
export_report=$("$python_binary" "$release/docker-volume-config.py" \
    --docker "$docker_binary" --container "$container_id" \
    --expected-container-id "$container_id" --state running \
    --action export --output "$snapshot")
original_hash=$("$python_binary" -c \
    'import json,sys; print(json.loads(sys.argv[1])["sha256"])' "$export_report")
[[ "$(stat -c '%a %u:%g' "$snapshot")" == "600 0:0" ]] \
    || die "host snapshot permissions are not private"
[[ "$(docker container ls --all --quiet --no-trunc --filter "volume=$volume")" == "$container_id" ]] \
    || die "running export created or leaked a helper container"

docker exec --user 0:0 "$container_id" /bin/chmod 0620 /data/maddy.conf
if "$python_binary" "$release/docker-volume-config.py" \
    --docker "$docker_binary" --container "$container_id" \
    --expected-container-id "$container_id" --state running \
    --action export --output "$work/writable.conf" >/dev/null 2>&1; then
    die "running export accepted a group-writable configuration"
fi
docker exec --user 0:0 "$container_id" /bin/chmod 4600 /data/maddy.conf
if "$python_binary" "$release/docker-volume-config.py" \
    --docker "$docker_binary" --container "$container_id" \
    --expected-container-id "$container_id" --state running \
    --action export --output "$work/special.conf" >/dev/null 2>&1; then
    die "running export accepted special mode bits"
fi
docker exec --user 0:0 "$container_id" /bin/chmod 0600 /data/maddy.conf

candidate="$work/candidate.conf"
cp -- "$snapshot" "$candidate"
edit_report=$("$python_binary" "$release/manage-submission.py" \
    --action add --config "$candidate" --backup-dir "$work")
candidate_hash=$("$python_binary" -c \
    'import json,sys; print(json.loads(sys.argv[1])["after_sha256"])' "$edit_report")

docker pause "$container_id" >/dev/null
"$python_binary" "$release/docker-volume-config.py" \
    --docker "$docker_binary" --container "$container_id" \
    --expected-container-id "$container_id" --state paused \
    --action replace --candidate "$candidate" \
    --expected-current-sha256 "$original_hash" \
    --expected-candidate-sha256 "$candidate_hash" >/dev/null
paused_copy="$work/paused.conf"
"$python_binary" "$release/docker-volume-config.py" \
    --docker "$docker_binary" --container "$container_id" \
    --expected-container-id "$container_id" --state paused \
    --action export --output "$paused_copy" >/dev/null
[[ "$(sha256sum "$paused_copy" | awk '{print $1}')" == "$candidate_hash" ]] \
    || die "paused helper did not read back candidate"
metadata=$(docker run --rm --network none --read-only \
    --mount "type=volume,source=$volume,target=/data,readonly" \
    --entrypoint /bin/stat "$image" -c '%a %u:%g %h' /data/maddy.conf)
[[ "$metadata" == "600 1234:1234 1" ]] \
    || die "replace did not preserve non-root owner, mode, and link count"

if "$python_binary" "$release/docker-volume-config.py" \
    --docker "$docker_binary" --container "$container_id" \
    --expected-container-id "$container_id" --state paused \
    --action replace --candidate "$snapshot" \
    --expected-current-sha256 "$(printf '0%.0s' {1..64})" \
    --expected-candidate-sha256 "$original_hash" >/dev/null 2>&1; then
    die "replace accepted a stale current hash"
fi

# A stopped same-ID container remains a valid rollback source; no new target
# container or daemon storage path is supplied to the tool.
docker unpause "$container_id" >/dev/null
docker stop --time 1 "$container_id" >/dev/null
stopped_copy="$work/stopped.conf"
"$python_binary" "$release/docker-volume-config.py" \
    --docker "$docker_binary" --container "$container_id" \
    --expected-container-id "$container_id" --state stopped \
    --action export --output "$stopped_copy" >/dev/null
[[ "$(sha256sum "$stopped_copy" | awk '{print $1}')" == "$candidate_hash" ]] \
    || die "stopped-state export changed content"
docker start "$container_id" >/dev/null

docker run --detach --name "$second" --label "$label" --network none \
    --mount "type=volume,source=$volume,target=/data" \
    --entrypoint /bin/sleep "$image" 600 >/dev/null
if "$python_binary" "$release/check-maddy-container.py" \
    --docker "$docker_binary" --container "$container_id" \
    --host-config /data/maddy.conf >/dev/null 2>&1; then
    die "checker accepted a volume referenced by another container"
fi
docker rm --force "$second" >/dev/null

if "$python_binary" "$release/check-maddy-container.py" \
    --docker "$docker_binary" --container "$container_id" \
    --host-config /data/other.conf >/dev/null 2>&1; then
    die "checker accepted an arbitrary named-volume config path"
fi
if DOCKER_HOST=unix:///tmp/forbidden.sock \
    "$python_binary" "$release/docker-volume-config.py" \
    --docker "$docker_binary" --container "$container_id" \
    --expected-container-id "$container_id" --state running \
    --action export --output "$work/forbidden.conf" >/dev/null 2>&1; then
    die "tool accepted a Docker daemon environment override"
fi

# Restore the exact original, then exercise the top-level 0.8.2 transaction.
docker pause "$container_id" >/dev/null
"$python_binary" "$release/docker-volume-config.py" \
    --docker "$docker_binary" --container "$container_id" \
    --expected-container-id "$container_id" --state paused \
    --action replace --candidate "$snapshot" \
    --expected-current-sha256 "$candidate_hash" \
    --expected-candidate-sha256 "$original_hash" >/dev/null
docker unpause "$container_id" >/dev/null

common_args=(
    --action add --environment development --host "$(hostname)" --mode docker
    --maddy-config /data/maddy.conf --docker-binary "$docker_binary"
    --container "$container" --python "$python_binary" --backup-dir "$work/backups"
)
if "$release/configure-submission.sh" "${common_args[@]}" --apply >/dev/null 2>&1; then
    die "Maddy 0.8.2 mutation did not require --allow-downtime"
fi

lock_dir=/run/lock/maddyweb-submission.lock
if [[ ! -e "$lock_dir" ]]; then install -d -o root -g root -m 0700 "$lock_dir"; fi
exec {competing_lock_fd}<"$lock_dir"
flock -n "$competing_lock_fd" || die "could not establish competing transaction lock"
if "$release/configure-submission.sh" "${common_args[@]}" \
    --allow-downtime --apply >/dev/null 2>&1; then
    die "second apply did not fail fast on the transaction lock"
fi
flock -u "$competing_lock_fd"
exec {competing_lock_fd}<&-
[[ "$(docker inspect --format '{{.State.Running}} {{.State.Paused}}' "$container_id")" == "true false" ]] \
    || die "lock contention changed target container state"

# The sleep fixture cannot open 1587, so apply must fail after restart and
# restore the exact original by candidate hash.  This deliberately covers the
# failure rollback rather than pretending the endpoint became healthy.
if "$release/configure-submission.sh" "${common_args[@]}" \
    --allow-downtime --apply >/dev/null 2>&1; then
    die "fixture unexpectedly passed the listener gate"
fi
[[ "$(docker inspect --format '{{.State.Running}} {{.State.Paused}}' "$container_id")" == "true false" ]] \
    || die "failed transaction did not restore running/unpaused state"
final_copy="$work/final.conf"
"$python_binary" "$release/docker-volume-config.py" \
    --docker "$docker_binary" --container "$container_id" \
    --expected-container-id "$container_id" --state running \
    --action export --output "$final_copy" >/dev/null
[[ "$(sha256sum "$final_copy" | awk '{print $1}')" == "$original_hash" ]] \
    || die "failed transaction did not restore exact original content"

printf 'named-volume Submission integration passed\n'
