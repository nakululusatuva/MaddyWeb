#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ROOT=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
docker_binary=${DOCKER_BINARY:-$(command -v docker || true)}
python_binary=${PYTHON_BINARY:-$(command -v python3 || true)}
openssl_binary=${OPENSSL_BINARY:-$(command -v openssl || true)}
[[ -n "$docker_binary" && -n "$python_binary" && -n "$openssl_binary" ]] || exit 77
"$docker_binary" info >/dev/null 2>&1 || exit 77

image=$(
    "$python_binary" - "$ROOT/tests/integration/maddy-image-lock.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)["images"]["0.9.5"])
PY
)
[[ "$image" =~ ^ghcr\.io/foxcpp/maddy@sha256:[0-9a-f]{64}$ ]]
"$docker_binary" image inspect "$image" >/dev/null 2>&1 || exit 77

work=$(mktemp -d)
container="maddyweb-filter-restart-$$"
cleanup() {
    "$docker_binary" rm -f -v "$container" >/dev/null 2>&1 || true
    rm -rf -- "$work"
}
trap cleanup EXIT INT TERM

data="$work/data"
mkdir -p "$data/tls" "$data/maddyweb-filter"
"$docker_binary" run --rm --entrypoint /bin/cat "$image" /data/maddy.conf \
    > "$data/maddy.conf"
install -m 0600 -- "$data/maddy.conf" "$work/maddy.conf.original"
install -m 0555 -- "$ROOT/deploy/maddyweb-filter-docker" \
    "$data/maddyweb-filter/maddyweb-filter-client"
printf '%s\n' 'abababababababababababababababababababababababababababababababab' \
    > "$data/maddyweb-filter/client.token"
printf '%s\n' '127.0.0.1:18787' > "$data/maddyweb-filter/client.endpoint"
chmod 0400 "$data/maddyweb-filter/client.token" \
    "$data/maddyweb-filter/client.endpoint"
"$openssl_binary" req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=mail.example.test' \
    -keyout "$data/tls/privkey.pem" -out "$data/tls/fullchain.pem" \
    >/dev/null 2>&1
chmod 0600 "$data/tls/privkey.pem"
chmod 0644 "$data/tls/fullchain.pem"

listener_snapshot() {
    "$docker_binary" exec "$container" /bin/cat /proc/net/tcp /proc/net/tcp6 \
        | awk '$4 == "0A" {print $2}' \
        | LC_ALL=C sort -u
}

update_pipe_ready() {
    "$docker_binary" exec "$container" /bin/sh -c \
        'set -- /tmp/sql-*.sock; [ "$#" -eq 1 ] && [ -S "$1" ]'
}

wait_ready() {
    local listeners version
    for _ in {1..100}; do
        version=$(
            "$docker_binary" exec "$container" /bin/maddy version 2>/dev/null \
                | sed -n '1p' || true
        )
        listeners=$(listener_snapshot 2>/dev/null || true)
        if [[ "$version" == 0.9.5\ * && -n "$listeners" ]] \
            && update_pipe_ready >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

verify_live_config() {
    local expected=${1:?expected config is required}
    rm -f -- "$work/maddy.conf.observed"
    "$docker_binary" cp "$container:/data/maddy.conf" "$work/maddy.conf.observed" \
        >/dev/null
    cmp -s -- "$expected" "$work/maddy.conf.observed"
}

"$docker_binary" run -d --name "$container" \
    --env MADDY_HOSTNAME=mail.example.test --env MADDY_DOMAIN=example.test \
    --volume "$data:/data" "$image" >/dev/null
wait_ready
container_id=$("$docker_binary" inspect --format '{{.Id}}' "$container")
initial_listeners=$(listener_snapshot)
[[ -n "$initial_listeners" ]]

"$python_binary" "$ROOT/scripts/manage-imap-filter.py" --action render-add \
    --config "$work/maddy.conf.original" --mode docker \
    > "$work/maddy.conf.candidate"
"$docker_binary" cp "$work/maddy.conf.candidate" \
    "$container:/data/.maddy.conf.restart-test" >/dev/null
"$docker_binary" exec --workdir /data "$container" /bin/maddy \
    -config /data/.maddy.conf.restart-test verify-config >/dev/null 2>&1
"$docker_binary" exec "$container" /bin/busybox rm -f \
    /data/.maddy.conf.restart-test
install -m 0600 -- "$work/maddy.conf.candidate" "$data/.maddy.conf.next"
mv -fT -- "$data/.maddy.conf.next" "$data/maddy.conf"
started_before_add=$("$docker_binary" inspect --format '{{.State.StartedAt}}' "$container")
"$docker_binary" restart --time 10 "$container" >/dev/null
wait_ready
started_after_add=$("$docker_binary" inspect --format '{{.State.StartedAt}}' "$container")
[[ "$started_after_add" != "$started_before_add" ]]
[[ "$("$docker_binary" inspect --format '{{.Id}}' "$container")" == "$container_id" ]]
[[ "$(listener_snapshot)" == "$initial_listeners" ]]
verify_live_config "$work/maddy.conf.candidate"

install -m 0600 -- "$work/maddy.conf.original" "$data/.maddy.conf.next"
mv -fT -- "$data/.maddy.conf.next" "$data/maddy.conf"
started_before_restore=$("$docker_binary" inspect --format '{{.State.StartedAt}}' "$container")
"$docker_binary" restart --time 10 "$container" >/dev/null
wait_ready
started_after_restore=$("$docker_binary" inspect --format '{{.State.StartedAt}}' "$container")
[[ "$started_after_restore" != "$started_before_restore" ]]
[[ "$("$docker_binary" inspect --format '{{.Id}}' "$container")" == "$container_id" ]]
[[ "$(listener_snapshot)" == "$initial_listeners" ]]
verify_live_config "$work/maddy.conf.original"

logs=$("$docker_binary" logs "$container" 2>&1)
if grep -Eq 'failed to initialize updates pipe|failed to remove socket' <<< "$logs"; then
    exit 1
fi

printf 'filter-restart-lifecycle=ok\n'
