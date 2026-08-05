#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ROOT=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
docker_binary=${DOCKER_BINARY:-$(command -v docker || true)}
python_binary=${PYTHON_BINARY:-$(command -v python3 || true)}
[[ -n "$docker_binary" && -n "$python_binary" ]] || exit 77
"$docker_binary" info >/dev/null 2>&1 || exit 77

work=$(mktemp -d)
server_pid=""
cleanup() {
    if [[ -n "$server_pid" ]]; then kill "$server_pid" >/dev/null 2>&1 || true; fi
    rm -rf -- "$work"
}
trap cleanup EXIT INT TERM

cat > "$work/server.py" <<'PY'
import socket

with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 18787))
    listener.listen(1)
    connection, _address = listener.accept()
    with connection:
        payload = bytearray()
        while chunk := connection.recv(65536):
            payload.extend(chunk)
        line, separator, message = payload.partition(b"\n")
        expected = b"MADDYWEB-FILTER/1 " + (b"ab" * 32) + b" user@example.test"
        if separator != b"\n" or line != expected or b"Subject: bridge test" not in message:
            raise SystemExit(2)
        connection.sendall(b"Archive\n")
PY

mapfile -t images < <(
    "$python_binary" - "$ROOT/tests/integration/maddy-image-lock.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    images = json.load(handle)["images"]
for version in ("0.8.2", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "0.9.4", "0.9.5"):
    print(images[version])
PY
)

for image in "${images[@]}"; do
    "$python_binary" "$work/server.py" &
    server_pid=$!
    for _ in {1..50}; do
        if "$python_binary" - <<'PY' >/dev/null 2>&1
import socket
with socket.socket() as client:
    raise SystemExit(client.connect_ex(("127.0.0.1", 18787)) != 0)
PY
        then
            break
        fi
        sleep 0.05
    done
    # The readiness probe consumed no accepted connection because connect_ex
    # establishes one. Restart the one-shot server for the real client.
    wait "$server_pid" 2>/dev/null || true
    "$python_binary" "$work/server.py" &
    server_pid=$!
    sleep 0.1
    output=$(
        printf 'Subject: bridge test\r\n\r\nbody\r\n' \
            | "$docker_binary" run --rm --network host -i \
                --volume "$ROOT/deploy/maddyweb-filter-docker:/asset:ro" \
                --entrypoint /bin/sh "$image" -c '
                    mkdir -p /data/maddyweb-filter
                    cp /asset /data/maddyweb-filter/maddyweb-filter-client
                    chmod 0555 /data/maddyweb-filter/maddyweb-filter-client
                    printf "%s\n" "abababababababababababababababababababababababababababababababab" > /data/maddyweb-filter/client.token
                    printf "%s\n" "127.0.0.1:18787" > /data/maddyweb-filter/client.endpoint
                    chown 0:0 /data/maddyweb-filter/client.token /data/maddyweb-filter/client.endpoint
                    chmod 0400 /data/maddyweb-filter/client.token /data/maddyweb-filter/client.endpoint
                    exec /data/maddyweb-filter/maddyweb-filter-client user@example.test
                '
    )
    wait "$server_pid"
    server_pid=""
    [[ "$output" == Archive ]]

    output=$(
        printf 'Subject: unavailable bridge\r\n\r\nbody\r\n' \
            | "$docker_binary" run --rm --network host -i \
                --volume "$ROOT/deploy/maddyweb-filter-docker:/asset:ro" \
                --entrypoint /bin/sh "$image" -c '
                    mkdir -p /data/maddyweb-filter
                    cp /asset /data/maddyweb-filter/maddyweb-filter-client
                    chmod 0555 /data/maddyweb-filter/maddyweb-filter-client
                    printf "%s\n" "abababababababababababababababababababababababababababababababab" > /data/maddyweb-filter/client.token
                    printf "%s\n" "127.0.0.1:18787" > /data/maddyweb-filter/client.endpoint
                    chown 0:0 /data/maddyweb-filter/client.token /data/maddyweb-filter/client.endpoint
                    chmod 0400 /data/maddyweb-filter/client.token /data/maddyweb-filter/client.endpoint
                    exec /data/maddyweb-filter/maddyweb-filter-client user@example.test
                '
    )
    [[ -z "$output" ]]
done

printf 'filter-docker-client=ok\n'
