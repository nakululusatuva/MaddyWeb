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

work=$(mktemp -d)
containers=()
networks=()
cleanup() {
    for container in "${containers[@]}"; do
        "$docker_binary" rm -f -v "$container" >/dev/null 2>&1 || true
    done
    for network in "${networks[@]}"; do
        "$docker_binary" network rm "$network" >/dev/null 2>&1 || true
    done
    rm -rf -- "$work"
}
trap cleanup EXIT INT TERM

python_image='python@sha256:4c92ffcde4dd6f1ff72a24518f49fd4990b27134987dfa31a733badde66df9f8'
cat > "$work/bridge-server.py" <<'PY'
from __future__ import annotations

import socket
import sys
import types
from pathlib import Path

# Keep this integration process dependency-free.  The production function has
# stricter canonicalization; this fixture accepts only the one fixed test ID.
auth = types.ModuleType("maddyweb.auth")


def canonicalize_email(value: str) -> str:
    if value != "user@example.test":
        raise ValueError("unexpected fixture account")
    return value


auth.canonicalize_email = canonicalize_email
sys.modules["maddyweb.auth"] = auth
sys.path.insert(0, "/workspace/src")

from maddyweb.filter_bridge import serve_filter_bridge  # noqa: E402

address = socket.gethostbyname(socket.gethostname())
serve_filter_bridge(
    f"{address}:18787",
    Path("/state/bridge.token"),
    snapshot_dir=Path("/state/snapshots"),
)
PY

mapfile -t versions_and_images < <(
    "$python_binary" - "$ROOT/tests/integration/maddy-image-lock.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    images = json.load(handle)["images"]
for version in ("0.8.2", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "0.9.4", "0.9.5"):
    print(version + " " + images[version])
PY
)

for record in "${versions_and_images[@]}"; do
    version=${record%% *}
    image=${record#* }
    data="$work/data-$version"
    bridge_fixture="$work/bridge-$version"
    mkdir -p "$bridge_fixture/snapshots"
    chmod 0750 "$bridge_fixture/snapshots"
    printf '%s\n' 'abababababababababababababababababababababababababababababababab' \
        > "$bridge_fixture/bridge.token"
    chmod 0640 "$bridge_fixture/bridge.token"
    "$python_binary" - "$bridge_fixture/snapshots" "$version" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

account = "user@example.test"
directory = Path(sys.argv[1])
version = sys.argv[2]
document = {
    "version": 1,
    "account": account,
    "rules": [
        {
            "rule_id": "1" * 32,
            "enabled": True,
            "position": 0,
            "condition": {
                "field": "subject",
                "operator": "contains",
                "value": f"matched delivery {version}",
            },
            "target_mailbox": "RuleMatches",
            "stop_processing": True,
            "revision": 1,
        }
    ],
}
name = hashlib.sha256(account.encode("ascii")).hexdigest() + ".json"
path = directory / name
path.write_bytes(
    json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
)
os.chmod(path, 0o640)
PY
    mkdir -p "$data/tls" "$data/maddyweb-filter"
    "$docker_binary" run --rm --entrypoint /bin/cat "$image" /data/maddy.conf \
        > "$data/maddy.conf"
    "$python_binary" - "$data/maddy.conf" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
header = "submission tls://0.0.0.0:465 tcp://0.0.0.0:587 {"
replacement = "submission tcp://0.0.0.0:587 {\n    tls off"
if source.count(header) != 1:
    raise SystemExit(2)
path.write_text(source.replace(header, replacement), encoding="utf-8")
PY
    "$python_binary" "$ROOT/scripts/manage-imap-filter.py" --action render-add \
        --config "$data/maddy.conf" --mode docker > "$data/maddy.conf.new"
    mv -f -- "$data/maddy.conf.new" "$data/maddy.conf"
    install -m 0555 "$ROOT/deploy/maddyweb-filter-docker" \
        "$data/maddyweb-filter/maddyweb-filter-client"
    printf '%s\n' 'abababababababababababababababababababababababababababababababab' \
        > "$data/maddyweb-filter/client.token"
    printf '%s\n' '127.0.0.1:18787' > "$data/maddyweb-filter/client.endpoint"
    chmod 0400 "$data/maddyweb-filter/client.token" "$data/maddyweb-filter/client.endpoint"
    "$openssl_binary" req -x509 -newkey rsa:2048 -nodes -days 1 \
        -subj '/CN=mail.example.test' \
        -keyout "$data/tls/privkey.pem" -out "$data/tls/fullchain.pem" >/dev/null 2>&1
    chmod 0600 "$data/tls/privkey.pem"
    chmod 0644 "$data/tls/fullchain.pem"

    network="maddyweb-filter-delivery-${version//./-}-$$"
    networks+=("$network")
    "$docker_binary" network create "$network" >/dev/null
    bridge="maddyweb-filter-bridge-${version//./-}-$$"
    containers+=("$bridge")
    "$docker_binary" run -d --name "$bridge" --network "$network" \
        --volume "$ROOT/src:/workspace/src:ro" \
        --volume "$bridge_fixture:/fixture:ro" \
        --volume "$work/bridge-server.py:/bridge-server.py:ro" \
        --entrypoint /bin/sh "$python_image" -c '
            mkdir -p /state/snapshots
            cp /fixture/bridge.token /state/bridge.token
            cp /fixture/snapshots/*.json /state/snapshots/
            chown -R 0:0 /state
            chmod 0750 /state /state/snapshots
            chmod 0640 /state/bridge.token /state/snapshots/*.json
            exec /usr/local/bin/python -I /bridge-server.py
        ' >/dev/null
    bridge_ip=$(
        "$docker_binary" inspect --format \
            "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}" \
            "$bridge"
    )
    [[ "$bridge_ip" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]

    container="maddyweb-filter-delivery-${version//./-}-$$"
    containers+=("$container")
    "$docker_binary" run -d --name "$container" --network "$network" \
        --env MADDY_HOSTNAME=mail.example.test --env MADDY_DOMAIN=example.test \
        --volume "$data:/data" "$image" >/dev/null
    for _ in {1..100}; do
        if "$docker_binary" exec "$container" /bin/maddy version >/dev/null 2>&1; then
            break
        fi
        sleep 0.1
    done
    "$docker_binary" exec "$container" /bin/maddy creds create \
        -p 'filter-fixture-password' user@example.test >/dev/null
    "$docker_binary" exec "$container" /bin/maddy imap-acct create user@example.test \
        >/dev/null
    auth=$(
        "$python_binary" -c \
            'import base64; print(base64.b64encode(b"\0user@example.test\0filter-fixture-password").decode())'
    )
    smtp_reply=$(
        printf 'EHLO localhost\r\nAUTH PLAIN %s\r\nMAIL FROM:<user@example.test>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nFrom: user@example.test\r\nTo: user@example.test\r\nSubject: fail-open delivery %s\r\n\r\nbody\r\n.\r\nQUIT\r\n' \
            "$auth" "$version" \
            | "$docker_binary" exec -i "$container" /usr/bin/nc -w 15 127.0.0.1 587
    )
    grep -Eq '(^|[[:space:]])250[[:space:]]+2\.0\.0' <<< "$smtp_reply"
    messages=$(
        "$docker_binary" exec "$container" /bin/maddy imap-msgs list \
            user@example.test INBOX
    )
    grep -Fq "fail-open delivery $version" <<< "$messages"
    if "$docker_binary" exec "$container" /bin/maddy imap-mboxes list user@example.test \
        | grep -Fxq Archive; then
        archive_messages=$(
            "$docker_binary" exec "$container" /bin/maddy imap-msgs list \
                user@example.test Archive
        )
        if grep -Fq "fail-open delivery $version" <<< "$archive_messages"; then
            exit 1
        fi
    fi
    "$docker_binary" exec "$container" /bin/maddy imap-mboxes create \
        user@example.test RuleMatches >/dev/null
    chmod 0600 "$data/maddyweb-filter/client.endpoint"
    printf '%s:18787\n' "$bridge_ip" > "$data/maddyweb-filter/client.endpoint"
    chmod 0400 "$data/maddyweb-filter/client.endpoint"
    for _ in {1..100}; do
        if "$docker_binary" exec "$container" /usr/bin/nc -z -w 2 \
            "$bridge_ip" 18787 >/dev/null 2>&1; then
            break
        fi
        sleep 0.1
    done
    "$docker_binary" exec "$container" /usr/bin/nc -z -w 2 \
        "$bridge_ip" 18787 >/dev/null 2>&1
    smtp_reply=$(
        printf 'EHLO localhost\r\nAUTH PLAIN %s\r\nMAIL FROM:<user@example.test>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nFrom: user@example.test\r\nTo: user@example.test\r\nSubject: matched delivery %s\r\n\r\nbody\r\n.\r\nQUIT\r\n' \
            "$auth" "$version" \
            | "$docker_binary" exec -i "$container" /usr/bin/nc -w 15 127.0.0.1 587
    )
    grep -Eq '(^|[[:space:]])250[[:space:]]+2\.0\.0' <<< "$smtp_reply"
    archive_messages=$(
        "$docker_binary" exec "$container" /bin/maddy imap-msgs list \
            user@example.test RuleMatches
    )
    [[ "$(grep -Fc "matched delivery $version" <<< "$archive_messages")" -eq 1 ]]
    inbox_messages=$(
        "$docker_binary" exec "$container" /bin/maddy imap-msgs list \
            user@example.test INBOX
    )
    if grep -Fq "matched delivery $version" <<< "$inbox_messages"; then
        exit 1
    fi
    "$docker_binary" rm -f -v "$container" >/dev/null
    "$docker_binary" rm -f -v "$bridge" >/dev/null
    "$docker_binary" network rm "$network" >/dev/null
done

containers=()
networks=()
printf 'filter-maddy-delivery=ok\n'
