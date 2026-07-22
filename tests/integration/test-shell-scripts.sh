#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ROOT=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

while IFS= read -r -d '' script; do
    bash -n -- "$script" || fail "syntax error: $script"
done < <(find "$ROOT/scripts" "$ROOT/tests/integration" -type f -name '*.sh' -print0)

grep -Fq 'ListenStream=/run/maddyweb/helper.sock' "$ROOT/deploy/systemd/maddyweb-helper.socket" || fail "helper socket path changed"
grep -Fq 'SocketMode=0660' "$ROOT/deploy/systemd/maddyweb-helper.socket" || fail "helper socket mode changed"
grep -Eq '^RestrictAddressFamilies=.*AF_UNIX.*AF_INET' "$ROOT/deploy/systemd/maddyweb-helper.service" || fail "helper cannot reach loopback submission"
grep -Fq 'ReadWritePaths=/var/tmp/maddyweb' "$ROOT/deploy/systemd/maddyweb.service" || fail "web temp directory is not allowlisted"
grep -Eq '^ReadWritePaths=.*(/etc/letsencrypt)' "$ROOT/deploy/systemd/maddyweb-helper.service" || fail "certbot renewal path is not writable"
grep -Fq 'd /run/maddyweb         0750 root     maddyweb -' "$ROOT/deploy/systemd/maddyweb.tmpfiles" || fail "helper socket parent ownership changed"
grep -Fq 'd /run/maddyweb-approval 0700 root     root     -' "$ROOT/deploy/systemd/maddyweb.tmpfiles" || fail "approval directory is not isolated"
grep -Fq 'MADDYWEB_APPROVAL_ROOT="/run/maddyweb-approval"' "$ROOT/scripts/lib/common.sh" || fail "approval root is not isolated"
grep -Fq 'unexpectedly advertises verify-config' "$ROOT/scripts/lib/common.sh" || fail "0.8.2 verify-config guard is missing"

if grep -RIEq '(password[[:space:]]*=|--password|0\.0\.0\.0:8787)' \
    "$ROOT/deploy" "$ROOT/docker" "$ROOT/scripts"; then
    fail "an operational artifact contains a forbidden password/public-listener pattern"
fi

if grep -RIEq '(nginx[[:space:]]+(-s|reload)|systemctl[[:space:]]+(reload|restart)[[:space:]]+nginx|/etc/nginx)' \
    "$ROOT/deploy" "$ROOT/docker" "$ROOT/scripts"; then
    fail "an operational script appears to modify Nginx"
fi

printf 'shell-contracts=ok\n'
