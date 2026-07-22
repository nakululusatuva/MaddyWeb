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
grep -Fq 'PrivateTmp=yes' "$ROOT/deploy/systemd/maddyweb.service" || fail "web private temp isolation is disabled"
if grep -Fq 'ReadWritePaths=/var/tmp/maddyweb' "$ROOT/deploy/systemd/maddyweb.service"; then
    fail "web private temp directory must not be a host path allow-list"
fi
helper_write_paths=$(sed -n 's/^ReadWritePaths=//p' "$ROOT/deploy/systemd/maddyweb-helper.service")
expected_helper_write_paths='/var/backups/maddyweb /run/maddyweb'
[[ "$helper_write_paths" == "$expected_helper_write_paths" ]] \
    || fail "base helper write allow-list changed or gained native Maddy paths"
grep -Fq 'd /run/maddyweb         0750 root     maddyweb -' "$ROOT/deploy/systemd/maddyweb.tmpfiles" || fail "helper socket parent ownership changed"
grep -Fq 'd /run/maddyweb-approval 0700 root     root     -' "$ROOT/deploy/systemd/maddyweb.tmpfiles" || fail "approval directory is not isolated"
grep -Fq 'MADDYWEB_APPROVAL_ROOT="/run/maddyweb-approval"' "$ROOT/scripts/lib/common.sh" || fail "approval root is not isolated"
grep -Fq 'unexpectedly advertises verify-config' "$ROOT/scripts/lib/common.sh" || fail "0.8.2 verify-config guard is missing"
grep -Fq "IFS=\$' \t' read -r python_version py_gil_disabled gil_enabled" \
    "$ROOT/scripts/preflight.sh" || fail "Python diagnostics parser ignores spaces"

# shellcheck disable=SC1091
source "$ROOT/scripts/lib/common.sh"
actual_version=$(extract_maddy_version $'0.8.2 linux/amd64 go1.23.12\ndefault config: /data/maddy.conf')
[[ "$actual_version" == 0.8.2 ]] || fail "real Maddy version output was not parsed"
version_in_supported_range 0.8.2 || fail "official Maddy 0.8.2 was rejected"
version_in_supported_range 0.9.5 || fail "official Maddy 0.9.5 was rejected"
if version_in_supported_range 0.8.3; then
    fail "non-release Maddy 0.8.3 was accepted"
fi

contract_tmp=$(mktemp -d)
trap 'rm -rf -- "$contract_tmp"' EXIT
fake_maddy="$contract_tmp/maddy-tampered-help"
cat > "$fake_maddy" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'creds imap-acct imap-mboxes imap-msgs list create remove password appendlimit --value USERNAME rename add add-flags rem-flags set-flags copy move dump --uid --full MAILBOX --yes SEQSET tampered'
EOF
chmod 0700 -- "$fake_maddy"
if (assert_maddy_082_help_profile "$fake_maddy" >/dev/null 2>&1); then
    fail "tampered Maddy 0.8.2 help output matched the verified fingerprint"
fi

if grep -RIEq '(password[[:space:]]*=|--password|0\.0\.0\.0:8787)' \
    "$ROOT/deploy" "$ROOT/docker" "$ROOT/scripts"; then
    fail "an operational artifact contains a forbidden password/public-listener pattern"
fi

if grep -RIEq '(nginx[[:space:]]+(-s|reload)|systemctl[[:space:]]+(reload|restart)[[:space:]]+nginx|/etc/nginx)' \
    "$ROOT/deploy" "$ROOT/docker" "$ROOT/scripts"; then
    fail "an operational script appears to modify Nginx"
fi

printf 'shell-contracts=ok\n'
