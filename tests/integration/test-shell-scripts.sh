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

# shellcheck disable=SC1091
source "$ROOT/scripts/lib/common.sh"
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
