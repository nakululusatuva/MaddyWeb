#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    cat <<'EOF'
Usage: authorize-production.sh --action install|backup|rollback|submission-add|submission-remove

Creates a root-owned, host-bound approval in /run/maddyweb-approval. The approval
expires after ten minutes and is consumed by exactly one operational command.
The script never reads or stores a password; sudo performs the one human
authentication when elevation is needed.
EOF
}

action=""
while (($#)); do
    case "$1" in
        --action) (($# >= 2)) || die "--action requires a value"; action=$2; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$action" in
    install|backup|rollback|submission-add|submission-remove) ;;
    *) die "unsupported production action" ;;
esac

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    require_command sudo
    [[ -t 0 && -t 2 ]] || die "production authorization requires an interactive terminal"
    exec sudo -- "$0" --action "$action"
fi

[[ -t 0 && -t 2 ]] || die "production authorization requires an interactive terminal"
require_command hostname
require_command date
require_command od
require_command install

host=$(hostname)
phrase="AUTHORIZE ${action} ON ${host}"
printf 'Type exactly "%s" to continue: ' "$phrase" >&2
IFS= read -r entered
[[ "$entered" == "$phrase" ]] || die "confirmation did not match"

install -d -o root -g root -m 0700 -- "$MADDYWEB_APPROVAL_ROOT"
[[ ! -L "$MADDYWEB_APPROVAL_ROOT" ]] || die "approval root must not be a symbolic link"
nonce=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
[[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || die "failed to generate approval nonce"
approval="$MADDYWEB_APPROVAL_ROOT/approval-${action}-${nonce}"
expires=$(($(date +%s) + 600))

( set -o noclobber
  printf 'format=%s\naction=%s\nhost=%s\nexpires=%s\nnonce=%s\n' \
      'maddyweb-production-approval-v1' "$action" "$host" "$expires" "$nonce" > "$approval"
)
chmod 0600 -- "$approval"
chown root:root -- "$approval"
printf '%s\n' "$approval"
