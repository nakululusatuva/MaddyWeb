#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

if [[ ${EUID:-$(id -u)} -ne 0 ]] \
    || ! command -v systemd-run >/dev/null 2>&1 \
    || ! systemctl show-environment >/dev/null 2>&1; then
    printf 'systemd-sandbox-runtime=skipped\n'
    exit 0
fi

if id -u maddyweb >/dev/null 2>&1; then
    web_user=maddyweb
else
    web_user=nobody
fi

root=$(mktemp -d /srv/maddyweb-systemd-sandbox.XXXXXXXX)
[[ "$(realpath -- "$root")" == /srv/maddyweb-systemd-sandbox.* ]] \
    || { printf 'unsafe systemd sandbox fixture path\n' >&2; exit 1; }
chmod 0755 -- "$root"
web="$root/web-spool"
web_denied="$root/web-denied"
data="$root/maddy-state"
certificates="$root/maddy-tls"
helper_denied="$root/helper-denied"
unit_suffix=$(basename -- "$root" | tr -cd 'A-Za-z0-9')
private_web=$(mktemp -d "/var/tmp/maddyweb-systemd-private-$unit_suffix.XXXXXXXX")
[[ "$private_web" == "/var/tmp/maddyweb-systemd-private-$unit_suffix."* ]] \
    || { printf 'unsafe private temp fixture path\n' >&2; exit 1; }

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -d "$private_web" && ! -L "$private_web" \
        && "$private_web" == "/var/tmp/maddyweb-systemd-private-$unit_suffix."* ]]; then
        rmdir -- "$private_web" || status=1
    fi
    if [[ -d "$root" && ! -L "$root" && "$root" == /srv/maddyweb-systemd-sandbox.* ]]; then
        rm -rf -- "$root"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

install -d -o "$web_user" -g "$web_user" -m 0700 -- "$web" "$web_denied"
chown "$web_user:$web_user" -- "$private_web"
chmod 0700 -- "$private_web"
install -d -o root -g root -m 0700 -- "$data" "$certificates" "$helper_denied"

# PrivateTmp replaces /var/tmp inside the mount namespace.  The application can
# create its private 0700 spool there without a host path allow-list, and files
# created inside the service must not appear in the host directory.
systemd-run --quiet --wait --collect --pipe \
    --unit "maddyweb-sandbox-private-tmp-$unit_suffix" \
    --property PrivateTmp=yes \
    --property ProtectSystem=strict \
    --uid="$web_user" --gid="$web_user" \
    /usr/bin/sh -eu -c \
        'mkdir -p -m 0700 -- "$1"; touch -- "$1/probe"; test -f "$1/probe"' \
        sh "$private_web"

[[ -d "$private_web" && ! -e "$private_web/probe" ]]

systemd-run --quiet --wait --collect --pipe \
    --unit "maddyweb-sandbox-web-$unit_suffix" \
    --property PrivateTmp=yes \
    --property ProtectSystem=strict \
    --property "ReadWritePaths=$web" \
    --uid="$web_user" --gid="$web_user" \
    /usr/bin/touch "$web/probe"

if systemd-run --quiet --wait --collect --pipe \
    --unit "maddyweb-sandbox-web-deny-$unit_suffix" \
    --property PrivateTmp=yes \
    --property ProtectSystem=strict \
    --property "ReadWritePaths=$web" \
    --uid="$web_user" --gid="$web_user" \
    /usr/bin/touch "$web_denied/probe" >/dev/null 2>&1; then
    printf 'web sandbox unexpectedly wrote outside its allow-list\n' >&2
    exit 1
fi

systemd-run --quiet --wait --collect --pipe \
    --unit "maddyweb-sandbox-helper-$unit_suffix" \
    --property ProtectSystem=strict \
    --property "ReadWritePaths=$data" \
    --property "ReadWritePaths=$certificates" \
    /usr/bin/touch "$data/probe" "$certificates/probe"

if systemd-run --quiet --wait --collect --pipe \
    --unit "maddyweb-sandbox-helper-deny-$unit_suffix" \
    --property ProtectSystem=strict \
    --property "ReadWritePaths=$data" \
    --property "ReadWritePaths=$certificates" \
    /usr/bin/touch "$helper_denied/probe" >/dev/null 2>&1; then
    printf 'helper sandbox unexpectedly wrote outside its allow-list\n' >&2
    exit 1
fi

[[ -f "$web/probe" && -f "$data/probe" && -f "$certificates/probe" ]]
[[ ! -e "$web_denied/probe" && ! -e "$helper_denied/probe" ]]
printf 'systemd-sandbox-runtime=ok\n'
