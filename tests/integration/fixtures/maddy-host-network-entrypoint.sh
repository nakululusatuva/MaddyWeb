#!/bin/sh
set -eu

case "${MADDYWEB_SAFE_SOURCE_PORT:-}" in
    *[!0-9]*|"") exit 64 ;;
esac
if [ "$MADDYWEB_SAFE_SOURCE_PORT" -lt 20000 ] \
    || [ "$MADDYWEB_SAFE_SOURCE_PORT" -gt 60999 ] \
    || [ "$MADDYWEB_SAFE_SOURCE_PORT" -eq 1587 ]; then
    exit 64
fi

source_header='submission tls://0.0.0.0:465 tcp://0.0.0.0:587 {'
runtime_header="submission tcp://127.0.0.1:${MADDYWEB_SAFE_SOURCE_PORT} {"
runtime_candidate=/data/runtime.conf.new

/bin/sed \
    -e "s#^${source_header}\$#${runtime_header}#" \
    -e "/^submission tcp:\\/\\/127\\.0\\.0\\.1:${MADDYWEB_SAFE_SOURCE_PORT} {\$/a\\    tls off" \
    /data/maddy.conf > "$runtime_candidate"
/bin/chmod 0600 "$runtime_candidate"
/bin/mv "$runtime_candidate" /data/runtime.conf
exec /bin/maddy -config /data/runtime.conf run
