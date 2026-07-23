#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export MALLOC_ARENA_MAX=1
export MALLOC_TRIM_THRESHOLD_=65536

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd -- "$REPO_ROOT"

perf_log=$(mktemp)
perf_pid=""
cleanup() {
    if [[ -n "$perf_pid" ]]; then
        kill "$perf_pid" 2>/dev/null || true
        wait "$perf_pid" 2>/dev/null || true
    fi
    rm -f -- "$perf_log"
}
trap cleanup EXIT

.venv/bin/python tests/integration/performance_fixture.py >"$perf_log" 2>&1 &
perf_pid=$!
ready=false
for _ in {1..50}; do
    if /usr/bin/ss -H -ltn 'sport = :8787' | grep -q '127.0.0.1:8787'; then
        ready=true
        break
    fi
    sleep 0.1
done
if [[ "$ready" != true ]]; then
    sed -n '1,40p' "$perf_log" >&2
    exit 1
fi

# Initialize the request path, then measure the specified idle-service budget
# before loading the lazy email sanitizer and generating the larger API working
# set.  A separate post-workload ceiling below catches unbounded retention.
.venv/bin/python scripts/performance-test.py \
    --requests 8 --concurrency 1 --warmup 1 --max-p95-ms 500
awk '
    /^Pss:/ { pss += $2 }
    /^Rss:/ { rss += $2 }
    END {
        printf "idle_process_pss_kib=%d idle_process_rss_kib=%d\n", pss, rss
        if (pss > 45 * 1024 || rss > 45 * 1024) exit 1
    }
' "/proc/$perf_pid/smaps_rollup"

.venv/bin/python scripts/performance-test.py \
    --requests 400 --concurrency 8 --max-p95-ms 500
.venv/bin/python scripts/performance-test.py \
    --url http://127.0.0.1:8787/ \
    --requests 200 --concurrency 8 --max-p95-ms 500
.venv/bin/python scripts/performance-test.py \
    --url http://127.0.0.1:8787/api/v1/accounts \
    --requests 200 --concurrency 8 --max-p95-ms 500
.venv/bin/python scripts/performance-test.py \
    --url 'http://127.0.0.1:8787/api/v1/mail?account=user00%40example.test&mailbox=INBOX' \
    --requests 200 --concurrency 8 --max-p95-ms 500
.venv/bin/python scripts/performance-test.py \
    --url 'http://127.0.0.1:8787/api/v1/mail/42?account=user00%40example.test&mailbox=INBOX' \
    --requests 100 --concurrency 8 --max-p95-ms 500

awk '
    /^Pss:/ { pss += $2 }
    /^Rss:/ { rss += $2 }
    END {
        printf "post_workload_pss_kib=%d post_workload_rss_kib=%d\n", pss, rss
        if (pss > 55 * 1024 || rss > 55 * 1024) exit 1
    }
' "/proc/$perf_pid/smaps_rollup"
