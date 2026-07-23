#!/usr/bin/env python3
"""Bounded, read-only performance gate for fixed loopback application targets."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Never

MAX_HEALTH_BODY = 4096
MAX_RESPONSE_BODY = 512 * 1024
HEALTH_FIELDS = {
    "status",
    "version",
    "maddy_version",
    "maddy_write_enabled",
    "storage_available",
    "certbot_available",
    "certificate_management_enabled",
}
TARGETS = {
    ("/", ""): ("html", b"Administration overview"),
    ("/api/v1/accounts", ""): ("api", b"user49@example.test"),
    (
        "/api/v1/mail",
        "account=user00%40example.test&mailbox=INBOX",
    ): ("api", b"Performance message"),
    (
        "/api/v1/mail/42",
        "account=user00%40example.test&mailbox=INBOX",
    ): ("api", b"Performance fixture"),
}


def fail(message: str) -> Never:
    print(f"performance gate failed: {message}", file=sys.stderr)
    raise SystemExit(1)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


OPENER = urllib.request.build_opener(NoRedirect)


@dataclass(frozen=True)
class Result:
    seconds: float
    error: str | None


def request_once(
    url: str,
    timeout: float,
    target_kind: str,
    expected_marker: bytes | None,
) -> Result:
    started = time.perf_counter()
    error: str | None = None
    try:
        # main() accepts only the exact loopback HTTP health URL.
        request = urllib.request.Request(  # noqa: S310
            url,
            method="GET",
            headers={"Accept": "application/json", "User-Agent": "maddyweb-local-perf/1"},
        )
        with OPENER.open(request, timeout=timeout) as response:
            maximum = MAX_HEALTH_BODY if target_kind == "health" else MAX_RESPONSE_BODY
            body = response.read(maximum + 1)
            if response.status != 200:
                error = f"http-{response.status}"
            elif len(body) > maximum:
                error = "response-too-large"
            elif target_kind == "html":
                content_type = response.headers.get_content_type()
                if content_type != "text/html":
                    error = "unexpected-content-type"
                elif (
                    b"<!doctype html>" not in body.lower()
                    or expected_marker is None
                    or expected_marker not in body
                ):
                    error = "unexpected-html"
            elif target_kind == "api":
                content_type = response.headers.get_content_type()
                if content_type != "application/json":
                    error = "unexpected-content-type"
                else:
                    try:
                        payload = json.loads(body)
                    except UnicodeDecodeError, json.JSONDecodeError:
                        error = "invalid-json"
                    else:
                        if (
                            not isinstance(payload, dict)
                            or payload.get("api_version") != "v1"
                            or payload.get("ok") is not True
                            or not isinstance(payload.get("data"), dict)
                            or expected_marker is None
                            or expected_marker not in body
                        ):
                            error = "unexpected-api-payload"
            elif target_kind == "health":
                try:
                    payload = json.loads(body)
                except UnicodeDecodeError, json.JSONDecodeError:
                    error = "invalid-json"
                else:
                    if (
                        not isinstance(payload, dict)
                        or set(payload) != HEALTH_FIELDS
                        or payload.get("status") != "ok"
                        or not isinstance(payload.get("version"), str)
                        or not isinstance(payload.get("maddy_version"), str)
                        or payload.get("maddy_write_enabled") is not True
                        or payload.get("storage_available") is not True
                        or not isinstance(payload.get("certbot_available"), bool)
                        or not isinstance(payload.get("certificate_management_enabled"), bool)
                    ):
                        error = "unexpected-payload"
            else:
                error = "invalid-target-kind"
    except urllib.error.HTTPError as exc:
        error = f"http-{exc.code}"
    except (OSError, urllib.error.URLError) as exc:
        error = type(exc).__name__
    return Result(time.perf_counter() - started, error)


def percentile(values: list[float], proportion: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * proportion) - 1)
    return ordered[index]


def assert_loopback_listener() -> None:
    try:
        result = subprocess.run(
            ["/usr/bin/ss", "-H", "-ltn", "sport = :8787"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        fail(f"cannot inspect listeners with ss: {exc}")
    listeners: list[str] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            fail(f"cannot parse ss output: {line!r}")
        listeners.append(fields[3])
    if not listeners:
        fail("no listener found on port 8787")
    if any(address != "127.0.0.1:8787" for address in listeners):
        fail(f"non-loopback or unexpected listener found: {listeners}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8787/healthz")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--timeout-seconds", type=float, default=3.0)
    parser.add_argument("--max-p95-ms", type=float, default=250.0)
    parser.add_argument("--warmup", type=int, default=5)
    args = parser.parse_args()

    parsed = urllib.parse.urlsplit(args.url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port != 8787
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        fail("URL must use the fixed http://127.0.0.1:8787 listener")
    target = (parsed.path, parsed.query)
    if target == ("/healthz", ""):
        target_kind = "health"
        expected_marker = None
    elif target in TARGETS:
        target_kind, expected_marker = TARGETS[target]
    else:
        fail("URL path and query are not a fixed performance target")
    if not 1 <= args.requests <= 100_000:
        fail("--requests must be in 1..100000")
    if not 1 <= args.concurrency <= 256 or args.concurrency > args.requests:
        fail("--concurrency must be in 1..256 and not exceed requests")
    if not 0.1 <= args.timeout_seconds <= 30:
        fail("--timeout-seconds must be in 0.1..30")
    if not 1 <= args.warmup <= 1000:
        fail("--warmup must be in 1..1000")
    if not 1 <= args.max_p95_ms <= 60_000:
        fail("--max-p95-ms must be in 1..60000")

    assert_loopback_listener()

    for _ in range(args.warmup):
        result = request_once(args.url, args.timeout_seconds, target_kind, expected_marker)
        if result.error:
            fail(f"warmup request failed: {result.error}")

    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        results = list(
            executor.map(
                lambda _: request_once(
                    args.url,
                    args.timeout_seconds,
                    target_kind,
                    expected_marker,
                ),
                range(args.requests),
            )
        )
    wall_seconds = time.perf_counter() - started
    errors = [result.error for result in results if result.error]
    latencies_ms = [result.seconds * 1000 for result in results]
    report = {
        "status": "ok" if not errors else "failed",
        "requests": len(results),
        "concurrency": args.concurrency,
        "errors": len(errors),
        "error_types": sorted(set(errors)),
        "mean_ms": round(statistics.fmean(latencies_ms), 3),
        "p50_ms": round(percentile(latencies_ms, 0.50), 3),
        "p95_ms": round(percentile(latencies_ms, 0.95), 3),
        "p99_ms": round(percentile(latencies_ms, 0.99), 3),
        "throughput_rps": round(len(results) / wall_seconds, 3),
    }
    print(json.dumps(report, sort_keys=True))
    if errors:
        fail(f"{len(errors)} request(s) failed")
    if report["p95_ms"] > args.max_p95_ms:
        fail(f"p95 {report['p95_ms']} ms exceeds {args.max_p95_ms} ms")


if __name__ == "__main__":
    main()
