#!/usr/bin/env python3
"""Strict local production smoke gate; performs no authenticated mutation."""

from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Never

HEALTH_FIELDS = {
    "status",
    "version",
    "maddy_version",
    "maddy_write_enabled",
    "storage_available",
    "certbot_available",
    "certificate_management_enabled",
}
VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def fail(message: str) -> Never:
    print(f"smoke test failed: {message}", file=sys.stderr)
    raise SystemExit(1)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def assert_loopback_listener(timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail("no listener found on port 8787")
        try:
            result = subprocess.run(
                ["/usr/bin/ss", "-H", "-ltn", "sport = :8787"],
                check=True,
                capture_output=True,
                text=True,
                timeout=min(5.0, remaining),
            )
        except (FileNotFoundError, subprocess.SubprocessError) as exc:
            fail(f"cannot inspect listeners with ss: {exc}")
        listeners = []
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4:
                fail(f"cannot parse ss output: {line!r}")
            listeners.append(fields[3])
        if any(listener != "127.0.0.1:8787" for listener in listeners):
            fail(f"listener policy violation: {listeners}")
        if listeners:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail("no listener found on port 8787")
        time.sleep(min(0.1, remaining))


def assert_helper_socket(path: Path, timeout: float) -> None:
    if path != Path("/run/maddyweb/helper.sock"):
        fail("helper socket path must be /run/maddyweb/helper.sock")
    try:
        stat_result = path.lstat()
    except OSError as exc:
        fail(f"cannot inspect helper socket: {exc}")
    if not path.is_socket():
        fail("helper endpoint is not a Unix socket")
    if stat_result.st_mode & 0o007:
        fail("helper socket grants access to other users")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(str(path))
    except OSError as exc:
        fail(f"helper socket is not reachable: {exc}")
    finally:
        client.close()


def get_health(url: str, timeout: float) -> dict[str, Any]:
    # main() accepts only the exact loopback HTTP health URL.
    request = urllib.request.Request(  # noqa: S310
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "maddyweb-local-smoke/1"},
    )
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(4097)
            if response.status != 200:
                fail(f"health endpoint returned HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        fail(f"health endpoint returned HTTP {exc.code}")
    except (OSError, urllib.error.URLError) as exc:
        fail(f"health request failed: {exc}")
    if len(body) > 4096:
        fail("health response exceeded 4096 bytes")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"health endpoint returned invalid JSON: {exc}")
    if not isinstance(payload, dict) or set(payload) != HEALTH_FIELDS:
        fail("health payload fields do not match the public contract")
    return payload


def assert_health(payload: dict[str, Any], expected_app_version: str | None) -> None:
    if payload["status"] != "ok":
        fail(f"health status is {payload['status']!r}, expected 'ok'")
    if not isinstance(payload["version"], str) or not payload["version"]:
        fail("application version is missing")
    if expected_app_version is not None and payload["version"] != expected_app_version:
        fail(f"application version is {payload['version']!r}, expected {expected_app_version!r}")
    if payload["maddy_write_enabled"] is not True:
        fail("Maddy write capability is not enabled")
    if payload["storage_available"] is not True:
        fail("Maddy storage is not available")
    if not isinstance(payload["certbot_available"], bool):
        fail("Certbot availability is not a boolean")
    if not isinstance(payload["certificate_management_enabled"], bool):
        fail("certificate capability is not a boolean")
    if not isinstance(payload["maddy_version"], str):
        fail("Maddy version is missing")
    match = VERSION_RE.fullmatch(payload["maddy_version"])
    if match is None:
        fail("Maddy version is not strict SemVer")
    version = tuple(map(int, match.groups()))
    if not (version >= (0, 8, 2) and version <= (0, 9, 5)):
        fail(f"unsupported Maddy version: {payload['maddy_version']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8787/healthz")
    parser.add_argument("--helper-socket", type=Path, default=Path("/run/maddyweb/helper.sock"))
    parser.add_argument("--timeout-seconds", type=float, default=3.0)
    parser.add_argument("--startup-timeout-seconds", type=float, default=20.0)
    parser.add_argument("--expected-app-version")
    args = parser.parse_args()

    parsed = urllib.parse.urlsplit(args.url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port != 8787
        or parsed.path != "/healthz"
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        fail("URL must be exactly http://127.0.0.1:8787/healthz")
    if not 0.1 <= args.timeout_seconds <= 30:
        fail("--timeout-seconds must be in 0.1..30")
    if not 0.1 <= args.startup_timeout_seconds <= 30:
        fail("--startup-timeout-seconds must be in 0.1..30")

    assert_loopback_listener(args.startup_timeout_seconds)
    assert_helper_socket(args.helper_socket, args.timeout_seconds)
    payload = get_health(args.url, args.timeout_seconds)
    assert_health(payload, args.expected_app_version)
    print(json.dumps({"status": "ok", "health": payload}, sort_keys=True))


if __name__ == "__main__":
    main()
