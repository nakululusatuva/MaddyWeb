#!/usr/bin/env python3
"""Fail-closed validation for deployment-facing MaddyWeb configuration."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Never

SCHEMA: dict[str, set[str]] = {
    "server": {
        "listen",
        "allowed_hosts",
        "concurrency",
        "backlog",
        "keepalive_seconds",
        "request_body_timeout_seconds",
        "max_upload_bytes",
        "page_size",
        "temp_dir",
    },
    "maddy": {
        "mode",
        "container",
        "binary",
        "config_path",
        "data_dir",
        "service_user",
        "helper_socket",
        "submission_host",
        "submission_port",
        "command_timeout_seconds",
    },
    "certificates": {
        "enabled",
        "names",
        "certbot_binary",
        "openssl_binary",
        "nginx_binary",
        "renewal_dir",
        "live_dir",
        "timer_unit",
        "command_timeout_seconds",
        "deployed_cert_path",
        "deployed_key_path",
    },
    "security": {"session_key_file", "csrf_ttl_seconds", "cookie_name"},
    "logging": {"level"},
}
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SERVICE_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SYSTEMD_PATH_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_+.][A-Za-z0-9_.+-]*$")


def fail(message: str) -> Never:
    print(f"config validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def table(config: dict[str, Any], name: str) -> dict[str, Any]:
    value = config.get(name)
    if not isinstance(value, dict):
        fail(f"[{name}] must be a table")
    missing = SCHEMA[name] - value.keys()
    unknown = value.keys() - SCHEMA[name]
    if missing:
        fail(f"[{name}] is missing: {', '.join(sorted(missing))}")
    if unknown:
        fail(f"[{name}] has unknown keys: {', '.join(sorted(unknown))}")
    return value


def string(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        fail(f"{name} must be a {'possibly empty ' if allow_empty else 'non-empty '}string")
    return value


def integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        fail(f"{name} must be an integer in {minimum}..{maximum}")
    return value


def number(value: Any, name: str, minimum: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not minimum <= value <= maximum
    ):
        fail(f"{name} must be a number in {minimum}..{maximum}")
    return float(value)


def absolute(value: Any, name: str) -> str:
    result = string(value, name)
    path = PurePosixPath(result)
    if (
        not path.is_absolute()
        or result == "/"
        or str(path) != result
        or any(
            part in {".", ".."} or SYSTEMD_PATH_COMPONENT_RE.fullmatch(part) is None
            for part in path.parts[1:]
        )
    ):
        fail(f"{name} must be a safe canonical absolute POSIX/systemd path")
    return result


def string_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        fail(f"{name} must be a list of non-empty strings")
    return value


def validate(
    config: dict[str, Any],
    expected_host: str,
    expected_port: int,
    expected_maddy_mode: str | None,
    expected_container: str | None,
    expected_maddy_binary: str | None,
    expected_maddy_config: str | None,
    expected_maddy_data: str | None,
) -> None:
    unknown_tables = config.keys() - SCHEMA.keys()
    missing_tables = SCHEMA.keys() - config.keys()
    if missing_tables:
        fail(f"missing tables: {', '.join(sorted(missing_tables))}")
    if unknown_tables:
        fail(f"unknown top-level tables: {', '.join(sorted(unknown_tables))}")

    server = table(config, "server")
    listen = string(server["listen"], "server.listen")
    expected_listen = f"{expected_host}:{expected_port}"
    if listen != expected_listen:
        fail(f"server.listen must be exactly {expected_listen}")
    try:
        if not ipaddress.ip_address(expected_host).is_loopback:
            fail("the expected server address itself is not loopback")
    except ValueError:
        fail("expected host must be a literal loopback address")
    hosts = string_list(server["allowed_hosts"], "server.allowed_hosts")
    if not hosts or not set(hosts) <= {"127.0.0.1", "localhost"}:
        fail("server.allowed_hosts may contain only 127.0.0.1 and localhost")
    integer(server["concurrency"], "server.concurrency", 1, 64)
    integer(server["backlog"], "server.backlog", 1, 256)
    integer(server["keepalive_seconds"], "server.keepalive_seconds", 1, 30)
    number(
        server["request_body_timeout_seconds"],
        "server.request_body_timeout_seconds",
        1,
        120,
    )
    integer(server["max_upload_bytes"], "server.max_upload_bytes", 1024, 100 * 1024 * 1024)
    integer(server["page_size"], "server.page_size", 1, 200)
    absolute(server["temp_dir"], "server.temp_dir")

    maddy = table(config, "maddy")
    mode = string(maddy["mode"], "maddy.mode")
    if mode not in {"native", "docker"}:
        fail("maddy.mode must be native or docker")
    if expected_maddy_mode is not None and mode != expected_maddy_mode:
        fail(f"maddy.mode must be {expected_maddy_mode} for this deployment")
    container = string(maddy["container"], "maddy.container")
    if CONTAINER_RE.fullmatch(container) is None:
        fail("maddy.container is invalid")
    if expected_container is not None and container != expected_container:
        fail(f"maddy.container must be {expected_container}")
    binary = absolute(maddy["binary"], "maddy.binary")
    config_path = absolute(maddy["config_path"], "maddy.config_path")
    data_dir = absolute(maddy["data_dir"], "maddy.data_dir")
    expected_paths = (
        (binary, expected_maddy_binary, "maddy.binary"),
        (config_path, expected_maddy_config, "maddy.config_path"),
        (data_dir, expected_maddy_data, "maddy.data_dir"),
    )
    for actual, expected, label in expected_paths:
        if expected is not None and actual != expected:
            fail(f"{label} must exactly match the preflight path {expected}")
    service_user = string(maddy["service_user"], "maddy.service_user")
    if SERVICE_USER_RE.fullmatch(service_user) is None:
        fail("maddy.service_user is invalid")
    helper_socket = absolute(maddy["helper_socket"], "maddy.helper_socket")
    if helper_socket != "/run/maddyweb/helper.sock":
        fail("maddy.helper_socket must be /run/maddyweb/helper.sock")
    submission_host = string(maddy["submission_host"], "maddy.submission_host")
    try:
        if not ipaddress.ip_address(submission_host).is_loopback:
            fail("maddy.submission_host must be a literal loopback address")
    except ValueError:
        fail("maddy.submission_host must be a literal IP address")
    integer(maddy["submission_port"], "maddy.submission_port", 1, 65535)
    number(maddy["command_timeout_seconds"], "maddy.command_timeout_seconds", 1, 120)

    certificates = table(config, "certificates")
    if not isinstance(certificates["enabled"], bool):
        fail("certificates.enabled must be a boolean")
    names = string_list(certificates["names"], "certificates.names")
    for field in (
        "certbot_binary",
        "openssl_binary",
        "nginx_binary",
        "renewal_dir",
        "live_dir",
        "deployed_cert_path",
        "deployed_key_path",
    ):
        absolute(certificates[field], f"certificates.{field}")
    for field in ("deployed_cert_path", "deployed_key_path"):
        if PurePosixPath(str(certificates[field])).parent == PurePosixPath("/"):
            fail(f"certificates.{field} parent must not be the filesystem root")
    string(certificates["timer_unit"], "certificates.timer_unit")
    number(
        certificates["command_timeout_seconds"],
        "certificates.command_timeout_seconds",
        30,
        900,
    )
    if certificates["enabled"] and not names:
        fail("certificates.names cannot be empty when certificate support is enabled")

    security = table(config, "security")
    absolute(security["session_key_file"], "security.session_key_file")
    integer(security["csrf_ttl_seconds"], "security.csrf_ttl_seconds", 60, 3600)
    cookie = string(security["cookie_name"], "security.cookie_name")
    if not cookie.startswith("__Host-"):
        fail("security.cookie_name must use the __Host- prefix")

    logging = table(config, "logging")
    if string(logging["level"], "logging.level").upper() not in {
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
    }:
        fail("logging.level is invalid")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--expected-host", default="127.0.0.1")
    parser.add_argument("--expected-port", type=int, default=8787)
    parser.add_argument("--expected-maddy-mode", choices=("native", "docker"))
    parser.add_argument("--expected-container")
    parser.add_argument("--expected-maddy-binary")
    parser.add_argument("--expected-maddy-config")
    parser.add_argument("--expected-maddy-data")
    args = parser.parse_args()
    try:
        raw = args.config.read_bytes()
    except OSError as exc:
        fail(f"cannot read {args.config}: {exc}")
    try:
        config = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        fail(f"invalid UTF-8 TOML: {exc}")
    validate(
        config,
        args.expected_host,
        args.expected_port,
        args.expected_maddy_mode,
        args.expected_container,
        args.expected_maddy_binary,
        args.expected_maddy_config,
        args.expected_maddy_data,
    )
    print(f"config=ok path={args.config}")


if __name__ == "__main__":
    main()
