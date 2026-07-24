"""Strict TOML configuration for MaddyWeb.

Configuration is deliberately small and closed: unknown sections and keys are
errors.  A misspelled security setting must never silently fall back to a default.
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Self

_CONTAINER_RE = re.compile(r"\A[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")
_UNIT_RE = re.compile(r"\A[a-zA-Z0-9][a-zA-Z0-9_.@-]*\.timer\Z")
_CERT_RE = re.compile(r"\A[a-zA-Z0-9][a-zA-Z0-9_.-]{0,252}\Z")
_SECTIONS = {"server", "maddy", "certificates", "security", "logging"}
_DEFAULT_TEMP_DIR = PurePosixPath("/var/tmp/maddyweb")  # noqa: S108 - private state
_DEFAULT_MADDY_BINARY = PurePosixPath("/usr/bin/maddy")
_DEFAULT_MADDY_CONFIG = PurePosixPath("/data/maddy.conf")
_DEFAULT_MADDY_DATA = PurePosixPath("/data")
_NATIVE_MADDY_CONFIG = PurePosixPath("/etc/maddy/maddy.conf")
_NATIVE_MADDY_DATA = PurePosixPath("/var/lib/maddy")
_DEFAULT_HELPER_SOCKET = PurePosixPath("/run/maddyweb/helper.sock")
_DEFAULT_CERTBOT_BINARY = PurePosixPath("/usr/bin/certbot")
_DEFAULT_OPENSSL_BINARY = PurePosixPath("/usr/bin/openssl")
_DEFAULT_NGINX_BINARY = PurePosixPath("/usr/bin/nginx")
_DEFAULT_RENEWAL_DIR = PurePosixPath("/etc/letsencrypt/renewal")
_DEFAULT_LIVE_DIR = PurePosixPath("/etc/letsencrypt/live")
_CUSTOM_CERTBOT_CONFIG_ROOTS = (
    PurePosixPath("/var/lib/maddyweb/certbot"),
    PurePosixPath("/srv/maddyweb/certbot"),
)
_DEFAULT_DEPLOYED_CERT = PurePosixPath("/data/tls/fullchain.pem")
_DEFAULT_DEPLOYED_KEY = PurePosixPath("/data/tls/privkey.pem")
_NATIVE_DEPLOYED_CERT = PurePosixPath("/var/lib/maddy/tls/fullchain.pem")
_NATIVE_DEPLOYED_KEY = PurePosixPath("/var/lib/maddy/tls/privkey.pem")
_DEFAULT_SESSION_KEY = PurePosixPath("/var/lib/maddyweb/session.key")

DEFAULT_WEB_HOST = "127.0.0.1"
DEFAULT_WEB_PORT = 8787
DEFAULT_WEB_LISTEN = f"{DEFAULT_WEB_HOST}:{DEFAULT_WEB_PORT}"


class ConfigError(ValueError):
    """Raised when configuration is unsafe or malformed."""


def _closed(section: str, values: dict[str, Any], allowed: set[str]) -> None:
    unknown = set(values) - allowed
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ConfigError(f"unknown key(s) in [{section}]: {names}")


def _string(raw: dict[str, Any], key: str, default: str, qualified: str) -> str:
    value = raw.get(key, default)
    if not isinstance(value, str):
        raise ConfigError(f"{qualified} must be a string")
    return value


def _integer(raw: dict[str, Any], key: str, default: int, qualified: str) -> int:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{qualified} must be an integer")
    return value


def _number(raw: dict[str, Any], key: str, default: float, qualified: str) -> float:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigError(f"{qualified} must be a number")
    return float(value)


def _boolean(raw: dict[str, Any], key: str, default: bool, qualified: str) -> bool:
    value = raw.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{qualified} must be a boolean")
    return value


def _strings(
    raw: dict[str, Any],
    key: str,
    default: tuple[str, ...],
    qualified: str,
) -> tuple[str, ...]:
    value = raw.get(key, default)
    if not isinstance(value, list | tuple) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"{qualified} must be an array of strings")
    return tuple(value)


def _absolute(value: str, name: str) -> PurePosixPath:
    # Deployment paths are Linux paths even when configuration is validated by
    # a Windows development workstation.  ``WindowsPath('/var/lib/...')`` is
    # not considered absolute, so validate with POSIX semantics explicitly.
    if (
        not value
        or "\\" in value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ConfigError(f"{name} must be a safe absolute POSIX path")
    path = PurePosixPath(value)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ConfigError(f"{name} must be an absolute path")
    return path


@dataclass(frozen=True, slots=True)
class ServerConfig:
    listen: str = DEFAULT_WEB_LISTEN
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost")
    concurrency: int = 8
    backlog: int = 16
    keepalive_seconds: int = 5
    request_body_timeout_seconds: float = 15.0
    max_upload_bytes: int = 20 * 1024 * 1024
    page_size: int = 50
    temp_dir: PurePosixPath = _DEFAULT_TEMP_DIR

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Self:
        defaults = cls()
        allowed = {
            "listen",
            "allowed_hosts",
            "concurrency",
            "backlog",
            "keepalive_seconds",
            "request_body_timeout_seconds",
            "max_upload_bytes",
            "page_size",
            "temp_dir",
        }
        _closed("server", raw, allowed)
        try:
            listen = _string(raw, "listen", defaults.listen, "server.listen")
            host, port_text = listen.rsplit(":", 1)
            port = int(port_text)
            address = ipaddress.ip_address(host)
        except (ValueError, TypeError) as exc:
            raise ConfigError("server.listen must be an IPv4 address and port") from exc
        if str(address) != DEFAULT_WEB_HOST:
            raise ConfigError(f"server.listen must use exactly {DEFAULT_WEB_HOST}")
        if not 1 <= port <= 65535:
            raise ConfigError("server.listen port is out of range")
        hosts = tuple(
            item.lower()
            for item in _strings(
                raw,
                "allowed_hosts",
                defaults.allowed_hosts,
                "server.allowed_hosts",
            )
        )
        if not hosts or not set(hosts) <= {"127.0.0.1", "localhost"}:
            raise ConfigError("server.allowed_hosts may contain only 127.0.0.1 and localhost")
        concurrency = _integer(raw, "concurrency", defaults.concurrency, "server.concurrency")
        backlog = _integer(raw, "backlog", defaults.backlog, "server.backlog")
        keepalive = _integer(
            raw,
            "keepalive_seconds",
            defaults.keepalive_seconds,
            "server.keepalive_seconds",
        )
        request_body_timeout = _number(
            raw,
            "request_body_timeout_seconds",
            defaults.request_body_timeout_seconds,
            "server.request_body_timeout_seconds",
        )
        max_upload = _integer(
            raw,
            "max_upload_bytes",
            defaults.max_upload_bytes,
            "server.max_upload_bytes",
        )
        page_size = _integer(raw, "page_size", defaults.page_size, "server.page_size")
        if not 1 <= concurrency <= 64:
            raise ConfigError("server.concurrency must be between 1 and 64")
        if not 1 <= backlog <= 256:
            raise ConfigError("server.backlog must be between 1 and 256")
        if not 1 <= keepalive <= 30:
            raise ConfigError("server.keepalive_seconds must be between 1 and 30")
        if not 1.0 <= request_body_timeout <= 120.0:
            raise ConfigError("server.request_body_timeout_seconds must be between 1 and 120")
        if not 1024 <= max_upload <= 100 * 1024 * 1024:
            raise ConfigError("server.max_upload_bytes must be between 1 KiB and 100 MiB")
        if not 1 <= page_size <= 200:
            raise ConfigError("server.page_size must be between 1 and 200")
        return cls(
            listen=f"{DEFAULT_WEB_HOST}:{port}",
            allowed_hosts=hosts,
            concurrency=concurrency,
            backlog=backlog,
            keepalive_seconds=keepalive,
            request_body_timeout_seconds=request_body_timeout,
            max_upload_bytes=max_upload,
            page_size=page_size,
            temp_dir=_absolute(
                _string(raw, "temp_dir", str(defaults.temp_dir), "server.temp_dir"),
                "server.temp_dir",
            ),
        )

    @property
    def host_port(self) -> tuple[str, int]:
        host, port = self.listen.rsplit(":", 1)
        return host, int(port)


@dataclass(frozen=True, slots=True)
class MaddyConfig:
    mode: Literal["docker", "native"] = "docker"
    docker_submission_scope: Literal["container", "host-loopback"] = "container"
    container: str = "maddy"
    binary: PurePosixPath = _DEFAULT_MADDY_BINARY
    config_path: PurePosixPath = _DEFAULT_MADDY_CONFIG
    data_dir: PurePosixPath = _DEFAULT_MADDY_DATA
    service_user: str = "maddy"
    helper_socket: PurePosixPath = _DEFAULT_HELPER_SOCKET
    submission_host: str = "127.0.0.1"
    submission_port: int = 1587
    command_timeout_seconds: float = 15.0

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Self:
        defaults = cls()
        allowed = {
            "mode",
            "docker_submission_scope",
            "container",
            "binary",
            "config_path",
            "data_dir",
            "service_user",
            "helper_socket",
            "submission_host",
            "submission_port",
            "command_timeout_seconds",
        }
        _closed("maddy", raw, allowed)
        if "mode" not in raw:
            raise ConfigError("maddy.mode must be explicitly configured")
        mode = _string(raw, "mode", defaults.mode, "maddy.mode")
        if mode not in {"docker", "native"}:
            raise ConfigError("maddy.mode must be docker or native")
        docker_submission_scope = _string(
            raw,
            "docker_submission_scope",
            defaults.docker_submission_scope,
            "maddy.docker_submission_scope",
        )
        if docker_submission_scope not in {"container", "host-loopback"}:
            raise ConfigError("maddy.docker_submission_scope must be container or host-loopback")
        if mode == "native" and docker_submission_scope == "host-loopback":
            raise ConfigError(
                "maddy.docker_submission_scope cannot be host-loopback when maddy.mode is native"
            )
        default_config_path = _DEFAULT_MADDY_CONFIG if mode == "docker" else _NATIVE_MADDY_CONFIG
        default_data_dir = _DEFAULT_MADDY_DATA if mode == "docker" else _NATIVE_MADDY_DATA
        container = _string(raw, "container", defaults.container, "maddy.container")
        if not _CONTAINER_RE.fullmatch(container):
            raise ConfigError("maddy.container is invalid")
        service_user = _string(
            raw,
            "service_user",
            defaults.service_user,
            "maddy.service_user",
        )
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", service_user):
            raise ConfigError("maddy.service_user is invalid")
        host = _string(
            raw,
            "submission_host",
            defaults.submission_host,
            "maddy.submission_host",
        )
        if host != "127.0.0.1":
            raise ConfigError("maddy.submission_host must use exactly 127.0.0.1")
        port = _integer(
            raw,
            "submission_port",
            defaults.submission_port,
            "maddy.submission_port",
        )
        timeout = _number(
            raw,
            "command_timeout_seconds",
            defaults.command_timeout_seconds,
            "maddy.command_timeout_seconds",
        )
        if port != 1587:
            raise ConfigError("maddy.submission_port must use exactly 1587")
        if not 1.0 <= timeout <= 120.0:
            raise ConfigError("maddy.command_timeout_seconds must be between 1 and 120")
        return cls(
            mode=mode,  # type: ignore[arg-type]
            docker_submission_scope=docker_submission_scope,  # type: ignore[arg-type]
            container=container,
            binary=_absolute(
                _string(raw, "binary", str(defaults.binary), "maddy.binary"),
                "maddy.binary",
            ),
            config_path=_absolute(
                _string(
                    raw,
                    "config_path",
                    str(default_config_path),
                    "maddy.config_path",
                ),
                "maddy.config_path",
            ),
            data_dir=_absolute(
                _string(raw, "data_dir", str(default_data_dir), "maddy.data_dir"),
                "maddy.data_dir",
            ),
            service_user=service_user,
            helper_socket=_absolute(
                _string(
                    raw,
                    "helper_socket",
                    str(defaults.helper_socket),
                    "maddy.helper_socket",
                ),
                "maddy.helper_socket",
            ),
            submission_host=host,
            submission_port=port,
            command_timeout_seconds=timeout,
        )


@dataclass(frozen=True, slots=True)
class CertificateConfig:
    enabled: bool = False
    names: tuple[str, ...] = ()
    certbot_binary: PurePosixPath = _DEFAULT_CERTBOT_BINARY
    openssl_binary: PurePosixPath = _DEFAULT_OPENSSL_BINARY
    nginx_binary: PurePosixPath = _DEFAULT_NGINX_BINARY
    renewal_dir: PurePosixPath = _DEFAULT_RENEWAL_DIR
    webroot_roots: tuple[PurePosixPath, ...] = ()
    live_dir: PurePosixPath = _DEFAULT_LIVE_DIR
    timer_unit: str = "certbot-renew.timer"
    deployed_cert_path: PurePosixPath = _DEFAULT_DEPLOYED_CERT
    deployed_key_path: PurePosixPath = _DEFAULT_DEPLOYED_KEY
    command_timeout_seconds: float = 300.0

    @classmethod
    def from_dict(
        cls,
        raw: dict[str, Any],
        *,
        maddy_mode: Literal["docker", "native"],
    ) -> Self:
        defaults = cls()
        default_deployed_cert = (
            _DEFAULT_DEPLOYED_CERT if maddy_mode == "docker" else _NATIVE_DEPLOYED_CERT
        )
        default_deployed_key = (
            _DEFAULT_DEPLOYED_KEY if maddy_mode == "docker" else _NATIVE_DEPLOYED_KEY
        )
        allowed = {
            "enabled",
            "names",
            "certbot_binary",
            "openssl_binary",
            "nginx_binary",
            "renewal_dir",
            "webroot_roots",
            "live_dir",
            "timer_unit",
            "deployed_cert_path",
            "deployed_key_path",
            "command_timeout_seconds",
        }
        _closed("certificates", raw, allowed)
        enabled = _boolean(raw, "enabled", defaults.enabled, "certificates.enabled")
        names = _strings(raw, "names", defaults.names, "certificates.names")
        if any(not _CERT_RE.fullmatch(item) for item in names):
            raise ConfigError("certificates.names contains an invalid certificate name")
        if enabled and not names:
            raise ConfigError(
                "certificates.names cannot be empty when certificate support is enabled"
            )
        timer = _string(raw, "timer_unit", defaults.timer_unit, "certificates.timer_unit")
        if not _UNIT_RE.fullmatch(timer):
            raise ConfigError("certificates.timer_unit is invalid")
        command_timeout = _number(
            raw,
            "command_timeout_seconds",
            defaults.command_timeout_seconds,
            "certificates.command_timeout_seconds",
        )
        if not 30.0 <= command_timeout <= 900.0:
            raise ConfigError("certificates.command_timeout_seconds must be between 30 and 900")
        webroot_roots = tuple(
            _absolute(value, "certificates.webroot_roots")
            for value in _strings(
                raw,
                "webroot_roots",
                (),
                "certificates.webroot_roots",
            )
        )
        if len(set(webroot_roots)) != len(webroot_roots):
            raise ConfigError("certificates.webroot_roots contains duplicates")
        permitted_webroot_roots = (PurePosixPath("/var/www"), PurePosixPath("/srv/www"))
        if any(
            not any(
                root == allowed or root.is_relative_to(allowed)
                for allowed in permitted_webroot_roots
            )
            for root in webroot_roots
        ):
            raise ConfigError("certificates.webroot_roots must stay below /var/www or /srv/www")
        renewal_dir = _absolute(
            _string(
                raw,
                "renewal_dir",
                str(defaults.renewal_dir),
                "certificates.renewal_dir",
            ),
            "certificates.renewal_dir",
        )
        if renewal_dir.name != "renewal":
            raise ConfigError("certificates.renewal_dir must end with /renewal")
        config_root = renewal_dir.parent
        if config_root != _DEFAULT_RENEWAL_DIR.parent and not any(
            config_root == allowed or config_root.is_relative_to(allowed)
            for allowed in _CUSTOM_CERTBOT_CONFIG_ROOTS
        ):
            raise ConfigError("certificates.renewal_dir uses a forbidden config root")
        live_dir = _absolute(
            _string(
                raw,
                "live_dir",
                str(defaults.live_dir),
                "certificates.live_dir",
            ),
            "certificates.live_dir",
        )
        if live_dir != renewal_dir.parent / "live":
            raise ConfigError("certificates.live_dir must be the config root live directory")
        return cls(
            enabled=enabled,
            names=names,
            certbot_binary=_absolute(
                _string(
                    raw,
                    "certbot_binary",
                    str(defaults.certbot_binary),
                    "certificates.certbot_binary",
                ),
                "certificates.certbot_binary",
            ),
            openssl_binary=_absolute(
                _string(
                    raw,
                    "openssl_binary",
                    str(defaults.openssl_binary),
                    "certificates.openssl_binary",
                ),
                "certificates.openssl_binary",
            ),
            nginx_binary=_absolute(
                _string(
                    raw,
                    "nginx_binary",
                    str(defaults.nginx_binary),
                    "certificates.nginx_binary",
                ),
                "certificates.nginx_binary",
            ),
            renewal_dir=renewal_dir,
            webroot_roots=webroot_roots,
            live_dir=live_dir,
            timer_unit=timer,
            deployed_cert_path=_absolute(
                _string(
                    raw,
                    "deployed_cert_path",
                    str(default_deployed_cert),
                    "certificates.deployed_cert_path",
                ),
                "certificates.deployed_cert_path",
            ),
            deployed_key_path=_absolute(
                _string(
                    raw,
                    "deployed_key_path",
                    str(default_deployed_key),
                    "certificates.deployed_key_path",
                ),
                "certificates.deployed_key_path",
            ),
            command_timeout_seconds=command_timeout,
        )


@dataclass(frozen=True, slots=True)
class SecurityConfig:
    session_key_file: PurePosixPath = _DEFAULT_SESSION_KEY
    csrf_ttl_seconds: int = 900
    cookie_name: str = "__Host-maddyweb"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Self:
        defaults = cls()
        allowed = {"session_key_file", "csrf_ttl_seconds", "cookie_name"}
        _closed("security", raw, allowed)
        ttl = _integer(
            raw,
            "csrf_ttl_seconds",
            defaults.csrf_ttl_seconds,
            "security.csrf_ttl_seconds",
        )
        if not 60 <= ttl <= 3600:
            raise ConfigError("security.csrf_ttl_seconds must be between 60 and 3600")
        cookie = _string(raw, "cookie_name", defaults.cookie_name, "security.cookie_name")
        if not cookie.startswith("__Host-") or not re.fullmatch(
            r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}", cookie
        ):
            raise ConfigError("security.cookie_name is invalid")
        return cls(
            session_key_file=_absolute(
                _string(
                    raw,
                    "session_key_file",
                    str(defaults.session_key_file),
                    "security.session_key_file",
                ),
                "security.session_key_file",
            ),
            csrf_ttl_seconds=ttl,
            cookie_name=cookie,
        )


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Self:
        defaults = cls()
        _closed("logging", raw, {"level"})
        level = _string(raw, "level", defaults.level, "logging.level").upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
            raise ConfigError("logging.level is invalid")
        return cls(level=level)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class AppConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    maddy: MaddyConfig = field(default_factory=MaddyConfig)
    certificates: CertificateConfig = field(default_factory=CertificateConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Self:
        unknown = set(raw) - _SECTIONS
        if unknown:
            raise ConfigError(f"unknown section(s): {', '.join(sorted(unknown))}")
        for name, value in raw.items():
            if not isinstance(value, dict):
                raise ConfigError(f"[{name}] must be a table")
        if "maddy" not in raw:
            raise ConfigError("[maddy] with an explicit mode is required")
        maddy = MaddyConfig.from_dict(raw["maddy"])
        certificates = CertificateConfig.from_dict(
            raw.get("certificates", {}),
            maddy_mode=maddy.mode,
        )
        if certificates.enabled and maddy.mode == "docker":
            for name, path in (
                ("certificates.deployed_cert_path", certificates.deployed_cert_path),
                ("certificates.deployed_key_path", certificates.deployed_key_path),
            ):
                if not path.is_relative_to(maddy.data_dir):
                    raise ConfigError(f"{name} must be inside maddy.data_dir in Docker mode")
        return cls(
            server=ServerConfig.from_dict(raw.get("server", {})),
            maddy=maddy,
            certificates=certificates,
            security=SecurityConfig.from_dict(raw.get("security", {})),
            logging=LoggingConfig.from_dict(raw.get("logging", {})),
        )


def load_config(path: str | Path) -> AppConfig:
    """Read and strictly validate a TOML configuration file."""
    config_path = Path(path)
    try:
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot load configuration: {exc}") from exc
    return AppConfig.from_dict(raw)
