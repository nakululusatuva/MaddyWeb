"""Command-line entry points for the unprivileged Web and root helper units."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import socket
import stat
import sys
import sysconfig
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Never

from aiohttp import web

from . import __version__
from .config import AppConfig, ConfigError, load_config
from .gateway import HelperGateway
from .web import create_app

LOGGER = logging.getLogger(__name__)
_SYSTEMD_FD_START = 3
_MAX_REQUESTS_PER_ACTIVATION = 64
_HELPER_SPOOL_DIRECTORY = Path("/run/maddyweb/helper-tmp")


def _service_account(name: str) -> Any:
    try:
        import pwd
    except ImportError as exc:
        raise RuntimeError("service-account lookup is unavailable on this platform") from exc
    try:
        return pwd.getpwnam(name)
    except KeyError as exc:
        raise RuntimeError(f"configured service account does not exist: {name}") from exc


class _DisabledCertificateManager:
    """Fail closed if a compromised Web asks for disabled certificate writes."""

    @staticmethod
    def list_certificates() -> list[object]:
        return []

    @staticmethod
    def health() -> dict[str, bool]:
        return {
            "certbot_available": False,
            "timer_enabled": False,
            "timer_active": False,
            "source_readable": False,
            "deployed_matches_source": False,
        }

    @staticmethod
    def _denied(*_args: object, **_kwargs: object) -> Never:
        from .certificates import CertificateCommandError

        raise CertificateCommandError("certificate management is disabled")

    status = _denied
    set_timer_enabled = _denied
    dry_run = _denied
    renew = _denied


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _validate_python_runtime() -> None:
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14):
        raise RuntimeError("MaddyWeb requires CPython 3.14")
    is_gil_enabled = getattr(sys, "_is_gil_enabled", None)
    if not callable(is_gil_enabled):
        raise RuntimeError("CPython runtime does not expose GIL state")
    free_threaded = bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
    if free_threaded and os.environ.get("PYTHON_GIL") == "0" and is_gil_enabled():
        raise RuntimeError("a module unexpectedly enabled the GIL in the 3.14t GIL-off lane")


def _private_helper_spool_directory() -> Path:
    # Never share a root helper spool with the unprivileged Web process.  In
    # particular, Docker ``cp`` consumes host pathnames and would otherwise
    # create a substitution race in a Web-owned directory.
    directory = _HELPER_SPOOL_DIRECTORY
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or directory.is_symlink():
        raise RuntimeError("configured helper spool is not a regular directory")
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RuntimeError("configured helper spool permissions are too broad")
    return directory


def _certificate_manager(
    config: AppConfig,
    runner: Any,
    maddy: Any,
    spool_dir: Path,
) -> Any:
    from .certificates import CertificateManager

    if not config.certificates.enabled:
        return _DisabledCertificateManager()

    deploy_callback = None
    status_callback = None
    if config.maddy.mode == "docker":
        from .docker_certificates import DockerCertificateAdapter

        adapter = DockerCertificateAdapter.from_config(
            config.maddy,
            config.certificates,
            runner=runner,
            spool_dir=spool_dir,
            timeout=config.certificates.command_timeout_seconds,
        )
        deploy_callback = adapter.deploy
        status_callback = adapter.status

    owner_uid: int | None = None
    owner_gid: int | None = None
    if config.maddy.mode == "native":
        service_account = _service_account(config.maddy.service_user)
        owner_uid = service_account.pw_uid
        owner_gid = service_account.pw_gid

    return CertificateManager.from_config(
        config.certificates,
        runner=runner,
        reload_callback=maddy.reload,
        deploy_callback=deploy_callback,
        deployed_status_callback=status_callback,
        deployment_mode=config.maddy.mode,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        command_timeout=config.certificates.command_timeout_seconds,
    )


def _dispatcher(config: AppConfig) -> Any:
    from .helper import PrivilegedDispatcher, SMTPSubmissionClient
    from .maddy import MaddyService, SubprocessRunner

    spool_dir = _private_helper_spool_directory()
    runner = SubprocessRunner()
    maddy = MaddyService.from_config(config.maddy, runner=runner)
    certificates = _certificate_manager(config, runner, maddy, spool_dir)
    smtp = SMTPSubmissionClient.from_config(config.maddy)
    return PrivilegedDispatcher(
        maddy,
        certificates,
        spool_dir=spool_dir,
        smtp=smtp,
    )


def _activated_socket(expected_path: Path) -> socket.socket:
    try:
        listen_pid = int(os.environ.pop("LISTEN_PID"))
        listen_fds = int(os.environ.pop("LISTEN_FDS"))
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("helper requires one systemd-activated socket") from exc
    descriptor_names = os.environ.pop("LISTEN_FDNAMES", "")
    if listen_pid != os.getpid() or listen_fds != 1:
        raise RuntimeError("helper received an invalid systemd socket set")
    if descriptor_names not in {"", "helper"}:
        raise RuntimeError("helper received an unexpected socket descriptor name")
    listener = socket.socket(fileno=_SYSTEMD_FD_START)
    try:
        if listener.family != socket.AF_UNIX:
            raise RuntimeError("helper activation socket is not AF_UNIX")
        if listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
            raise RuntimeError("helper activation socket is not SOCK_STREAM")
        actual = listener.getsockname()
        if isinstance(actual, bytes):
            actual = os.fsdecode(actual)
        if not isinstance(actual, str) or Path(actual) != expected_path:
            raise RuntimeError("helper activation socket path does not match configuration")
        if listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1:
            raise RuntimeError("helper activation descriptor is not listening")
        return listener
    except BaseException:
        listener.close()
        raise


def _run_helper(config: AppConfig) -> None:
    from .helper import UnixHelperServer

    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("the privileged helper must run as root")
    peer_uid = _service_account("maddyweb").pw_uid
    listener = _activated_socket(Path(config.maddy.helper_socket))
    server = UnixHelperServer(
        _dispatcher(config),
        socket_timeout=max(config.maddy.command_timeout_seconds + 5.0, 30.0),
        allowed_peer_uid=peer_uid,
    )
    served = 0
    try:
        while served < _MAX_REQUESTS_PER_ACTIVATION:
            if served:
                listener.settimeout(0.25)
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                break
            with connection:
                server.serve_connection(connection)
            served += 1
    finally:
        listener.close()


def _run_web(config: AppConfig, *, allow_root_development: bool) -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0 and not allow_root_development:
        raise RuntimeError("the Web process refuses to run as root")
    gateway = HelperGateway(config)
    app = create_app(config, gateway)

    async def startup_probe(_app: web.Application) -> None:
        status = await gateway.health()
        LOGGER.info(
            "startup probe status=%s maddy=%s writes=%s certificates=%s",
            status.get("status"),
            status.get("maddy_version"),
            status.get("maddy_write_enabled"),
            status.get("certificate_management_enabled"),
        )

    app.on_startup.append(startup_probe)
    host, port = config.server.host_port
    web.run_app(
        app,
        host=host,
        port=port,
        backlog=config.server.backlog,
        keepalive_timeout=float(config.server.keepalive_seconds),
        shutdown_timeout=5.0,
        access_log=None,
        print=None,
        reuse_port=False,
        handler_cancellation=True,
    )


def _load(path: Path) -> AppConfig:
    config = load_config(path)
    _configure_logging(config.logging.level)
    return config


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="maddyweb",
        description="Loopback-only Maddy administration service",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate-config", help="validate TOML and exit")
    validate.add_argument("--config", type=Path, required=True)

    diagnose = subparsers.add_parser("diagnose", help="print a non-sensitive readiness result")
    diagnose.add_argument("--config", type=Path, required=True)

    serve = subparsers.add_parser("serve", help="run the unprivileged loopback Web service")
    serve.add_argument("--config", type=Path, required=True)
    serve.add_argument(
        "--allow-root-development",
        action="store_true",
        help="allow root only for an isolated local development fixture",
    )

    helper = subparsers.add_parser("helper", help="serve the systemd-activated root helper")
    helper.add_argument("--config", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    try:
        _validate_python_runtime()
        arguments = _parser().parse_args(argv)
        config = _load(arguments.config)
        if arguments.command == "validate-config":
            print("config=ok")
        elif arguments.command == "diagnose":
            print(
                json.dumps(
                    asyncio.run(HelperGateway(config).health()),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        elif arguments.command == "serve":
            _run_web(
                config,
                allow_root_development=bool(arguments.allow_root_development),
            )
        elif arguments.command == "helper":
            _run_helper(config)
        else:  # pragma: no cover - argparse enforces the closed command set.
            raise RuntimeError("unsupported command")
    except (ConfigError, OSError, RuntimeError) as exc:
        LOGGER.error("%s", exc)
        raise SystemExit(2) from exc


__all__ = ["main"]
