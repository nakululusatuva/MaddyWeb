"""Command-line entry points for the unprivileged Web and root helper units."""

from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import logging
import os
import re
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
_HELPER_IDLE_SECONDS = 5.0
_HELPER_SPOOL_DIRECTORY = Path("/run/maddyweb/helper-tmp")
_AUTH_DATABASE_NAME = "auth.sqlite3"
_AUTH_MASTER_KEY_NAME = "master.key"
_AUTH_BOOTSTRAP_MAX_BYTES = 1024 * 1024


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


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


def _private_auth_directory(config: AppConfig) -> Path:
    directory = Path(config.security.auth_state_dir)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = directory.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or directory.is_symlink()
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise RuntimeError("authentication state directory must be root-owned mode 0700")
    return directory


def _auth_master_key(directory: Path) -> bytes:
    path = directory / _AUTH_MASTER_KEY_NAME
    flags = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, os.O_RDONLY | flags)
    except FileNotFoundError:
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | flags,
                0o600,
            )
        except FileExistsError:
            descriptor = os.open(path, os.O_RDONLY | flags)
        else:
            try:
                key = os.urandom(32)
                if os.write(descriptor, key) != len(key):
                    raise RuntimeError("authentication master key write was incomplete")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            directory_flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            directory_descriptor = os.open(directory, directory_flags)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
            descriptor = os.open(path, os.O_RDONLY | flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != 32
        ):
            raise RuntimeError(
                "authentication master key must be root-owned mode 0600 with one link"
            )
        key = os.read(descriptor, 33)
    finally:
        os.close(descriptor)
    if len(key) != 32:
        raise RuntimeError("authentication master key must contain exactly 32 bytes")
    return key


def _auth_store(config: AppConfig) -> Any:
    from .auth import AuthStore

    directory = _private_auth_directory(config)
    store = AuthStore(
        directory / _AUTH_DATABASE_NAME,
        _auth_master_key(directory),
        config.security.totp_issuer,
    )
    _validate_python_runtime()
    return store


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
        auth_store=_auth_store(config),
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
    dispatcher = _dispatcher(config)
    server = UnixHelperServer(
        dispatcher,
        socket_timeout=max(config.maddy.command_timeout_seconds + 5.0, 30.0),
        allowed_peer_uid=peer_uid,
    )
    served = 0
    try:
        while served < _MAX_REQUESTS_PER_ACTIVATION:
            if served:
                # Keep one initialized helper warm for a short interactive burst.
                # It still exits after the bounded idle window while mailbox requests
                # avoid repeated capability probes and authentication database setup.
                listener.settimeout(_HELPER_IDLE_SECONDS)
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                break
            with connection:
                server.serve_connection(connection)
            served += 1
    finally:
        listener.close()
        dispatcher.close()


def _read_bootstrap_document() -> list[dict[str, Any]]:
    content = bytearray(sys.stdin.buffer.read(_AUTH_BOOTSTRAP_MAX_BYTES + 1))
    try:
        if not content or len(content) > _AUTH_BOOTSTRAP_MAX_BYTES:
            raise RuntimeError("authentication bootstrap input is empty or too large")
        try:
            document = json.loads(
                bytes(content),
                object_pairs_hook=_unique_json_object,
            )
        except (UnicodeError, ValueError) as exc:
            raise RuntimeError("authentication bootstrap input is invalid JSON") from exc
    finally:
        content[:] = b"\0" * len(content)
        content.clear()
    if not isinstance(document, dict) or set(document) != {"accounts"}:
        raise RuntimeError("authentication bootstrap document must contain only accounts")
    accounts = document["accounts"]
    if (
        not isinstance(accounts, list)
        or not accounts
        or len(accounts) > 1000
        or any(not isinstance(value, dict) for value in accounts)
    ):
        raise RuntimeError("authentication bootstrap accounts list is invalid")
    return accounts


def _validated_bootstrap_records(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from .auth import Role, canonicalize_email, decode_totp_secret

    allowed = {
        "email",
        "role",
        "totp_secret",
        "recovery_codes",
        "password_change_required",
        "create_account",
        "initial_password",
    }
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in values:
        if set(value) - allowed or {
            "email",
            "role",
            "totp_secret",
            "recovery_codes",
            "password_change_required",
            "create_account",
        } - set(value):
            raise RuntimeError("authentication bootstrap account fields are invalid")
        try:
            email = canonicalize_email(value["email"])
            role = Role(value["role"])
            decode_totp_secret(value["totp_secret"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authentication bootstrap identity is invalid") from exc
        recovery_codes = value["recovery_codes"]
        if not isinstance(recovery_codes, list) or len(recovery_codes) != 10:
            raise RuntimeError("authentication bootstrap recovery codes are invalid")
        if any(
            not isinstance(code, str)
            or re.fullmatch(r"[0-9a-f]{32}", code.replace("-", "").lower()) is None
            for code in recovery_codes
        ):
            raise RuntimeError("authentication bootstrap recovery codes are invalid")
        if len(set(recovery_codes)) != 10:
            raise RuntimeError("authentication bootstrap recovery codes are invalid")
        required = value["password_change_required"]
        create_account = value["create_account"]
        if not isinstance(required, bool) or not isinstance(create_account, bool):
            raise RuntimeError("authentication bootstrap flags must be booleans")
        password = value.get("initial_password", "")
        if not isinstance(password, str) or any(char in password for char in "\r\n\0"):
            raise RuntimeError("authentication bootstrap initial password is invalid")
        if create_account and not 16 <= len(password) <= 256:
            raise RuntimeError("new bootstrap account password must contain 16 to 256 characters")
        if not create_account and password:
            raise RuntimeError("existing bootstrap accounts must not carry a password")
        if email in seen:
            raise RuntimeError("authentication bootstrap contains a duplicate account")
        seen.add(email)
        records.append(
            {
                "email": email,
                "role": role,
                "totp_secret": value["totp_secret"],
                "recovery_codes": tuple(recovery_codes),
                "password_change_required": required,
                "create_account": create_account,
                "initial_password": password,
            }
        )
    return records


def _run_auth_bootstrap(config: AppConfig) -> None:
    from .auth import AccountBootstrap
    from .helper import SMTPSubmissionClient
    from .maddy import MaddyService, SubprocessRunner

    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("authentication bootstrap must run as root")
    records = _validated_bootstrap_records(_read_bootstrap_document())
    runner = SubprocessRunner()
    maddy = MaddyService.from_config(config.maddy, runner=runner)
    # Constructing the SMTP client verifies that the same configured identity
    # path used by login remains available, without transmitting a credential.
    SMTPSubmissionClient.from_config(config.maddy)
    created_count = 0
    created_accounts: list[str] = []
    store: Any | None = None
    try:
        store = _auth_store(config)
        current = {
            str(record["username"]).casefold(): record
            for record in maddy.list_accounts(include_append_limits=False)
        }
        for record in records:
            email = str(record["email"])
            existing = current.get(email.casefold())
            if record["create_account"]:
                if existing is not None:
                    raise RuntimeError("new bootstrap target already exists in Maddy")
            elif (
                existing is None
                or existing.get("has_credentials") is not True
                or existing.get("has_mailbox") is not True
            ):
                raise RuntimeError("bootstrap target is not a complete enabled Maddy account")
        for record in records:
            if record["create_account"]:
                email = str(record["email"])
                maddy.create_account(email, str(record["initial_password"]))
                created_accounts.append(email)
                created_count += 1
        store.bootstrap_active_accounts(
            AccountBootstrap(
                email=str(record["email"]),
                role=record["role"],
                totp_secret=str(record["totp_secret"]),
                recovery_codes=tuple(record["recovery_codes"]),
                password_change_required=bool(record["password_change_required"]),
            )
            for record in records
        )
    except Exception as exc:
        rollback_failed = False
        for email in reversed(created_accounts):
            try:
                maddy.delete_account(email)
            except Exception:
                rollback_failed = True
        if rollback_failed:
            raise RuntimeError(
                "authentication bootstrap failed and new-account rollback was not verified"
            ) from exc
        raise
    finally:
        for record in records:
            record["initial_password"] = ""
        if store is not None:
            store.close()
    print(f"bootstrap=ok accounts={len(records)} maddy_accounts_created={created_count}")


def _run_auth_role(config: AppConfig, email: str, role: str) -> None:
    from .auth import Role, canonicalize_email
    from .maddy import MaddyService, SubprocessRunner

    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("authentication role changes must run as root")
    try:
        canonical = canonicalize_email(email)
        normalized_role = Role(role)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("authentication role identity is invalid") from exc
    maddy = MaddyService.from_config(config.maddy, runner=SubprocessRunner())
    if not any(
        record.get("username") == canonical
        and record.get("has_credentials") is True
        and record.get("has_mailbox") is True
        for record in maddy.list_accounts(include_append_limits=False)
    ):
        raise RuntimeError("role target must be an enabled Maddy account")
    store = _auth_store(config)
    try:
        account = store.sync_accounts(
            (canonical,),
            password_change_required=False,
        )[0]
        store.set_role(account.account_id, normalized_role, revoke_sessions=True)
    finally:
        store.close()
    print(f"role=ok email={canonical} value={normalized_role.value}")


def _run_auth_purge(config: AppConfig, email: str, confirmation: str) -> None:
    """Remove authentication metadata only after Maddy no longer has the identity."""

    from .auth import canonicalize_email
    from .maddy import MaddyService, SubprocessRunner

    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("authentication metadata purge must run as root")
    try:
        canonical = canonicalize_email(email)
        confirmed = canonicalize_email(confirmation)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("authentication purge identity is invalid") from exc
    if not hmac.compare_digest(canonical, confirmed):
        raise RuntimeError("authentication purge confirmation does not match")
    maddy = MaddyService.from_config(config.maddy, runner=SubprocessRunner())
    if any(
        isinstance(record.get("username"), str) and str(record["username"]).casefold() == canonical
        for record in maddy.list_accounts(include_append_limits=False)
    ):
        raise RuntimeError("authentication purge target still exists in Maddy")
    store = _auth_store(config)
    removed = 0
    try:
        account = store.get_account(canonical)
        if account is not None:
            store.delete_account(account.account_id)
            removed = 1
    finally:
        store.close()
    print(f"auth_purge=ok email={canonical} removed={removed}")


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

    auth_bootstrap = subparsers.add_parser(
        "auth-bootstrap",
        help="import root-only authentication metadata from standard input",
    )
    auth_bootstrap.add_argument("--config", type=Path, required=True)

    auth_role = subparsers.add_parser(
        "auth-role",
        help="assign a root-controlled role to an existing mailbox",
    )
    auth_role.add_argument("--config", type=Path, required=True)
    auth_role.add_argument("--email", required=True)
    auth_role.add_argument("--role", choices=("admin", "user"), required=True)

    auth_purge = subparsers.add_parser(
        "auth-purge",
        help="purge metadata for a mailbox already removed from Maddy",
    )
    auth_purge.add_argument("--config", type=Path, required=True)
    auth_purge.add_argument("--email", required=True)
    auth_purge.add_argument("--confirm-email", required=True)
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
        elif arguments.command == "auth-bootstrap":
            _run_auth_bootstrap(config)
        elif arguments.command == "auth-role":
            _run_auth_role(config, arguments.email, arguments.role)
        elif arguments.command == "auth-purge":
            _run_auth_purge(
                config,
                arguments.email,
                arguments.confirm_email,
            )
        else:  # pragma: no cover - argparse enforces the closed command set.
            raise RuntimeError("unsupported command")
    except (ConfigError, OSError, RuntimeError) as exc:
        LOGGER.error("%s", exc)
        raise SystemExit(2) from exc


__all__ = ["main"]
