"""Least-privilege UNIX-socket dispatcher and strict local SMTP submission.

Only the operations in :data:`ALLOWED_OPERATIONS` are callable.  Large message
bodies cross the socket as exact-length binary streams and are held in helper-
created mode-0600 spools; browser supplied filesystem paths are never accepted.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import queue
import re
import socket
import struct
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Literal, Protocol

from .certificates import CertificateCommandError, CertificateError, CertificateManager
from .maddy import (
    Capability,
    CapabilityFingerprintError,
    CommandFailed,
    CommandInputError,
    CommandLaunchError,
    CommandOutputLimit,
    CommandTimeout,
    InvalidMaddyArgument,
    LegacyLDAPUnsafe,
    MaddyError,
    MaddyService,
    MaddyTarget,
    PartialOperationError,
    RuntimeConfigUnsafe,
    StaleMessageCursor,
    UnsupportedCapability,
    UnsupportedVersion,
)
from .protocol import (
    DEFAULT_MAX_FRAME_BYTES,
    DEFAULT_MAX_STREAM_BYTES,
    ConnectionClosed,
    ProtocolError,
    Request,
    Response,
    StreamError,
    receive_frame,
    receive_stream_payload,
    send_frame,
    send_stream_frame,
)
from .rule_snapshots import (
    RuleSnapshotError,
    publish_snapshot,
    remove_snapshot,
    replace_snapshot_set,
)
from .rules import Rule, compile_rule, condition_from_mapping, condition_to_mapping

_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "secret",
        "token",
        "key",
        "private_key",
        "body",
        "raw",
        "content",
        "message",
        "attachment",
        "authorization",
        "challenge",
        "code",
        "credential",
        "condition",
        "expression",
        "match",
        "rule_snapshot",
        "state",
    }
)
_EMAIL_RE = re.compile(r"\A[^\s<>@]+@[^\s<>@]+\Z")
_DOCKER_NETWORK_MODE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_CONTAINER_ID_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_PROC_NET_ROW_RE = re.compile(
    r"\A\s*\d+:\s+"
    r"([0-9A-Fa-f]+):([0-9A-Fa-f]{4})\s+"
    r"([0-9A-Fa-f]+):([0-9A-Fa-f]{4})\s+"
    r"([0-9A-Fa-f]{2})(?:\s+.*)?\Z"
)
_SUBMISSION_PORT = 1587
_SUBMISSION_PORT_HEX = "0633"
_IPV4_LOOPBACK_PROC_HEX = "0100007F"
_DOCKER_LOCAL_HOST_ARG = "--host=unix:///var/run/docker.sock"
_DOCKER_INSPECT_MAX_OUTPUT = 256 * 1024
_PROC_NET_MAX_OUTPUT = 4 * 1024 * 1024
_PROC_NET_COMBINED_MAX_OUTPUT = 2 * _PROC_NET_MAX_OUTPUT
_DOCKER_INSPECT_TEMPLATE = (
    '{"id":{{json .Id}},'
    '"running":{{json .State.Running}},'
    '"paused":{{json .State.Paused}},'
    '"network_mode":{{json .HostConfig.NetworkMode}},'
    '"port_bindings":{{json .HostConfig.PortBindings}},'
    '"runtime_ports":{{json .NetworkSettings.Ports}}}'
)
_FIXED_SUBPROCESS_ENV = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}
_RULE_RUN_BATCH_SIZE = 20
_MAX_RULE_RUN_MAILBOXES = 64
_MAX_RULE_RESPONSE_BYTES = 48 * 1024


def redact_for_audit(value: Any, *, key: str = "") -> Any:
    """Recursively redact secret-like fields and summarize binary values."""

    normalized = key.lower().replace("-", "_")
    if any(secret in normalized for secret in _SENSITIVE_KEYS):
        if isinstance(value, bytes | bytearray | memoryview):
            return {"redacted": True, "bytes": len(value)}
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(name): redact_for_audit(item, key=str(name)) for name, item in value.items()}
    if isinstance(value, list | tuple):
        return [redact_for_audit(item, key=key) for item in value]
    if isinstance(value, bytes | bytearray | memoryview):
        return {"bytes": len(value)}
    if isinstance(value, str) and len(value) > 256:
        return {"characters": len(value)}
    return value


def _default_audit(action: str, *, outcome: str, fields: Mapping[str, Any]) -> None:
    try:
        from .audit import record

        record(action, outcome=outcome, fields=redact_for_audit(fields))
    except ImportError, RuntimeError:
        return


class SMTPError(RuntimeError):
    """Base class for local SMTP submission failures."""


class SMTPRejected(SMTPError):
    def __init__(self, code: int, stage: str) -> None:
        self.code = code
        self.stage = stage
        self.temporary = 400 <= code < 500
        super().__init__(f"SMTP rejected {stage} with status {code}")


class SMTPOutcomeUnknown(SMTPError):
    """Connection failed after DATA terminator but before the final reply."""


class SMTPTransportError(SMTPError):
    """Connection failed before the message could have been accepted."""


class AuthorizationDenied(RuntimeError):
    """An authenticated browser identity lacks permission for an operation."""


class InvalidCredentials(RuntimeError):
    """Mailbox credentials were rejected without revealing which field failed."""


class PasswordChangeRequired(AuthorizationDenied):
    """The identity must replace its bootstrap password before continuing."""


class StepUpRequired(AuthorizationDenied):
    """A dangerous administrator operation requires fresh reauthentication."""


class RuleMailboxConflict(ValueError):
    """A mailbox mutation would invalidate a stored delivery rule."""


@dataclass(frozen=True, slots=True)
class _DockerSubmissionRuntime:
    container_id: str
    network_mode: str


def _bounded_command_output(
    argv: Sequence[str],
    *,
    timeout: float,
    maximum: int,
) -> bytes:
    """Run one fixed command while bounding time and captured output."""

    if timeout <= 0 or maximum <= 0:
        raise SMTPTransportError("Docker Submission runtime check limits are invalid")
    try:
        process = subprocess.Popen(  # noqa: S603
            tuple(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=os.name == "posix",
            env=dict(_FIXED_SUBPROCESS_ENV),
        )
    except OSError as exc:
        raise SMTPTransportError("Docker Submission runtime check failed") from exc

    stdout = process.stdout
    stderr = process.stderr
    if stdout is None or stderr is None:
        with suppress(OSError):
            process.kill()
        raise SMTPTransportError("Docker Submission runtime check failed")

    captured = (bytearray(), bytearray())
    overflow = threading.Event()
    reader_failed = threading.Event()

    def consume(stream: BinaryIO, destination: bytearray) -> None:
        try:
            while chunk := stream.read(8192):
                remaining = maximum - len(destination)
                if remaining > 0:
                    destination.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()
                    with suppress(OSError):
                        process.kill()
        except OSError:
            reader_failed.set()
            with suppress(OSError):
                process.kill()

    readers = (
        threading.Thread(target=consume, args=(stdout, captured[0]), daemon=True),
        threading.Thread(target=consume, args=(stderr, captured[1]), daemon=True),
    )
    for reader in readers:
        reader.start()

    failed = False
    try:
        return_code = process.wait(timeout=timeout)
    except OSError, subprocess.TimeoutExpired:
        failed = True
        with suppress(OSError):
            process.kill()
        with suppress(OSError, subprocess.TimeoutExpired):
            process.wait(timeout=1.0)
        return_code = None
    finally:
        for reader in readers:
            reader.join(timeout=1.0)
        with suppress(OSError):
            stdout.close()
        with suppress(OSError):
            stderr.close()

    if (
        failed
        or return_code != 0
        or overflow.is_set()
        or reader_failed.is_set()
        or any(reader.is_alive() for reader in readers)
    ):
        raise SMTPTransportError("Docker Submission runtime check failed")
    return bytes(captured[0])


def _parse_proc_net_table(table: bytes, *, ipv6: bool) -> tuple[str, ...]:
    """Return LISTEN addresses for port 1587 from one procfs TCP table."""

    if not table or len(table) > _PROC_NET_MAX_OUTPUT:
        raise SMTPTransportError("Docker Submission socket table is invalid")
    try:
        lines = table.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise SMTPTransportError("Docker Submission socket table is invalid") from exc
    if not lines or not _is_proc_net_header(lines[0]):
        raise SMTPTransportError("Docker Submission socket table is invalid")

    address_length = 32 if ipv6 else 8
    listeners: list[str] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        match = _PROC_NET_ROW_RE.fullmatch(line)
        if (
            match is None
            or len(match.group(1)) != address_length
            or len(match.group(3)) != address_length
        ):
            raise SMTPTransportError("Docker Submission socket table is invalid")
        local_address, local_port, _remote_address, _remote_port, state = (
            value.upper() for value in match.groups()
        )
        if state == "0A" and local_port == _SUBMISSION_PORT_HEX:
            listeners.append(local_address)
    return tuple(listeners)


def _is_proc_net_header(line: str) -> bool:
    fields = line.split()[:4]
    return (
        len(fields) == 4
        and fields[0] == "sl"
        and fields[1] == "local_address"
        and fields[2] in {"rem_address", "remote_address"}
        and fields[3] == "st"
    )


def _split_proc_net_tables(payload: bytes) -> tuple[bytes, bytes]:
    """Split one fixed cat of the IPv4 and IPv6 procfs TCP tables."""

    if not payload or len(payload) > _PROC_NET_COMBINED_MAX_OUTPUT:
        raise SMTPTransportError("Docker Submission socket tables are invalid")
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise SMTPTransportError("Docker Submission socket tables are invalid") from exc
    header_indexes = [index for index, line in enumerate(lines) if _is_proc_net_header(line)]
    if len(header_indexes) != 2 or header_indexes[0] != 0:
        raise SMTPTransportError("Docker Submission socket tables are invalid")
    boundary = header_indexes[1]
    ipv4 = ("\n".join(lines[:boundary]) + "\n").encode("ascii")
    ipv6 = ("\n".join(lines[boundary:]) + "\n").encode("ascii")
    return ipv4, ipv6


def _submission_listeners(ipv4_table: bytes, ipv6_table: bytes) -> tuple[tuple[str, str], ...]:
    ipv4 = (("ipv4", address) for address in _parse_proc_net_table(ipv4_table, ipv6=False))
    ipv6 = (("ipv6", address) for address in _parse_proc_net_table(ipv6_table, ipv6=True))
    return (*ipv4, *ipv6)


def _require_submission_listener(
    ipv4_table: bytes,
    ipv6_table: bytes,
    *,
    present: bool,
) -> None:
    listeners = _submission_listeners(ipv4_table, ipv6_table)
    expected = (("ipv4", _IPV4_LOOPBACK_PROC_HEX),) if present else ()
    if listeners != expected:
        raise SMTPTransportError("Docker Submission listener state is unsafe")


def _port_metadata_is_safe(value: Any) -> bool:
    if value is None:
        return True
    if not isinstance(value, dict):
        return False
    for container_port, records in value.items():
        if not isinstance(container_port, str):
            return False
        container_port_number = container_port.split("/", 1)[0]
        if container_port_number.isdecimal() and int(container_port_number) == _SUBMISSION_PORT:
            return False
        if records is None:
            continue
        if not isinstance(records, list):
            return False
        for record in records:
            if not isinstance(record, dict):
                return False
            host_port = record.get("HostPort")
            if host_port is not None and type(host_port) not in {str, int}:
                return False
            host_port_number = str(host_port)
            if host_port_number.isdecimal() and int(host_port_number) == _SUBMISSION_PORT:
                return False
    return True


def _parse_docker_submission_runtime(
    payload: bytes,
    *,
    scope: str,
) -> _DockerSubmissionRuntime:
    if scope not in {"container", "host-loopback"}:
        raise SMTPTransportError("Docker Submission scope is invalid")
    try:
        metadata = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SMTPTransportError("Docker Submission runtime metadata is invalid") from exc
    expected_fields = {
        "id",
        "running",
        "paused",
        "network_mode",
        "port_bindings",
        "runtime_ports",
    }
    if not isinstance(metadata, dict) or set(metadata) != expected_fields:
        raise SMTPTransportError("Docker Submission runtime metadata is invalid")

    container_id = metadata["id"]
    running = metadata["running"]
    paused = metadata["paused"]
    network_mode = metadata["network_mode"]
    if (
        not isinstance(container_id, str)
        or _CONTAINER_ID_RE.fullmatch(container_id) is None
        or type(running) is not bool
        or type(paused) is not bool
        or running is not True
        or paused is not False
    ):
        raise SMTPTransportError("Docker Submission container is not running safely")
    if (
        not isinstance(network_mode, str)
        or _DOCKER_NETWORK_MODE_RE.fullmatch(network_mode) is None
        or network_mode == "none"
        or network_mode.startswith("container:")
    ):
        raise SMTPTransportError("Docker Submission network mode is invalid")
    if (scope == "container" and network_mode == "host") or (
        scope == "host-loopback" and network_mode != "host"
    ):
        raise SMTPTransportError("Docker Submission network scope changed")
    if not (
        _port_metadata_is_safe(metadata["port_bindings"])
        and _port_metadata_is_safe(metadata["runtime_ports"])
    ):
        raise SMTPTransportError("Docker Submission port publication is unsafe")
    return _DockerSubmissionRuntime(container_id, network_mode)


class _SMTPChannel(Protocol):
    def readline(self, timeout: float) -> bytes: ...
    def write(self, data: bytes) -> None: ...
    def close(self) -> None: ...


class _SocketChannel:
    def __init__(self, host: str, port: int, timeout: float) -> None:
        self._socket = socket.create_connection((host, port), timeout=timeout)
        self._file = self._socket.makefile("rwb", buffering=0)

    def readline(self, timeout: float) -> bytes:
        self._socket.settimeout(timeout)
        line = self._file.readline(4097)
        if not line:
            raise SMTPTransportError("SMTP connection closed")
        if len(line) > 4096 or not line.endswith(b"\n"):
            raise SMTPTransportError("SMTP response line is invalid")
        return line

    def write(self, data: bytes) -> None:
        self._file.write(data)

    def close(self) -> None:
        try:
            self._file.close()
        finally:
            self._socket.close()


class _ProcessChannel:
    """Interactive docker-exec/nc transport with bounded background readers."""

    def __init__(self, argv: Sequence[str]) -> None:
        self._process = subprocess.Popen(  # noqa: S603
            tuple(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=os.name == "posix",
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            },
        )
        self._lines: queue.Queue[bytes | BaseException | None] = queue.Queue(maxsize=32)
        self._stderr = bytearray()

        stdout = self._process.stdout
        stderr = self._process.stderr
        if stdout is None or stderr is None or self._process.stdin is None:
            self._process.kill()
            raise SMTPTransportError("SMTP transport pipes are unavailable")

        def stdout_reader() -> None:
            line = bytearray()
            try:
                while chunk := stdout.read(1):
                    line.extend(chunk)
                    if len(line) > 4096:
                        self._lines.put(SMTPTransportError("SMTP response line is too long"))
                        return
                    if chunk == b"\n":
                        self._lines.put(bytes(line))
                        line.clear()
                if line:
                    self._lines.put(SMTPTransportError("SMTP response was truncated"))
                self._lines.put(None)
            except BaseException as exc:
                self._lines.put(exc)

        def stderr_reader() -> None:
            while chunk := stderr.read(4096):
                remaining = 64 * 1024 - len(self._stderr)
                if remaining > 0:
                    self._stderr.extend(chunk[:remaining])

        threading.Thread(target=stdout_reader, daemon=True).start()
        threading.Thread(target=stderr_reader, daemon=True).start()

    def readline(self, timeout: float) -> bytes:
        try:
            item = self._lines.get(timeout=timeout)
        except queue.Empty as exc:
            raise SMTPTransportError("SMTP response timed out") from exc
        if item is None:
            raise SMTPTransportError("SMTP connection closed")
        if isinstance(item, BaseException):
            raise SMTPTransportError("SMTP transport reader failed") from item
        return item

    def write(self, data: bytes) -> None:
        try:
            stdin = self._process.stdin
            if stdin is None:
                raise SMTPTransportError("SMTP transport input is unavailable")
            stdin.write(data)
            stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise SMTPTransportError("SMTP transport closed while writing") from exc

    def close(self) -> None:
        try:
            if self._process.stdin is not None:
                self._process.stdin.close()
        except OSError:
            pass
        try:
            self._process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()


def _email_address(value: str, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 254
        or _EMAIL_RE.fullmatch(value) is None
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise ValueError(f"invalid {field}")
    return value


class SMTPSubmissionClient:
    """Strict response-by-response SMTP client for the local submission endpoint."""

    def __init__(
        self,
        target: MaddyTarget,
        *,
        host: str = "127.0.0.1",
        port: int = 1587,
        docker_submission_scope: str = "container",
        timeout: float = 15.0,
        max_message_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        if host != "127.0.0.1" or port != _SUBMISSION_PORT:
            raise ValueError("SMTP submission must use exactly 127.0.0.1:1587")
        if docker_submission_scope not in {"container", "host-loopback"}:
            raise ValueError("invalid Docker Submission scope")
        if timeout <= 0 or max_message_bytes <= 0:
            raise ValueError("SMTP limits must be positive")
        self.target = target
        self.host = host
        self.port = port
        self.docker_submission_scope = docker_submission_scope
        self.timeout = timeout
        self.max_message_bytes = max_message_bytes

    @classmethod
    def from_config(cls, config: Any) -> SMTPSubmissionClient:
        return cls(
            MaddyTarget.from_config(config),
            host=str(config.submission_host),
            port=int(config.submission_port),
            docker_submission_scope=str(config.docker_submission_scope),
            timeout=float(config.command_timeout_seconds),
        )

    def _channel(self, *, docker_container: str | None = None) -> _SMTPChannel:
        if self.target.mode.value == "native":
            if docker_container is not None:
                raise SMTPTransportError("native SMTP transport received a Docker identity")
            return _SocketChannel(self.host, self.port, self.timeout)
        if docker_container is None or _CONTAINER_ID_RE.fullmatch(docker_container) is None:
            raise SMTPTransportError("Docker SMTP transport lacks a validated container identity")
        return _ProcessChannel(
            (
                self.target.docker_executable,
                _DOCKER_LOCAL_HOST_ARG,
                "exec",
                "-i",
                docker_container,
                "/usr/bin/nc",
                self.host,
                str(self.port),
            )
        )

    def _guard_command(self, suffix: Sequence[str], *, maximum: int) -> bytes:
        return _bounded_command_output(
            (self.target.docker_executable, _DOCKER_LOCAL_HOST_ARG, *suffix),
            timeout=min(self.timeout, 5.0),
            maximum=maximum,
        )

    @staticmethod
    def _host_socket_tables() -> tuple[bytes, bytes]:
        tables: list[bytes] = []
        for name in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(name, "rb") as handle:
                    table = handle.read(_PROC_NET_MAX_OUTPUT + 1)
            except OSError as exc:
                raise SMTPTransportError(
                    "Docker Submission host socket table is unavailable"
                ) from exc
            if not table or len(table) > _PROC_NET_MAX_OUTPUT:
                raise SMTPTransportError("Docker Submission host socket table is invalid")
            tables.append(table)
        return tables[0], tables[1]

    def _validate_docker_runtime(self) -> str:
        if self.host != "127.0.0.1" or self.port != _SUBMISSION_PORT:
            raise SMTPTransportError("Docker Submission endpoint changed")
        container = str(self.target.container)
        metadata = self._guard_command(
            (
                "container",
                "inspect",
                "--format",
                _DOCKER_INSPECT_TEMPLATE,
                container,
            ),
            maximum=_DOCKER_INSPECT_MAX_OUTPUT,
        )
        runtime = _parse_docker_submission_runtime(
            metadata,
            scope=self.docker_submission_scope,
        )
        socket_tables = self._guard_command(
            (
                "exec",
                runtime.container_id,
                "/bin/cat",
                "/proc/net/tcp",
                "/proc/net/tcp6",
            ),
            maximum=_PROC_NET_COMBINED_MAX_OUTPUT,
        )
        ipv4_table, ipv6_table = _split_proc_net_tables(socket_tables)
        _require_submission_listener(ipv4_table, ipv6_table, present=True)

        host_ipv4, host_ipv6 = self._host_socket_tables()
        _require_submission_listener(
            host_ipv4,
            host_ipv6,
            present=self.docker_submission_scope == "host-loopback",
        )
        return runtime.container_id

    @staticmethod
    def _response(channel: _SMTPChannel, deadline: float) -> tuple[int, str]:
        lines: list[str] = []
        expected_code: int | None = None
        total = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SMTPTransportError("SMTP transaction timed out")
            line = channel.readline(remaining)
            total += len(line)
            if total > 64 * 1024 or len(line) < 4 or not line[:3].isdigit():
                raise SMTPTransportError("SMTP response is malformed")
            code = int(line[:3])
            if expected_code is None:
                expected_code = code
            elif code != expected_code:
                raise SMTPTransportError("SMTP multiline response changed status code")
            separator = line[3:4]
            if separator not in {b"-", b" "}:
                raise SMTPTransportError("SMTP response separator is malformed")
            lines.append(line[4:].decode("utf-8", errors="replace").strip())
            if separator == b" ":
                return code, " ".join(lines)[:512]

    @classmethod
    def _command(
        cls,
        channel: _SMTPChannel,
        command: bytes,
        deadline: float,
        expected: set[int],
        stage: str,
    ) -> tuple[int, str]:
        channel.write(command + b"\r\n")
        code, text = cls._response(channel, deadline)
        if code not in expected:
            raise SMTPRejected(code, stage)
        return code, text

    @staticmethod
    def _write_data(
        channel: _SMTPChannel,
        source: BinaryIO,
        declared_length: int,
    ) -> None:
        remaining = declared_length
        at_line_start = True
        pending_cr = False
        output = bytearray()

        def emit(value: bytes) -> None:
            output.extend(value)
            if len(output) >= 64 * 1024:
                channel.write(bytes(output))
                output.clear()

        while remaining:
            chunk = source.read(min(64 * 1024, remaining))
            if not chunk:
                raise SMTPTransportError("message spool ended before its declared length")
            if not isinstance(chunk, bytes):
                raise SMTPTransportError("message spool is not binary")
            remaining -= len(chunk)
            for value in chunk:
                if pending_cr:
                    emit(b"\r\n")
                    at_line_start = True
                    pending_cr = False
                    if value == 0x0A:
                        continue
                if value == 0x0D:
                    pending_cr = True
                elif value == 0x0A:
                    emit(b"\r\n")
                    at_line_start = True
                else:
                    if at_line_start and value == 0x2E:
                        emit(b".")
                    emit(bytes((value,)))
                    at_line_start = False
        if source.read(1):
            raise SMTPTransportError("message spool exceeds its declared length")
        if pending_cr or not at_line_start:
            emit(b"\r\n")
        if output:
            channel.write(bytes(output))

    @staticmethod
    def _validated_password(password: str) -> str:
        if (
            not isinstance(password, str)
            or not password
            or len(password) > 1024
            or any(char in password for char in "\r\n\0")
        ):
            raise ValueError("invalid SMTP password")
        return password

    def _open_channel(self) -> _SMTPChannel:
        if self.target.mode.value == "docker":
            container_id = self._validate_docker_runtime()
            return self._channel(docker_container=container_id)
        return self._channel()

    @classmethod
    def _authenticate_channel(
        cls,
        channel: _SMTPChannel,
        *,
        username: str,
        password: str,
        deadline: float,
    ) -> None:
        code, _ = cls._response(channel, deadline)
        if code != 220:
            raise SMTPRejected(code, "greeting")
        cls._command(channel, b"EHLO maddyweb.local", deadline, {250}, "EHLO")
        auth = base64.b64encode(b"\0" + username.encode() + b"\0" + password.encode())
        code, _ = cls._command(
            channel,
            b"AUTH PLAIN " + auth,
            deadline,
            {235, 334},
            "AUTH",
        )
        if code == 334:
            cls._command(channel, auth, deadline, {235}, "AUTH")

    def authenticate(self, *, username: str, password: str) -> None:
        """Verify one Maddy credential without starting a mail transaction."""

        username = _email_address(username, "SMTP username")
        password = self._validated_password(password)
        channel = self._open_channel()
        deadline = time.monotonic() + self.timeout
        try:
            self._authenticate_channel(
                channel,
                username=username,
                password=password,
                deadline=deadline,
            )
            with suppress(SMTPError):
                self._command(channel, b"QUIT", deadline, {221}, "QUIT")
        finally:
            channel.close()

    def send(
        self,
        *,
        username: str,
        password: str,
        mail_from: str,
        recipients: Sequence[str],
        message: BinaryIO,
        message_length: int,
    ) -> dict[str, Any]:
        username = _email_address(username, "SMTP username")
        mail_from = _email_address(mail_from, "envelope sender")
        recipients = tuple(_email_address(value, "recipient") for value in recipients)
        if not recipients or len(recipients) > 100:
            raise ValueError("SMTP requires between 1 and 100 recipients")
        password = self._validated_password(password)
        if type(message_length) is not int or not 1 <= message_length <= self.max_message_bytes:
            raise ValueError("invalid message length")

        channel = self._open_channel()
        deadline = time.monotonic() + self.timeout
        data_terminator_sent = False
        try:
            self._authenticate_channel(
                channel,
                username=username,
                password=password,
                deadline=deadline,
            )
            self._command(
                channel,
                f"MAIL FROM:<{mail_from}>".encode(),
                deadline,
                {250},
                "MAIL FROM",
            )
            for recipient in recipients:
                self._command(
                    channel,
                    f"RCPT TO:<{recipient}>".encode(),
                    deadline,
                    {250, 251},
                    "RCPT TO",
                )
            self._command(channel, b"DATA", deadline, {354}, "DATA")
            self._write_data(channel, message, message_length)
            # From this point a failed write or read is ambiguous: the server
            # may have received the complete terminator and accepted the mail.
            data_terminator_sent = True
            channel.write(b".\r\n")
            try:
                code, _ = self._response(channel, deadline)
            except SMTPTransportError as exc:
                raise SMTPOutcomeUnknown(
                    "SMTP connection failed after DATA; delivery outcome is unknown"
                ) from exc
            if code != 250:
                raise SMTPRejected(code, "message body")
            # The server already accepted the message after DATA.
            with suppress(SMTPError):
                self._command(channel, b"QUIT", deadline, {221}, "QUIT")
            return {"accepted": True, "recipients": len(recipients)}
        except SMTPTransportError as exc:
            if data_terminator_sent:
                raise SMTPOutcomeUnknown(
                    "SMTP transport failed after DATA; delivery outcome is unknown"
                ) from exc
            raise
        finally:
            channel.close()


@dataclass(slots=True)
class TrustedSpool:
    path: Path
    handle: BinaryIO
    length: int = 0

    @classmethod
    def create(cls, directory: Path) -> TrustedSpool:
        if not directory.is_dir() or directory.is_symlink():
            raise RuntimeError("configured spool directory is unavailable")
        descriptor, name = tempfile.mkstemp(prefix="maddyweb-", suffix=".spool", dir=directory)
        os.chmod(name, 0o600)
        return cls(Path(name), os.fdopen(descriptor, "w+b", buffering=0))

    def rewind(self) -> None:
        self.handle.seek(0)

    def close(self) -> None:
        try:
            self.handle.close()
        finally:
            self.path.unlink(missing_ok=True)


@dataclass(frozen=True, slots=True)
class _Operation:
    method: str
    mutating: bool = False
    stream_in: bool = False
    stream_out: bool = False
    permission: Literal["public", "session", "admin", "admin_account", "account"] = "admin"
    step_up: bool = False
    touch_session: bool = True
    audit_success: bool = True


ALLOWED_OPERATIONS: Mapping[str, _Operation] = {
    "maddy.health": _Operation("_maddy_health", permission="public"),
    "maddy.version": _Operation("_version", permission="public"),
    "maddy.verify_config": _Operation("_verify_config"),
    "auth.password_begin": _Operation("_auth_password_begin", mutating=True, permission="public"),
    "auth.enrollment_begin": _Operation(
        "_auth_enrollment_begin",
        mutating=True,
        permission="public",
    ),
    "auth.enrollment_complete": _Operation(
        "_auth_enrollment_complete",
        mutating=True,
        permission="public",
    ),
    "auth.totp_complete": _Operation(
        "_auth_totp_complete",
        mutating=True,
        permission="public",
    ),
    "auth.recovery_complete": _Operation(
        "_auth_recovery_complete",
        mutating=True,
        permission="public",
    ),
    "auth.passkey_login_begin": _Operation(
        "_auth_passkey_login_begin",
        mutating=True,
        permission="public",
    ),
    "auth.passkey_login_complete": _Operation(
        "_auth_passkey_login_complete",
        mutating=True,
        permission="public",
    ),
    "auth.session": _Operation("_auth_session", permission="session"),
    "auth.session_peek": _Operation(
        "_auth_session",
        permission="session",
        touch_session=False,
        audit_success=False,
    ),
    "auth.logout": _Operation("_auth_logout", mutating=True, permission="session"),
    "auth.change_password": _Operation(
        "_auth_change_password",
        mutating=True,
        permission="session",
        step_up=True,
    ),
    "auth.recovery_regenerate": _Operation(
        "_auth_recovery_regenerate",
        mutating=True,
        permission="session",
    ),
    "auth.step_up": _Operation("_auth_step_up", mutating=True, permission="session"),
    "auth.passkeys_list": _Operation("_auth_passkeys_list", permission="session"),
    "auth.passkey_register_begin": _Operation(
        "_auth_passkey_register_begin",
        mutating=True,
        permission="session",
        step_up=True,
    ),
    "auth.passkey_register_complete": _Operation(
        "_auth_passkey_register_complete",
        mutating=True,
        permission="session",
        step_up=True,
    ),
    "auth.passkey_delete": _Operation(
        "_auth_passkey_delete",
        mutating=True,
        permission="session",
        step_up=True,
    ),
    "auth.passkey_step_up_begin": _Operation(
        "_auth_passkey_step_up_begin",
        mutating=True,
        permission="session",
    ),
    "auth.passkey_step_up_complete": _Operation(
        "_auth_passkey_step_up_complete",
        mutating=True,
        permission="session",
    ),
    "auth.sessions_list": _Operation("_auth_sessions_list", permission="session"),
    "auth.session_revoke_other": _Operation(
        "_auth_session_revoke_other",
        mutating=True,
        permission="session",
        step_up=True,
    ),
    "auth.admin_rotate_totp": _Operation(
        "_auth_admin_rotate_totp",
        mutating=True,
        permission="admin",
        step_up=True,
    ),
    "accounts.list": _Operation("_accounts_list"),
    "accounts.create": _Operation("_accounts_create", mutating=True, step_up=True),
    "accounts.change_password": _Operation(
        "_accounts_password",
        mutating=True,
        permission="admin_account",
        step_up=True,
    ),
    "accounts.disable_credentials": _Operation(
        "_accounts_disable",
        mutating=True,
        permission="admin_account",
        step_up=True,
    ),
    "accounts.delete_imap_account": _Operation(
        "_accounts_delete_imap",
        mutating=True,
        permission="admin_account",
        step_up=True,
    ),
    "accounts.get_append_limit": _Operation(
        "_append_limit_get",
        permission="admin_account",
    ),
    "accounts.set_append_limit": _Operation(
        "_append_limit_set",
        mutating=True,
        permission="admin_account",
        step_up=True,
    ),
    "mailboxes.list": _Operation("_mailboxes_list", permission="account"),
    "mailboxes.create": _Operation("_mailboxes_create", mutating=True, permission="account"),
    "mailboxes.delete": _Operation("_mailboxes_delete", mutating=True, permission="account"),
    "mailboxes.rename": _Operation("_mailboxes_rename", mutating=True, permission="account"),
    "rules.list": _Operation("_rules_list", permission="account"),
    "rules.create": _Operation(
        "_rules_create",
        mutating=True,
        permission="account",
        step_up=True,
    ),
    "rules.update": _Operation(
        "_rules_update",
        mutating=True,
        permission="account",
        step_up=True,
    ),
    "rules.delete": _Operation(
        "_rules_delete",
        mutating=True,
        permission="account",
        step_up=True,
    ),
    "rules.reorder": _Operation(
        "_rules_reorder",
        mutating=True,
        permission="account",
        step_up=True,
    ),
    "rules.run_create": _Operation(
        "_rules_run_create",
        mutating=True,
        permission="account",
        step_up=True,
    ),
    "rules.run_status": _Operation("_rules_run_status", permission="account"),
    "rules.run_step": _Operation(
        "_rules_run_step",
        mutating=True,
        permission="account",
        step_up=True,
    ),
    "rules.run_cancel": _Operation("_rules_run_cancel", mutating=True, permission="account"),
    "messages.list": _Operation("_messages_list", permission="account"),
    "messages.latest": _Operation(
        "_messages_latest",
        permission="account",
        touch_session=False,
        audit_success=False,
    ),
    "messages.get": _Operation("_messages_get", stream_out=True, permission="account"),
    "messages.append": _Operation(
        "_messages_append",
        mutating=True,
        stream_in=True,
        permission="account",
    ),
    "messages.delete": _Operation(
        "_messages_delete",
        mutating=True,
        permission="account",
        step_up=True,
    ),
    "messages.delete_many": _Operation(
        "_messages_delete_many",
        mutating=True,
        permission="account",
        step_up=True,
    ),
    "messages.copy": _Operation("_messages_copy", mutating=True, permission="account"),
    "messages.move": _Operation("_messages_move", mutating=True, permission="account"),
    "messages.set_flags": _Operation(
        "_messages_set_flags",
        mutating=True,
        permission="account",
    ),
    "messages.add_flags": _Operation(
        "_messages_add_flags",
        mutating=True,
        permission="account",
    ),
    "messages.remove_flags": _Operation(
        "_messages_remove_flags",
        mutating=True,
        permission="account",
    ),
    "messages.send": _Operation(
        "_messages_send",
        mutating=True,
        stream_in=True,
        permission="account",
    ),
    "certificates.list": _Operation("_certificates_list"),
    "certificates.health": _Operation("_certificates_health"),
    "certificates.status": _Operation("_certificates_status"),
    "certificates.timer_enable": _Operation(
        "_certificates_timer_enable",
        mutating=True,
        step_up=True,
    ),
    "certificates.timer_disable": _Operation(
        "_certificates_timer_disable",
        mutating=True,
        step_up=True,
    ),
    "certificates.renew_dry_run": _Operation(
        "_certificates_dry_run",
        mutating=True,
        step_up=True,
    ),
    "certificates.renew": _Operation("_certificates_renew", mutating=True, step_up=True),
}


@dataclass(slots=True)
class DispatchResult:
    response: Response
    output_spool: TrustedSpool | None = None


def _params(
    request: Request,
    *,
    required: set[str] = frozenset(),
    optional: set[str] = frozenset(),
) -> dict[str, Any]:
    names = set(request.params)
    if names - required - optional:
        raise ValueError("unknown operation parameter")
    if required - names:
        raise ValueError("missing operation parameter")
    return request.params


def _confirmed(params: Mapping[str, Any]) -> None:
    if params.get("confirm") is not True:
        raise ValueError("destructive operation requires confirm=true")


def _selected_message_uid_set(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("message UID selection must be text")
    values = value.split(",")
    if not 1 <= len(values) <= 50:
        raise ValueError("message UID selection must contain between 1 and 50 UIDs")
    selected: list[str] = []
    seen: set[str] = set()
    for item in values:
        if not item.isascii() or not item.isdecimal() or item.startswith("0"):
            raise ValueError("message UID selection contains an invalid UID")
        uid = int(item)
        if not 1 <= uid <= (1 << 32) - 1:
            raise ValueError("message UID selection contains an invalid UID")
        normalized = str(uid)
        if normalized in seen:
            raise ValueError("message UID selection contains duplicate UIDs")
        seen.add(normalized)
        selected.append(normalized)
    return ",".join(selected)


class PrivilegedDispatcher:
    def __init__(
        self,
        maddy: MaddyService,
        certificates: CertificateManager,
        *,
        spool_dir: Path,
        smtp: SMTPSubmissionClient | None = None,
        auth_store: Any | None = None,
        rule_snapshot_dir: Path | None = None,
        rule_snapshot_group_id: int | None = None,
        audit: Callable[..., None] = _default_audit,
    ) -> None:
        self.maddy = maddy
        self.certificates = certificates
        self.smtp = smtp
        self.auth_store = auth_store
        self.rule_snapshot_dir = rule_snapshot_dir
        self.rule_snapshot_group_id = rule_snapshot_group_id
        self.spool_dir = spool_dir
        self.audit = audit
        self._lock = threading.RLock()
        self._request_context = threading.local()
        if self.rule_snapshot_dir is not None:
            self._reconcile_mail_rule_snapshots()
        missing_handlers = sorted(
            operation.method
            for operation in ALLOWED_OPERATIONS.values()
            if not callable(getattr(self, operation.method, None))
        )
        if missing_handlers:
            raise RuntimeError(
                "allow-listed helper operations are missing handlers: "
                + ", ".join(missing_handlers)
            )

    def close(self) -> None:
        close = getattr(self.auth_store, "close", None)
        if callable(close):
            close()

    @staticmethod
    def _role_value(principal: Any) -> str:
        role = getattr(principal, "role", "")
        return str(getattr(role, "value", role))

    def _current_principal(self) -> Any:
        principal = getattr(self._request_context, "principal", None)
        if principal is None:
            raise AuthorizationDenied("authenticated principal is unavailable")
        return principal

    def _maddy_account(self, email: str) -> Mapping[str, Any] | None:
        normalized = email.casefold()
        for record in self.maddy.list_accounts(include_append_limits=False):
            username = record.get("username")
            if isinstance(username, str) and username.casefold() == normalized:
                return record
        return None

    def _require_active_principal(self, principal: Any) -> None:
        record = self._maddy_account(str(principal.email))
        if (
            record is not None
            and record.get("has_credentials") is True
            and record.get("has_mailbox") is True
        ):
            return
        self.auth_store.revoke_sessions(principal.account_id)
        raise AuthorizationDenied("mailbox identity is disabled or incomplete")

    def _set_auth_audit(
        self,
        principal: Any,
        *,
        method: str,
        client_ip: str,
    ) -> None:
        self._request_context.auth_audit = {
            "actor": str(principal.email),
            "role": self._role_value(principal),
            "authentication_method": method,
            "client_ip": self._client_ip(client_ip),
        }

    def _authorize_request(
        self,
        request: Request,
        operation: _Operation,
        *,
        touch: bool,
        audit_fields: dict[str, Any] | None = None,
    ) -> tuple[Request, Any | None]:
        if self.auth_store is None:
            if operation.permission == "public":
                return request, None
            raise AuthorizationDenied("authentication service is unavailable")
        if operation.permission == "public":
            return request, None
        if request.auth_token is None:
            raise AuthorizationDenied("authentication is required")
        principal = self.auth_store.authenticate_session(request.auth_token, touch=touch)
        if audit_fields is not None:
            audit_fields["actor"] = principal.email
            audit_fields["role"] = self._role_value(principal)
        self._require_active_principal(principal)
        if getattr(principal, "password_change_required", False) and request.operation not in {
            "auth.session",
            "auth.session_peek",
            "auth.logout",
            "auth.change_password",
            "auth.step_up",
            "auth.passkeys_list",
            "auth.passkey_step_up_begin",
            "auth.passkey_step_up_complete",
            "auth.sessions_list",
        }:
            raise PasswordChangeRequired("mailbox password change is required")
        if (
            operation.permission in {"admin", "admin_account"}
            and self._role_value(principal) != "admin"
        ):
            raise AuthorizationDenied("administrator role is required")
        if operation.step_up:
            try:
                self.auth_store.require_step_up(request.auth_token)
            except Exception as exc:
                if type(exc).__name__ in {
                    "InvalidSessionError",
                    "StepUpRequiredError",
                }:
                    raise StepUpRequired("fresh authentication is required") from exc
                raise

        params = dict(request.params)
        if operation.permission in {"account", "admin_account"}:
            target_id = params.pop("target_account_id", None)
            if target_id is not None and not isinstance(target_id, str):
                raise ValueError("target account identifier must be text")
            if operation.permission == "admin_account" and target_id is None:
                raise ValueError("administrator target account is required")
            if target_id is not None:
                target = self.auth_store.resolve_account_id(target_id)
                if (
                    self._role_value(principal) != "admin"
                    and target.account_id != principal.account_id
                ):
                    raise AuthorizationDenied("cross-account access is forbidden")
            else:
                target = self.auth_store.resolve_account_id(principal.account_id)
            params["username"] = target.email
            if audit_fields is not None:
                audit_fields["target"] = target.email
        elif request.operation == "auth.admin_rotate_totp":
            target_id = params.get("target_account_id")
            if not isinstance(target_id, str):
                raise ValueError("administrator target account is required")
            target = self.auth_store.resolve_account_id(target_id)
            if audit_fields is not None:
                audit_fields["target"] = target.email
        return (
            Request(
                request_id=request.request_id,
                operation=request.operation,
                params=params,
                auth_token=request.auth_token,
                stream_length=request.stream_length,
            ),
            principal,
        )

    def preflight(
        self,
        request: Request,
    ) -> tuple[Response | None, dict[str, Any]]:
        """Authorize a control frame before receiving any declared upload body."""

        fields = {
            "request_id": request.request_id,
            "operation": request.operation,
            "actor": None,
            "params": redact_for_audit(request.params),
            "stream_length": request.stream_length or 0,
        }
        operation = ALLOWED_OPERATIONS.get(request.operation)
        if operation is None:
            self.audit("helper.operation", outcome="operation_denied", fields=fields)
            return (
                Response.failure(
                    request.request_id,
                    "operation_denied",
                    "Operation is not allow-listed",
                ),
                fields,
            )
        if operation.stream_in is not (request.stream_length is not None):
            self.audit("helper.operation", outcome="invalid_stream", fields=fields)
            return (
                Response.failure(
                    request.request_id,
                    "invalid_stream",
                    "Operation stream shape does not match",
                ),
                fields,
            )
        try:
            self._authorize_request(
                request,
                operation,
                touch=False,
                audit_fields=fields,
            )
        except Exception as exc:
            code, message = self._safe_error(exc)
            self.audit(
                "helper.operation",
                outcome=code,
                fields={**fields, "error_type": type(exc).__name__},
            )
            return Response.failure(request.request_id, code, message), fields
        return None, fields

    def dispatch(self, request: Request, input_spool: TrustedSpool | None = None) -> DispatchResult:
        fields = {
            "request_id": request.request_id,
            "operation": request.operation,
            "actor": None,
            "params": redact_for_audit(request.params),
            "stream_length": input_spool.length if input_spool is not None else 0,
        }
        operation = ALLOWED_OPERATIONS.get(request.operation)
        if operation is None:
            self.audit("helper.operation", outcome="operation_denied", fields=fields)
            return DispatchResult(
                Response.failure(
                    request.request_id,
                    "operation_denied",
                    "Operation is not allow-listed",
                )
            )
        if operation.stream_in is not (input_spool is not None):
            self.audit("helper.operation", outcome="invalid_stream", fields=fields)
            return DispatchResult(
                Response.failure(
                    request.request_id,
                    "invalid_stream",
                    "Operation stream shape does not match",
                )
            )
        try:
            request, principal = self._authorize_request(
                request,
                operation,
                touch=operation.touch_session,
                audit_fields=fields,
            )
            if principal is not None:
                fields["actor"] = principal.email
                fields["role"] = self._role_value(principal)
            self._request_context.principal = principal
            handler = getattr(self, operation.method)
            if operation.mutating:
                with self._lock:
                    value = handler(request, input_spool)
            else:
                value = handler(request, input_spool)
            if isinstance(value, TrustedSpool):
                value.rewind()
                try:
                    response = Response.success(
                        request.request_id,
                        {"stream": True},
                        stream_length=value.length,
                    )
                except Exception:
                    value.close()
                    raise
                result = DispatchResult(response, value)
            else:
                result = DispatchResult(Response.success(request.request_id, value))
            authentication_fields = getattr(self._request_context, "auth_audit", None)
            if isinstance(authentication_fields, Mapping):
                fields.update(authentication_fields)
            if operation.audit_success:
                self.audit("helper.operation", outcome="ok", fields=fields)
            return result
        except Exception as exc:
            code, message = self._safe_error(exc)
            self.audit(
                "helper.operation",
                outcome=code,
                fields={**fields, "error_type": type(exc).__name__},
            )
            return DispatchResult(Response.failure(request.request_id, code, message))
        finally:
            self._request_context.principal = None
            self._request_context.auth_audit = None

    @staticmethod
    def _safe_error(exc: Exception) -> tuple[str, str]:
        auth_error = type(exc).__name__
        if auth_error == "LoginRateLimitedError":
            return "rate_limited", "Authentication rate limit exceeded"
        if auth_error in {"InvalidSessionError"}:
            return "unauthorized", "Authentication is required"
        if auth_error in {"InvalidChallengeError"}:
            return "invalid_challenge", "Authentication challenge is invalid or expired"
        if auth_error in {"InvalidSecondFactorError"}:
            return "invalid_second_factor", "The authentication code is invalid"
        if auth_error in {"InvalidPasskeyError"}:
            return "invalid_credentials", "The authentication request was rejected"
        if auth_error in {"PasskeyLimitError"}:
            return "limit_exceeded", "The passkey limit has been reached"
        if auth_error in {"AccountNotFoundError", "EnrollmentStateError"}:
            return "invalid_credentials", "Email address or password is invalid"
        if isinstance(exc, InvalidCredentials):
            return "invalid_credentials", "Email address or password is invalid"
        if isinstance(exc, PasswordChangeRequired):
            return "password_change_required", "Mailbox password change is required"
        if isinstance(exc, StepUpRequired):
            return "step_up_required", "Recent authentication is required"
        if isinstance(exc, AuthorizationDenied):
            return (
                "forbidden",
                "The authenticated identity is not allowed to perform this operation",
            )
        if isinstance(exc, SMTPOutcomeUnknown):
            return "smtp_outcome_unknown", "Delivery outcome is unknown; do not retry automatically"
        if isinstance(exc, SMTPRejected):
            if exc.stage == "AUTH":
                return (
                    "smtp_authentication_rejection",
                    "SMTP authentication was rejected",
                )
            kind = "temporary" if exc.temporary else "permanent"
            return f"smtp_{kind}_rejection", f"SMTP rejected {exc.stage} ({exc.code})"
        if isinstance(exc, SMTPTransportError):
            return "smtp_transport", "Local SMTP transport failed before acceptance"
        if auth_error == "MailRuleNotFoundError":
            return "not_found", "Mail rule or existing-mail run does not exist"
        if auth_error == "MailRuleConflictError" or isinstance(exc, RuleMailboxConflict):
            return "conflict", "Mail rule state conflicts with this operation"
        if auth_error == "MailRuleLimitError":
            return "limit_exceeded", "The mail rule limit has been reached"
        if isinstance(exc, (ValueError, InvalidMaddyArgument, ProtocolError, StreamError)):
            return "invalid_request", "Request parameters are invalid"
        if isinstance(exc, (UnsupportedVersion, UnsupportedCapability)):
            return "unsupported_maddy", "Installed Maddy version does not support this operation"
        if isinstance(
            exc,
            (CapabilityFingerprintError, LegacyLDAPUnsafe, RuntimeConfigUnsafe),
        ):
            return "writes_disabled", "Maddy write safety checks did not pass"
        if isinstance(exc, (CommandTimeout, TimeoutError)):
            return "timeout", "Privileged operation timed out"
        if isinstance(exc, (CommandOutputLimit, CommandInputError)):
            return "limit_exceeded", "Privileged operation exceeded a configured limit"
        if isinstance(exc, StaleMessageCursor):
            return "stale_cursor", "Mailbox changed; refresh before continuing"
        if isinstance(exc, (CommandFailed, CommandLaunchError, PartialOperationError, MaddyError)):
            return "maddy_failed", "Maddy administration operation failed"
        if isinstance(exc, (CertificateCommandError, CertificateError)):
            return "certificate_failed", "Certificate operation failed"
        return "internal_error", "Privileged helper failed safely"

    def _version(self, request: Request, _spool: TrustedSpool | None) -> Any:
        _params(request)
        return self.maddy.version_info()

    def _maddy_health(self, request: Request, _spool: TrustedSpool | None) -> Any:
        _params(request)
        info = self.maddy.version_info()
        self.maddy.list_accounts(include_append_limits=False)
        return {
            "available": True,
            "version": info["version"],
            "writes_enabled": info["writes_enabled"],
            "write_block_reason": info["write_block_reason"],
            "mode": info["mode"],
            "storage_available": True,
        }

    def _verify_config(self, request: Request, _spool: TrustedSpool | None) -> Any:
        _params(request)
        return {"output": self.maddy.verify_config()}

    @staticmethod
    def _client_ip(value: Any) -> str:
        if not isinstance(value, str) or len(value) > 64:
            raise ValueError("client IP is invalid")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("client IP is invalid") from exc

    @staticmethod
    def _client_user_agent(value: Any) -> str | None:
        if not isinstance(value, str):
            raise ValueError("user agent is invalid")
        normalized = value.strip()
        if not normalized:
            return None
        if len(normalized) > 512 or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in normalized
        ):
            raise ValueError("user agent is invalid")
        return normalized

    @staticmethod
    def _passkey_credential(value: Any) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise ValueError("passkey credential must be an object")
        credential = dict(value)
        try:
            encoded = json.dumps(
                credential,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("passkey credential must be valid JSON") from exc
        if not 1 <= len(encoded) <= 64 * 1024:
            raise ValueError("passkey credential exceeds the safety limit")
        return credential

    @staticmethod
    def _passkey_name(value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("passkey name must be text")
        normalized = value.strip()
        if not 1 <= len(normalized) <= 100 or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in normalized
        ):
            raise ValueError("passkey name is invalid")
        return normalized

    @staticmethod
    def _public_auth_id(value: Any, label: str) -> str:
        if (
            not isinstance(value, str)
            or len(value) != 32
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError(f"{label} is invalid")
        return value

    def _principal_payload(self, principal: Any) -> dict[str, Any]:
        if self.auth_store is None:
            raise RuntimeError("authentication service is unavailable")
        return {
            "account_id": principal.account_id,
            "email": principal.email,
            "role": self._role_value(principal),
            "password_change_required": principal.password_change_required,
            "enrollment_state": str(
                getattr(principal.enrollment_state, "value", principal.enrollment_state)
            ),
            "recovery_codes_remaining": self.auth_store.recovery_code_count(principal.account_id),
            "idle_expires_at": principal.idle_expires_at,
            "absolute_expires_at": principal.absolute_expires_at,
            "step_up_until": principal.step_up_until,
            "session_id": principal.session_id,
        }

    def _issued_session_payload(
        self,
        issued: Any,
        *,
        recovery_codes: Sequence[str] = (),
    ) -> dict[str, Any]:
        return {
            "session_token": issued.token,
            "principal": self._principal_payload(issued.principal),
            "recovery_codes": list(recovery_codes),
        }

    def _auth_password_begin(self, request: Request, _spool: TrustedSpool | None) -> Any:
        if self.auth_store is None or self.smtp is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(
            request,
            required={"email", "password", "client_ip"},
        )
        email = _email_address(values["email"], "email address").casefold()
        password = self.smtp._validated_password(values["password"])
        client_ip = self._client_ip(values["client_ip"])
        self.auth_store.check_login_rate(email, client_ip)
        try:
            self.smtp.authenticate(username=email, password=password)
        except SMTPRejected as exc:
            if exc.stage == "AUTH":
                self.auth_store.record_login_result(email, client_ip, success=False)
                raise InvalidCredentials("email address or password is invalid") from exc
            raise
        account_record = self._maddy_account(email)
        if (
            account_record is None
            or account_record.get("has_credentials") is not True
            or account_record.get("has_mailbox") is not True
        ):
            self.auth_store.record_login_result(email, client_ip, success=False)
            raise InvalidCredentials("email address or password is invalid")
        accounts = self.auth_store.sync_accounts(
            (email,),
            password_change_required=False,
        )
        if len(accounts) != 1:
            raise RuntimeError("authentication metadata synchronization failed")
        account = accounts[0]
        challenge = self.auth_store.create_pending_challenge(email)
        self._set_auth_audit(account, method="password", client_ip=client_ip)
        enrollment_state = str(getattr(account.enrollment_state, "value", account.enrollment_state))
        return {
            "challenge": challenge,
            "next": "totp" if enrollment_state == "active" else "enrollment",
        }

    def _auth_enrollment_begin(self, request: Request, _spool: TrustedSpool | None) -> Any:
        if self.auth_store is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(request, required={"challenge"})
        enrollment = self.auth_store.begin_totp_enrollment(values["challenge"])
        return {
            "secret": enrollment.secret,
            "provisioning_uri": enrollment.provisioning_uri,
        }

    def _auth_enrollment_complete(
        self,
        request: Request,
        _spool: TrustedSpool | None,
    ) -> Any:
        if self.auth_store is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(
            request,
            required={"challenge", "code", "client_ip", "user_agent"},
        )
        client_ip = self._client_ip(values["client_ip"])
        result = self.auth_store.confirm_totp_enrollment(
            values["challenge"],
            values["code"],
            client_ip=client_ip,
            user_agent=self._client_user_agent(values["user_agent"]),
        )
        self.auth_store.record_login_result(
            result.session.principal.email,
            client_ip,
            success=True,
        )
        self._set_auth_audit(
            result.session.principal,
            method="totp_enrollment",
            client_ip=client_ip,
        )
        return self._issued_session_payload(
            result.session,
            recovery_codes=result.recovery_codes,
        )

    def _auth_totp_complete(self, request: Request, _spool: TrustedSpool | None) -> Any:
        if self.auth_store is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(
            request,
            required={"challenge", "code", "client_ip", "user_agent"},
        )
        client_ip = self._client_ip(values["client_ip"])
        issued = self.auth_store.complete_totp_challenge(
            values["challenge"],
            values["code"],
            client_ip=client_ip,
            user_agent=self._client_user_agent(values["user_agent"]),
        )
        self.auth_store.record_login_result(issued.principal.email, client_ip, success=True)
        self._set_auth_audit(issued.principal, method="totp", client_ip=client_ip)
        return self._issued_session_payload(issued)

    def _auth_recovery_complete(
        self,
        request: Request,
        _spool: TrustedSpool | None,
    ) -> Any:
        if self.auth_store is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(
            request,
            required={"challenge", "recovery_code", "client_ip", "user_agent"},
        )
        client_ip = self._client_ip(values["client_ip"])
        issued = self.auth_store.complete_recovery_challenge(
            values["challenge"],
            values["recovery_code"],
            client_ip=client_ip,
            user_agent=self._client_user_agent(values["user_agent"]),
        )
        self.auth_store.record_login_result(issued.principal.email, client_ip, success=True)
        self._set_auth_audit(
            issued.principal,
            method="recovery_code",
            client_ip=client_ip,
        )
        return self._issued_session_payload(issued)

    @staticmethod
    def _passkey_payload(passkey: Any) -> dict[str, Any]:
        return {
            "id": passkey.public_id,
            "name": passkey.name,
            "device_type": passkey.device_type,
            "backed_up": passkey.backed_up,
            "transports": list(passkey.transports),
            "created_at": passkey.created_at,
            "last_used_at": passkey.last_used_at,
        }

    @staticmethod
    def _passkey_ceremony_payload(ceremony: Any) -> dict[str, Any]:
        return {
            "challenge": ceremony.challenge_token,
            "options": ceremony.options,
        }

    def _auth_passkey_login_begin(
        self,
        request: Request,
        _spool: TrustedSpool | None,
    ) -> Any:
        if self.auth_store is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(request, required={"client_ip"})
        client_ip = self._client_ip(values["client_ip"])
        self.auth_store.check_passkey_login_rate(client_ip)
        ceremony = self.auth_store.begin_passkey_login()
        return self._passkey_ceremony_payload(ceremony)

    def _auth_passkey_login_complete(
        self,
        request: Request,
        _spool: TrustedSpool | None,
    ) -> Any:
        if self.auth_store is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(
            request,
            required={"challenge", "credential", "client_ip", "user_agent"},
        )
        client_ip = self._client_ip(values["client_ip"])
        try:
            identity = self.auth_store.verify_passkey_login(
                values["challenge"],
                self._passkey_credential(values["credential"]),
            )
        except Exception as exc:
            if type(exc).__name__ in {
                "AccountNotFoundError",
                "InvalidChallengeError",
                "InvalidPasskeyError",
            }:
                raise InvalidCredentials("authentication request was rejected") from exc
            raise
        account_record = self._maddy_account(identity.email)
        if (
            account_record is None
            or account_record.get("has_credentials") is not True
            or account_record.get("has_mailbox") is not True
        ):
            raise InvalidCredentials("authentication request was rejected")
        self.auth_store.record_passkey_login_result(client_ip, success=True)
        try:
            issued = self.auth_store.issue_verified_passkey_session(
                identity,
                client_ip=client_ip,
                user_agent=self._client_user_agent(values["user_agent"]),
            )
        except Exception as exc:
            if type(exc).__name__ == "AccountNotFoundError":
                raise InvalidCredentials("authentication request was rejected") from exc
            raise
        self._set_auth_audit(issued.principal, method="passkey", client_ip=client_ip)
        return self._issued_session_payload(issued)

    def _auth_passkeys_list(self, request: Request, _spool: TrustedSpool | None) -> Any:
        _params(request)
        if self.auth_store is None:
            raise RuntimeError("authentication service is unavailable")
        principal = self._current_principal()
        return {
            "passkeys": [
                self._passkey_payload(passkey)
                for passkey in self.auth_store.list_passkeys(principal.account_id)
            ]
        }

    def _auth_passkey_register_begin(
        self,
        request: Request,
        _spool: TrustedSpool | None,
    ) -> Any:
        _params(request)
        if self.auth_store is None or request.auth_token is None:
            raise RuntimeError("authentication service is unavailable")
        ceremony = self.auth_store.begin_passkey_registration(request.auth_token)
        return self._passkey_ceremony_payload(ceremony)

    def _auth_passkey_register_complete(
        self,
        request: Request,
        _spool: TrustedSpool | None,
    ) -> Any:
        if self.auth_store is None or request.auth_token is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(request, required={"challenge", "credential", "name"})
        passkey = self.auth_store.complete_passkey_registration(
            request.auth_token,
            values["challenge"],
            self._passkey_credential(values["credential"]),
            name=self._passkey_name(values["name"]),
        )
        return {"passkey": self._passkey_payload(passkey)}

    def _auth_passkey_delete(self, request: Request, _spool: TrustedSpool | None) -> Any:
        if self.auth_store is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(request, required={"passkey_id", "confirm"})
        _confirmed(values)
        principal = self._current_principal()
        passkey_id = self._public_auth_id(values["passkey_id"], "passkey identifier")
        return {"deleted": self.auth_store.delete_passkey(principal.account_id, passkey_id)}

    def _auth_passkey_step_up_begin(
        self,
        request: Request,
        _spool: TrustedSpool | None,
    ) -> Any:
        _params(request)
        if self.auth_store is None or request.auth_token is None:
            raise RuntimeError("authentication service is unavailable")
        ceremony = self.auth_store.begin_passkey_step_up(request.auth_token)
        return self._passkey_ceremony_payload(ceremony)

    def _auth_passkey_step_up_complete(
        self,
        request: Request,
        _spool: TrustedSpool | None,
    ) -> Any:
        if self.auth_store is None or request.auth_token is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(request, required={"challenge", "credential"})
        principal = self.auth_store.complete_passkey_step_up(
            request.auth_token,
            values["challenge"],
            self._passkey_credential(values["credential"]),
        )
        return {
            "step_up_expires_in": 300,
            "step_up_until": principal.step_up_until,
        }

    def _auth_sessions_list(self, request: Request, _spool: TrustedSpool | None) -> Any:
        _params(request)
        if self.auth_store is None or request.auth_token is None:
            raise RuntimeError("authentication service is unavailable")
        principal = self._current_principal()
        sessions = self.auth_store.list_sessions(
            principal.account_id,
            current_session_token=request.auth_token,
        )
        return {
            "sessions": [
                {
                    "id": session.session_id,
                    "created_at": session.created_at,
                    "last_seen_at": session.last_seen_at,
                    "idle_expires_at": session.idle_expires_at,
                    "absolute_expires_at": session.absolute_expires_at,
                    "step_up_until": session.step_up_until,
                    "client_ip": session.client_ip,
                    "user_agent": session.user_agent,
                    "current": session.current,
                }
                for session in sessions
            ]
        }

    def _auth_session_revoke_other(
        self,
        request: Request,
        _spool: TrustedSpool | None,
    ) -> Any:
        if self.auth_store is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(request, required={"session_id", "confirm"})
        _confirmed(values)
        principal = self._current_principal()
        session_id = self._public_auth_id(values["session_id"], "session identifier")
        if principal.session_id is None or session_id == principal.session_id:
            raise AuthorizationDenied("the current session cannot be remotely revoked")
        return {
            "revoked": self.auth_store.revoke_session_by_id(
                principal.account_id,
                session_id,
            )
        }

    def _auth_session(self, request: Request, _spool: TrustedSpool | None) -> Any:
        _params(request)
        return self._principal_payload(self._current_principal())

    def _auth_logout(self, request: Request, _spool: TrustedSpool | None) -> Any:
        _params(request)
        if self.auth_store is None or request.auth_token is None:
            raise AuthorizationDenied("authentication is required")
        self.auth_store.revoke_session(request.auth_token)
        return {"logged_out": True}

    def _auth_change_password(self, request: Request, _spool: TrustedSpool | None) -> Any:
        if self.auth_store is None or self.smtp is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(
            request,
            required={"current_password", "new_password", "client_ip"},
        )
        principal = self._current_principal()
        current_password = self.smtp._validated_password(values["current_password"])
        new_password = self.smtp._validated_password(values["new_password"])
        client_ip = self._client_ip(values["client_ip"])
        self.auth_store.check_login_rate(principal.email, client_ip)
        try:
            self.smtp.authenticate(username=principal.email, password=current_password)
        except SMTPRejected as exc:
            if exc.stage == "AUTH":
                self.auth_store.record_login_result(
                    principal.email,
                    client_ip,
                    success=False,
                )
                raise InvalidCredentials("email address or password is invalid") from exc
            raise
        self.auth_store.revoke_sessions(principal.account_id)
        self.maddy.change_password(principal.email, new_password)
        self.auth_store.set_password_change_required(
            principal.account_id,
            False,
            revoke_sessions=False,
        )
        self.auth_store.record_login_result(principal.email, client_ip, success=True)
        return {"changed": True, "reauthenticate": True}

    def _auth_recovery_regenerate(
        self,
        request: Request,
        _spool: TrustedSpool | None,
    ) -> Any:
        if self.auth_store is None or self.smtp is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(request, required={"password", "code", "client_ip"})
        principal = self._current_principal()
        password = self.smtp._validated_password(values["password"])
        client_ip = self._client_ip(values["client_ip"])
        self.auth_store.check_login_rate(principal.email, client_ip)
        try:
            self.smtp.authenticate(username=principal.email, password=password)
        except SMTPRejected as exc:
            if exc.stage == "AUTH":
                self.auth_store.record_login_result(
                    principal.email,
                    client_ip,
                    success=False,
                )
                raise InvalidCredentials("email address or password is invalid") from exc
            raise
        codes = self.auth_store.regenerate_recovery_codes(
            principal.account_id,
            values["code"],
        )
        self.auth_store.record_login_result(principal.email, client_ip, success=True)
        return {"recovery_codes": list(codes), "reauthenticate": True}

    def _auth_step_up(self, request: Request, _spool: TrustedSpool | None) -> Any:
        if self.auth_store is None or self.smtp is None or request.auth_token is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(request, required={"password", "code", "client_ip"})
        principal = self._current_principal()
        password = self.smtp._validated_password(values["password"])
        client_ip = self._client_ip(values["client_ip"])
        self.auth_store.check_login_rate(principal.email, client_ip)
        try:
            self.smtp.authenticate(username=principal.email, password=password)
        except SMTPRejected as exc:
            if exc.stage == "AUTH":
                self.auth_store.record_login_result(
                    principal.email,
                    client_ip,
                    success=False,
                )
                raise InvalidCredentials("email address or password is invalid") from exc
            raise
        self.auth_store.verify_totp(principal.account_id, values["code"])
        self.auth_store.mark_step_up(request.auth_token)
        self.auth_store.record_login_result(principal.email, client_ip, success=True)
        return {"step_up_expires_in": 300}

    def _auth_admin_rotate_totp(
        self,
        request: Request,
        _spool: TrustedSpool | None,
    ) -> Any:
        if self.auth_store is None:
            raise RuntimeError("authentication service is unavailable")
        values = _params(request, required={"target_account_id", "confirm"})
        _confirmed(values)
        target = self.auth_store.resolve_account_id(values["target_account_id"])
        enrollment, recovery_codes = self.auth_store.rotate_totp(target.account_id)
        return {
            "account_id": target.account_id,
            "email": target.email,
            "totp_secret": enrollment.secret,
            "totp_uri": enrollment.provisioning_uri,
            "recovery_codes": list(recovery_codes),
        }

    def _accounts_list(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, optional={"include_append_limits"})
        include_append_limits = values.get("include_append_limits", True)
        if type(include_append_limits) is not bool:
            raise ValueError("include_append_limits must be a boolean")
        records = self.maddy.list_accounts(include_append_limits=include_append_limits)
        if self.auth_store is None:
            return records
        accounts = self.auth_store.sync_accounts(
            record["username"] for record in records if isinstance(record.get("username"), str)
        )
        metadata = {account.email.casefold(): account for account in accounts}
        result: list[dict[str, Any]] = []
        for record in records:
            account = metadata.get(str(record.get("username", "")).casefold())
            if account is None:
                raise RuntimeError("authentication metadata synchronization failed")
            result.append(
                {
                    **record,
                    "id": account.account_id,
                    "address": account.email,
                    "role": self._role_value(account),
                    "enrollment_state": str(
                        getattr(account.enrollment_state, "value", account.enrollment_state)
                    ),
                    "password_change_required": account.password_change_required,
                }
            )
        return result

    def _accounts_create(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "password"})
        created = self.maddy.create_account(values["username"], values["password"])
        if self.auth_store is None:
            return created
        try:
            account, enrollment, recovery_codes = self.auth_store.provision_active_account(
                values["username"],
                password_change_required=False,
            )
        except Exception as exc:
            try:
                self.maddy.delete_account(values["username"])
            except Exception as rollback_exc:
                raise PartialOperationError(
                    "account authentication setup failed and Maddy rollback was not verified",
                    completed=("credentials.create", "mailbox.create"),
                    rollback_succeeded=False,
                ) from rollback_exc
            raise PartialOperationError(
                "account authentication setup failed; Maddy account was rolled back",
                completed=("credentials.create", "mailbox.create"),
                rollback_succeeded=True,
            ) from exc
        return {
            **created,
            "id": account.account_id,
            "address": account.email,
            "role": self._role_value(account),
            "totp_secret": enrollment.secret,
            "totp_uri": enrollment.provisioning_uri,
            "recovery_codes": list(recovery_codes),
        }

    def _accounts_password(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "password"})
        target = (
            self.auth_store.get_account(values["username"]) if self.auth_store is not None else None
        )
        if self.auth_store is not None and target is None:
            raise RuntimeError("authentication metadata synchronization failed")
        if self.auth_store is not None and target is not None:
            self.auth_store.set_password_change_required(
                target.account_id,
                True,
                revoke_sessions=True,
            )
        self.maddy.change_password(values["username"], values["password"])
        return {"changed": True}

    def _accounts_disable(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "confirm"})
        _confirmed(values)
        self.maddy.disable_credentials(values["username"])
        if self.auth_store is not None:
            target = self.auth_store.get_account(values["username"])
            if target is not None:
                self.auth_store.revoke_sessions(target.account_id)
        return {"credentials_disabled": True}

    def _accounts_delete_imap(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "confirm"})
        _confirmed(values)
        account_record = self._maddy_account(values["username"])
        target = (
            self.auth_store.get_account(values["username"]) if self.auth_store is not None else None
        )
        if account_record is not None and account_record.get("has_credentials") is True:
            self.maddy.disable_credentials(values["username"])
            if target is not None:
                self.auth_store.revoke_sessions(target.account_id)
        if account_record is not None and account_record.get("has_mailbox") is True:
            self.maddy.delete_imap_account(values["username"])
        if self.auth_store is not None and target is not None:
            if self.rule_snapshot_dir is not None:
                remove_snapshot(self.rule_snapshot_dir, target.email)
            self.auth_store.delete_account(target.account_id)
        return {"imap_account_deleted": True}

    def _append_limit_get(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username"})
        return {"append_limit": self.maddy.get_append_limit(values["username"])}

    def _append_limit_set(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "value"})
        return {"append_limit": self.maddy.set_append_limit(values["username"], values["value"])}

    def _mailboxes_list(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username"}, optional={"subscribed_only"})
        return self.maddy.list_mailboxes(
            values["username"], subscribed_only=values.get("subscribed_only", False)
        )

    def _mailboxes_create(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "mailbox"}, optional={"special"})
        self.maddy.create_mailbox(
            values["username"], values["mailbox"], special=values.get("special")
        )
        return {"created": True}

    def _mailboxes_delete(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "mailbox", "confirm"})
        _confirmed(values)
        if self.auth_store is not None:
            account = self._rule_account(values["username"])
            if self.auth_store.mailbox_rule_reference_count(
                account.account_id,
                values["mailbox"],
            ):
                raise RuleMailboxConflict("mailbox is referenced by a mail rule")
        if self.maddy.list_message_window(
            values["username"],
            values["mailbox"],
            limit=1,
        ):
            raise ValueError("mailbox must be empty before deletion")
        self.maddy.delete_mailbox(values["username"], values["mailbox"])
        return {"deleted": True}

    def _mailboxes_rename(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "old_name", "new_name"})
        if self.auth_store is not None:
            account = self._rule_account(values["username"])
            if self.auth_store.mailbox_rule_reference_count(
                account.account_id,
                values["old_name"],
            ):
                raise RuleMailboxConflict("mailbox is referenced by a mail rule")
        self.maddy.rename_mailbox(values["username"], values["old_name"], values["new_name"])
        return {"renamed": True}

    def _rule_account(self, username: str) -> Any:
        if self.auth_store is None:
            raise RuntimeError("mail rule storage is unavailable")
        account = self.auth_store.get_account(username)
        if account is None:
            raise ValueError("mail rule account does not exist")
        return account

    @staticmethod
    def _rule_expression(values: Mapping[str, Any]) -> dict[str, object]:
        aliases = [name for name in ("match", "expression", "condition") if name in values]
        if len(aliases) != 1:
            raise ValueError("exactly one mail rule condition must be supplied")
        condition = condition_from_mapping(values[aliases[0]])
        return condition_to_mapping(condition)

    def _require_rule_target(
        self,
        username: str,
        target_mailbox: Any,
        *,
        mailboxes: Sequence[Mapping[str, Any]] | None = None,
    ) -> str:
        expression = {"field": "subject", "operator": "exists"}
        target = Rule.from_mapping(
            {"condition": expression, "target_mailbox": target_mailbox}
        ).target_mailbox
        records = self.maddy.list_mailboxes(username) if mailboxes is None else mailboxes
        names = [record.get("name") for record in records if isinstance(record, Mapping)]
        if not any(
            name == target
            or (
                isinstance(name, str)
                and name.casefold() == "inbox"
                and target.casefold() == "inbox"
            )
            for name in names
        ):
            raise ValueError("mail rule target mailbox does not exist")
        return target

    @staticmethod
    def _mail_rule_payload(rule: Any) -> dict[str, object]:
        return {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "enabled": rule.enabled,
            "position": rule.position,
            "match": rule.expression,
            "target_mailbox": rule.target_mailbox,
            "stop_processing": rule.stop_processing,
            "revision": rule.revision,
            "created_at": rule.created_at,
            "updated_at": rule.updated_at,
        }

    @staticmethod
    def _mail_rule_run_payload(run: Any) -> dict[str, object]:
        rule_name = run.rule_snapshot.get("rule_name")
        payload: dict[str, object] = {
            "run_id": run.run_id,
            "rule_id": run.rule_id,
            "status": run.status,
            "processed": run.scanned,
            "matched": run.matched,
            "moved": run.moved,
            "failed": run.failed,
            "created_at": run.created_at,
            "started_at": run.started_at,
            "updated_at": run.updated_at,
            "finished_at": run.finished_at,
            "error_code": run.error_code,
        }
        if isinstance(rule_name, str) and rule_name:
            payload["rule_name"] = rule_name
        total = run.state.get("total")
        if type(total) is int and total >= 0:
            payload["total"] = total
        return payload

    @staticmethod
    def _bounded_mail_rule_result(
        rules: Sequence[Mapping[str, object]],
        *,
        active_run: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "rules": [dict(rule) for rule in rules],
            "active_run": None if active_run is None else dict(active_run),
        }
        try:
            size = len(
                json.dumps(
                    result,
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("mail rule response is not valid JSON") from exc
        if size > _MAX_RULE_RESPONSE_BYTES:
            raise CommandOutputLimit("mail rule collection exceeds the response frame budget")
        return result

    def _mail_rule_list_result(self, account: Any) -> dict[str, object]:
        active_run = self.auth_store.get_active_mail_rule_run(account.account_id)
        return self._bounded_mail_rule_result(
            [
                self._mail_rule_payload(rule)
                for rule in self.auth_store.list_mail_rules(account.account_id)
            ],
            active_run=(
                None if active_run is None else self._mail_rule_run_payload(active_run)
            ),
        )

    def _mail_rule_snapshot_records(self, account: Any) -> list[dict[str, object]]:
        records = self.auth_store.list_mail_rules(account.account_id)
        return [
            {
                "rule_id": rule.rule_id,
                "enabled": rule.enabled,
                "position": rule.position,
                "condition": rule.expression,
                "target_mailbox": rule.target_mailbox,
                "stop_processing": rule.stop_processing,
                "revision": rule.revision,
            }
            for rule in records
        ]

    def _reconcile_mail_rule_snapshots(self) -> None:
        if self.rule_snapshot_dir is None:
            return
        snapshots = {
            account.email: self._mail_rule_snapshot_records(account)
            for account in self.auth_store.list_accounts()
        }
        replace_snapshot_set(
            self.rule_snapshot_dir,
            snapshots,
            group_id=self.rule_snapshot_group_id,
        )

    def _publish_mail_rules(self, account: Any) -> None:
        if self.rule_snapshot_dir is None:
            return
        publish_snapshot(
            self.rule_snapshot_dir,
            account.email,
            self._mail_rule_snapshot_records(account),
            group_id=self.rule_snapshot_group_id,
        )

    def _pause_mail_rule_delivery(self, account: Any) -> None:
        if self.rule_snapshot_dir is None:
            return
        publish_snapshot(
            self.rule_snapshot_dir,
            account.email,
            [],
            group_id=self.rule_snapshot_group_id,
        )

    def _publish_mail_rules_after_mutation(self, account: Any) -> bool:
        try:
            self._publish_mail_rules(account)
        except (OSError, RuleSnapshotError, ValueError) as exc:
            self.audit(
                "mail_rules.snapshot",
                outcome="pending",
                fields={"account": account.email, "error_type": type(exc).__name__},
            )
            return False
        return True

    def _rules_list(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username"})
        account = self._rule_account(values["username"])
        return self._mail_rule_list_result(account)

    def _rules_create(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(
            request,
            required={"username", "name", "enabled", "target_mailbox", "stop_processing"},
            optional={"match", "expression", "condition", "apply_existing"},
        )
        apply_existing = values.get("apply_existing", False)
        if type(apply_existing) is not bool:
            raise ValueError("apply_existing must be a boolean")
        account = self._rule_account(values["username"])
        if (
            apply_existing
            and self.auth_store.get_active_mail_rule_run(account.account_id) is not None
        ):
            raise RuleMailboxConflict("an existing-mail rule run is already active")
        expression = self._rule_expression(values)
        target = self._require_rule_target(values["username"], values["target_mailbox"])
        prepared_run_state = (
            self._new_rule_run_state(values["username"], target) if apply_existing else None
        )
        existing = [
            self._mail_rule_payload(item)
            for item in self.auth_store.list_mail_rules(account.account_id)
        ]
        self._bounded_mail_rule_result(
            [
                *existing,
                {
                    "rule_id": "0" * 32,
                    "name": values["name"],
                    "enabled": values["enabled"],
                    "position": len(existing),
                    "match": expression,
                    "target_mailbox": target,
                    "stop_processing": values["stop_processing"],
                    "revision": 1,
                    "created_at": 9_999_999_999,
                    "updated_at": 9_999_999_999,
                },
            ]
        )
        self._pause_mail_rule_delivery(account)
        run = None
        try:
            if apply_existing:
                if prepared_run_state is None:
                    raise RuntimeError("mail rule run state is unexpectedly unavailable")
                source_mailboxes = prepared_run_state["mailboxes"]
                mailbox_index = prepared_run_state["mailbox_index"]
                if not isinstance(source_mailboxes, list) or type(mailbox_index) is not int:
                    raise RuntimeError("mail rule run state is unexpectedly invalid")
                rule, run = self.auth_store.create_mail_rule_with_run(
                    account.account_id,
                    name=values["name"],
                    enabled=values["enabled"],
                    expression=expression,
                    target_mailbox=target,
                    stop_processing=values["stop_processing"],
                    run_state=prepared_run_state,
                    run_completed=mailbox_index == len(source_mailboxes),
                )
            else:
                rule = self.auth_store.create_mail_rule(
                    account.account_id,
                    name=values["name"],
                    enabled=values["enabled"],
                    expression=expression,
                    target_mailbox=target,
                    stop_processing=values["stop_processing"],
                )
        except Exception:
            # A failed database transaction must not leave delivery paused for
            # rules that remain authoritative and unchanged.
            self._publish_mail_rules_after_mutation(account)
            raise
        delivery_ready = self._publish_mail_rules_after_mutation(account)
        result: dict[str, object] = {
            "rule": self._mail_rule_payload(rule),
            "delivery_ready": delivery_ready,
        }
        if run is not None:
            result["run"] = self._mail_rule_run_payload(run)
        return result

    def _rules_update(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(
            request,
            required={
                "username",
                "rule_id",
                "name",
                "enabled",
                "target_mailbox",
                "stop_processing",
            },
            optional={
                "match",
                "expression",
                "condition",
                "expected_revision",
                "revision",
            },
        )
        revision_fields = {"expected_revision", "revision"} & set(values)
        if len(revision_fields) != 1:
            raise ValueError("mail rule revision must be supplied exactly once")
        account = self._rule_account(values["username"])
        current = self.auth_store.get_mail_rule(account.account_id, values["rule_id"])
        expected_revision = values[next(iter(revision_fields))]
        if type(expected_revision) is not int or expected_revision < 1:
            raise ValueError("mail rule revision must be a positive integer")
        if expected_revision != current.revision:
            raise RuleMailboxConflict("mail rule revision is stale")
        expression = self._rule_expression(values)
        target = self._require_rule_target(values["username"], values["target_mailbox"])
        prospective: list[dict[str, object]] = []
        for item in self.auth_store.list_mail_rules(account.account_id):
            payload = self._mail_rule_payload(item)
            if item.rule_id == current.rule_id:
                payload.update(
                    {
                        "name": values["name"],
                        "enabled": values["enabled"],
                        "match": expression,
                        "target_mailbox": target,
                        "stop_processing": values["stop_processing"],
                        "revision": current.revision + 1,
                    }
                )
            prospective.append(payload)
        self._bounded_mail_rule_result(prospective)
        self._pause_mail_rule_delivery(account)
        rule = self.auth_store.update_mail_rule(
            account.account_id,
            current.rule_id,
            expected_revision=expected_revision,
            name=values["name"],
            enabled=values["enabled"],
            expression=expression,
            target_mailbox=target,
            stop_processing=values["stop_processing"],
        )
        delivery_ready = self._publish_mail_rules_after_mutation(account)
        return {
            "rule": self._mail_rule_payload(rule),
            "delivery_ready": delivery_ready,
        }

    def _rules_delete(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "rule_id"})
        account = self._rule_account(values["username"])
        self.auth_store.get_mail_rule(account.account_id, values["rule_id"])
        self._pause_mail_rule_delivery(account)
        self.auth_store.delete_mail_rule(account.account_id, values["rule_id"])
        delivery_ready = self._publish_mail_rules_after_mutation(account)
        return {"deleted": True, "delivery_ready": delivery_ready}

    def _rules_reorder(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "rule_ids"})
        account = self._rule_account(values["username"])
        current_rules = self.auth_store.list_mail_rules(account.account_id)
        current_ids = [rule.rule_id for rule in current_rules]
        supplied_ids = values["rule_ids"]
        if (
            not isinstance(supplied_ids, list | tuple)
            or any(not isinstance(rule_id, str) for rule_id in supplied_ids)
            or len(supplied_ids) != len(set(supplied_ids))
            or set(supplied_ids) != set(current_ids)
        ):
            raise ValueError("mail rule order must contain every rule exactly once")
        current_by_id = {
            rule.rule_id: self._mail_rule_payload(rule) for rule in current_rules
        }
        prospective: list[dict[str, object]] = []
        for position, rule_id in enumerate(supplied_ids):
            payload = current_by_id[rule_id]
            payload["position"] = position
            prospective.append(payload)
        # Refuse an unrepresentable response before pausing delivery or
        # changing authoritative metadata. The final response deliberately
        # omits active-run state and has this same bounded rule collection.
        self._bounded_mail_rule_result(prospective)
        self._pause_mail_rule_delivery(account)
        self.auth_store.reorder_mail_rules(account.account_id, values["rule_ids"])
        delivery_ready = self._publish_mail_rules_after_mutation(account)
        result = self._bounded_mail_rule_result(
            [
                self._mail_rule_payload(rule)
                for rule in self.auth_store.list_mail_rules(account.account_id)
            ]
        )
        result.pop("active_run", None)
        result["delivery_ready"] = delivery_ready
        return result

    @staticmethod
    def _rule_run_snapshot(rule: Any) -> dict[str, object]:
        return {
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "condition": rule.expression,
            "target_mailbox": rule.target_mailbox,
            "revision": rule.revision,
        }

    def _new_rule_run_state(self, username: str, target_mailbox: str) -> dict[str, object]:
        records = self.maddy.list_mailboxes(username)
        if len(records) > _MAX_RULE_RUN_MAILBOXES:
            raise ValueError("account has too many mailboxes for an existing-mail run")
        excluded = {target_mailbox.casefold(), "trash", "archive"}
        sources: list[dict[str, object]] = []
        seen: set[str] = set()
        for record in records:
            if not isinstance(record, Mapping):
                raise MaddyError("Maddy returned an invalid mailbox record")
            name = record.get("name")
            attributes = record.get("attributes", ())
            if (
                not isinstance(name, str)
                or not name
                or not isinstance(attributes, list | tuple)
            ):
                raise MaddyError("Maddy returned an invalid mailbox record")
            folded = name.casefold()
            flags = {str(value).casefold() for value in attributes}
            if folded in seen:
                raise MaddyError("Maddy returned duplicate mailbox names")
            seen.add(folded)
            if folded in excluded or flags & {"\\trash", "\\archive"}:
                continue
            cursor = self.maddy.latest_message_uid(username, name)
            sources.append({"mailbox": name, "cursor": cursor, "done": cursor == 0})
        index = 0
        while index < len(sources) and sources[index]["done"] is True:
            index += 1
        return {"mailboxes": sources, "mailbox_index": index}

    def _create_rule_run(
        self,
        account: Any,
        username: str,
        rule: Any,
        *,
        state: dict[str, object] | None = None,
    ) -> Any:
        if self.auth_store.get_active_mail_rule_run(account.account_id) is not None:
            raise RuleMailboxConflict("an existing-mail rule run is already active")
        if state is None:
            self._require_rule_target(username, rule.target_mailbox)
            state = self._new_rule_run_state(username, rule.target_mailbox)
        run = self.auth_store.create_mail_rule_run(
            account.account_id,
            rule.rule_id,
            rule_snapshot=self._rule_run_snapshot(rule),
            state=state,
        )
        if state["mailbox_index"] == len(state["mailboxes"]):
            run = self.auth_store.update_mail_rule_run(
                account.account_id,
                run.run_id,
                state=state,
                status="completed",
                scanned=0,
                matched=0,
                moved=0,
                failed=0,
            )
        return run

    def _rules_run_create(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "rule_id"})
        account = self._rule_account(values["username"])
        rule = self.auth_store.get_mail_rule(account.account_id, values["rule_id"])
        run = self._create_rule_run(account, values["username"], rule)
        return {"run": self._mail_rule_run_payload(run)}

    def _rules_run_status(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "run_id"})
        account = self._rule_account(values["username"])
        run = self.auth_store.get_mail_rule_run(account.account_id, values["run_id"])
        return {"run": self._mail_rule_run_payload(run)}

    @staticmethod
    def _validated_rule_run_state(run: Any) -> tuple[list[dict[str, object]], int]:
        state = run.state
        if not isinstance(state, Mapping) or set(state) != {"mailboxes", "mailbox_index"}:
            raise ValueError("mail rule run state is invalid")
        raw_sources = state.get("mailboxes")
        index = state.get("mailbox_index")
        if (
            not isinstance(raw_sources, list)
            or len(raw_sources) > _MAX_RULE_RUN_MAILBOXES
            or type(index) is not int
            or not 0 <= index <= len(raw_sources)
        ):
            raise ValueError("mail rule run state is invalid")
        sources: list[dict[str, object]] = []
        seen: set[str] = set()
        for raw in raw_sources:
            if not isinstance(raw, Mapping) or set(raw) != {"mailbox", "cursor", "done"}:
                raise ValueError("mail rule run mailbox state is invalid")
            mailbox = raw.get("mailbox")
            cursor = raw.get("cursor")
            done = raw.get("done")
            if (
                not isinstance(mailbox, str)
                or not mailbox
                or mailbox.casefold() in seen
                or type(cursor) is not int
                or not 0 <= cursor <= (1 << 32) - 1
                or type(done) is not bool
                or (done and cursor != 0)
            ):
                raise ValueError("mail rule run mailbox state is invalid")
            seen.add(mailbox.casefold())
            sources.append({"mailbox": mailbox, "cursor": cursor, "done": done})
        return sources, index

    @staticmethod
    def _compiled_rule_run(run: Any) -> Any:
        snapshot = run.rule_snapshot
        if not isinstance(snapshot, Mapping) or set(snapshot) != {
            "rule_id",
            "rule_name",
            "condition",
            "target_mailbox",
            "revision",
        }:
            raise ValueError("mail rule run snapshot is invalid")
        if (
            not isinstance(snapshot.get("rule_id"), str)
            or not isinstance(snapshot.get("rule_name"), str)
            or type(snapshot.get("revision")) is not int
            or int(snapshot["revision"]) < 1
        ):
            raise ValueError("mail rule run snapshot is invalid")
        return compile_rule(
            Rule.from_mapping(
                {
                    "condition": snapshot["condition"],
                    "target_mailbox": snapshot["target_mailbox"],
                }
            )
        )

    def _rules_run_step(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "run_id"})
        account = self._rule_account(values["username"])
        run = self.auth_store.get_mail_rule_run(account.account_id, values["run_id"])
        if run.status in {"completed", "failed", "cancelled"}:
            return {"run": self._mail_rule_run_payload(run)}
        sources, index = self._validated_rule_run_state(run)
        compiled = self._compiled_rule_run(run)
        if run.status == "queued":
            run = self.auth_store.update_mail_rule_run(
                account.account_id,
                run.run_id,
                state={"mailboxes": sources, "mailbox_index": index},
                status="running",
                scanned=run.scanned,
                matched=run.matched,
                moved=run.moved,
                failed=run.failed,
            )
        while index < len(sources) and sources[index]["done"] is True:
            index += 1
        if index >= len(sources):
            completed = self.auth_store.update_mail_rule_run(
                account.account_id,
                run.run_id,
                state={"mailboxes": sources, "mailbox_index": index},
                status="completed",
                scanned=run.scanned,
                matched=run.matched,
                moved=run.moved,
                failed=run.failed,
            )
            return {"run": self._mail_rule_run_payload(completed)}

        source = sources[index]
        mailbox = str(source["mailbox"])
        try:
            records = self.maddy.list_message_window(
                values["username"],
                mailbox,
                limit=_RULE_RUN_BATCH_SIZE,
                cursor_uid=int(source["cursor"]),
            )
            if len(records) > _RULE_RUN_BATCH_SIZE + 1:
                raise MaddyError("Maddy returned an oversized rule-run window")
            ordered = sorted(records, key=lambda item: int(item.get("uid", 0)), reverse=True)
            seen_uids: set[int] = set()
            for record in ordered:
                uid = record.get("uid")
                if (
                    type(uid) is not int
                    or not 1 <= uid <= (1 << 32) - 1
                    or uid in seen_uids
                ):
                    raise MaddyError("Maddy returned an invalid rule-run UID")
                seen_uids.add(uid)
            candidates = ordered[:_RULE_RUN_BATCH_SIZE]
            next_cursor = (
                int(ordered[_RULE_RUN_BATCH_SIZE]["uid"])
                if len(ordered) > _RULE_RUN_BATCH_SIZE
                else 0
            )
            matched_uids: list[str] = []
            for record in candidates:
                uid = int(record["uid"])
                raw_message = self.maddy.dump_message(values["username"], mailbox, uid)
                if compiled.matches_raw(raw_message):
                    matched_uids.append(str(uid))
            if matched_uids:
                self.maddy.move_messages(
                    values["username"],
                    mailbox,
                    _selected_message_uid_set(",".join(matched_uids)),
                    compiled.target_mailbox,
                )
        except MaddyError as exc:
            failed = self.auth_store.update_mail_rule_run(
                account.account_id,
                run.run_id,
                state={"mailboxes": sources, "mailbox_index": index},
                status="failed",
                scanned=run.scanned,
                matched=run.matched,
                moved=run.moved,
                failed=run.failed + 1,
                error_code=(
                    "stale_cursor" if isinstance(exc, StaleMessageCursor) else "maddy_failed"
                ),
            )
            return {"run": self._mail_rule_run_payload(failed)}

        source["cursor"] = next_cursor
        source["done"] = next_cursor == 0
        if source["done"] is True:
            index += 1
            while index < len(sources) and sources[index]["done"] is True:
                index += 1
        status = "completed" if index >= len(sources) else "running"
        updated = self.auth_store.update_mail_rule_run(
            account.account_id,
            run.run_id,
            state={"mailboxes": sources, "mailbox_index": index},
            status=status,
            scanned=run.scanned + len(candidates),
            matched=run.matched + len(matched_uids),
            moved=run.moved + len(matched_uids),
            failed=run.failed,
        )
        return {"run": self._mail_rule_run_payload(updated)}

    def _rules_run_cancel(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "run_id"})
        account = self._rule_account(values["username"])
        run = self.auth_store.cancel_mail_rule_run(account.account_id, values["run_id"])
        return {"run": self._mail_rule_run_payload(run)}

    def _messages_list(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(
            request,
            required={"username", "mailbox", "limit", "offset"},
        )
        limit = values["limit"]
        offset = values["offset"]
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("message page limit must be between 1 and 200")
        if type(offset) is not int or not 0 <= offset <= (1 << 32) - 1:
            raise ValueError("message page cursor is invalid")
        messages = self.maddy.list_message_window(
            values["username"],
            values["mailbox"],
            limit=limit,
            cursor_uid=offset,
        )
        messages.sort(key=lambda item: int(item.get("uid", 0)), reverse=True)
        if len(messages) > limit + 1:
            raise MaddyError("Maddy returned an oversized message window")
        for message in messages:
            uid = message.get("uid")
            if type(uid) is not int or not 1 <= uid <= (1 << 32) - 1:
                raise MaddyError("Maddy returned an invalid message UID")

        current_offset = int(messages[0]["uid"]) if offset == 0 and messages else offset
        candidates = messages[:limit]
        page: list[dict[str, Any]] = []
        for candidate in candidates:
            bounded = {
                key: (value[:512] if isinstance(value, str) else value)
                for key, value in candidate.items()
            }
            trial_page = [*page, bounded]
            trial_next = (
                int(messages[len(trial_page)]["uid"]) if len(trial_page) < len(messages) else None
            )
            trial = {
                "items": trial_page,
                "offset": current_offset,
                "limit": limit,
                "total": None,
                "next_offset": trial_next,
            }
            if len(json.dumps(trial, ensure_ascii=False).encode("utf-8")) > 48 * 1024:
                break
            page.append(bounded)
        if candidates and not page:
            raise CommandOutputLimit("one message record exceeds the response frame limit")
        return {
            "items": page,
            "offset": current_offset,
            "limit": limit,
            "total": None,
            "next_offset": (int(messages[len(page)]["uid"]) if len(page) < len(messages) else None),
        }

    def _messages_latest(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "mailbox"})
        return {
            "uid": self.maddy.latest_message_uid(
                values["username"],
                values["mailbox"],
            )
        }

    def _messages_get(self, request: Request, _spool: TrustedSpool | None) -> TrustedSpool:
        values = _params(request, required={"username", "mailbox", "uid"})
        output = TrustedSpool.create(self.spool_dir)
        try:
            output.length = self.maddy.dump_message_to(
                values["username"], values["mailbox"], values["uid"], output.handle
            )
            if type(output.length) is not int or not 1 <= output.length <= DEFAULT_MAX_STREAM_BYTES:
                raise MaddyError("Maddy returned an invalid message stream length")
            return output
        except Exception:
            output.close()
            raise

    def _messages_append(self, request: Request, spool: TrustedSpool | None) -> Any:
        if spool is None:
            raise ValueError("message append requires a request body")
        values = _params(
            request,
            required={"username", "mailbox_special"},
            optional={"flags", "internal_date"},
        )
        mailbox = self.maddy.resolve_special_mailbox(values["username"], values["mailbox_special"])
        spool.rewind()
        uid = self.maddy.append_message(
            values["username"],
            mailbox,
            spool.handle,
            content_length=spool.length,
            flags=values.get("flags", ()),
            internal_date=values.get("internal_date"),
        )
        return {"uid": uid, "mailbox": mailbox}

    def _messages_delete(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "mailbox", "uid", "confirm"})
        _confirmed(values)
        self.maddy.delete_message(values["username"], values["mailbox"], values["uid"])
        return {"deleted": True}

    def _messages_delete_many(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(
            request,
            required={"username", "mailbox", "uid_set", "confirm"},
        )
        _confirmed(values)
        uid_set = _selected_message_uid_set(values["uid_set"])
        trash = self.maddy.resolve_special_mailbox(values["username"], "trash")
        if values["mailbox"] != trash:
            raise ValueError("bulk permanent deletion is restricted to the Trash mailbox")
        self.maddy.delete_messages(values["username"], trash, uid_set)
        return {"deleted": True}

    def _messages_copy(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "source", "uid_set", "target"})
        self.maddy.copy_messages(
            values["username"], values["source"], values["uid_set"], values["target"]
        )
        return {"copied": True}

    def _messages_move(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(
            request,
            required={"username", "source"},
            optional={"uid", "uid_set", "target_special", "target"},
        )
        if ("uid" in values) is ("uid_set" in values):
            raise ValueError("exactly one message UID selector must be supplied")
        if ("target_special" in values) is ("target" in values):
            raise ValueError("exactly one message target must be supplied")
        target = (
            self.maddy.resolve_special_mailbox(values["username"], values["target_special"])
            if "target_special" in values
            else values["target"]
        )
        if "uid_set" in values:
            self.maddy.move_messages(
                values["username"],
                values["source"],
                _selected_message_uid_set(values["uid_set"]),
                target,
            )
        else:
            self.maddy.move_message(
                values["username"],
                values["source"],
                values["uid"],
                target,
            )
        return {"moved": True, "target": target}

    def _message_flags(self, request: Request, method: str) -> Any:
        values = _params(request, required={"username", "mailbox", "uid_set", "flags"})
        getattr(self.maddy, method)(
            values["username"], values["mailbox"], values["uid_set"], values["flags"]
        )
        return {"changed": True}

    def _messages_set_flags(self, request: Request, _spool: TrustedSpool | None) -> Any:
        return self._message_flags(request, "set_message_flags")

    def _messages_add_flags(self, request: Request, _spool: TrustedSpool | None) -> Any:
        return self._message_flags(request, "add_message_flags")

    def _messages_remove_flags(self, request: Request, _spool: TrustedSpool | None) -> Any:
        return self._message_flags(request, "remove_message_flags")

    def _messages_send(self, request: Request, spool: TrustedSpool | None) -> Any:
        if self.smtp is None:
            raise SMTPTransportError("SMTP submission is not configured")
        if spool is None:
            raise ValueError("message send requires a request body")
        values = _params(
            request,
            required={"username", "password", "mail_from", "recipients"},
        )
        if values["mail_from"] != values["username"]:
            raise ValueError("envelope sender must exactly equal the account username")
        self.maddy.require_write_safety(Capability.MESSAGE_ADMIN)
        account = next(
            (
                item
                for item in self.maddy.list_accounts()
                if item.get("username") == values["username"]
            ),
            None,
        )
        if (
            account is None
            or account.get("has_credentials") is not True
            or account.get("has_mailbox") is not True
        ):
            raise ValueError("SMTP account is disabled or missing")
        spool.rewind()
        return self.smtp.send(
            username=values["username"],
            password=values["password"],
            mail_from=values["mail_from"],
            recipients=values["recipients"],
            message=spool.handle,
            message_length=spool.length,
        )

    def _certificates_list(self, request: Request, _spool: TrustedSpool | None) -> Any:
        _params(request)
        return self.certificates.list_certificates()

    def _certificates_health(self, request: Request, _spool: TrustedSpool | None) -> Any:
        _params(request)
        return self.certificates.health()

    def _certificates_status(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"name"})
        return self.certificates.status(values["name"])

    def _certificates_timer_enable(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"confirm"})
        _confirmed(values)
        return self.certificates.set_timer_enabled(True)

    def _certificates_timer_disable(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"confirm"})
        _confirmed(values)
        return self.certificates.set_timer_enabled(False)

    def _certificates_dry_run(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"name"})
        return self.certificates.dry_run(values["name"])

    def _certificates_renew(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"name", "confirm"})
        _confirmed(values)
        return self.certificates.renew(values["name"])


class UnixHelperServer:
    """Serve one framed request per already-authorized UNIX connection."""

    def __init__(
        self,
        dispatcher: PrivilegedDispatcher,
        *,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
        socket_timeout: float = 30.0,
        allowed_peer_uid: int | None = None,
        audit: Callable[..., None] = _default_audit,
    ) -> None:
        self.dispatcher = dispatcher
        self.max_frame_bytes = max_frame_bytes
        self.max_stream_bytes = max_stream_bytes
        self.socket_timeout = socket_timeout
        if allowed_peer_uid is None and os.name == "posix":
            try:
                import pwd

                allowed_peer_uid = pwd.getpwnam("maddyweb").pw_uid
            except ImportError, KeyError:
                allowed_peer_uid = None
        self.allowed_peer_uid = allowed_peer_uid
        self.audit = audit

    def _verify_peer(self, connection: socket.socket) -> None:
        if (
            os.name != "posix"
            or not hasattr(socket, "SO_PEERCRED")
            or self.allowed_peer_uid is None
        ):
            raise ProtocolError("UNIX peer credential verification is unavailable")
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _pid, uid, _gid = struct.unpack("3i", credentials)
        if uid != self.allowed_peer_uid:
            raise ProtocolError("UNIX peer uid is not authorized")

    def serve_connection(self, connection: socket.socket) -> None:
        connection.settimeout(self.socket_timeout)
        input_spool: TrustedSpool | None = None
        output_spool: TrustedSpool | None = None
        stream_audit_fields: dict[str, Any] | None = None
        receiving_stream = False
        try:
            self._verify_peer(connection)
            request = Request.from_payload(
                receive_frame(connection, max_bytes=self.max_frame_bytes)
            )
            if request.stream_length is not None:
                # Stream requests must be authorized before any attacker-controlled
                # bytes are accepted. Dispatch authorizes them again after the upload
                # so a session cannot be revoked midway and still perform a write.
                preflight_failure, preflight_fields = self.dispatcher.preflight(request)
                if preflight_failure is not None:
                    send_frame(
                        connection,
                        preflight_failure.to_payload(),
                        max_bytes=self.max_frame_bytes,
                    )
                    return
                stream_audit_fields = preflight_fields
                receiving_stream = True
                if request.stream_length > self.max_stream_bytes:
                    raise StreamError("request stream exceeds configured limit")
                input_spool = TrustedSpool.create(self.dispatcher.spool_dir)
                receive_stream_payload(
                    connection,
                    input_spool.handle,
                    request.stream_length,
                    max_stream_bytes=self.max_stream_bytes,
                    require_eof=True,
                )
                input_spool.length = request.stream_length
                input_spool.rewind()
                receiving_stream = False
            result = self.dispatcher.dispatch(request, input_spool)
            output_spool = result.output_spool
            if output_spool is None:
                send_frame(connection, result.response.to_payload(), max_bytes=self.max_frame_bytes)
            else:
                send_stream_frame(
                    connection,
                    result.response.to_payload(),
                    output_spool.handle,
                    max_frame_bytes=self.max_frame_bytes,
                    max_stream_bytes=self.max_stream_bytes,
                )
        except (ConnectionClosed, ProtocolError, StreamError, OSError) as exc:
            if receiving_stream and stream_audit_fields is not None:
                self.dispatcher.audit(
                    "helper.operation",
                    outcome="stream_receive_failed",
                    fields={
                        **stream_audit_fields,
                        "error_type": type(exc).__name__,
                    },
                )
            self.audit(
                "helper.protocol",
                outcome="rejected",
                fields={"error_type": type(exc).__name__},
            )
        finally:
            if input_spool is not None:
                input_spool.close()
            if output_spool is not None:
                output_spool.close()


__all__ = [
    "ALLOWED_OPERATIONS",
    "DispatchResult",
    "PrivilegedDispatcher",
    "SMTPOutcomeUnknown",
    "SMTPRejected",
    "SMTPSubmissionClient",
    "SMTPTransportError",
    "TrustedSpool",
    "UnixHelperServer",
    "redact_for_audit",
]
