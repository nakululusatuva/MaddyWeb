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
    "auth.session": _Operation("_auth_session", permission="session"),
    "auth.logout": _Operation("_auth_logout", mutating=True, permission="session"),
    "auth.change_password": _Operation(
        "_auth_change_password",
        mutating=True,
        permission="session",
    ),
    "auth.recovery_regenerate": _Operation(
        "_auth_recovery_regenerate",
        mutating=True,
        permission="session",
    ),
    "auth.step_up": _Operation("_auth_step_up", mutating=True, permission="admin"),
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
    ),
    "mailboxes.list": _Operation("_mailboxes_list", permission="account"),
    "mailboxes.create": _Operation("_mailboxes_create", mutating=True, permission="account"),
    "mailboxes.delete": _Operation("_mailboxes_delete", mutating=True, permission="account"),
    "mailboxes.rename": _Operation("_mailboxes_rename", mutating=True, permission="account"),
    "messages.list": _Operation("_messages_list", permission="account"),
    "messages.get": _Operation("_messages_get", stream_out=True, permission="account"),
    "messages.append": _Operation(
        "_messages_append",
        mutating=True,
        stream_in=True,
        permission="account",
    ),
    "messages.delete": _Operation("_messages_delete", mutating=True, permission="account"),
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
    "certificates.renew_dry_run": _Operation("_certificates_dry_run", mutating=True),
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


class PrivilegedDispatcher:
    def __init__(
        self,
        maddy: MaddyService,
        certificates: CertificateManager,
        *,
        spool_dir: Path,
        smtp: SMTPSubmissionClient | None = None,
        auth_store: Any | None = None,
        audit: Callable[..., None] = _default_audit,
    ) -> None:
        self.maddy = maddy
        self.certificates = certificates
        self.smtp = smtp
        self.auth_store = auth_store
        self.spool_dir = spool_dir
        self.audit = audit
        self._lock = threading.RLock()
        self._request_context = threading.local()

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
        # Unit tests can construct a dispatcher without an authentication store.
        # The production CLI always supplies the root-owned store.
        if self.auth_store is None:
            return request, None
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
            "auth.logout",
            "auth.change_password",
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
                    raise StepUpRequired("fresh administrator authentication is required") from exc
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

    def preflight(self, request: Request) -> Response | None:
        """Authorize a control frame before receiving any declared upload body."""

        operation = ALLOWED_OPERATIONS.get(request.operation)
        if operation is None:
            return Response.failure(
                request.request_id,
                "operation_denied",
                "Operation is not allow-listed",
            )
        if operation.stream_in is not (request.stream_length is not None):
            return Response.failure(
                request.request_id,
                "invalid_stream",
                "Operation stream shape does not match",
            )
        try:
            self._authorize_request(request, operation, touch=False)
        except Exception as exc:
            code, message = self._safe_error(exc)
            return Response.failure(request.request_id, code, message)
        return None

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
                touch=True,
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
        if auth_error in {"AccountNotFoundError", "EnrollmentStateError"}:
            return "invalid_credentials", "Email address or password is invalid"
        if isinstance(exc, InvalidCredentials):
            return "invalid_credentials", "Email address or password is invalid"
        if isinstance(exc, PasswordChangeRequired):
            return "password_change_required", "Mailbox password change is required"
        if isinstance(exc, StepUpRequired):
            return "step_up_required", "Fresh administrator authentication is required"
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
        values = _params(request, required={"challenge", "code", "client_ip"})
        result = self.auth_store.confirm_totp_enrollment(
            values["challenge"],
            values["code"],
        )
        client_ip = self._client_ip(values["client_ip"])
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
        values = _params(request, required={"challenge", "code", "client_ip"})
        issued = self.auth_store.complete_totp_challenge(
            values["challenge"],
            values["code"],
        )
        client_ip = self._client_ip(values["client_ip"])
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
            required={"challenge", "recovery_code", "client_ip"},
        )
        issued = self.auth_store.complete_recovery_challenge(
            values["challenge"],
            values["recovery_code"],
        )
        client_ip = self._client_ip(values["client_ip"])
        self.auth_store.record_login_result(issued.principal.email, client_ip, success=True)
        self._set_auth_audit(
            issued.principal,
            method="recovery_code",
            client_ip=client_ip,
        )
        return self._issued_session_payload(issued)

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
        self.maddy.rename_mailbox(values["username"], values["old_name"], values["new_name"])
        return {"renamed": True}

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

    def _messages_copy(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "source", "uid_set", "target"})
        self.maddy.copy_messages(
            values["username"], values["source"], values["uid_set"], values["target"]
        )
        return {"copied": True}

    def _messages_move(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(
            request,
            required={"username", "source", "uid"},
            optional={"target_special", "target"},
        )
        if ("target_special" in values) is ("target" in values):
            raise ValueError("exactly one message target must be supplied")
        target = (
            self.maddy.resolve_special_mailbox(values["username"], values["target_special"])
            if "target_special" in values
            else values["target"]
        )
        self.maddy.move_message(values["username"], values["source"], values["uid"], target)
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
        try:
            self._verify_peer(connection)
            request = Request.from_payload(
                receive_frame(connection, max_bytes=self.max_frame_bytes)
            )
            preflight_failure = self.dispatcher.preflight(request)
            if preflight_failure is not None:
                send_frame(
                    connection,
                    preflight_failure.to_payload(),
                    max_bytes=self.max_frame_bytes,
                )
                return
            if request.stream_length is not None:
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
