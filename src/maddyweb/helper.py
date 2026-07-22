"""Least-privilege UNIX-socket dispatcher and strict local SMTP submission.

Only the operations in :data:`ALLOWED_OPERATIONS` are callable.  Large message
bodies cross the socket as exact-length binary streams and are held in helper-
created mode-0600 spools; browser supplied filesystem paths are never accepted.
"""

from __future__ import annotations

import base64
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
from typing import Any, BinaryIO, Protocol

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
    }
)
_EMAIL_RE = re.compile(r"\A[^\s<>@]+@[^\s<>@]+\Z")


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
        timeout: float = 15.0,
        max_message_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        if host != "127.0.0.1" or not 1 <= port <= 65535:
            raise ValueError("SMTP submission must use configured IPv4 loopback")
        if timeout <= 0 or max_message_bytes <= 0:
            raise ValueError("SMTP limits must be positive")
        self.target = target
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_message_bytes = max_message_bytes

    @classmethod
    def from_config(cls, config: Any) -> SMTPSubmissionClient:
        return cls(
            MaddyTarget.from_config(config),
            host=str(config.submission_host),
            port=int(config.submission_port),
            timeout=float(config.command_timeout_seconds),
        )

    def _channel(self) -> _SMTPChannel:
        if self.target.mode.value == "native":
            return _SocketChannel(self.host, self.port, self.timeout)
        return _ProcessChannel(
            (
                self.target.docker_executable,
                "exec",
                "-i",
                str(self.target.container),
                "/usr/bin/nc",
                self.host,
                str(self.port),
            )
        )

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
        if not password or len(password) > 1024 or any(char in password for char in "\r\n\0"):
            raise ValueError("invalid SMTP password")
        if type(message_length) is not int or not 1 <= message_length <= self.max_message_bytes:
            raise ValueError("invalid message length")

        channel = self._channel()
        deadline = time.monotonic() + self.timeout
        data_terminator_sent = False
        try:
            code, _ = self._response(channel, deadline)
            if code != 220:
                raise SMTPRejected(code, "greeting")
            self._command(channel, b"EHLO maddyweb.local", deadline, {250}, "EHLO")
            auth = base64.b64encode(b"\0" + username.encode() + b"\0" + password.encode())
            code, _ = self._command(
                channel,
                b"AUTH PLAIN " + auth,
                deadline,
                {235, 334},
                "AUTH",
            )
            if code == 334:
                self._command(channel, auth, deadline, {235}, "AUTH")
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


ALLOWED_OPERATIONS: Mapping[str, _Operation] = {
    "maddy.health": _Operation("_maddy_health"),
    "maddy.version": _Operation("_version"),
    "maddy.verify_config": _Operation("_verify_config"),
    "accounts.list": _Operation("_accounts_list"),
    "accounts.create": _Operation("_accounts_create", mutating=True),
    "accounts.change_password": _Operation("_accounts_password", mutating=True),
    "accounts.disable_credentials": _Operation("_accounts_disable", mutating=True),
    "accounts.delete_imap_account": _Operation("_accounts_delete_imap", mutating=True),
    "accounts.get_append_limit": _Operation("_append_limit_get"),
    "accounts.set_append_limit": _Operation("_append_limit_set", mutating=True),
    "mailboxes.list": _Operation("_mailboxes_list"),
    "mailboxes.create": _Operation("_mailboxes_create", mutating=True),
    "mailboxes.delete": _Operation("_mailboxes_delete", mutating=True),
    "mailboxes.rename": _Operation("_mailboxes_rename", mutating=True),
    "messages.list": _Operation("_messages_list"),
    "messages.get": _Operation("_messages_get", stream_out=True),
    "messages.append": _Operation("_messages_append", mutating=True, stream_in=True),
    "messages.delete": _Operation("_messages_delete", mutating=True),
    "messages.copy": _Operation("_messages_copy", mutating=True),
    "messages.move": _Operation("_messages_move", mutating=True),
    "messages.set_flags": _Operation("_messages_set_flags", mutating=True),
    "messages.add_flags": _Operation("_messages_add_flags", mutating=True),
    "messages.remove_flags": _Operation("_messages_remove_flags", mutating=True),
    "messages.send": _Operation("_messages_send", mutating=True, stream_in=True),
    "certificates.list": _Operation("_certificates_list"),
    "certificates.health": _Operation("_certificates_health"),
    "certificates.status": _Operation("_certificates_status"),
    "certificates.timer_enable": _Operation("_certificates_timer_enable", mutating=True),
    "certificates.timer_disable": _Operation("_certificates_timer_disable", mutating=True),
    "certificates.renew_dry_run": _Operation("_certificates_dry_run", mutating=True),
    "certificates.renew": _Operation("_certificates_renew", mutating=True),
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
        audit: Callable[..., None] = _default_audit,
    ) -> None:
        self.maddy = maddy
        self.certificates = certificates
        self.smtp = smtp
        self.spool_dir = spool_dir
        self.audit = audit
        self._lock = threading.RLock()

    def dispatch(self, request: Request, input_spool: TrustedSpool | None = None) -> DispatchResult:
        fields = {
            "request_id": request.request_id,
            "operation": request.operation,
            "actor": request.actor,
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

    @staticmethod
    def _safe_error(exc: Exception) -> tuple[str, str]:
        if isinstance(exc, SMTPOutcomeUnknown):
            return "smtp_outcome_unknown", "Delivery outcome is unknown; do not retry automatically"
        if isinstance(exc, SMTPRejected):
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
        return {
            "available": True,
            "version": info["version"],
            "writes_enabled": info["writes_enabled"],
            "write_block_reason": info["write_block_reason"],
            "mode": info["mode"],
        }

    def _verify_config(self, request: Request, _spool: TrustedSpool | None) -> Any:
        _params(request)
        return {"output": self.maddy.verify_config()}

    def _accounts_list(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, optional={"include_append_limits"})
        include_append_limits = values.get("include_append_limits", True)
        if type(include_append_limits) is not bool:
            raise ValueError("include_append_limits must be a boolean")
        return self.maddy.list_accounts(include_append_limits=include_append_limits)

    def _accounts_create(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "password"})
        return self.maddy.create_account(values["username"], values["password"])

    def _accounts_password(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "password"})
        self.maddy.change_password(values["username"], values["password"])
        return {"changed": True}

    def _accounts_disable(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "confirm"})
        _confirmed(values)
        self.maddy.disable_credentials(values["username"])
        return {"credentials_disabled": True}

    def _accounts_delete_imap(self, request: Request, _spool: TrustedSpool | None) -> Any:
        values = _params(request, required={"username", "confirm"})
        _confirmed(values)
        self.maddy.delete_imap_account(values["username"])
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
            required={"username", "source", "uid", "target_special"},
        )
        target = self.maddy.resolve_special_mailbox(values["username"], values["target_special"])
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
        if account is None or account.get("has_credentials") is not True:
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
