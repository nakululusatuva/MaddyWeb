"""Versioned JSON frames for the local privileged UNIX-socket boundary.

Each frame is a four-byte unsigned network-order length followed by one UTF-8
JSON object.  A length is checked before allocation and JSON constants such as
NaN are rejected, so malformed peers cannot turn the helper into an unbounded
buffer or smuggle non-standard values across the trust boundary.
"""

from __future__ import annotations

import json
import re
import socket
import struct
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Self

PROTOCOL_VERSION = 1
HEADER_SIZE = 4
DEFAULT_MAX_FRAME_BYTES = 64 * 1024
DEFAULT_MAX_STREAM_BYTES = 32 * 1024 * 1024
STREAM_CHUNK_BYTES = 64 * 1024
_HEADER = struct.Struct("!I")
_ID_RE = re.compile(r"\A[A-Za-z0-9_.-]{1,64}\Z")
_OPERATION_RE = re.compile(r"\A[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,5}\Z")
_ERROR_CODE_RE = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")


class ProtocolError(ValueError):
    """A peer sent a malformed frame or message."""


class FrameTooLarge(ProtocolError):
    """The advertised or encoded frame exceeds the configured bound."""


class ConnectionClosed(EOFError):
    """The peer closed before a complete frame was received."""


class StreamError(ProtocolError):
    """A binary stream did not match its control frame."""


class StreamTooLarge(StreamError):
    """A declared binary stream exceeds its configured bound."""


class StreamTruncated(StreamError):
    """A binary stream ended before its declared byte length."""


def _reject_constant(value: str) -> None:
    raise ProtocolError(f"non-standard JSON constant is not allowed: {value}")


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > 32:
        raise ProtocolError("JSON nesting is too deep")
    if value is None or isinstance(value, bool | int | float | str):
        if isinstance(value, float) and (value != value or value in {float("inf"), float("-inf")}):
            raise ProtocolError("non-finite JSON number")
        return
    if isinstance(value, list | tuple):
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolError("JSON object keys must be strings")
            _validate_json_value(item, depth=depth + 1)
        return
    raise ProtocolError(f"value of type {type(value).__name__} is not JSON serializable")


def encode_frame(message: Mapping[str, Any], *, max_bytes: int = DEFAULT_MAX_FRAME_BYTES) -> bytes:
    """Serialize one deterministic JSON object with a checked length prefix."""

    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if not isinstance(message, Mapping):
        raise ProtocolError("a protocol message must be a JSON object")
    _validate_json_value(message)
    try:
        body = json.dumps(
            dict(message),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ProtocolError("message cannot be encoded as UTF-8 JSON") from exc
    if not body:
        raise ProtocolError("empty JSON body")
    if len(body) > max_bytes:
        raise FrameTooLarge(f"frame exceeds {max_bytes} bytes")
    return _HEADER.pack(len(body)) + body


def decode_payload(payload: bytes, *, max_bytes: int = DEFAULT_MAX_FRAME_BYTES) -> dict[str, Any]:
    if not payload:
        raise ProtocolError("empty JSON body")
    if len(payload) > max_bytes:
        raise FrameTooLarge(f"frame exceeds {max_bytes} bytes")
    try:
        decoded = json.loads(payload.decode("utf-8"), parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise ProtocolError("frame body is not valid UTF-8") from exc
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ProtocolError("frame body is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise ProtocolError("a protocol message must be a JSON object")
    _validate_json_value(decoded)
    return decoded


def _read_exact_stream(stream: BinaryIO, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.read(size - len(chunks))
        if not chunk:
            raise ConnectionClosed("peer closed before the frame was complete")
        chunks.extend(chunk)
    return bytes(chunks)


def read_frame(stream: BinaryIO, *, max_bytes: int = DEFAULT_MAX_FRAME_BYTES) -> dict[str, Any]:
    header = _read_exact_stream(stream, HEADER_SIZE)
    (length,) = _HEADER.unpack(header)
    if length == 0:
        raise ProtocolError("zero-length frame")
    if length > max_bytes:
        raise FrameTooLarge(f"peer advertised {length} bytes; limit is {max_bytes}")
    return decode_payload(_read_exact_stream(stream, length), max_bytes=max_bytes)


def write_frame(
    stream: BinaryIO,
    message: Mapping[str, Any],
    *,
    max_bytes: int = DEFAULT_MAX_FRAME_BYTES,
) -> None:
    stream.write(encode_frame(message, max_bytes=max_bytes))
    stream.flush()


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ConnectionClosed("peer closed before the frame was complete")
        chunks.extend(chunk)
    return bytes(chunks)


def receive_frame(
    sock: socket.socket,
    *,
    max_bytes: int = DEFAULT_MAX_FRAME_BYTES,
) -> dict[str, Any]:
    header = _recv_exact(sock, HEADER_SIZE)
    (length,) = _HEADER.unpack(header)
    if length == 0:
        raise ProtocolError("zero-length frame")
    if length > max_bytes:
        raise FrameTooLarge(f"peer advertised {length} bytes; limit is {max_bytes}")
    return decode_payload(_recv_exact(sock, length), max_bytes=max_bytes)


def send_frame(
    sock: socket.socket,
    message: Mapping[str, Any],
    *,
    max_bytes: int = DEFAULT_MAX_FRAME_BYTES,
) -> None:
    sock.sendall(encode_frame(message, max_bytes=max_bytes))


def _stream_length(message: Mapping[str, Any], maximum: int) -> int:
    value = message.get("stream_length")
    if type(value) is not int or value <= 0:
        raise StreamError("control frame has an invalid stream_length")
    if value > maximum:
        raise StreamTooLarge(f"stream advertises {value} bytes; limit is {maximum}")
    return value


def send_stream_frame(
    sock: socket.socket,
    message: Mapping[str, Any],
    source: BinaryIO,
    *,
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
    require_eof: bool = True,
) -> None:
    """Send a JSON control frame followed by exactly ``stream_length`` bytes."""

    length = _stream_length(message, max_stream_bytes)
    send_frame(sock, message, max_bytes=max_frame_bytes)
    remaining = length
    while remaining:
        requested = min(STREAM_CHUNK_BYTES, remaining)
        chunk = source.read(requested)
        if not chunk:
            raise StreamTruncated("stream source ended before its declared length")
        if not isinstance(chunk, bytes):
            raise StreamError("stream source must be opened in binary mode")
        if len(chunk) > requested:
            raise StreamError("stream source returned more bytes than requested")
        sock.sendall(chunk)
        remaining -= len(chunk)
    if require_eof and source.read(1):
        raise StreamError("stream source contains bytes beyond its declared length")


def receive_stream_frame(
    sock: socket.socket,
    destination: BinaryIO,
    *,
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
) -> tuple[dict[str, Any], int]:
    """Receive a control frame and copy its exact binary payload into a trusted sink."""

    message = receive_frame(sock, max_bytes=max_frame_bytes)
    length = _stream_length(message, max_stream_bytes)
    receive_stream_payload(
        sock,
        destination,
        length,
        max_stream_bytes=max_stream_bytes,
        require_eof=True,
    )
    return message, length


def receive_stream_payload(
    sock: socket.socket,
    destination: BinaryIO,
    length: int,
    *,
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
    require_eof: bool = False,
) -> int:
    """Copy an already-declared exact stream from ``sock`` to ``destination``."""

    if type(length) is not int or length <= 0:
        raise StreamError("invalid declared stream length")
    if length > max_stream_bytes:
        raise StreamTooLarge(f"stream advertises {length} bytes; limit is {max_stream_bytes}")
    remaining = length
    while remaining:
        try:
            chunk = sock.recv(min(STREAM_CHUNK_BYTES, remaining))
        except OSError as exc:
            raise StreamTruncated("stream ended before its declared length") from exc
        if not chunk:
            raise StreamTruncated("stream ended before its declared length")
        destination.write(chunk)
        remaining -= len(chunk)
    destination.flush()
    if require_eof:
        try:
            extra = sock.recv(1)
        except OSError as exc:
            raise StreamError("cannot verify end of request stream") from exc
        if extra:
            raise StreamError("peer sent bytes beyond its declared stream length")
    return length


def _check_keys(payload: Mapping[str, Any], allowed: set[str], required: set[str]) -> None:
    unknown = set(payload) - allowed
    missing = required - set(payload)
    if unknown:
        raise ProtocolError(f"unknown message field(s): {', '.join(sorted(unknown))}")
    if missing:
        raise ProtocolError(f"missing message field(s): {', '.join(sorted(missing))}")


def _check_identifier(value: Any, pattern: re.Pattern[str], name: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ProtocolError(f"invalid {name}")
    return value


@dataclass(frozen=True, slots=True)
class Request:
    request_id: str
    operation: str
    params: dict[str, Any] = field(default_factory=dict)
    actor: str | None = None
    stream_length: int | None = None

    def __post_init__(self) -> None:
        _check_identifier(self.request_id, _ID_RE, "request id")
        _check_identifier(self.operation, _OPERATION_RE, "operation")
        if not isinstance(self.params, dict):
            raise ProtocolError("params must be an object")
        _validate_json_value(self.params)
        if self.actor is not None and (
            not isinstance(self.actor, str)
            or not self.actor
            or len(self.actor) > 128
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in self.actor)
        ):
            raise ProtocolError("invalid actor")
        if self.stream_length is not None and (
            type(self.stream_length) is not int or self.stream_length <= 0
        ):
            raise ProtocolError("invalid stream_length")

    @classmethod
    def create(
        cls,
        operation: str,
        params: Mapping[str, Any] | None = None,
        *,
        actor: str | None = None,
        request_id: str | None = None,
        stream_length: int | None = None,
    ) -> Self:
        return cls(
            request_id or uuid.uuid4().hex,
            operation,
            dict(params or {}),
            actor,
            stream_length,
        )

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> Self:
        _check_keys(
            payload,
            {"version", "id", "operation", "params", "actor", "stream_length"},
            {"version", "id", "operation", "params"},
        )
        if payload["version"] != PROTOCOL_VERSION:
            raise ProtocolError("unsupported protocol version")
        params = payload["params"]
        if not isinstance(params, dict):
            raise ProtocolError("params must be an object")
        return cls(
            request_id=payload["id"],
            operation=payload["operation"],
            params=dict(params),
            actor=payload.get("actor"),
            stream_length=payload.get("stream_length"),
        )

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "version": PROTOCOL_VERSION,
            "id": self.request_id,
            "operation": self.operation,
            "params": self.params,
        }
        if self.actor is not None:
            payload["actor"] = self.actor
        if self.stream_length is not None:
            payload["stream_length"] = self.stream_length
        return payload


@dataclass(frozen=True, slots=True)
class ErrorPayload:
    code: str
    message: str

    def __post_init__(self) -> None:
        _check_identifier(self.code, _ERROR_CODE_RE, "error code")
        if (
            not isinstance(self.message, str)
            or not self.message
            or len(self.message) > 512
            or any(char in "\r\n\0" for char in self.message)
        ):
            raise ProtocolError("invalid error message")

    def to_payload(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True, slots=True)
class Response:
    request_id: str
    ok: bool
    result: Any = None
    error: ErrorPayload | None = None
    stream_length: int | None = None

    def __post_init__(self) -> None:
        _check_identifier(self.request_id, _ID_RE, "request id")
        if type(self.ok) is not bool:
            raise ProtocolError("ok must be a boolean")
        if self.ok and self.error is not None:
            raise ProtocolError("successful response cannot contain an error")
        if not self.ok and self.error is None:
            raise ProtocolError("failed response must contain an error")
        if self.stream_length is not None and (
            not self.ok or type(self.stream_length) is not int or self.stream_length <= 0
        ):
            raise ProtocolError("invalid response stream_length")
        stream_marker = isinstance(self.result, dict) and self.result == {"stream": True}
        if self.ok and (self.stream_length is not None) is not stream_marker:
            raise ProtocolError("response stream marker and stream_length do not match")
        _validate_json_value(self.result)

    @classmethod
    def success(
        cls,
        request_id: str,
        result: Any = None,
        *,
        stream_length: int | None = None,
    ) -> Self:
        return cls(request_id, True, result, None, stream_length)

    @classmethod
    def failure(cls, request_id: str, code: str, message: str) -> Self:
        return cls(request_id, False, None, ErrorPayload(code, message), None)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> Self:
        _check_keys(
            payload,
            {"version", "id", "ok", "result", "error", "stream_length"},
            {"version", "id", "ok"},
        )
        if payload["version"] != PROTOCOL_VERSION:
            raise ProtocolError("unsupported protocol version")
        ok = payload["ok"]
        if type(ok) is not bool:
            raise ProtocolError("ok must be a boolean")
        if ok:
            if "error" in payload:
                raise ProtocolError("successful response contains an error")
            return cls.success(
                payload["id"],
                payload.get("result"),
                stream_length=payload.get("stream_length"),
            )
        if "result" in payload:
            raise ProtocolError("failed response contains a result")
        if "stream_length" in payload:
            raise ProtocolError("failed response contains a stream")
        raw_error = payload.get("error")
        if not isinstance(raw_error, dict):
            raise ProtocolError("failed response is missing its error object")
        _check_keys(raw_error, {"code", "message"}, {"code", "message"})
        return cls.failure(payload["id"], raw_error["code"], raw_error["message"])

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "version": PROTOCOL_VERSION,
            "id": self.request_id,
            "ok": self.ok,
        }
        if self.ok:
            payload["result"] = self.result
            if self.stream_length is not None:
                payload["stream_length"] = self.stream_length
        else:
            if self.error is None:
                raise ValueError("failed response requires an error payload")
            payload["error"] = self.error.to_payload()
        return payload


class UnixSocketClient:
    """One-request-per-connection client for the local privileged helper."""

    def __init__(
        self,
        path: str | Path,
        *,
        timeout: float = 15.0,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
    ) -> None:
        self.path = str(path)
        self.timeout = timeout
        self.max_frame_bytes = max_frame_bytes
        if not self.path or "\0" in self.path:
            raise ValueError("invalid UNIX socket path")
        if timeout <= 0 or max_frame_bytes <= 0:
            raise ValueError("client limits must be positive")

    def call(self, request: Request) -> Response:
        if request.stream_length is not None:
            raise ProtocolError("use call_with_stream for a streaming request")
        if not hasattr(socket, "AF_UNIX"):
            raise OSError("AF_UNIX is not supported on this platform")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(self.path)
            send_frame(sock, request.to_payload(), max_bytes=self.max_frame_bytes)
            response = Response.from_payload(receive_frame(sock, max_bytes=self.max_frame_bytes))
        if response.request_id != request.request_id:
            raise ProtocolError("response id does not match request id")
        if response.stream_length is not None:
            raise ProtocolError("use call_to_stream for a streaming response")
        return response

    def call_with_stream(self, request: Request, source: BinaryIO) -> Response:
        if request.stream_length is None:
            raise ProtocolError("streaming request is missing stream_length")
        if not hasattr(socket, "AF_UNIX"):
            raise OSError("AF_UNIX is not supported on this platform")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(self.path)
            send_stream_frame(
                sock,
                request.to_payload(),
                source,
                max_frame_bytes=self.max_frame_bytes,
                max_stream_bytes=DEFAULT_MAX_STREAM_BYTES,
            )
            sock.shutdown(socket.SHUT_WR)
            response = Response.from_payload(receive_frame(sock, max_bytes=self.max_frame_bytes))
        if response.request_id != request.request_id:
            raise ProtocolError("response id does not match request id")
        if response.stream_length is not None:
            raise ProtocolError("upload response unexpectedly contains a stream")
        return response

    def call_to_stream(self, request: Request, destination: BinaryIO) -> Response:
        if request.stream_length is not None:
            raise ProtocolError("download request cannot also contain an upload stream")
        if not hasattr(socket, "AF_UNIX"):
            raise OSError("AF_UNIX is not supported on this platform")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(self.path)
            send_frame(sock, request.to_payload(), max_bytes=self.max_frame_bytes)
            response = Response.from_payload(receive_frame(sock, max_bytes=self.max_frame_bytes))
            if response.request_id != request.request_id:
                raise ProtocolError("response id does not match request id")
            if response.ok:
                if response.stream_length is None:
                    raise ProtocolError("download response is missing stream_length")
                receive_stream_payload(
                    sock,
                    destination,
                    response.stream_length,
                    max_stream_bytes=DEFAULT_MAX_STREAM_BYTES,
                    require_eof=True,
                )
        return response


__all__ = [
    "DEFAULT_MAX_FRAME_BYTES",
    "DEFAULT_MAX_STREAM_BYTES",
    "PROTOCOL_VERSION",
    "ConnectionClosed",
    "ErrorPayload",
    "FrameTooLarge",
    "ProtocolError",
    "Request",
    "Response",
    "StreamError",
    "StreamTooLarge",
    "StreamTruncated",
    "UnixSocketClient",
    "decode_payload",
    "encode_frame",
    "read_frame",
    "receive_frame",
    "receive_stream_frame",
    "receive_stream_payload",
    "send_frame",
    "send_stream_frame",
    "write_frame",
]
