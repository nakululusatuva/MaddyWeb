"""Private Docker/native bridge for Maddy's delivery-time command filter."""

from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import re
import socket
import socketserver
import stat
import tempfile
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from .identity import canonicalize_email
from .rule_snapshots import DEFAULT_FILTER_SNAPSHOT_DIR, load_snapshot
from .rules import Rule, RuleValidationError, compile_rule, parse_rule_message

LOGGER = logging.getLogger(__name__)

FILTER_PROTOCOL: Final[str] = "MADDYWEB-FILTER/1"
DEFAULT_FILTER_PORT: Final[int] = 18787
MAX_PROTOCOL_LINE_BYTES: Final[int] = 512
MAX_FILTER_MESSAGE_BYTES: Final[int] = 25 * 1024 * 1024
MAX_FILTER_CONNECTIONS: Final[int] = 8
FILTER_SOCKET_TIMEOUT_SECONDS: Final[float] = 5.0
_TOKEN_RE = re.compile(r"[0-9a-f]{64}")
_RULE_ID_RE = re.compile(r"[0-9a-f]{32}")


class FilterBridgeError(RuntimeError):
    """A private filter bridge request or runtime setting is invalid."""


def parse_filter_listen(value: str) -> tuple[str, int]:
    if not isinstance(value, str) or value.count(":") != 1:
        raise FilterBridgeError("filter bridge listen address must be IPv4:port")
    host, raw_port = value.rsplit(":", 1)
    try:
        address = ipaddress.ip_address(host)
        port = int(raw_port)
    except ValueError as exc:
        raise FilterBridgeError("filter bridge listen address is invalid") from exc
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or address.is_unspecified
        or address.is_multicast
        or not (address.is_loopback or address.is_private)
        or port != DEFAULT_FILTER_PORT
    ):
        raise FilterBridgeError(
            f"filter bridge must use loopback or private IPv4 port {DEFAULT_FILTER_PORT}"
        )
    return str(address), port


def load_bridge_token(path: Path) -> str:
    if not isinstance(path, Path) or not path.is_absolute() or path == Path("/"):
        raise FilterBridgeError("filter bridge token path is invalid")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_nlink != 1:
        raise FilterBridgeError("filter bridge token must be a single-link regular file")
    if os.name == "posix" and (
        metadata.st_uid != 0
        or metadata.st_gid != os.getegid()
        or stat.S_IMODE(metadata.st_mode) != 0o640
    ):
        raise FilterBridgeError("filter bridge token permissions are invalid")
    try:
        token = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise FilterBridgeError("filter bridge token cannot be read") from exc
    if _TOKEN_RE.fullmatch(token) is None:
        raise FilterBridgeError("filter bridge token must be 32-byte lowercase hexadecimal")
    return token


def evaluate_filter_message(
    canonical_email: str,
    raw_message: bytes,
    *,
    snapshot_dir: Path = DEFAULT_FILTER_SNAPSHOT_DIR,
) -> str | None:
    """Evaluate one bounded message using an account's immutable published snapshot."""

    account = canonicalize_email(canonical_email)
    if not isinstance(raw_message, bytes) or not 1 <= len(raw_message) <= MAX_FILTER_MESSAGE_BYTES:
        return None
    document = load_snapshot(snapshot_dir, account)
    if document is None:
        return None
    raw_rules = document.get("rules")
    if not isinstance(raw_rules, list) or len(raw_rules) > 100:
        raise FilterBridgeError("published rule list is invalid")
    prepared: list[tuple[int, bool, object]] = []
    seen_ids: set[str] = set()
    for value in raw_rules:
        if not isinstance(value, Mapping) or set(value) != {
            "rule_id",
            "enabled",
            "position",
            "condition",
            "target_mailbox",
            "stop_processing",
            "revision",
        }:
            raise FilterBridgeError("published rule record is invalid")
        rule_id = value["rule_id"]
        position = value["position"]
        enabled = value["enabled"]
        stop_processing = value["stop_processing"]
        revision = value["revision"]
        if (
            not isinstance(rule_id, str)
            or _RULE_ID_RE.fullmatch(rule_id) is None
            or rule_id in seen_ids
            or type(position) is not int
            or not 0 <= position < 100
            or type(enabled) is not bool
            or type(stop_processing) is not bool
            or type(revision) is not int
            or revision < 1
        ):
            raise FilterBridgeError("published rule metadata is invalid")
        seen_ids.add(rule_id)
        if not enabled:
            continue
        compiled = compile_rule(
            Rule.from_mapping(
                {
                    "condition": value["condition"],
                    "target_mailbox": value["target_mailbox"],
                }
            )
        )
        prepared.append((position, stop_processing, compiled))
    if len({position for position, _stop, _rule in prepared}) != len(prepared):
        raise FilterBridgeError("published rule order is invalid")
    try:
        message = parse_rule_message(raw_message)
    except Exception:
        return None
    target: str | None = None
    for _position, stop_processing, compiled in sorted(prepared, key=lambda item: item[0]):
        if compiled.matches(message):
            target = compiled.target_mailbox
            if stop_processing:
                break
    return target


def evaluate_bridge_payload(
    payload: bytes,
    *,
    expected_token: str,
    snapshot_dir: Path = DEFAULT_FILTER_SNAPSHOT_DIR,
) -> bytes:
    """Validate one complete versioned frame and return the Maddy command stdout."""

    if not isinstance(payload, bytes) or not 1 <= len(payload) <= (
        MAX_PROTOCOL_LINE_BYTES + MAX_FILTER_MESSAGE_BYTES
    ):
        return b""
    line, separator, raw_message = payload.partition(b"\n")
    if not separator or not raw_message or len(line) > MAX_PROTOCOL_LINE_BYTES:
        return b""
    account = _authenticated_account(line, expected_token)
    if account is None:
        return b""
    try:
        target = evaluate_filter_message(account, raw_message, snapshot_dir=snapshot_dir)
    except (FilterBridgeError, RuleValidationError, OSError, ValueError):
        LOGGER.warning("delivery-time mail rule evaluation failed closed")
        return b""
    if target is None:
        return b""
    try:
        rendered = target.encode("utf-8")
    except UnicodeEncodeError:
        return b""
    if not rendered or b"\n" in rendered or b"\r" in rendered or len(rendered) > 1024:
        return b""
    return rendered + b"\n"


def _authenticated_account(line: bytes, expected_token: str) -> str | None:
    if not line or len(line) > MAX_PROTOCOL_LINE_BYTES:
        return None
    try:
        decoded = line.decode("ascii", "strict")
    except UnicodeDecodeError:
        return None
    parts = decoded.split(" ")
    if len(parts) != 3 or parts[0] != FILTER_PROTOCOL:
        return None
    supplied_token, raw_account = parts[1:]
    if _TOKEN_RE.fullmatch(expected_token) is None or not hmac.compare_digest(
        supplied_token,
        expected_token,
    ):
        return None
    try:
        return canonicalize_email(raw_account)
    except ValueError:
        return None


def _render_filter_target(target: str | None) -> bytes:
    if target is None:
        return b""
    try:
        rendered = target.encode("utf-8")
    except UnicodeEncodeError:
        return b""
    if not rendered or b"\n" in rendered or b"\r" in rendered or len(rendered) > 1024:
        return b""
    return rendered + b"\n"


class _BoundedFilterServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = True
    request_queue_size = 16

    def __init__(
        self,
        server_address: tuple[str, int],
        expected_token: str,
        snapshot_dir: Path,
    ) -> None:
        self.expected_token = expected_token
        self.snapshot_dir = snapshot_dir
        self._capacity = threading.BoundedSemaphore(MAX_FILTER_CONNECTIONS)
        self._evaluation_lock = threading.Lock()
        super().__init__(server_address, _FilterRequestHandler, bind_and_activate=True)

    def process_request(self, request: socket.socket, client_address: object) -> None:
        if not self._capacity.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._capacity.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: object) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._capacity.release()


class _FilterRequestHandler(socketserver.BaseRequestHandler):
    server: _BoundedFilterServer

    def handle(self) -> None:
        connection = self.request
        if not isinstance(connection, socket.socket):
            return
        connection.settimeout(FILTER_SOCKET_TIMEOUT_SECONDS)
        control = bytearray()
        initial_body = bytearray()
        try:
            while b"\n" not in control and len(control) <= MAX_PROTOCOL_LINE_BYTES:
                chunk = connection.recv(min(4096, MAX_PROTOCOL_LINE_BYTES + 1 - len(control)))
                if not chunk:
                    return
                control.extend(chunk)
            line, separator, remainder = control.partition(b"\n")
            if not separator or len(line) > MAX_PROTOCOL_LINE_BYTES:
                return
            account = _authenticated_account(bytes(line), self.server.expected_token)
            if account is None:
                return
            initial_body.extend(remainder)
            with tempfile.TemporaryFile(mode="w+b") as spool:
                transferred = len(initial_body)
                if transferred > MAX_FILTER_MESSAGE_BYTES:
                    return
                if initial_body:
                    spool.write(initial_body)
                while transferred <= MAX_FILTER_MESSAGE_BYTES:
                    chunk = connection.recv(
                        min(64 * 1024, MAX_FILTER_MESSAGE_BYTES + 1 - transferred)
                    )
                    if not chunk:
                        break
                    transferred += len(chunk)
                    if transferred > MAX_FILTER_MESSAGE_BYTES:
                        return
                    spool.write(chunk)
                if transferred == 0:
                    return
                spool.flush()
                spool.seek(0)
                with self.server._evaluation_lock:
                    raw_message = spool.read(MAX_FILTER_MESSAGE_BYTES + 1)
                    if len(raw_message) != transferred:
                        return
                    try:
                        target = evaluate_filter_message(
                            account,
                            raw_message,
                            snapshot_dir=self.server.snapshot_dir,
                        )
                    except (FilterBridgeError, RuleValidationError, OSError, ValueError):
                        LOGGER.warning("delivery-time mail rule evaluation failed closed")
                        target = None
                    response = _render_filter_target(target)
            if response:
                connection.sendall(response)
        except (OSError, TimeoutError):
            return
        finally:
            control[:] = b"\0" * len(control)
            control.clear()
            initial_body[:] = b"\0" * len(initial_body)
            initial_body.clear()


def serve_filter_bridge(
    listen: str,
    token_file: Path,
    *,
    snapshot_dir: Path = DEFAULT_FILTER_SNAPSHOT_DIR,
) -> None:
    endpoint = parse_filter_listen(listen)
    token = load_bridge_token(token_file)
    with _BoundedFilterServer(endpoint, token, snapshot_dir) as server:
        LOGGER.info("delivery-time mail rule bridge ready")
        server.serve_forever(poll_interval=0.5)


__all__ = [
    "DEFAULT_FILTER_PORT",
    "FILTER_PROTOCOL",
    "FilterBridgeError",
    "evaluate_bridge_payload",
    "evaluate_filter_message",
    "load_bridge_token",
    "parse_filter_listen",
    "serve_filter_bridge",
]
