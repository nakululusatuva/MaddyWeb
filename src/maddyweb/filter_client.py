"""Fail-open client for Maddy's delivery-time command filter."""

from __future__ import annotations

import ipaddress
import os
import socket
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import BinaryIO, Final

from .identity import canonicalize_email

FILTER_PROTOCOL: Final[bytes] = b"MADDYWEB-FILTER/1"
FILTER_PORT: Final[int] = 18787
CLIENT_ENDPOINT_FILE: Final[Path] = Path("/etc/maddyweb-filter/client.endpoint")
CLIENT_TOKEN_FILE: Final[Path] = Path("/etc/maddyweb-filter/client.token")
MAX_FILTER_MESSAGE_BYTES: Final[int] = 25 * 1024 * 1024
MAX_FILTER_RESPONSE_BYTES: Final[int] = 1025
SOCKET_TIMEOUT_SECONDS: Final[float] = 5.0


class FilterClientError(RuntimeError):
    """The local filter client contract was not satisfied."""


def _client_file_metadata_is_valid(metadata: os.stat_result) -> bool:
    if os.name != "posix":
        return True
    groups = {os.getegid(), *os.getgroups()}
    return (
        metadata.st_uid == 0
        and metadata.st_gid in groups
        and stat.S_IMODE(metadata.st_mode) == 0o640
    )


def _read_root_owned_client_file(path: Path) -> str:
    if not path.is_absolute() or path == Path("/"):
        raise FilterClientError("client file path is invalid")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_nlink != 1
    ):
        raise FilterClientError("client file must be a single-link regular file")
    if not _client_file_metadata_is_valid(metadata):
        raise FilterClientError("client file permissions are invalid")
    try:
        value = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise FilterClientError("client file cannot be read") from exc
    if not value.endswith("\n") or "\n" in value[:-1] or "\r" in value:
        raise FilterClientError("client file must contain one terminated line")
    return value[:-1]


def load_client_endpoint(path: Path = CLIENT_ENDPOINT_FILE) -> tuple[str, int]:
    value = _read_root_owned_client_file(path)
    if value.count(":") != 1:
        raise FilterClientError("client endpoint must be IPv4:port")
    host, raw_port = value.split(":", 1)
    try:
        address = ipaddress.ip_address(host)
        port = int(raw_port)
    except ValueError as exc:
        raise FilterClientError("client endpoint is invalid") from exc
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or address.is_unspecified
        or address.is_multicast
        or not (address.is_loopback or address.is_private)
        or port != FILTER_PORT
    ):
        raise FilterClientError("client endpoint is outside the private filter boundary")
    return str(address), port


def load_client_token(path: Path = CLIENT_TOKEN_FILE) -> str:
    value = _read_root_owned_client_file(path)
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise FilterClientError("client token is invalid")
    return value


def _validated_response(response: bytes) -> bytes:
    if not response:
        return b""
    if (
        len(response) > MAX_FILTER_RESPONSE_BYTES
        or not response.endswith(b"\n")
        or response.count(b"\n") != 1
        or b"\r" in response
    ):
        return b""
    target = response[:-1]
    try:
        rendered = target.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return b""
    if not rendered or any(ord(char) < 0x20 or ord(char) == 0x7F for char in rendered):
        return b""
    return response


def run_filter_client(
    account: str,
    source: BinaryIO,
    destination: BinaryIO,
    *,
    endpoint_file: Path = CLIENT_ENDPOINT_FILE,
    token_file: Path = CLIENT_TOKEN_FILE,
) -> int:
    """Forward one message to the private bridge and always fail open for delivery."""

    try:
        canonical_account = canonicalize_email(account)
        endpoint = load_client_endpoint(endpoint_file)
        token = load_client_token(token_file)
        header = b" ".join(
            (FILTER_PROTOCOL, token.encode("ascii"), canonical_account.encode("ascii"))
        ) + b"\n"
        transferred = 0
        with socket.create_connection(endpoint, timeout=SOCKET_TIMEOUT_SECONDS) as connection:
            connection.settimeout(SOCKET_TIMEOUT_SECONDS)
            connection.sendall(header)
            while True:
                chunk = source.read(min(64 * 1024, MAX_FILTER_MESSAGE_BYTES + 1 - transferred))
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise FilterClientError("message input must be bytes")
                transferred += len(chunk)
                if transferred > MAX_FILTER_MESSAGE_BYTES:
                    raise FilterClientError("message exceeds the filter size limit")
                connection.sendall(chunk)
            if transferred == 0:
                raise FilterClientError("message input is empty")
            connection.shutdown(socket.SHUT_WR)
            response = bytearray()
            while len(response) <= MAX_FILTER_RESPONSE_BYTES:
                chunk = connection.recv(MAX_FILTER_RESPONSE_BYTES + 1 - len(response))
                if not chunk:
                    break
                response.extend(chunk)
            rendered = _validated_response(bytes(response))
            response[:] = b"\0" * len(response)
            if rendered:
                destination.write(rendered)
                destination.flush()
    except (FilterClientError, OSError, TimeoutError, ValueError):
        # Maddy treats empty stdout as "no filtering effect".  Delivery must
        # remain available if the optional bridge or its snapshot is absent.
        return 0
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        return 0
    return run_filter_client(arguments[0], sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":  # pragma: no cover - exercised as a command.
    raise SystemExit(main())


__all__ = [
    "CLIENT_ENDPOINT_FILE",
    "CLIENT_TOKEN_FILE",
    "FILTER_PORT",
    "FilterClientError",
    "load_client_endpoint",
    "load_client_token",
    "main",
    "run_filter_client",
]
