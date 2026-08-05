from __future__ import annotations

import io
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import maddyweb.filter_client as filter_client
from maddyweb.filter_client import (
    FilterClientError,
    load_client_endpoint,
    load_client_token,
    run_filter_client,
)

TOKEN = "ab" * 32
MESSAGE = b"From: sender@example.test\r\nTo: user@example.test\r\n\r\nhello\r\n"


@pytest.fixture(autouse=True)
def _portable_root_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    if filter_client.os.name == "posix" and filter_client.os.geteuid() != 0:
        monkeypatch.setattr(filter_client, "_client_file_metadata_is_valid", lambda _value: True)


def _client_files(tmp_path: Path, endpoint: str) -> tuple[Path, Path]:
    endpoint_file = tmp_path / "client.endpoint"
    token_file = tmp_path / "client.token"
    endpoint_file.write_text(endpoint + "\n", encoding="ascii")
    token_file.write_text(TOKEN + "\n", encoding="ascii")
    endpoint_file.chmod(0o640)
    token_file.chmod(0o640)
    return endpoint_file, token_file


def test_filter_client_forwards_one_frame_and_emits_valid_target(tmp_path: Path) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    host, port = listener.getsockname()
    listener.listen(1)
    received = bytearray()

    def serve() -> None:
        connection, _address = listener.accept()
        with connection:
            while chunk := connection.recv(65536):
                received.extend(chunk)
            connection.sendall(b"Archive\n")

    thread = threading.Thread(target=serve)
    thread.start()
    endpoint_file, token_file = _client_files(tmp_path, f"{host}:18787")
    output = io.BytesIO()
    try:
        # The production port is fixed. Redirect only the socket connection in
        # this unit test while retaining the parsed endpoint contract.
        original = socket.create_connection

        def connect(_endpoint: tuple[str, int], timeout: float) -> socket.socket:
            return original((host, port), timeout=timeout)

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(socket, "create_connection", connect)
            assert (
                run_filter_client(
                    "User@Example.Test",
                    io.BytesIO(MESSAGE),
                    output,
                    endpoint_file=endpoint_file,
                    token_file=token_file,
                )
                == 0
            )
    finally:
        thread.join(timeout=3)
        listener.close()
    assert output.getvalue() == b"Archive\n"
    assert bytes(received) == (
        b"MADDYWEB-FILTER/1 " + TOKEN.encode() + b" user@example.test\n" + MESSAGE
    )


def test_filter_client_unavailable_bridge_is_empty_success(tmp_path: Path) -> None:
    endpoint_file, token_file = _client_files(tmp_path, "127.0.0.1:18787")
    output = io.BytesIO()
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            socket,
            "create_connection",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(ConnectionRefusedError()),
        )
        assert (
            run_filter_client(
                "user@example.test",
                io.BytesIO(MESSAGE),
                output,
                endpoint_file=endpoint_file,
                token_file=token_file,
            )
            == 0
        )
    assert output.getvalue() == b""


@pytest.mark.parametrize(
    ("endpoint", "valid"),
    [
        ("127.0.0.1:18787", True),
        ("10.0.0.1:18787", True),
        ("127.0.0.1:18788", False),
        ("0.0.0.0:18787", False),
        ("8.8.8.8:18787", False),
        ("[::1]:18787", False),
    ],
)
def test_filter_client_endpoint_is_fixed_and_private(
    tmp_path: Path,
    endpoint: str,
    valid: bool,
) -> None:
    endpoint_file, _token_file = _client_files(tmp_path, endpoint)
    if valid:
        assert load_client_endpoint(endpoint_file)[1] == 18787
    else:
        with pytest.raises(FilterClientError):
            load_client_endpoint(endpoint_file)


def test_filter_client_token_requires_one_terminated_hex_line(tmp_path: Path) -> None:
    token_file = tmp_path / "client.token"
    token_file.write_text(TOKEN, encoding="ascii")
    token_file.chmod(0o640)
    with pytest.raises(FilterClientError):
        load_client_token(token_file)
    token_file.write_text(TOKEN + "\n", encoding="ascii")
    token_file.chmod(0o640)
    assert load_client_token(token_file) == TOKEN


def test_filter_client_import_does_not_load_authentication_stack() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import sys; import maddyweb.filter_client; "
                "raise SystemExit('maddyweb.auth' in sys.modules)"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
