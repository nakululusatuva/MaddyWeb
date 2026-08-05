from __future__ import annotations

import os
import socket
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import maddyweb.filter_bridge as bridge_module
from maddyweb.filter_bridge import (
    DEFAULT_FILTER_PORT,
    FILTER_PROTOCOL,
    FilterBridgeError,
    evaluate_bridge_payload,
    evaluate_filter_message,
    load_bridge_token,
    parse_filter_listen,
)
from maddyweb.rule_snapshots import publish_snapshot

TOKEN = "ab" * 32
ACCOUNT = "user@example.test"


def _snapshots(tmp_path: Path) -> Path:
    directory = tmp_path / "snapshots"
    directory.mkdir(mode=0o750)
    if os.name == "posix":
        directory.chmod(0o750)
    return directory


def _rules() -> list[dict[str, object]]:
    return [
        {
            "rule_id": "1" * 32,
            "enabled": True,
            "position": 0,
            "condition": {
                "field": "subject",
                "operator": "contains",
                "value": "invoice",
            },
            "target_mailbox": "Finance/Invoices",
            "stop_processing": True,
            "revision": 1,
        }
    ]


def test_bridge_evaluates_private_snapshot(tmp_path: Path) -> None:
    directory = _snapshots(tmp_path)
    publish_snapshot(directory, ACCOUNT, _rules())
    raw = b"From: vendor@example.test\r\nSubject: Invoice 42\r\n\r\nBody"
    payload = f"{FILTER_PROTOCOL} {TOKEN} {ACCOUNT}\n".encode() + raw

    assert evaluate_filter_message(ACCOUNT, raw, snapshot_dir=directory) == "Finance/Invoices"
    assert (
        evaluate_bridge_payload(payload, expected_token=TOKEN, snapshot_dir=directory)
        == b"Finance/Invoices\n"
    )


def test_bridge_fails_open_without_exposing_rule_data(tmp_path: Path) -> None:
    directory = _snapshots(tmp_path)
    publish_snapshot(directory, ACCOUNT, _rules())
    raw = b"Subject: ordinary\r\n\r\nBody"
    prefix = f"{FILTER_PROTOCOL} {TOKEN} {ACCOUNT}\n".encode()

    assert (
        evaluate_bridge_payload(prefix + raw, expected_token=TOKEN, snapshot_dir=directory)
        == b""
    )
    assert (
        evaluate_bridge_payload(
            prefix.replace(TOKEN.encode(), ("cd" * 32).encode()) + raw,
            expected_token=TOKEN,
            snapshot_dir=directory,
        )
        == b""
    )
    assert evaluate_bridge_payload(b"bad\n" + raw, expected_token=TOKEN) == b""


def test_bridge_authenticates_control_line_before_opening_message_spool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = _snapshots(tmp_path)
    client, server = socket.socketpair()
    try:
        client.sendall(
            f"{FILTER_PROTOCOL} {'cd' * 32} {ACCOUNT}\n".encode("ascii")
            + b"Subject: rejected\r\n\r\n"
        )
        client.shutdown(socket.SHUT_WR)

        def unexpected_spool(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("unauthenticated input reached the message spool")

        monkeypatch.setattr(bridge_module.tempfile, "TemporaryFile", unexpected_spool)
        bridge_module._FilterRequestHandler(
            server,
            ("127.0.0.1", 1),
            SimpleNamespace(
                expected_token=TOKEN,
                snapshot_dir=directory,
                _evaluation_lock=threading.Lock(),
            ),
        )
    finally:
        client.close()
        server.close()


def test_rule_order_and_continue_semantics(tmp_path: Path) -> None:
    directory = _snapshots(tmp_path)
    rules = _rules()
    rules[0]["stop_processing"] = False
    rules.append(
        {
            "rule_id": "2" * 32,
            "enabled": True,
            "position": 1,
            "condition": {
                "field": "from",
                "operator": "contains",
                "value": "vendor@example.test",
            },
            "target_mailbox": "Vendors",
            "stop_processing": True,
            "revision": 1,
        }
    )
    publish_snapshot(directory, ACCOUNT, rules)
    raw = b"From: vendor@example.test\r\nSubject: invoice\r\n\r\nBody"
    assert evaluate_filter_message(ACCOUNT, raw, snapshot_dir=directory) == "Vendors"


@pytest.mark.parametrize(
    "value",
    ["0.0.0.0:18787", "[::1]:18787", "8.8.8.8:18787", "127.0.0.1:80", "bad"],
)
def test_filter_listen_rejects_unsafe_addresses(value: str) -> None:
    with pytest.raises(FilterBridgeError):
        parse_filter_listen(value)
    assert parse_filter_listen(f"127.0.0.1:{DEFAULT_FILTER_PORT}") == (
        "127.0.0.1",
        DEFAULT_FILTER_PORT,
    )


def test_token_file_metadata_and_content(tmp_path: Path) -> None:
    path = tmp_path / "bridge.token"
    path.write_text(TOKEN + "\n", encoding="ascii")
    if os.name == "posix":
        path.chmod(0o640)
        if os.geteuid() != 0:
            with pytest.raises(FilterBridgeError, match="permissions"):
                load_bridge_token(path)
            return
    assert load_bridge_token(path) == TOKEN
