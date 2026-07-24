from __future__ import annotations

import io
import json
import os
import socket
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import maddyweb.helper as helper_module
from maddyweb.helper import (
    ALLOWED_OPERATIONS,
    PrivilegedDispatcher,
    SMTPOutcomeUnknown,
    SMTPRejected,
    SMTPSubmissionClient,
    SMTPTransportError,
    TrustedSpool,
    UnixHelperServer,
    redact_for_audit,
)
from maddyweb.maddy import Capability, LegacyLDAPUnsafe, MaddyTarget, StaleMessageCursor
from maddyweb.protocol import (
    ProtocolError,
    Request,
    Response,
    receive_frame,
    receive_stream_frame,
    send_frame,
    send_stream_frame,
)

_PROC_HEADER = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt\n"
_PROC6_HEADER = (
    b"  sl  local_address                         remote_address"
    b"                        st tx_queue rx_queue tr tm->when retrnsmt\n"
)
_CONTAINER_ID = "a" * 64


def _proc_table(*rows: str, ipv6: bool = False) -> bytes:
    header = _PROC6_HEADER if ipv6 else _PROC_HEADER
    return header + "".join(f"{row}\n" for row in rows).encode("ascii")


def _runtime_metadata(**changes: Any) -> bytes:
    values: dict[str, Any] = {
        "id": _CONTAINER_ID,
        "running": True,
        "paused": False,
        "network_mode": "bridge",
        "port_bindings": {"25/tcp": [{"HostIp": "127.0.0.1", "HostPort": "25"}]},
        "runtime_ports": {"25/tcp": [{"HostIp": "127.0.0.1", "HostPort": "25"}]},
    }
    values.update(changes)
    return json.dumps(values, separators=(",", ":")).encode("ascii")


class FakeMaddy:
    def __init__(
        self,
        messages: list[dict[str, Any]] | None = None,
        *,
        write_safe: bool = True,
    ) -> None:
        self.messages = messages or []
        self.account_list_modes: list[bool] = []
        self.append_calls = 0
        self.appended = b""
        self.dump_data = b"From: sender@example.test\r\n\r\ndownload\r\n"
        self.write_safe = write_safe
        self.write_safety_calls: list[Capability] = []
        self.message_list_kwargs: list[dict[str, Any]] = []
        self.deleted: list[tuple[str, str, str]] = []
        self.moved: list[tuple[str, str, str, str]] = []

    def require_write_safety(self, capability: Capability) -> None:
        self.write_safety_calls.append(capability)
        if not self.write_safe:
            raise LegacyLDAPUnsafe("fixture write gate is closed")

    def list_accounts(self, *, include_append_limits: bool = True) -> list[dict[str, Any]]:
        self.account_list_modes.append(include_append_limits)
        return [
            {
                "username": "sender@example.test",
                "has_credentials": True,
                "has_mailbox": True,
                "append_limit": None,
            }
        ]

    def create_account(self, username: str, _password: str) -> dict[str, Any]:
        return {"username": username, "has_credentials": True, "has_mailbox": True}

    def list_message_window(self, *_args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        self.message_list_kwargs.append(kwargs)
        ordered = sorted(self.messages, key=lambda item: int(item["uid"]), reverse=True)
        cursor_uid = int(kwargs["cursor_uid"])
        if cursor_uid:
            try:
                start = next(
                    index for index, item in enumerate(ordered) if int(item["uid"]) == cursor_uid
                )
            except StopIteration as exc:
                raise StaleMessageCursor("fixture cursor is stale") from exc
        else:
            start = 0
        limit = int(kwargs["limit"])
        return [dict(item) for item in ordered[start : start + limit + 1]]

    def append_message(
        self,
        _username: str,
        _mailbox: str,
        content: Any,
        *,
        content_length: int,
        **_kwargs: Any,
    ) -> int:
        self.append_calls += 1
        self.appended = content.read(content_length)
        return 42

    def resolve_special_mailbox(self, _username: str, special: str) -> str:
        return {"sent": "Custom Sent", "trash": "Custom Trash"}[special]

    def delete_message(self, username: str, mailbox: str, uid: str) -> None:
        self.deleted.append((username, mailbox, uid))

    def move_message(self, username: str, source: str, uid: str, target: str) -> None:
        self.moved.append((username, source, uid, target))

    def dump_message_to(
        self,
        _username: str,
        _mailbox: str,
        _uid: int,
        destination: Any,
    ) -> int:
        destination.write(self.dump_data)
        return len(self.dump_data)


class RecordingSMTP:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def send(self, **values: Any) -> dict[str, Any]:
        message = values.pop("message")
        values["message"] = message.read(values["message_length"])
        self.calls.append(values)
        return {"accepted": True, "recipients": len(values["recipients"])}


def make_dispatcher(
    tmp_path: Path,
    maddy: Any,
    *,
    smtp: Any = None,
    audit: Any = None,
) -> PrivilegedDispatcher:
    return PrivilegedDispatcher(
        maddy,
        SimpleNamespace(),
        spool_dir=tmp_path,
        smtp=smtp,
        audit=audit or (lambda *_args, **_kwargs: None),
    )


def test_dispatcher_allowlist_and_sensitive_audit(tmp_path: Path) -> None:
    audit_records: list[tuple[str, str, dict[str, Any]]] = []

    def audit(action: str, *, outcome: str, fields: dict[str, Any]) -> None:
        audit_records.append((action, outcome, fields))

    dispatcher = make_dispatcher(tmp_path, FakeMaddy(), audit=audit)
    submitted = "-".join(("browser", "account", "value"))
    created = dispatcher.dispatch(
        Request.create(
            "accounts.create",
            {"username": "sender@example.test", "password": submitted},
            actor="operator",
        )
    )
    assert created.response.ok is True
    assert audit_records[-1][2]["params"]["password"] == "[REDACTED]"  # noqa: S105
    assert submitted not in repr(audit_records)

    denied = dispatcher.dispatch(
        Request.create("accounts.delete", {"username": "sender@example.test"})
    )
    assert denied.response.error is not None
    assert denied.response.error.code == "operation_denied"
    assert audit_records[-1][1] == "operation_denied"
    assert redact_for_audit({"nested": {"private_key": b"secret"}}) == {
        "nested": {"private_key": {"redacted": True, "bytes": 6}}
    }

    assert "accounts.disable_credentials" in ALLOWED_OPERATIONS
    assert "accounts.delete_imap_account" in ALLOWED_OPERATIONS
    assert "accounts.delete" not in ALLOWED_OPERATIONS
    assert "certificates.install" not in ALLOWED_OPERATIONS
    assert "certificates.upload" not in ALLOWED_OPERATIONS


def test_accounts_list_appendlimit_mode_is_optional_and_strict(tmp_path: Path) -> None:
    maddy = FakeMaddy()
    dispatcher = make_dispatcher(tmp_path, maddy)
    assert dispatcher.dispatch(Request.create("accounts.list")).response.ok is True
    assert (
        dispatcher.dispatch(
            Request.create("accounts.list", {"include_append_limits": False})
        ).response.ok
        is True
    )
    invalid = dispatcher.dispatch(Request.create("accounts.list", {"include_append_limits": 0}))
    assert invalid.response.error is not None
    assert invalid.response.error.code == "invalid_request"
    assert maddy.account_list_modes == [True, False]


def test_message_pagination_uses_stable_uid_continuation(
    tmp_path: Path,
) -> None:
    maddy = FakeMaddy([{"uid": uid, "subject": str(uid)} for uid in range(1, 6)])
    dispatcher = make_dispatcher(tmp_path, maddy)
    result = dispatcher.dispatch(
        Request.create(
            "messages.list",
            {
                "username": "sender@example.test",
                "mailbox": "INBOX",
                "limit": 2,
                "offset": 4,
            },
        )
    )
    assert result.response.result == {
        "items": [{"uid": 4, "subject": "4"}, {"uid": 3, "subject": "3"}],
        "offset": 4,
        "limit": 2,
        "total": None,
        "next_offset": 2,
    }
    assert maddy.message_list_kwargs == [{"limit": 2, "cursor_uid": 4}]

    stale = dispatcher.dispatch(
        Request.create(
            "messages.list",
            {
                "username": "sender@example.test",
                "mailbox": "INBOX",
                "limit": 2,
                "offset": 999,
            },
        )
    )
    assert stale.response.error is not None
    assert stale.response.error.code == "stale_cursor"

    full_request = dispatcher.dispatch(
        Request.create(
            "messages.list",
            {
                "username": "sender@example.test",
                "mailbox": "INBOX",
                "limit": 2,
                "offset": 0,
                "full": True,
            },
        )
    )
    assert full_request.response.error is not None
    assert full_request.response.error.code == "invalid_request"

    oversized = {"uid": 1, **{f"field_{index}": "x" * 600 for index in range(100)}}
    limited = make_dispatcher(tmp_path, FakeMaddy([oversized])).dispatch(
        Request.create(
            "messages.list",
            {
                "username": "sender@example.test",
                "mailbox": "INBOX",
                "limit": 1,
                "offset": 0,
            },
        )
    )
    assert limited.response.error is not None
    assert limited.response.error.code == "limit_exceeded"


def test_destructive_message_operations_accept_only_one_uid_and_resolve_trash(
    tmp_path: Path,
) -> None:
    maddy = FakeMaddy()
    dispatcher = make_dispatcher(tmp_path, maddy)
    moved = dispatcher.dispatch(
        Request.create(
            "messages.move",
            {
                "username": "sender@example.test",
                "source": "INBOX",
                "uid": "42",
                "target_special": "trash",
            },
        )
    )
    assert moved.response.result == {"moved": True, "target": "Custom Trash"}
    assert maddy.moved == [("sender@example.test", "INBOX", "42", "Custom Trash")]

    injected = dispatcher.dispatch(
        Request.create(
            "messages.delete",
            {
                "username": "sender@example.test",
                "mailbox": "INBOX",
                "uid_set": "1:*",
                "confirm": True,
            },
        )
    )
    assert injected.response.error is not None
    assert injected.response.error.code == "invalid_request"
    assert maddy.deleted == []


def test_message_frame_truncation_continues_at_first_undisplayed_uid(tmp_path: Path) -> None:
    oversized = {"uid": 99, **{f"field_{index}": "x" * 600 for index in range(100)}}
    maddy = FakeMaddy(
        [
            {"uid": 100, "subject": "fits"},
            oversized,
            {"uid": 98, "subject": "must not be skipped"},
        ]
    )
    result = make_dispatcher(tmp_path, maddy).dispatch(
        Request.create(
            "messages.list",
            {
                "username": "sender@example.test",
                "mailbox": "INBOX",
                "limit": 2,
                "offset": 0,
            },
        )
    )

    assert result.response.result == {
        "items": [{"uid": 100, "subject": "fits"}],
        "offset": 100,
        "limit": 2,
        "total": None,
        "next_offset": 99,
    }


def test_submission_uses_account_password_and_does_not_archive_sent(
    tmp_path: Path,
) -> None:
    maddy = FakeMaddy()
    smtp = RecordingSMTP()
    dispatcher = make_dispatcher(tmp_path, maddy, smtp=smtp)
    spool = TrustedSpool.create(tmp_path)
    try:
        message = b"From: sender@example.test\r\n\r\nhello\r\n"
        submitted = "-".join(("browser", "supplied", "value"))
        spool.handle.write(message)
        spool.length = len(message)
        accepted = dispatcher.dispatch(
            Request.create(
                "messages.send",
                {
                    "username": "sender@example.test",
                    "password": submitted,
                    "mail_from": "sender@example.test",
                    "recipients": ["recipient@example.test"],
                },
            ),
            spool,
        )
        assert accepted.response.ok is True
        assert len(smtp.calls) == 1
        assert smtp.calls[0]["password"] == submitted
        assert smtp.calls[0]["message"] == message
        assert maddy.append_calls == 0
        assert maddy.write_safety_calls == [Capability.MESSAGE_ADMIN]
    finally:
        spool.close()


def test_submission_cannot_bypass_the_maddy_write_safety_gate(tmp_path: Path) -> None:
    maddy = FakeMaddy(write_safe=False)
    smtp = RecordingSMTP()
    dispatcher = make_dispatcher(tmp_path, maddy, smtp=smtp)
    spool = TrustedSpool.create(tmp_path)
    try:
        message = b"From: sender@example.test\r\n\r\nhello\r\n"
        spool.handle.write(message)
        spool.length = len(message)
        result = dispatcher.dispatch(
            Request.create(
                "messages.send",
                {
                    "username": "sender@example.test",
                    "password": "account-password",
                    "mail_from": "sender@example.test",
                    "recipients": ["recipient@example.test"],
                },
            ),
            spool,
        )
        assert result.response.error is not None
        assert result.response.error.code == "writes_disabled"
        assert smtp.calls == []
    finally:
        spool.close()


def test_submission_endpoint_and_scope_are_fixed() -> None:
    target = MaddyTarget(mode="docker", container="maddy", service_user=None)
    for values in (
        {"host": "127.0.0.2"},
        {"port": 587},
        {"docker_submission_scope": "automatic"},
    ):
        with pytest.raises(ValueError):
            SMTPSubmissionClient(target, **values)

    configured = SMTPSubmissionClient.from_config(
        SimpleNamespace(
            mode="docker",
            container="maddy",
            submission_host="127.0.0.1",
            submission_port=1587,
            docker_submission_scope="host-loopback",
            command_timeout_seconds=7.0,
        )
    )
    assert configured.docker_submission_scope == "host-loopback"
    assert (configured.host, configured.port) == ("127.0.0.1", 1587)


def test_proc_net_parser_requires_one_exact_ipv4_loopback_listener() -> None:
    exact = _proc_table(
        "0: 0100007F:0633 00000000:0000 0A",
        "1: 0100007F:0633 0100007F:1234 01",
        "2: 00000000:0019 00000000:0000 0A",
    )
    empty_ipv6 = _proc_table()
    assert helper_module._submission_listeners(exact, empty_ipv6) == (("ipv4", "0100007F"),)
    helper_module._require_submission_listener(exact, empty_ipv6, present=True)
    helper_module._require_submission_listener(_proc_table(), empty_ipv6, present=False)


def test_combined_proc_tables_require_exact_ipv4_and_ipv6_headers() -> None:
    ipv4 = _proc_table("0: 0100007F:0633 00000000:0000 0A")
    ipv6 = _proc_table(ipv6=True)
    assert helper_module._split_proc_net_tables(ipv4 + ipv6) == (ipv4, ipv6)
    assert helper_module._parse_proc_net_table(ipv6, ipv6=True) == ()
    for payload in (ipv4, ipv4 + ipv6 + _proc_table(), b"not-procfs\n"):
        with pytest.raises(SMTPTransportError):
            helper_module._split_proc_net_tables(payload)


@pytest.mark.parametrize(
    ("ipv4", "ipv6"),
    (
        (_proc_table(), _proc_table()),
        (_proc_table("0: 00000000:0633 00000000:0000 0A"), _proc_table()),
        (
            _proc_table(
                "0: 0100007F:0633 00000000:0000 0A",
                "1: 0100007F:0633 00000000:0000 0A",
            ),
            _proc_table(),
        ),
        (
            _proc_table(),
            _proc_table(
                "0: 00000000000000000000000001000000:0633 00000000000000000000000000000000:0000 0A"
            ),
        ),
        (
            _proc_table("malformed"),
            _proc_table(),
        ),
    ),
)
def test_proc_net_parser_rejects_missing_wildcard_duplicate_ipv6_and_malformed(
    ipv4: bytes,
    ipv6: bytes,
) -> None:
    with pytest.raises(SMTPTransportError):
        helper_module._require_submission_listener(ipv4, ipv6, present=True)


@pytest.mark.parametrize(
    ("changes", "scope"),
    (
        ({"running": False}, "container"),
        ({"paused": True}, "container"),
        ({"network_mode": "host"}, "container"),
        ({"network_mode": "bridge"}, "host-loopback"),
        ({"network_mode": "none"}, "container"),
        ({"port_bindings": {"1587/tcp": None}}, "container"),
        (
            {"runtime_ports": {"25/tcp": [{"HostIp": "127.0.0.1", "HostPort": "1587"}]}},
            "container",
        ),
    ),
)
def test_docker_runtime_parser_fails_closed_on_scope_or_publication_drift(
    changes: dict[str, Any],
    scope: str,
) -> None:
    with pytest.raises(SMTPTransportError):
        helper_module._parse_docker_submission_runtime(
            _runtime_metadata(**changes),
            scope=scope,
        )


def test_docker_runtime_parser_accepts_only_matching_scopes() -> None:
    isolated = helper_module._parse_docker_submission_runtime(
        _runtime_metadata(),
        scope="container",
    )
    assert (isolated.container_id, isolated.network_mode) == (_CONTAINER_ID, "bridge")

    host = helper_module._parse_docker_submission_runtime(
        _runtime_metadata(network_mode="host"),
        scope="host-loopback",
    )
    assert (host.container_id, host.network_mode) == (_CONTAINER_ID, "host")


class _CompletedGuardProcess:
    def __init__(self, stdout: bytes, *, stderr: bytes = b"", return_code: int = 0) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.return_code = return_code
        self.killed = False

    def wait(self, timeout: float) -> int:
        assert timeout > 0
        return self.return_code

    def kill(self) -> None:
        self.killed = True


def test_docker_runtime_guard_uses_fixed_bounded_commands_and_validated_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exact = _proc_table("0: 0100007F:0633 00000000:0000 0A")
    outputs = [_runtime_metadata(), exact + _proc_table()]
    calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    def popen(argv: tuple[str, ...], **kwargs: Any) -> _CompletedGuardProcess:
        calls.append((argv, kwargs))
        return _CompletedGuardProcess(outputs.pop(0))

    monkeypatch.setattr(helper_module.subprocess, "Popen", popen)

    class Client(SMTPSubmissionClient):
        @staticmethod
        def _host_socket_tables() -> tuple[bytes, bytes]:
            return _proc_table(), _proc_table()

    client = Client(MaddyTarget(mode="docker", container="maddy", service_user=None))
    assert client._validate_docker_runtime() == _CONTAINER_ID
    assert [call[0] for call in calls] == [
        (
            "/usr/bin/docker",
            helper_module._DOCKER_LOCAL_HOST_ARG,
            "container",
            "inspect",
            "--format",
            helper_module._DOCKER_INSPECT_TEMPLATE,
            "maddy",
        ),
        (
            "/usr/bin/docker",
            helper_module._DOCKER_LOCAL_HOST_ARG,
            "exec",
            _CONTAINER_ID,
            "/bin/cat",
            "/proc/net/tcp",
            "/proc/net/tcp6",
        ),
    ]
    for _argv, kwargs in calls:
        assert kwargs["shell"] is False
        assert kwargs["stdin"] is helper_module.subprocess.DEVNULL
        assert kwargs["env"] == helper_module._FIXED_SUBPROCESS_ENV
        assert "DOCKER_HOST" not in kwargs["env"]
        assert "DOCKER_CONTEXT" not in kwargs["env"]


def test_docker_smtp_channel_pins_local_daemon_and_validated_container_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    class Channel:
        def __init__(self, argv: tuple[str, ...]) -> None:
            calls.append(argv)

    monkeypatch.setattr(helper_module, "_ProcessChannel", Channel)
    client = SMTPSubmissionClient(MaddyTarget(mode="docker", container="maddy", service_user=None))
    channel = client._channel(docker_container=_CONTAINER_ID)
    assert isinstance(channel, Channel)
    assert calls == [
        (
            "/usr/bin/docker",
            helper_module._DOCKER_LOCAL_HOST_ARG,
            "exec",
            "-i",
            _CONTAINER_ID,
            "/usr/bin/nc",
            "127.0.0.1",
            "1587",
        )
    ]


def test_host_loopback_scope_requires_the_same_exact_host_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exact = _proc_table("0: 0100007F:0633 00000000:0000 0A")
    outputs = [_runtime_metadata(network_mode="host"), exact + _proc_table()]

    def popen(_argv: tuple[str, ...], **_kwargs: Any) -> _CompletedGuardProcess:
        return _CompletedGuardProcess(outputs.pop(0))

    monkeypatch.setattr(helper_module.subprocess, "Popen", popen)

    class Client(SMTPSubmissionClient):
        @staticmethod
        def _host_socket_tables() -> tuple[bytes, bytes]:
            return exact, _proc_table()

    client = Client(
        MaddyTarget(mode="docker", container="maddy", service_user=None),
        docker_submission_scope="host-loopback",
    )
    assert client._validate_docker_runtime() == _CONTAINER_ID


def test_docker_runtime_guard_rejects_oversized_subprocess_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _CompletedGuardProcess(b"x" * 33)
    monkeypatch.setattr(
        helper_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    with pytest.raises(SMTPTransportError):
        helper_module._bounded_command_output(
            ("/usr/bin/docker", "context", "show"),
            timeout=1,
            maximum=32,
        )
    assert process.killed is True


def test_docker_listener_drift_fails_before_channel_or_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    outputs = [
        _runtime_metadata(),
        _proc_table("0: 0100007F:0633 00000000:0000 0A") + _proc_table(),
    ]

    def popen(argv: tuple[str, ...], **_kwargs: Any) -> _CompletedGuardProcess:
        calls.append(argv)
        return _CompletedGuardProcess(outputs.pop(0))

    monkeypatch.setattr(helper_module.subprocess, "Popen", popen)

    class Client(SMTPSubmissionClient):
        channel_opened = False

        @staticmethod
        def _host_socket_tables() -> tuple[bytes, bytes]:
            return (
                _proc_table("0: 0100007F:0633 00000000:0000 0A"),
                _proc_table(),
            )

        def _channel(self, *, docker_container: str | None = None) -> ScriptedChannel:
            del docker_container
            self.channel_opened = True
            raise AssertionError("SMTP channel must not open after guard failure")

    client = Client(MaddyTarget(mode="docker", container="maddy", service_user=None))
    password = "-".join(("must", "not", "leave", "the", "helper"))
    with pytest.raises(SMTPTransportError, match="listener"):
        client.send(
            username="sender@example.test",
            password=password,
            mail_from="sender@example.test",
            recipients=["recipient@example.test"],
            message=io.BytesIO(b"body"),
            message_length=4,
        )
    assert client.channel_opened is False
    assert len(calls) == 2
    assert password not in repr(calls)


class ScriptedChannel:
    def __init__(self, responses: list[bytes | BaseException]) -> None:
        self.responses = list(responses)
        self.writes: list[bytes] = []
        self.closed = False

    def readline(self, _timeout: float) -> bytes:
        if not self.responses:
            raise SMTPTransportError("script exhausted")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    def close(self) -> None:
        self.closed = True


class _ScriptedSMTPClient(SMTPSubmissionClient):
    def __init__(self, channel: ScriptedChannel) -> None:
        super().__init__(MaddyTarget(mode="native", service_user=None))
        self.channel = channel

    def _channel(self) -> ScriptedChannel:
        return self.channel


class TerminatorFailureChannel(ScriptedChannel):
    def write(self, data: bytes) -> None:
        if data == b".\r\n":
            raise SMTPTransportError("terminator write outcome is ambiguous")
        super().write(data)


def send_scripted(channel: ScriptedChannel) -> dict[str, Any]:
    credential = "-".join(("one", "time", "credential"))
    message = b".first\nsecond\rthird"
    return _ScriptedSMTPClient(channel).send(
        username="sender@example.test",
        password=credential,
        mail_from="sender@example.test",
        recipients=["recipient@example.test"],
        message=io.BytesIO(message),
        message_length=len(message),
    )


@pytest.mark.parametrize(("code", "temporary"), [(450, True), (550, False)])
def test_smtp_rejects_4xx_and_5xx_response_by_response(code: int, temporary: bool) -> None:
    channel = ScriptedChannel(
        [
            b"220 ready\r\n",
            b"250 hello\r\n",
            b"235 authenticated\r\n",
            b"250 sender ok\r\n",
            f"{code} recipient rejected\r\n".encode(),
        ]
    )
    with pytest.raises(SMTPRejected) as raised:
        send_scripted(channel)
    assert raised.value.code == code
    assert raised.value.temporary is temporary
    assert raised.value.stage == "RCPT TO"
    assert not any(write == b"DATA\r\n" for write in channel.writes)
    assert channel.closed is True


@pytest.mark.parametrize("code", (454, 535))
def test_smtp_auth_rejection_has_fixed_safe_classification(code: int) -> None:
    error = SMTPRejected(code, "AUTH")
    assert PrivilegedDispatcher._safe_error(error) == (
        "smtp_authentication_rejection",
        "SMTP authentication was rejected",
    )


@pytest.mark.parametrize("code", (454, 535))
def test_smtp_client_stops_after_auth_rejection_and_hides_reply(code: int) -> None:
    hostile_reply = f"{code} credential and server detail must stay private\r\n".encode()
    channel = ScriptedChannel([b"220 ready\r\n", b"250 hello\r\n", hostile_reply])

    with pytest.raises(SMTPRejected) as raised:
        send_scripted(channel)

    wire = b"".join(channel.writes)
    assert raised.value.stage == "AUTH"
    assert raised.value.code == code
    assert b"AUTH PLAIN " in wire
    assert b"MAIL FROM" not in wire
    assert b"RCPT TO" not in wire
    assert b"DATA\r\n" not in wire
    safe_error = PrivilegedDispatcher._safe_error(raised.value)
    assert safe_error == (
        "smtp_authentication_rejection",
        "SMTP authentication was rejected",
    )
    assert b"credential and server detail" not in repr(safe_error).encode()
    assert channel.closed is True


def test_smtp_disconnect_after_data_is_unknown_but_after_acceptance_is_success() -> None:
    prefix: list[bytes | BaseException] = [
        b"220 ready\r\n",
        b"250 hello\r\n",
        b"235 authenticated\r\n",
        b"250 sender ok\r\n",
        b"250 recipient ok\r\n",
        b"354 continue\r\n",
    ]
    unknown = ScriptedChannel([*prefix, SMTPTransportError("closed before final DATA response")])
    with pytest.raises(SMTPOutcomeUnknown):
        send_scripted(unknown)
    assert unknown.closed is True

    terminator_failure = TerminatorFailureChannel(list(prefix))
    with pytest.raises(SMTPOutcomeUnknown):
        send_scripted(terminator_failure)
    assert terminator_failure.closed is True

    accepted = ScriptedChannel(
        [
            *prefix,
            b"250 queued\r\n",
            SMTPTransportError("closed after acceptance"),
        ]
    )
    assert send_scripted(accepted) == {"accepted": True, "recipients": 1}
    wire = b"".join(accepted.writes)
    assert b"..first\r\nsecond\r\nthird\r\n.\r\n" in wire
    assert accepted.closed is True


class _TestUnixHelperServer(UnixHelperServer):
    def _verify_peer(self, connection: socket.socket) -> None:
        del connection


def _serve_once(server: UnixHelperServer, connection: socket.socket) -> None:
    with connection:
        server.serve_connection(connection)


def test_socket_stream_upload_download_and_spool_cleanup(tmp_path: Path) -> None:
    maddy = FakeMaddy()
    server = _TestUnixHelperServer(make_dispatcher(tmp_path, maddy), allowed_peer_uid=0)
    message = b"From: sender@example.test\r\n\r\nupload\r\n"

    client_socket, server_socket = socket.socketpair()
    upload_thread = threading.Thread(target=_serve_once, args=(server, server_socket))
    upload_thread.start()
    try:
        request = Request.create(
            "messages.append",
            {"username": "sender@example.test", "mailbox_special": "sent"},
            stream_length=len(message),
        )
        send_stream_frame(client_socket, request.to_payload(), io.BytesIO(message))
        client_socket.shutdown(socket.SHUT_WR)
        response = Response.from_payload(receive_frame(client_socket))
        assert response.ok is True
        assert response.result == {"uid": 42, "mailbox": "Custom Sent"}
    finally:
        client_socket.close()
        upload_thread.join(timeout=2)
    assert not upload_thread.is_alive()
    assert maddy.appended == message
    assert list(tmp_path.glob("maddyweb-*.spool")) == []

    client_socket, server_socket = socket.socketpair()
    download_thread = threading.Thread(target=_serve_once, args=(server, server_socket))
    download_thread.start()
    destination = io.BytesIO()
    try:
        request = Request.create(
            "messages.get",
            {"username": "sender@example.test", "mailbox": "INBOX", "uid": 1},
        )
        send_frame(client_socket, request.to_payload())
        payload, length = receive_stream_frame(client_socket, destination)
        response = Response.from_payload(payload)
        assert response.ok is True
        assert length == len(maddy.dump_data)
        assert destination.getvalue() == maddy.dump_data
    finally:
        client_socket.close()
        download_thread.join(timeout=2)
    assert not download_thread.is_alive()
    assert list(tmp_path.glob("maddyweb-*.spool")) == []


def test_empty_download_closes_spool_instead_of_leaking_it(tmp_path: Path) -> None:
    maddy = FakeMaddy()
    maddy.dump_data = b""
    result = make_dispatcher(tmp_path, maddy).dispatch(
        Request.create(
            "messages.get",
            {"username": "sender@example.test", "mailbox": "INBOX", "uid": 1},
        )
    )
    assert result.response.error is not None
    assert result.response.error.code == "maddy_failed"
    assert list(tmp_path.glob("maddyweb-*.spool")) == []


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(socket, "SO_PEERCRED"),
    reason="SO_PEERCRED is Linux-only",
)
def test_so_peercred_rejects_wrong_uid(tmp_path: Path) -> None:
    current_uid = os.getuid()
    client_socket, server_socket = socket.socketpair()
    try:
        denied = UnixHelperServer(
            make_dispatcher(tmp_path, FakeMaddy()),
            allowed_peer_uid=current_uid + 1,
        )
        with pytest.raises(ProtocolError, match="not authorized"):
            denied._verify_peer(server_socket)

        explicitly_allowed = UnixHelperServer(
            make_dispatcher(tmp_path, FakeMaddy()),
            allowed_peer_uid=current_uid,
        )
        explicitly_allowed._verify_peer(server_socket)
    finally:
        client_socket.close()
        server_socket.close()
