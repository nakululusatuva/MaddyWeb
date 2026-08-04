from __future__ import annotations

import asyncio
import io
import json
import os
import queue
import socket
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import maddyweb.helper as helper_module
from maddyweb.auth import (
    AuthStore,
    InvalidSessionError,
    LoginRateLimitedError,
    Role,
    totp_code,
)
from maddyweb.config import AppConfig
from maddyweb.gateway import HelperGateway, bind_helper_identity
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
        accounts: list[dict[str, Any]] | None = None,
        write_safe: bool = True,
    ) -> None:
        self.messages = messages or []
        self.accounts = accounts or [
            {
                "username": "sender@example.test",
                "has_credentials": True,
                "has_mailbox": True,
                "append_limit": None,
            }
        ]
        self.account_list_modes: list[bool] = []
        self.append_calls = 0
        self.appended = b""
        self.dump_data = b"From: sender@example.test\r\n\r\ndownload\r\n"
        self.write_safe = write_safe
        self.write_safety_calls: list[Capability] = []
        self.message_list_args: list[tuple[Any, ...]] = []
        self.message_list_kwargs: list[dict[str, Any]] = []
        self.latest_message_uid_calls: list[tuple[str, str]] = []
        self.deleted: list[tuple[str, str, str]] = []
        self.moved: list[tuple[str, str, str, str]] = []
        self.moved_many: list[tuple[str, str, str, str]] = []
        self.password_changes: list[tuple[str, str]] = []

    def require_write_safety(self, capability: Capability) -> None:
        self.write_safety_calls.append(capability)
        if not self.write_safe:
            raise LegacyLDAPUnsafe("fixture write gate is closed")

    def list_accounts(self, *, include_append_limits: bool = True) -> list[dict[str, Any]]:
        self.account_list_modes.append(include_append_limits)
        return [dict(account) for account in self.accounts]

    def create_account(self, username: str, _password: str) -> dict[str, Any]:
        return {"username": username, "has_credentials": True, "has_mailbox": True}

    def change_password(self, username: str, password: str) -> None:
        self.password_changes.append((username, password))

    def list_message_window(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        self.message_list_args.append(args)
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

    def latest_message_uid(self, username: str, mailbox: str) -> int:
        self.latest_message_uid_calls.append((username, mailbox))
        return max((int(item["uid"]) for item in self.messages), default=0)

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

    def move_messages(self, username: str, source: str, uid_set: str, target: str) -> None:
        self.moved_many.append((username, source, uid_set, target))

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
    auth_store: Any = None,
    audit: Any = None,
) -> PrivilegedDispatcher:
    dispatcher_type = PrivilegedDispatcher
    if auth_store is None:

        class LegacyOperationDispatcher(PrivilegedDispatcher):
            def _authorize_request(
                self,
                request: Request,
                operation: Any,
                *,
                touch: bool,
                audit_fields: dict[str, Any] | None = None,
            ) -> tuple[Request, Any | None]:
                return request, None

        dispatcher_type = LegacyOperationDispatcher
    return dispatcher_type(
        maddy,
        SimpleNamespace(),
        spool_dir=tmp_path,
        smtp=smtp,
        auth_store=auth_store,
        audit=audit or (lambda *_args, **_kwargs: None),
    )


_AUTH_CLOCK = 1_700_000_000


def make_auth_store(tmp_path: Path, name: str = "auth.db") -> AuthStore:
    return AuthStore(
        (tmp_path / name).resolve(),
        b"K" * 32,
        "MaddyWeb Test",
        clock=lambda: _AUTH_CLOCK,
    )


def provision_session(
    store: AuthStore,
    email: str,
    *,
    role: Role = Role.USER,
    password_change_required: bool = False,
) -> tuple[Any, str]:
    account, enrollment, _recovery_codes = store.provision_active_account(
        email,
        role=role,
        password_change_required=password_change_required,
    )
    challenge = store.create_pending_challenge(email)
    issued = store.complete_totp_challenge(
        challenge,
        totp_code(enrollment.secret, timestamp=_AUTH_CLOCK),
    )
    return account, issued.token


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
        )
    )
    assert created.response.ok is True
    assert audit_records[-1][2]["params"]["password"] == "[REDACTED]"  # noqa: S105
    assert submitted not in repr(audit_records)
    assert redact_for_audit(
        {
            "challenge": "challenge-value",
            "code": "123456",
            "recovery_code": "recovery-value",
        }
    ) == {
        "challenge": "[REDACTED]",
        "code": "[REDACTED]",
        "recovery_code": "[REDACTED]",
    }

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


def test_dispatcher_without_authentication_store_fails_closed(tmp_path: Path) -> None:
    dispatcher = PrivilegedDispatcher(
        FakeMaddy(),
        SimpleNamespace(),
        spool_dir=tmp_path,
        audit=lambda *_args, **_kwargs: None,
    )
    denied = dispatcher.dispatch(Request.create("accounts.list"))
    assert denied.response.error is not None
    assert denied.response.error.code == "forbidden"


def test_production_auth_store_denies_missing_and_invalid_sessions(tmp_path: Path) -> None:
    with make_auth_store(tmp_path) as store:
        dispatcher = make_dispatcher(tmp_path, FakeMaddy(), auth_store=store)
        missing = dispatcher.dispatch(Request.create("auth.session"))
        invalid = dispatcher.dispatch(Request.create("auth.session", auth_token="X" * 43))

    assert missing.response.error is not None
    assert missing.response.error.code == "forbidden"
    assert invalid.response.error is not None
    assert invalid.response.error.code == "unauthorized"


def test_session_peek_neither_touches_session_nor_audits_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit_records: list[tuple[str, str, dict[str, Any]]] = []

    def audit(action: str, *, outcome: str, fields: dict[str, Any]) -> None:
        audit_records.append((action, outcome, fields))

    with make_auth_store(tmp_path) as store:
        account, token = provision_session(store, "sender@example.test")
        authenticate_session = store.authenticate_session
        touches: list[bool] = []

        def recording_authenticate_session(
            session_token: str,
            *,
            touch: bool = True,
        ) -> Any:
            touches.append(touch)
            return authenticate_session(session_token, touch=touch)

        monkeypatch.setattr(store, "authenticate_session", recording_authenticate_session)
        result = make_dispatcher(
            tmp_path,
            FakeMaddy(),
            auth_store=store,
            audit=audit,
        ).dispatch(Request.create("auth.session_peek", auth_token=token))

    assert result.response.ok is True
    assert result.response.result["account_id"] == account.account_id
    assert touches == [False]
    assert not any(
        action == "helper.operation" and outcome == "ok"
        for action, outcome, _fields in audit_records
    )


def test_user_mailbox_scope_accepts_only_the_principal_opaque_target(
    tmp_path: Path,
) -> None:
    accounts = [
        {
            "username": "sender@example.test",
            "has_credentials": True,
            "has_mailbox": True,
        },
        {
            "username": "target@example.test",
            "has_credentials": True,
            "has_mailbox": True,
        },
    ]
    maddy = FakeMaddy(accounts=accounts)
    with make_auth_store(tmp_path) as store:
        account, token = provision_session(store, "sender@example.test")
        target = store.create_account(
            "target@example.test",
            password_change_required=False,
        )
        dispatcher = make_dispatcher(
            tmp_path,
            maddy,
            auth_store=store,
        )
        derived = dispatcher.dispatch(
            Request.create(
                "messages.list",
                {
                    "username": "target@example.test",
                    "mailbox": "INBOX",
                    "limit": 50,
                    "offset": 0,
                },
                auth_token=token,
            )
        )
        cross_account = dispatcher.dispatch(
            Request.create(
                "messages.list",
                {
                    "target_account_id": target.account_id,
                    "mailbox": "INBOX",
                    "limit": 50,
                    "offset": 0,
                },
                auth_token=token,
            )
        )
        explicit_self = dispatcher.dispatch(
            Request.create(
                "messages.list",
                {
                    "target_account_id": account.account_id,
                    "mailbox": "INBOX",
                    "limit": 50,
                    "offset": 0,
                },
                auth_token=token,
            )
        )

    assert derived.response.ok is True
    assert explicit_self.response.ok is True
    assert maddy.message_list_args == [
        ("sender@example.test", "INBOX"),
        ("sender@example.test", "INBOX"),
    ]
    assert cross_account.response.error is not None
    assert cross_account.response.error.code == "forbidden"


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="UNIX helper integration requires POSIX")
async def test_gateway_and_helper_accept_ordinary_user_own_opaque_id(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "helper.sock"
    ready: queue.Queue[tuple[str, str, FakeMaddy]] = queue.Queue(maxsize=1)
    server_errors: list[BaseException] = []

    def serve_authenticated_request() -> None:
        try:
            with make_auth_store(tmp_path) as store:
                account, token = provision_session(store, "sender@example.test")
                maddy = FakeMaddy(
                    messages=[
                        {
                            "uid": 1,
                            "sender": "source@example.test",
                            "subject": "Gateway helper integration",
                            "date": "2026-07-25T00:00:00+00:00",
                            "flags": [],
                        }
                    ]
                )
                dispatcher = make_dispatcher(
                    tmp_path,
                    maddy,
                    auth_store=store,
                )
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    listener.bind(str(socket_path))
                    listener.listen(1)
                    ready.put((account.account_id, token, maddy))
                    connection, _address = listener.accept()
                    with connection:
                        _TestUnixHelperServer(
                            dispatcher,
                            allowed_peer_uid=0,
                        ).serve_connection(connection)
                finally:
                    listener.close()
        except BaseException as exc:
            server_errors.append(exc)

    thread = threading.Thread(target=serve_authenticated_request)
    thread.start()
    account_id, token, maddy = await asyncio.to_thread(ready.get, True, 5)
    application_config = AppConfig.from_dict(
        {
            "maddy": {
                "mode": "docker",
                "helper_socket": str(socket_path),
            }
        }
    )
    gateway = HelperGateway(application_config)
    with bind_helper_identity(token):
        page = await gateway.list_messages(
            account_id,
            "INBOX",
            limit=50,
            offset=0,
        )
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert server_errors == []
    assert page["items"][0]["uid"] == 1
    assert maddy.message_list_args == [("sender@example.test", "INBOX")]
    assert maddy.account_list_modes == [False]


def test_admin_can_resolve_an_opaque_target_account_id(tmp_path: Path) -> None:
    accounts = [
        {
            "username": "admin@example.test",
            "has_credentials": True,
            "has_mailbox": True,
        },
        {
            "username": "target@example.test",
            "has_credentials": True,
            "has_mailbox": True,
        },
    ]
    maddy = FakeMaddy(accounts=accounts)
    with make_auth_store(tmp_path) as store:
        _admin, token = provision_session(
            store,
            "admin@example.test",
            role=Role.ADMIN,
        )
        target = store.create_account(
            "target@example.test",
            password_change_required=False,
        )
        result = make_dispatcher(
            tmp_path,
            maddy,
            auth_store=store,
        ).dispatch(
            Request.create(
                "messages.list",
                {
                    "target_account_id": target.account_id,
                    "mailbox": "INBOX",
                    "limit": 50,
                    "offset": 0,
                },
                auth_token=token,
            )
        )

    assert result.response.ok is True
    assert maddy.message_list_args == [("target@example.test", "INBOX")]


def test_password_change_gate_and_dangerous_operation_step_up(tmp_path: Path) -> None:
    with make_auth_store(tmp_path) as required_store:
        _account, required_token = provision_session(
            required_store,
            "sender@example.test",
            password_change_required=True,
        )
        required_dispatcher = make_dispatcher(
            tmp_path,
            FakeMaddy(),
            auth_store=required_store,
        )
        session = required_dispatcher.dispatch(
            Request.create("auth.session", auth_token=required_token)
        )
        blocked = required_dispatcher.dispatch(
            Request.create(
                "messages.list",
                {"mailbox": "INBOX", "limit": 50, "offset": 0},
                auth_token=required_token,
            )
        )

    with make_auth_store(tmp_path, "admin-auth.db") as admin_store:
        _admin, admin_token = provision_session(
            admin_store,
            "sender@example.test",
            role=Role.ADMIN,
        )
        dangerous = make_dispatcher(
            tmp_path,
            FakeMaddy(),
            auth_store=admin_store,
        ).dispatch(
            Request.create(
                "accounts.create",
                {
                    "username": "new@example.test",
                    "password": "new-mailbox-password",
                },
                auth_token=admin_token,
            )
        )

    assert session.response.ok is True
    assert session.response.result["password_change_required"] is True
    assert blocked.response.error is not None
    assert blocked.response.error.code == "password_change_required"
    assert dangerous.response.error is not None
    assert dangerous.response.error.code == "step_up_required"


def test_password_login_rejection_is_generic_and_never_audits_secret(
    tmp_path: Path,
) -> None:
    class RejectingLoginSMTP:
        @staticmethod
        def _validated_password(password: str) -> str:
            return SMTPSubmissionClient._validated_password(password)

        @staticmethod
        def authenticate(*, username: str, password: str) -> None:
            assert username == "sender@example.test"
            assert password
            raise SMTPRejected(535, "AUTH")

    audit_records: list[tuple[str, str, dict[str, Any]]] = []

    def audit(action: str, *, outcome: str, fields: dict[str, Any]) -> None:
        audit_records.append((action, outcome, fields))

    secret = "-".join(("browser", "mailbox", "secret"))
    with make_auth_store(tmp_path) as store:
        result = make_dispatcher(
            tmp_path,
            FakeMaddy(),
            smtp=RejectingLoginSMTP(),
            auth_store=store,
            audit=audit,
        ).dispatch(
            Request.create(
                "auth.password_begin",
                {
                    "email": "sender@example.test",
                    "password": secret,
                    "client_ip": "127.0.0.1",
                },
            )
        )

    assert result.response.error is not None
    assert result.response.error.code == "invalid_credentials"
    assert result.response.error.message == "Email address or password is invalid"
    assert audit_records[-1][1] == "invalid_credentials"
    assert audit_records[-1][2]["actor"] is None
    assert audit_records[-1][2]["params"]["password"] == "[REDACTED]"  # noqa: S105
    assert secret not in repr(audit_records)


def test_successful_password_totp_and_recovery_audits_are_attributed(
    tmp_path: Path,
) -> None:
    mailbox_password = "-".join(("mailbox", "password"))

    class AcceptingLoginSMTP:
        @staticmethod
        def _validated_password(password: str) -> str:
            return SMTPSubmissionClient._validated_password(password)

        @staticmethod
        def authenticate(*, username: str, password: str) -> None:
            assert username == "sender@example.test"
            assert password == mailbox_password

    audit_records: list[tuple[str, str, dict[str, Any]]] = []

    def audit(action: str, *, outcome: str, fields: dict[str, Any]) -> None:
        audit_records.append((action, outcome, fields))

    with make_auth_store(tmp_path) as store:
        account, enrollment, recovery_codes = store.provision_active_account("sender@example.test")
        dispatcher = make_dispatcher(
            tmp_path,
            FakeMaddy(),
            smtp=AcceptingLoginSMTP(),
            auth_store=store,
            audit=audit,
        )
        password_result = dispatcher.dispatch(
            Request.create(
                "auth.password_begin",
                {
                    "email": account.email,
                    "password": mailbox_password,
                    "client_ip": "203.0.113.8",
                },
            )
        )
        challenge = password_result.response.result["challenge"]
        password_audit = audit_records[-1]
        assert password_audit[1] == "ok"
        assert password_audit[2]["actor"] == account.email
        assert password_audit[2]["role"] == "user"
        assert password_audit[2]["authentication_method"] == "password"
        assert password_audit[2]["client_ip"] == "203.0.113.8"

        totp_result = dispatcher.dispatch(
            Request.create(
                "auth.totp_complete",
                {
                    "challenge": challenge,
                    "code": totp_code(enrollment.secret, timestamp=_AUTH_CLOCK),
                    "client_ip": "203.0.113.8",
                },
            )
        )
        assert totp_result.response.ok is True
        totp_audit = audit_records[-1]
        assert totp_audit[2]["actor"] == account.email
        assert totp_audit[2]["authentication_method"] == "totp"

        recovery_begin = dispatcher.dispatch(
            Request.create(
                "auth.password_begin",
                {
                    "email": account.email,
                    "password": mailbox_password,
                    "client_ip": "203.0.113.8",
                },
            )
        )
        recovery_result = dispatcher.dispatch(
            Request.create(
                "auth.recovery_complete",
                {
                    "challenge": recovery_begin.response.result["challenge"],
                    "recovery_code": recovery_codes[0],
                    "client_ip": "203.0.113.8",
                },
            )
        )
        assert recovery_result.response.ok is True
        recovery_audit = audit_records[-1]
        assert recovery_audit[2]["actor"] == account.email
        assert recovery_audit[2]["authentication_method"] == "recovery_code"

    serialized = repr(audit_records)
    assert mailbox_password not in serialized
    assert enrollment.secret not in serialized
    assert recovery_codes[0] not in serialized
    assert challenge not in serialized


def test_successful_enrollment_completion_audit_is_attributed(
    tmp_path: Path,
) -> None:
    audit_records: list[tuple[str, str, dict[str, Any]]] = []

    def audit(action: str, *, outcome: str, fields: dict[str, Any]) -> None:
        audit_records.append((action, outcome, fields))

    with make_auth_store(tmp_path) as store:
        account = store.create_account(
            "sender@example.test",
            password_change_required=False,
        )
        challenge = store.create_pending_challenge(account.email)
        dispatcher = make_dispatcher(
            tmp_path,
            FakeMaddy(),
            auth_store=store,
            audit=audit,
        )
        beginning = dispatcher.dispatch(
            Request.create("auth.enrollment_begin", {"challenge": challenge})
        )
        secret = beginning.response.result["secret"]
        completed = dispatcher.dispatch(
            Request.create(
                "auth.enrollment_complete",
                {
                    "challenge": challenge,
                    "code": totp_code(secret, timestamp=_AUTH_CLOCK),
                    "client_ip": "198.51.100.9",
                },
            )
        )

    assert completed.response.ok is True
    record = audit_records[-1]
    assert record[1] == "ok"
    assert record[2]["actor"] == account.email
    assert record[2]["role"] == "user"
    assert record[2]["authentication_method"] == "totp_enrollment"
    assert record[2]["client_ip"] == "198.51.100.9"
    assert challenge not in repr(record)
    assert secret not in repr(record)


def test_password_login_rejects_identity_without_mailbox(
    tmp_path: Path,
) -> None:
    class AcceptingLoginSMTP:
        @staticmethod
        def _validated_password(password: str) -> str:
            return SMTPSubmissionClient._validated_password(password)

        @staticmethod
        def authenticate(*, username: str, password: str) -> None:
            assert username == "sender@example.test"
            assert password

    maddy = FakeMaddy(
        accounts=[
            {
                "username": "sender@example.test",
                "has_credentials": True,
                "has_mailbox": False,
            }
        ]
    )
    with make_auth_store(tmp_path) as store:
        result = make_dispatcher(
            tmp_path,
            maddy,
            smtp=AcceptingLoginSMTP(),
            auth_store=store,
        ).dispatch(
            Request.create(
                "auth.password_begin",
                {
                    "email": "sender@example.test",
                    "password": "mailbox-password",
                    "client_ip": "127.0.0.1",
                },
            )
        )

    assert result.response.error is not None
    assert result.response.error.code == "invalid_credentials"


def test_self_password_change_revokes_sessions_before_maddy_write(
    tmp_path: Path,
) -> None:
    class AcceptingLoginSMTP:
        @staticmethod
        def _validated_password(password: str) -> str:
            return SMTPSubmissionClient._validated_password(password)

        @staticmethod
        def authenticate(*, username: str, password: str) -> None:
            assert username == "sender@example.test"
            assert password == "-".join(("current", "password"))

    with make_auth_store(tmp_path) as store:
        account, token = provision_session(store, "sender@example.test")

        class OrderingMaddy(FakeMaddy):
            def change_password(self, username: str, password: str) -> None:
                with pytest.raises(InvalidSessionError):
                    store.authenticate_session(token)
                super().change_password(username, password)

        maddy = OrderingMaddy()
        result = make_dispatcher(
            tmp_path,
            maddy,
            smtp=AcceptingLoginSMTP(),
            auth_store=store,
        ).dispatch(
            Request.create(
                "auth.change_password",
                {
                    "current_password": "current-password",
                    "new_password": "replacement-password",
                    "client_ip": "203.0.113.50",
                },
                auth_token=token,
            )
        )

        assert result.response.ok is True
        assert maddy.password_changes == [("sender@example.test", "replacement-password")]
        assert store.resolve_account_id(account.account_id).password_change_required is False


def test_password_change_stops_before_maddy_if_session_revocation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class AcceptingLoginSMTP:
        @staticmethod
        def _validated_password(password: str) -> str:
            return SMTPSubmissionClient._validated_password(password)

        @staticmethod
        def authenticate(*, username: str, password: str) -> None:
            assert username == "sender@example.test"
            assert password

    maddy = FakeMaddy()
    with make_auth_store(tmp_path) as store:
        _account, token = provision_session(store, "sender@example.test")

        def fail_revocation(_account_id: str) -> None:
            raise OSError("simulated authentication database failure")

        monkeypatch.setattr(store, "revoke_sessions", fail_revocation)
        result = make_dispatcher(
            tmp_path,
            maddy,
            smtp=AcceptingLoginSMTP(),
            auth_store=store,
        ).dispatch(
            Request.create(
                "auth.change_password",
                {
                    "current_password": "current-password",
                    "new_password": "replacement-password",
                    "client_ip": "203.0.113.50",
                },
                auth_token=token,
            )
        )

    assert result.response.error is not None
    assert maddy.password_changes == []


@pytest.mark.parametrize(
    ("operation", "params"),
    [
        (
            "auth.change_password",
            {
                "current_password": "current-password",
                "new_password": "replacement-password",
                "client_ip": "203.0.113.51",
            },
        ),
        (
            "auth.recovery_regenerate",
            {
                "password": "current-password",
                "code": "123456",
                "client_ip": "203.0.113.52",
            },
        ),
        (
            "auth.step_up",
            {
                "password": "current-password",
                "code": "123456",
                "client_ip": "203.0.113.53",
            },
        ),
    ],
)
def test_authenticated_reverification_honors_helper_rate_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    params: dict[str, str],
) -> None:
    class NeverCalledSMTP:
        @staticmethod
        def _validated_password(password: str) -> str:
            return SMTPSubmissionClient._validated_password(password)

        @staticmethod
        def authenticate(*, username: str, password: str) -> None:
            raise AssertionError((username, password))

    with make_auth_store(tmp_path, f"{operation.replace('.', '-')}.db") as store:
        _account, token = provision_session(
            store,
            "sender@example.test",
            role=Role.ADMIN,
        )

        def reject_rate(_email: str, _client_ip: str) -> None:
            raise LoginRateLimitedError(60)

        monkeypatch.setattr(store, "check_login_rate", reject_rate)
        result = make_dispatcher(
            tmp_path,
            FakeMaddy(),
            smtp=NeverCalledSMTP(),
            auth_store=store,
        ).dispatch(Request.create(operation, params, auth_token=token))

    assert result.response.error is not None
    assert result.response.error.code == "rate_limited"


def test_admin_password_reset_marks_required_and_revokes_before_maddy_write(
    tmp_path: Path,
) -> None:
    accounts = [
        {
            "username": "admin@example.test",
            "has_credentials": True,
            "has_mailbox": True,
        },
        {
            "username": "target@example.test",
            "has_credentials": True,
            "has_mailbox": True,
        },
    ]
    with make_auth_store(tmp_path) as store:
        _admin, admin_token = provision_session(
            store,
            "admin@example.test",
            role=Role.ADMIN,
        )
        target, target_token = provision_session(store, "target@example.test")
        store.mark_step_up(admin_token)

        class OrderingMaddy(FakeMaddy):
            def change_password(self, username: str, password: str) -> None:
                with pytest.raises(InvalidSessionError):
                    store.authenticate_session(target_token)
                assert store.resolve_account_id(target.account_id).password_change_required is True
                super().change_password(username, password)

        maddy = OrderingMaddy(accounts=accounts)
        result = make_dispatcher(
            tmp_path,
            maddy,
            auth_store=store,
        ).dispatch(
            Request.create(
                "accounts.change_password",
                {
                    "target_account_id": target.account_id,
                    "password": "administrator-reset-password",
                },
                auth_token=admin_token,
            )
        )

    assert result.response.ok is True
    assert maddy.password_changes == [("target@example.test", "administrator-reset-password")]


def test_admin_password_reset_stops_before_maddy_if_metadata_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accounts = [
        {
            "username": "admin@example.test",
            "has_credentials": True,
            "has_mailbox": True,
        },
        {
            "username": "target@example.test",
            "has_credentials": True,
            "has_mailbox": True,
        },
    ]
    maddy = FakeMaddy(accounts=accounts)
    with make_auth_store(tmp_path) as store:
        _admin, admin_token = provision_session(
            store,
            "admin@example.test",
            role=Role.ADMIN,
        )
        target, _target_token = provision_session(store, "target@example.test")
        store.mark_step_up(admin_token)

        def fail_metadata_update(
            _account_id: str,
            _required: bool,
            *,
            revoke_sessions: bool,
        ) -> None:
            assert revoke_sessions is True
            raise OSError("simulated authentication database failure")

        monkeypatch.setattr(
            store,
            "set_password_change_required",
            fail_metadata_update,
        )
        result = make_dispatcher(
            tmp_path,
            maddy,
            auth_store=store,
        ).dispatch(
            Request.create(
                "accounts.change_password",
                {
                    "target_account_id": target.account_id,
                    "password": "administrator-reset-password",
                },
                auth_token=admin_token,
            )
        )

    assert result.response.error is not None
    assert maddy.password_changes == []


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


def test_latest_message_probe_neither_touches_session_nor_audits_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    maddy = FakeMaddy([{"uid": 42, "subject": "private metadata"}])
    audit_records: list[tuple[str, str, dict[str, Any]]] = []

    def audit(action: str, *, outcome: str, fields: dict[str, Any]) -> None:
        audit_records.append((action, outcome, fields))

    with make_auth_store(tmp_path) as store:
        account, token = provision_session(store, "sender@example.test")
        authenticate_session = store.authenticate_session
        touches: list[bool] = []

        def recording_authenticate_session(
            session_token: str,
            *,
            touch: bool = True,
        ) -> Any:
            touches.append(touch)
            return authenticate_session(session_token, touch=touch)

        monkeypatch.setattr(store, "authenticate_session", recording_authenticate_session)
        dispatcher = make_dispatcher(
            tmp_path,
            maddy,
            auth_store=store,
            audit=audit,
        )
        result = dispatcher.dispatch(
            Request.create(
                "messages.latest",
                {
                    "target_account_id": account.account_id,
                    "mailbox": "INBOX",
                },
                auth_token=token,
            )
        )

        assert result.response.result == {"uid": 42}
        assert touches == [False]
        assert maddy.latest_message_uid_calls == [("sender@example.test", "INBOX")]
        assert not any(
            action == "helper.operation" and outcome == "ok"
            for action, outcome, _fields in audit_records
        )

        failed = dispatcher.dispatch(
            Request.create(
                "messages.latest",
                {"target_account_id": account.account_id},
                auth_token=token,
            )
        )

    assert failed.response.error is not None
    assert failed.response.error.code == "invalid_request"
    assert touches == [False, False]
    assert any(
        action == "helper.operation"
        and outcome == "invalid_request"
        and fields["operation"] == "messages.latest"
        for action, outcome, fields in audit_records
    )


def test_message_moves_allow_bounded_selection_but_deletion_requires_one_uid(
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

    moved_many = dispatcher.dispatch(
        Request.create(
            "messages.move",
            {
                "username": "sender@example.test",
                "source": "INBOX",
                "uid_set": "41,42",
                "target_special": "trash",
            },
        )
    )
    assert moved_many.response.result == {"moved": True, "target": "Custom Trash"}
    assert maddy.moved_many == [("sender@example.test", "INBOX", "41,42", "Custom Trash")]

    move_all = dispatcher.dispatch(
        Request.create(
            "messages.move",
            {
                "username": "sender@example.test",
                "source": "INBOX",
                "uid_set": "1:*",
                "target_special": "trash",
            },
        )
    )
    assert move_all.response.error is not None
    assert move_all.response.error.code == "invalid_request"

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


def test_smtp_authenticate_stops_after_auth_and_quit() -> None:
    channel = ScriptedChannel(
        [
            b"220 ready\r\n",
            b"250 hello\r\n",
            b"235 authenticated\r\n",
            b"221 goodbye\r\n",
        ]
    )
    credential = "-".join(("mailbox", "password"))
    _ScriptedSMTPClient(channel).authenticate(
        username="sender@example.test",
        password=credential,
    )

    assert channel.writes[0] == b"EHLO maddyweb.local\r\n"
    assert channel.writes[1].startswith(b"AUTH PLAIN ")
    assert channel.writes[2] == b"QUIT\r\n"
    assert len(channel.writes) == 3
    wire = b"".join(channel.writes)
    assert b"MAIL FROM" not in wire
    assert b"RCPT TO" not in wire
    assert b"DATA\r\n" not in wire
    assert channel.closed is True


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


def test_stream_preflight_rejects_unauthorized_request_before_spooling(
    tmp_path: Path,
) -> None:
    audit_records: list[tuple[str, str, dict[str, Any]]] = []

    def audit(action: str, *, outcome: str, fields: dict[str, Any]) -> None:
        audit_records.append((action, outcome, fields))

    with make_auth_store(tmp_path) as store:
        server = _TestUnixHelperServer(
            make_dispatcher(
                tmp_path,
                FakeMaddy(),
                auth_store=store,
                audit=audit,
            ),
            allowed_peer_uid=0,
        )
        client_socket, server_socket = socket.socketpair()
        thread = threading.Thread(target=_serve_once, args=(server, server_socket))
        thread.start()
        try:
            request = Request.create(
                "messages.append",
                {"mailbox_special": "sent"},
                stream_length=1024,
            )
            send_frame(client_socket, request.to_payload())
            response = Response.from_payload(receive_frame(client_socket))
        finally:
            client_socket.close()
            thread.join(timeout=2)

    assert response.error is not None
    assert response.error.code == "forbidden"
    assert not thread.is_alive()
    assert list(tmp_path.glob("maddyweb-*.spool")) == []
    assert audit_records[-1][0] == "helper.operation"
    assert audit_records[-1][1] == "forbidden"
    assert audit_records[-1][2]["operation"] == "messages.append"


def test_authorized_truncated_stream_has_attributed_operation_audit(
    tmp_path: Path,
) -> None:
    audit_records: list[tuple[str, str, dict[str, Any]]] = []

    def audit(action: str, *, outcome: str, fields: dict[str, Any]) -> None:
        audit_records.append((action, outcome, fields))

    with make_auth_store(tmp_path) as store:
        _account, token = provision_session(store, "sender@example.test")
        server = _TestUnixHelperServer(
            make_dispatcher(
                tmp_path,
                FakeMaddy(),
                auth_store=store,
                audit=audit,
            ),
            allowed_peer_uid=0,
            audit=audit,
        )
        client_socket, server_socket = socket.socketpair()
        request = Request.create(
            "messages.append",
            {"mailbox_special": "sent"},
            auth_token=token,
            stream_length=1024,
        )

        def send_truncated_stream() -> None:
            with client_socket:
                send_frame(client_socket, request.to_payload())
                client_socket.shutdown(socket.SHUT_WR)

        thread = threading.Thread(target=send_truncated_stream)
        thread.start()
        try:
            with server_socket:
                server.serve_connection(server_socket)
        finally:
            thread.join(timeout=2)

    assert not thread.is_alive()
    operation_records = [
        record
        for record in audit_records
        if record[0] == "helper.operation" and record[1] == "stream_receive_failed"
    ]
    assert len(operation_records) == 1
    fields = operation_records[0][2]
    assert fields["request_id"] == request.request_id
    assert fields["operation"] == "messages.append"
    assert fields["actor"] == "sender@example.test"
    assert fields["target"] == "sender@example.test"
    assert fields["params"] == {"mailbox_special": "sent"}
    assert fields["error_type"] == "StreamTruncated"
    assert list(tmp_path.glob("maddyweb-*.spool")) == []


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
