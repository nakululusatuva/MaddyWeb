from __future__ import annotations

import asyncio
import io
import json
import time
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlencode

import pytest
import pytest_asyncio
from aiohttp import CookieJar, FormData
from aiohttp.test_utils import TestClient, TestServer

from maddyweb.mail import DeliveryRejected, PreparedMessage
from maddyweb.web import MessagePage, create_app

FIXTURE_CREDENTIAL = "-".join(("account", "credential"))


class FakeGateway:
    def __init__(self) -> None:
        self.accounts = [
            {
                "id": "admin@example.test",
                "address": "admin@example.test",
                "has_credentials": True,
                "has_mailbox": True,
                "append_limit": 1024,
            },
            {
                "id": "disabled@example.test",
                "address": "disabled@example.test",
                "has_credentials": False,
                "has_mailbox": True,
            },
        ]
        self.operations: list[tuple[object, ...]] = []
        self.certificate_automation_safe = True
        self.certificate_timer_enabled = True
        self.certificate_timer_active = True
        self.message_rows: list[dict[str, object]] = [
            {
                "uid": 42,
                "message_id": "<rfc-message-id@example.test>",
                "from": "sender@example.test",
                "subject": "Received message",
            }
        ]
        self.message_next_offset: int | None = None
        self.message_initial_offset = 42
        self.delivered: bytes | None = None
        self.sent: bytes | None = None
        self.delivery_error: Exception | None = None
        self.spool_gate: asyncio.Event | None = None
        self.spool_active = 0
        self.two_spools_started = asyncio.Event()
        self.health_payload: dict[str, object] = {
            "status": "ok",
            "version": "0.1.0",
            "maddy_version": "0.9.5",
            "maddy_write_enabled": True,
            "storage_available": True,
            "certbot_available": True,
            "certificate_management_enabled": True,
            "socket_path": "/secret/helper.sock",
            "accounts": ["must-not-leak@example.test"],
        }
        incoming = EmailMessage()
        incoming["From"] = "sender@example.test"
        incoming["To"] = "admin@example.test"
        incoming["Subject"] = "Received message"
        incoming.set_content("Plain text")
        incoming.add_alternative(
            '<script>alert(1)</script><img src="https://tracker.test/pixel">'
            '<img src="data:image/png;base64,AAAA"><img src="cid:missing">'
            '<img src="cid:logo"><b>Safe body</b>',
            subtype="html",
        )
        html_part = incoming.get_payload()[-1]
        assert isinstance(html_part, EmailMessage)
        html_part.add_related(
            b"\x89PNG\r\n\x1a\ninline-image",
            maintype="image",
            subtype="png",
            cid="<logo>",
            filename="logo.png",
            disposition="inline",
        )
        incoming.add_attachment(
            b"<script>attachment</script>",
            maintype="text",
            subtype="html",
            filename="page.html",
        )
        self.raw_message = incoming.as_bytes(policy=policy.SMTP)

    async def health(self) -> dict[str, object]:
        return self.health_payload

    async def list_accounts(self) -> list[dict[str, object]]:
        return self.accounts

    async def create_account(self, username: str, password: str) -> object:
        self.operations.append(("create_account", username, password))
        return {"address": username}

    async def change_password(self, account_id: str, password: str) -> None:
        self.operations.append(("change_password", account_id, password))

    async def set_append_limit(self, account_id: str, limit: int) -> None:
        self.operations.append(("set_append_limit", account_id, limit))

    async def disable_credentials(self, account_id: str) -> None:
        self.operations.append(("disable_credentials", account_id))

    async def delete_mailbox(self, account_id: str) -> None:
        self.operations.append(("delete_mailbox", account_id))

    async def list_mailboxes(self, account_id: str) -> list[dict[str, str]]:
        self.operations.append(("list_mailboxes", account_id))
        return [{"name": "INBOX"}, {"name": "Sent"}, {"name": "Trash"}]

    async def list_messages(
        self,
        account_id: str,
        mailbox: str,
        *,
        limit: int,
        offset: int,
    ) -> MessagePage:
        self.operations.append(("list_messages", account_id, mailbox, limit, offset))
        return MessagePage(
            self.message_rows,
            self.message_next_offset is not None,
            self.message_next_offset,
            offset or self.message_initial_offset,
        )

    async def spool_message(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
        destination_path: Path,
        *,
        max_bytes: int,
    ) -> int:
        self.operations.append(("spool_message", account_id, mailbox, message_id))
        if self.spool_gate is not None:
            self.spool_active += 1
            if self.spool_active == 2:
                self.two_spools_started.set()
            try:
                await self.spool_gate.wait()
            finally:
                self.spool_active -= 1
        if len(self.raw_message) > max_bytes:
            raise ValueError("message too large")
        return await asyncio.to_thread(destination_path.write_bytes, self.raw_message)

    async def move_message_to_trash(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
    ) -> str:
        self.operations.append(("trash", account_id, mailbox, message_id))
        return "Trash"

    async def delete_message_permanently(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
    ) -> None:
        self.operations.append(("delete_message", account_id, mailbox, message_id))

    async def certificate_status(self) -> dict[str, object]:
        return {
            "timer_enabled": self.certificate_timer_enabled,
            "timer_active": self.certificate_timer_active,
            "timer_state": "active",
            "timer_enable_safe": self.certificate_automation_safe,
            "certificates": [
                {
                    "name": "mail.example.test",
                    "expires": "2027-01-01",
                    "source_fingerprint": "AA:BB",
                    "deployed_fingerprint": "AA:BB",
                    "fingerprints_match": True,
                    "automation_safe": self.certificate_automation_safe,
                }
            ],
        }

    async def set_certificate_timer(self, enabled: bool) -> None:
        self.operations.append(("certificate_timer", enabled))

    async def certificate_dry_run(self, certificate_name: str) -> object:
        self.operations.append(("certificate_dry_run", certificate_name))
        return {"ok": True}

    async def renew_certificate_if_due(self, certificate_name: str) -> object:
        self.operations.append(("certificate_renew_if_due", certificate_name))
        return {"renewed": False}

    async def deliver_message(
        self,
        message: PreparedMessage,
        envelope_from: str,
        recipients: tuple[str, ...],
        submission_password: str,
    ) -> str:
        assert submission_password == FIXTURE_CREDENTIAL
        self.operations.append(("deliver", envelope_from, recipients))
        if self.delivery_error is not None:
            raise self.delivery_error
        self.delivered = b"".join(message.iter_chunks())
        return "smtp-1"

    async def save_sent(self, message: PreparedMessage) -> None:
        self.operations.append(("save_sent",))
        self.sent = b"".join(message.iter_chunks())


@pytest_asyncio.fixture
async def web_client(tmp_path: Path) -> tuple[TestClient, FakeGateway]:
    gateway = FakeGateway()
    config = {
        "server": {
            "allowed_hosts": ("127.0.0.1", "localhost"),
            "concurrency": 4,
            "max_upload_bytes": 4 * 1024 * 1024,
            "page_size": 20,
            "temp_dir": tmp_path,
        },
        "security": {
            "session_signing_key": b"k" * 32,
            "csrf_ttl_seconds": 300,
            "cookie_name": "maddyweb-csrf",
            "secure_cookies": False,
        },
    }
    client = TestClient(
        TestServer(create_app(config, gateway)),
        cookie_jar=CookieJar(unsafe=True),
    )
    await client.start_server()
    try:
        yield client, gateway
    finally:
        await client.close()


async def _get_token(client: TestClient) -> str:
    response = await client.get("/api/v1/session")
    assert response.status == 200
    payload = await response.json()
    assert payload["ok"] is True
    return str(payload["data"]["csrf_token"])


def _origin(client: TestClient) -> str:
    return str(client.make_url("/").origin())


async def _api_data(client: TestClient, path: str) -> tuple[object, dict[str, object]]:
    response = await client.get(path)
    payload = await response.json()
    assert payload["api_version"] == "v1"
    assert payload["ok"] is True
    return response, payload["data"]


async def _post_json(
    client: TestClient,
    path: str,
    token: str,
    payload: dict[str, object],
) -> object:
    return await client.post(
        path,
        json=payload,
        headers={"Origin": _origin(client), "X-CSRF-Token": token},
        allow_redirects=False,
    )


@pytest.mark.asyncio
async def test_home_static_assets_and_strict_headers(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, _gateway = web_client
    response = await client.get("/")
    page = await response.text()
    assert response.status == 200
    assert "Administration overview" in page
    assert 'href="/static/app.css?v=5"' in page
    assert 'src="/static/app.js?v=6"' in page
    assert '<main id="main" class="app-main" tabindex="-1">' in page
    assert "admin@example.test" not in page
    assert "csrf_token" not in page
    assert "Access-Control-Allow-Origin" not in response.headers
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert "img-src 'self' blob:" in response.headers["Content-Security-Policy"]
    assert response.headers["Referrer-Policy"] == "same-origin"

    stylesheet = await client.get("/static/app.css")
    assert stylesheet.status == 200
    assert stylesheet.content_type == "text/css"
    stylesheet_bytes = await stylesheet.read()
    assert b"@import" not in stylesheet_bytes
    assert b"url(" not in stylesheet_bytes

    javascript = await client.get("/static/app.js")
    assert javascript.status == 200
    assert javascript.content_type == "application/javascript"
    assert javascript.headers["X-Content-Type-Options"] == "nosniff"
    javascript_text = await javascript.text()
    assert "URL.createObjectURL" in javascript_text
    assert "FileReader" not in javascript_text
    for forbidden_sink in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "document.open",
        "srcdoc",
        "eval(",
    ):
        assert forbidden_sink not in javascript_text
    assert "serializeEditorNode" in javascript_text
    assert "X-CSRF-Token" in javascript_text

    rejected = await client.get("/", headers={"Host": "evil.example"})
    assert rejected.status == 400


@pytest.mark.asyncio
async def test_shell_supports_only_known_client_routes(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, _gateway = web_client
    for path in ("/", "/accounts", "/mail", "/compose", "/certificates"):
        response = await client.get(path)
        assert response.status == 200
        page = await response.text()
        assert 'aria-label="Main navigation"' in page
        assert "https://" not in page
        assert "http://" not in page
        assert " style=" not in page
    detail = await client.get("/mail/42?account=admin%40example.test&mailbox=INBOX")
    assert detail.status == 200
    assert "Administration overview" in await detail.text()
    assert (await client.get("/unknown-client-route")).status == 404
    api_missing = await client.get("/api/v1/not-real")
    assert api_missing.status == 404
    assert (await api_missing.json())["error"]["code"] == "not_found"


@pytest.mark.asyncio
async def test_health_has_fixed_non_sensitive_schema_and_degrades(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    response = await client.get("/healthz")
    assert response.status == 200
    payload = await response.json()
    assert set(payload) == {
        "status",
        "version",
        "maddy_version",
        "maddy_write_enabled",
        "storage_available",
        "certbot_available",
        "certificate_management_enabled",
    }
    serialized = json.dumps(payload)
    assert "helper.sock" not in serialized
    assert "must-not-leak" not in serialized
    api_response, api_payload = await _api_data(client, "/api/v1/health")
    assert api_response.status == 200
    assert api_payload == payload

    gateway.health_payload["status"] = "degraded"
    gateway.health_payload["maddy_write_enabled"] = False
    degraded = await client.get("/healthz")
    assert degraded.status == 503
    assert (await degraded.json())["status"] == "degraded"
    degraded_api = await client.get("/api/v1/health")
    assert degraded_api.status == 503
    assert (await degraded_api.json())["data"]["status"] == "degraded"


@pytest.mark.asyncio
async def test_account_actions_are_separate_and_mailbox_delete_is_confirmed(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    response, data = await _api_data(client, "/api/v1/accounts")
    assert response.status == 200
    assert [account["address"] for account in data["accounts"]] == [
        "admin@example.test",
        "disabled@example.test",
    ]

    token = await _get_token(client)
    created = await _post_json(
        client,
        "/api/v1/accounts",
        token,
        {"username": "new@example.test", "password": "valid-password"},
    )
    assert created.status == 201
    assert ("create_account", "new@example.test", "valid-password") in gateway.operations

    token = await _get_token(client)
    changed = await _post_json(
        client,
        "/api/v1/accounts/admin@example.test/password",
        token,
        {"password": "changed-password"},
    )
    assert changed.status == 200
    assert ("change_password", "admin@example.test", "changed-password") in gateway.operations

    token = await _get_token(client)
    limit = await _post_json(
        client,
        "/api/v1/accounts/admin@example.test/append-limit",
        token,
        {"limit": 0},
    )
    assert limit.status == 200
    assert ("set_append_limit", "admin@example.test", 0) in gateway.operations

    token = await _get_token(client)
    disabled = await _post_json(
        client,
        "/api/v1/accounts/admin@example.test/credentials/disable",
        token,
        {},
    )
    assert disabled.status == 200
    assert ("disable_credentials", "admin@example.test") in gateway.operations

    token = await _get_token(client)
    wrong = await _post_json(
        client,
        "/api/v1/accounts/admin@example.test/delete",
        token,
        {"confirmation": "wrong@example.test"},
    )
    assert wrong.status == 400
    assert not any(operation[0] == "delete_mailbox" for operation in gateway.operations)

    token = await _get_token(client)
    deleted = await _post_json(
        client,
        "/api/v1/accounts/admin@example.test/delete",
        token,
        {"confirmation": "admin@example.test"},
    )
    assert deleted.status == 200
    assert ("delete_mailbox", "admin@example.test") in gateway.operations


@pytest.mark.asyncio
async def test_json_writes_are_strict_bounded_and_rotate_after_handler_errors(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    origin = _origin(client)

    token = await _get_token(client)
    form_response = await client.post(
        "/api/v1/accounts",
        data={"username": "new@example.test", "password": "valid-password"},
        headers={"Origin": origin, "X-CSRF-Token": token},
    )
    assert form_response.status == 415
    assert (await form_response.json())["error"]["code"] == "unsupported_media_type"

    for raw_body in (
        b'{"username":"one@example.test","username":"two@example.test",'
        b'"password":"valid-password"}',
        b'{"username":"new@example.test","password":"valid-password","extra":true}',
        b'["new@example.test","valid-password"]',
        b'{"username":NaN,"password":"valid-password"}',
        ("[" * 80 + "0" + "]" * 80).encode(),
    ):
        token = await _get_token(client)
        rejected = await client.post(
            "/api/v1/accounts",
            data=raw_body,
            headers={
                "Content-Type": "application/json",
                "Origin": origin,
                "X-CSRF-Token": token,
            },
        )
        assert rejected.status == 400
        assert rejected.headers["X-CSRF-Token"] != token
        payload = await rejected.json()
        assert payload["ok"] is False
        assert payload["error"]["code"] == "invalid_request"

    token = await _get_token(client)

    async def oversized_json():
        yield b'{"username":"new@example.test","password":"'
        yield b"x" * (64 * 1024)
        yield b'"}'

    oversized = await client.post(
        "/api/v1/accounts",
        data=oversized_json(),
        headers={
            "Content-Type": "application/json",
            "Origin": origin,
            "X-CSRF-Token": token,
        },
    )
    assert oversized.status == 413
    assert (await oversized.json())["error"]["code"] == "payload_too_large"
    assert not any(operation[0] == "create_account" for operation in gateway.operations)


@pytest.mark.asyncio
async def test_invalid_backend_account_payload_fails_closed(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    gateway.accounts[0]["append_limit"] = object()
    response = await client.get("/api/v1/accounts")
    assert response.status == 502
    payload = await response.json()
    assert payload["error"]["code"] == "invalid_backend_response"
    assert "object at" not in json.dumps(payload)


@pytest.mark.asyncio
async def test_mail_requires_account_and_mailbox_context_and_has_two_delete_levels(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    response, data = await _api_data(client, "/api/v1/mail")
    assert response.status == 200
    assert data["selected_account"] == ""
    assert data["mailboxes"] == []
    assert data["messages"] == []
    assert not any(operation[0] == "list_messages" for operation in gateway.operations)

    context = urlencode({"account": "admin@example.test", "mailbox": "INBOX"})
    response, data = await _api_data(client, f"/api/v1/mail?{context}")
    assert response.status == 200
    assert data["messages"][0]["subject"] == "Received message"
    assert data["messages"][0]["uid"] == "42"
    assert "message_id" not in data["messages"][0]
    assert ("list_messages", "admin@example.test", "INBOX", 20, 0) in gateway.operations

    detail, detail_data = await _api_data(client, f"/api/v1/mail/42?{context}")
    assert detail.status == 200
    assert detail_data["subject"] == "Received message"
    assert detail_data["has_html"] is True
    assert detail_data["html_url"].startswith("/api/v1/mail/42/html?")
    assert detail_data["raw_url"].startswith("/api/v1/mail/42/raw?")
    assert detail_data["freshness_token"]

    html_body = await client.get(f"/api/v1/mail/42/html?{context}")
    rendered = await html_body.text()
    assert html_body.status == 200
    assert html_body.headers["Referrer-Policy"] == "no-referrer"
    iframe_csp = html_body.headers["Content-Security-Policy"]
    assert "sandbox" in iframe_csp
    assert "img-src 'self'" in iframe_csp
    assert "data:" not in iframe_csp
    assert "cid:" not in iframe_csp
    assert "tracker.test" not in rendered
    assert "script" not in rendered
    assert "data:image" not in rendered
    assert "cid:missing" not in rendered
    assert "cid:logo" not in rendered
    assert "/api/v1/mail/42/inline/0?account=admin%40example.test&amp;mailbox=INBOX" in rendered

    inline = await client.get(f"/api/v1/mail/42/inline/0?{context}")
    assert inline.status == 200
    assert inline.content_type == "image/png"
    assert inline.headers["X-Content-Type-Options"] == "nosniff"
    assert await inline.read() == b"\x89PNG\r\n\x1a\ninline-image"

    attachment = await client.get(f"/api/v1/mail/42/attachments/1?{context}")
    assert attachment.content_type == "application/octet-stream"
    assert attachment.headers["Content-Disposition"].startswith("attachment;")

    token = await _get_token(client)
    trashed = await _post_json(
        client,
        "/api/v1/mail/42/trash",
        token,
        {
            "account": "admin@example.test",
            "mailbox": "INBOX",
            "freshness": detail_data["freshness_token"],
        },
    )
    assert trashed.status == 200
    assert ("trash", "admin@example.test", "INBOX", "42") in gateway.operations

    _response, fresh_detail = await _api_data(client, f"/api/v1/mail/42?{context}")
    token = await _get_token(client)
    rejected = await _post_json(
        client,
        "/api/v1/mail/42/delete",
        token,
        {
            "account": "admin@example.test",
            "mailbox": "INBOX",
            "freshness": fresh_detail["freshness_token"],
            "confirmation": "Delete",
        },
    )
    assert rejected.status == 400
    assert not any(operation[0] == "delete_message" for operation in gateway.operations)


@pytest.mark.asyncio
async def test_single_uid_and_freshness_are_required_for_destructive_mail_actions(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    context = urlencode({"account": "admin@example.test", "mailbox": "INBOX"})

    for invalid_uid in ("1:*", "1,2", "9" * 100, "\u0661"):
        token = await _get_token(client)
        invalid = await _post_json(
            client,
            f"/api/v1/mail/{invalid_uid}/delete",
            token,
            {
                "account": "admin@example.test",
                "mailbox": "INBOX",
                "freshness": "invalid",
                "confirmation": "PERMANENTLY DELETE",
            },
        )
        assert invalid.status in {400, 404}

    _response, detail = await _api_data(client, f"/api/v1/mail/42?{context}")
    freshness = detail["freshness_token"]
    gateway.raw_message = gateway.raw_message.replace(b"Subject:", b"Subject: changed ", 1)
    token = await _get_token(client)
    stale = await _post_json(
        client,
        "/api/v1/mail/42/trash",
        token,
        {
            "account": "admin@example.test",
            "mailbox": "INBOX",
            "freshness": freshness,
        },
    )
    assert stale.status == 409
    assert not any(operation[0] == "trash" for operation in gateway.operations)

    _response, changed_detail = await _api_data(client, f"/api/v1/mail/42?{context}")
    token = await _get_token(client)
    deleted = await _post_json(
        client,
        "/api/v1/mail/42/delete",
        token,
        {
            "account": "admin@example.test",
            "mailbox": "INBOX",
            "freshness": changed_detail["freshness_token"],
            "confirmation": "PERMANENTLY DELETE",
        },
    )
    assert deleted.status == 200
    assert ("delete_message", "admin@example.test", "INBOX", "42") in gateway.operations


@pytest.mark.asyncio
async def test_nested_mailbox_name_is_allowed_when_returned_by_maddy(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client

    async def nested_mailboxes(account_id: str) -> list[dict[str, str]]:
        gateway.operations.append(("list_mailboxes", account_id))
        return [{"name": "INBOX"}, {"name": "Projects/2026"}]

    gateway.list_mailboxes = nested_mailboxes  # type: ignore[method-assign]
    context = urlencode({"account": "admin@example.test", "mailbox": "Projects/2026"})
    response = await client.get(f"/api/v1/mail?{context}")
    assert response.status == 200


@pytest.mark.asyncio
async def test_mailbox_pagination_is_bounded_and_preserves_context(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    gateway.message_rows = [
        {"id": str(index), "sender": "sender@example.test", "subject": f"Message {index}"}
        for index in range(1, 21)
    ]
    gateway.message_initial_offset = 100
    gateway.message_next_offset = 80
    context = urlencode({"account": "admin@example.test", "mailbox": "INBOX"})
    first, first_data = await _api_data(client, f"/api/v1/mail?{context}")
    assert first.status == 200
    next_cursor = str(first_data["next_cursor"])
    assert next_cursor
    assert first_data["previous_cursor"] is None
    next_query = urlencode(
        {
            "account": "admin@example.test",
            "mailbox": "INBOX",
            "cursor": next_cursor,
        }
    )
    next_href = f"/api/v1/mail?{next_query}"

    gateway.message_next_offset = None
    second, second_data = await _api_data(client, next_href)
    assert second.status == 200
    assert second_data["previous_cursor"]
    assert ("list_messages", "admin@example.test", "INBOX", 20, 80) in gateway.operations

    previous_query = urlencode(
        {
            "account": "admin@example.test",
            "mailbox": "INBOX",
            "cursor": str(second_data["previous_cursor"]),
        }
    )
    previous_href = f"/api/v1/mail?{previous_query}"
    await client.get(previous_href)
    assert ("list_messages", "admin@example.test", "INBOX", 20, 100) in gateway.operations

    tampered = next_href.replace("mailbox=INBOX", "mailbox=Sent")
    assert (await client.get(tampered)).status == 409

    invalid = await client.get(f"/api/v1/mail?{context}&page=1")
    assert invalid.status == 400


@pytest.mark.asyncio
async def test_mailbox_uses_authoritative_continuation_not_page_length(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    context = urlencode({"account": "admin@example.test", "mailbox": "INBOX"})

    gateway.message_initial_offset = 100
    gateway.message_rows = [{"id": "100", "sender": "sender@example.test", "subject": "Truncated"}]
    gateway.message_next_offset = 99
    _response, truncated_data = await _api_data(client, f"/api/v1/mail?{context}")
    continuation_query = urlencode(
        {
            "account": "admin@example.test",
            "mailbox": "INBOX",
            "cursor": str(truncated_data["next_cursor"]),
        }
    )
    continuation = f"/api/v1/mail?{continuation_query}"

    gateway.message_rows = [{"id": "99", "sender": "sender@example.test", "subject": "Continued"}]
    gateway.message_next_offset = None
    _response, continued_data = await _api_data(client, continuation)
    assert continued_data["previous_cursor"]
    assert ("list_messages", "admin@example.test", "INBOX", 20, 99) in gateway.operations

    gateway.message_rows = [
        {"id": str(index), "sender": "sender@example.test", "subject": f"Message {index}"}
        for index in range(1, 21)
    ]
    gateway.message_next_offset = None
    _response, complete_data = await _api_data(client, f"/api/v1/mail?{context}")
    assert complete_data["next_cursor"] is None


@pytest.mark.asyncio
async def test_oversized_preview_still_allows_streamed_raw_download(
    web_client: tuple[TestClient, FakeGateway],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, gateway = web_client
    monkeypatch.setattr("maddyweb.web.MAX_RAW_MESSAGE_BYTES", 64)
    gateway.raw_message = b"From: sender@example.test\r\n\r\n" + b"x" * (128 * 1024)
    context = urlencode({"account": "admin@example.test", "mailbox": "INBOX"})
    detail, data = await _api_data(client, f"/api/v1/mail/42?{context}")
    assert detail.status == 200
    assert data["preview_too_large"] is True
    assert data["size"] == len(gateway.raw_message)
    assert data["raw_url"].startswith("/api/v1/mail/42/raw?")
    assert "html_url" not in data

    raw = await client.get(f"/api/v1/mail/42/raw?{context}")
    assert raw.status == 200
    assert raw.content_type == "application/octet-stream"
    assert raw.headers["Content-Disposition"].startswith("attachment;")
    assert await raw.read() == gateway.raw_message


@pytest.mark.asyncio
async def test_heavy_mail_work_is_limited_to_two_and_rejects_third(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    gateway.spool_gate = asyncio.Event()
    context = urlencode({"account": "admin@example.test", "mailbox": "INBOX"})
    first = asyncio.create_task(client.get(f"/api/v1/mail/42?{context}"))
    second = asyncio.create_task(client.get(f"/api/v1/mail/42?{context}"))
    try:
        await asyncio.wait_for(gateway.two_spools_started.wait(), timeout=1)
        health = await asyncio.wait_for(client.get("/healthz"), timeout=0.1)
        assert health.status == 200
        third = await client.get(f"/api/v1/mail/42?{context}")
        assert third.status == 429
        assert third.headers["Retry-After"] == "1"
    finally:
        gateway.spool_gate.set()
    assert (await first).status == 200
    assert (await second).status == 200


@pytest.mark.asyncio
async def test_message_parse_runs_off_event_loop(
    web_client: tuple[TestClient, FakeGateway],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _gateway = web_client
    from maddyweb import web as web_module

    original = web_module.parse_message
    loop = asyncio.get_running_loop()
    started = asyncio.Event()

    def slow_parse(raw: bytes):
        loop.call_soon_threadsafe(started.set)
        time.sleep(0.15)
        return original(raw)

    monkeypatch.setattr(web_module, "parse_message", slow_parse)
    context = urlencode({"account": "admin@example.test", "mailbox": "INBOX"})
    detail_task = asyncio.create_task(client.get(f"/api/v1/mail/42?{context}"))
    await asyncio.wait_for(started.wait(), timeout=1)
    health = await asyncio.wait_for(client.get("/healthz"), timeout=0.08)
    assert health.status == 200
    assert (await detail_task).status == 200


@pytest.mark.asyncio
async def test_compose_uses_enabled_sender_and_streams_cid_mime(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    response, data = await _api_data(client, "/api/v1/compose")
    assert response.status == 200
    assert data["senders"] == ["admin@example.test"]
    token = await _get_token(client)

    form = FormData()
    form.add_field("sender", "admin@example.test")
    form.add_field("password", FIXTURE_CREDENTIAL)
    form.add_field("to", "recipient@example.test")
    form.add_field("cc", "")
    form.add_field("bcc", "hidden@example.test")
    form.add_field("subject", "Rich text")
    form.add_field("text", "plain")
    form.add_field("html", '<p>rich<img src="cid:logo@maddyweb.local"></p>')
    form.add_field("inline_cids", "logo@maddyweb.local")
    form.add_field(
        "inline_images",
        io.BytesIO(b"\x89PNG\r\n\x1a\nimage"),
        filename="logo.png",
        content_type="image/png",
    )
    form.add_field(
        "attachments",
        io.BytesIO(b"attachment"),
        filename="notes.txt",
        content_type="text/plain",
    )
    response = await client.post(
        "/api/v1/send",
        data=form,
        headers={"Origin": _origin(client), "X-CSRF-Token": token},
        allow_redirects=False,
    )
    assert response.status == 200
    payload = await response.json()
    assert payload["data"] == {"delivered": True, "saved_to_sent": True}
    assert "Remote inbox placement is not confirmed here." in payload["message"]
    assert gateway.delivered == gateway.sent
    assert gateway.delivered is not None
    parsed = BytesParser(policy=policy.default).parsebytes(gateway.delivered)
    assert parsed["Bcc"] is None
    assert any(part.get("Content-ID") == "<logo@maddyweb.local>" for part in parsed.walk())


@pytest.mark.asyncio
async def test_smtp_auth_rejection_is_actionable_and_does_not_echo_password(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    gateway.delivery_error = DeliveryRejected(
        "internal SMTP diagnostic",
        public_message=(
            "Authentication for the selected sending account was rejected. Check its mailbox "
            "password and confirm that credentials are enabled, then try again. The message "
            "was not submitted."
        ),
    )
    token = await _get_token(client)
    form = FormData()
    for name, value in {
        "sender": "admin@example.test",
        "password": FIXTURE_CREDENTIAL,
        "to": "recipient@example.test",
        "subject": "Authentication test",
        "text": "body",
        "html": "",
    }.items():
        form.add_field(name, value)
    form.add_field("attachments", io.BytesIO(b"x"), filename="x.txt")
    response = await client.post(
        "/api/v1/send",
        data=form,
        headers={"Origin": _origin(client), "X-CSRF-Token": token},
        allow_redirects=False,
    )
    payload = await response.json()
    serialized = json.dumps(payload)
    assert response.status == 502
    assert payload["error"]["code"] == "message_not_delivered"
    assert "Authentication for the selected sending account was rejected." in serialized
    assert FIXTURE_CREDENTIAL not in serialized
    assert "internal SMTP diagnostic" not in serialized
    assert "WWW-Authenticate" not in response.headers
    assert gateway.sent is None


@pytest.mark.asyncio
async def test_invalid_recipient_identifies_field_without_echoing_input(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    token = await _get_token(client)
    form = FormData()
    for name, value in {
        "sender": "admin@example.test",
        "password": FIXTURE_CREDENTIAL,
        "to": "private-invalid-value",
        "subject": "Address validation test",
        "text": "body",
        "html": "",
    }.items():
        form.add_field(name, value)
    form.add_field("attachments", io.BytesIO(b"x"), filename="x.txt")
    response = await client.post(
        "/api/v1/send",
        data=form,
        headers={"Origin": _origin(client), "X-CSRF-Token": token},
        allow_redirects=False,
    )
    payload = await response.json()
    serialized = json.dumps(payload)

    assert response.status == 400
    assert "The To field contains an invalid email address." in serialized
    assert "private-invalid-value" not in serialized
    assert gateway.delivered is None


@pytest.mark.asyncio
async def test_fullwidth_recipient_separators_are_normalized(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    token = await _get_token(client)
    form = FormData()
    for name, value in {
        "sender": "admin@example.test",
        "password": FIXTURE_CREDENTIAL,
        "to": "first@example.test\uff0csecond@example.test\uff1bthird@example.test",
        "subject": "Separator test",
        "text": "body",
        "html": "",
    }.items():
        form.add_field(name, value)
    form.add_field("attachments", io.BytesIO(b"x"), filename="x.txt")
    response = await client.post(
        "/api/v1/send",
        data=form,
        headers={"Origin": _origin(client), "X-CSRF-Token": token},
        allow_redirects=False,
    )

    assert response.status == 200
    assert (
        "deliver",
        "admin@example.test",
        ("first@example.test", "second@example.test", "third@example.test"),
    ) in gateway.operations


@pytest.mark.asyncio
async def test_slow_multipart_upload_times_out_and_releases_request_slot(
    tmp_path: Path,
) -> None:
    gateway = FakeGateway()
    config = {
        "server": {
            "allowed_hosts": ("127.0.0.1",),
            "concurrency": 1,
            "max_upload_bytes": 4 * 1024 * 1024,
            "request_body_timeout_seconds": 0.05,
            "temp_dir": tmp_path,
        },
        "security": {
            "session_signing_key": b"k" * 32,
            "cookie_name": "maddyweb-csrf",
            "secure_cookies": False,
        },
    }
    client = TestClient(
        TestServer(create_app(config, gateway)),
        cookie_jar=CookieJar(unsafe=True),
    )
    await client.start_server()
    try:
        token = await _get_token(client)
        boundary = "maddyweb-slow-boundary"

        async def slow_multipart():
            yield (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="sender"\r\n\r\n'
                "admin@example.test\r\n"
            ).encode()
            await asyncio.sleep(0.2)
            yield f"--{boundary}--\r\n".encode()

        response = await client.post(
            "/api/v1/send",
            data=slow_multipart(),
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Origin": _origin(client),
                "X-CSRF-Token": token,
            },
        )
        assert response.status == 408
        assert (await client.get("/healthz")).status == 200
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_compose_rejects_duplicate_scalars_and_bounds_password_bytes(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, _gateway = web_client
    token = await _get_token(client)
    duplicate = FormData()
    duplicate.add_field("sender", "admin@example.test")
    duplicate.add_field("sender", "admin@example.test")
    duplicate.add_field(
        "attachments",
        io.BytesIO(b"x"),
        filename="x.txt",
        content_type="text/plain",
    )
    response = await client.post(
        "/api/v1/send",
        data=duplicate,
        headers={"Origin": _origin(client), "X-CSRF-Token": token},
    )
    assert response.status == 400

    token = await _get_token(client)
    oversized = FormData()
    oversized.add_field("sender", "admin@example.test")
    oversized.add_field("password", "x" * 5000)
    oversized.add_field(
        "attachments",
        io.BytesIO(b"x"),
        filename="x.txt",
        content_type="text/plain",
    )
    response = await client.post(
        "/api/v1/send",
        data=oversized,
        headers={"Origin": _origin(client), "X-CSRF-Token": token},
    )
    assert response.status == 413


@pytest.mark.asyncio
async def test_disabled_sender_is_rejected_server_side(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    token = await _get_token(client)
    form = FormData()
    for name, value in {
        "sender": "disabled@example.test",
        "to": "recipient@example.test",
        "subject": "x",
        "text": "x",
        "html": "",
    }.items():
        form.add_field(name, value)
    form.add_field("attachments", io.BytesIO(b"x"), filename="x.txt")
    response = await client.post(
        "/api/v1/send",
        data=form,
        headers={"Origin": _origin(client), "X-CSRF-Token": token},
        allow_redirects=False,
    )
    assert response.status == 403
    assert gateway.delivered is None


@pytest.mark.asyncio
async def test_certificate_surface_has_no_file_or_delete_operations(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    response, data = await _api_data(client, "/api/v1/certificates")
    assert response.status == 200
    assert data["timer_enabled"] is True
    assert data["timer_active"] is True
    certificate = data["certificates"][0]
    assert certificate["name"] == "mail.example.test"
    assert certificate["source_fingerprint"] == "AA:BB"
    assert certificate["deployed_fingerprint"] == "AA:BB"
    assert certificate["automation_safe"] is True
    serialized = json.dumps(data)
    assert "private_key" not in serialized
    assert "path" not in serialized

    token = await _get_token(client)
    response = await _post_json(
        client,
        "/api/v1/certificates/dry-run",
        token,
        {"name": "mail.example.test"},
    )
    assert response.status == 200
    assert ("certificate_dry_run", "mail.example.test") in gateway.operations
    get_mutation = await client.get("/api/v1/certificates/dry-run")
    assert get_mutation.status == 404

    token = await _get_token(client)
    unknown = await _post_json(
        client,
        "/api/v1/certificates/dry-run",
        token,
        {"name": "unknown.example.test"},
    )
    assert unknown.status == 400
    assert ("certificate_dry_run", "unknown.example.test") not in gateway.operations


@pytest.mark.asyncio
async def test_unsafe_certbot_lineage_is_reported_read_only(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    gateway.certificate_automation_safe = False
    _response, data = await _api_data(client, "/api/v1/certificates")
    assert data["timer_enable_safe"] is False
    assert data["certificates"][0]["automation_safe"] is False


@pytest.mark.asyncio
async def test_active_but_disabled_timer_can_still_be_stopped(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    gateway.certificate_timer_enabled = False
    gateway.certificate_timer_active = True
    _response, data = await _api_data(client, "/api/v1/certificates")
    assert data["timer_enabled"] is False
    assert data["timer_active"] is True
    token = await _get_token(client)
    response = await _post_json(
        client,
        "/api/v1/certificates/timer",
        token,
        {"action": "disable"},
    )
    assert response.status == 200
    assert ("certificate_timer", False) in gateway.operations
