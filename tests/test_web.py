from __future__ import annotations

import asyncio
import html
import io
import json
import re
import time
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import quote, urlencode

import pytest
import pytest_asyncio
from aiohttp import CookieJar, FormData
from aiohttp.test_utils import TestClient, TestServer

from maddyweb.mail import PreparedMessage
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
        self.message_rows: list[dict[str, object]] = [
            {"id": "42", "sender": "sender@example.test", "subject": "Received message"}
        ]
        self.message_next_offset: int | None = None
        self.message_initial_offset = 42
        self.delivered: bytes | None = None
        self.sent: bytes | None = None
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
            "timer_enabled": True,
            "timer_state": "active",
            "certificates": [
                {
                    "name": "mail.example.test",
                    "expires": "2027-01-01",
                    "source_fingerprint": "AA:BB",
                    "deployed_fingerprint": "AA:BB",
                    "fingerprints_match": True,
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


async def _get_token(client: TestClient, path: str) -> tuple[str, str]:
    response = await client.get(path)
    page = await response.text()
    match = re.search(r'name="_csrf" value="([^"]+)"', page)
    if match is None:
        match = re.search(r'data-csrf="([^"]+)"', page)
    assert match is not None, page
    return html.unescape(match.group(1)), page


def _hidden_value(page: str, name: str) -> str:
    match = re.search(rf'name="{re.escape(name)}" value="([^"]+)"', page)
    assert match is not None, page
    return html.unescape(match.group(1))


def _origin(client: TestClient) -> str:
    return str(client.make_url("/").origin())


def _pagination_href(page: str, relation: str) -> str:
    match = re.search(rf'rel="{relation}" href="([^"]+)"', page)
    assert match is not None, page
    return html.unescape(match.group(1))


@pytest.mark.asyncio
async def test_home_static_assets_and_strict_headers(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, _gateway = web_client
    response = await client.get("/")
    page = await response.text()
    assert response.status == 200
    assert "Administration overview" in page
    assert "Access-Control-Allow-Origin" not in response.headers
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert "img-src 'self' blob:" in response.headers["Content-Security-Policy"]
    assert response.headers["Referrer-Policy"] == "same-origin"

    javascript = await client.get("/static/app.js")
    assert javascript.status == 200
    assert javascript.content_type == "application/javascript"
    assert javascript.headers["X-Content-Type-Options"] == "nosniff"
    javascript_text = await javascript.text()
    assert "contenteditable" not in javascript_text
    assert "URL.createObjectURL" in javascript_text
    assert "readAsDataURL" not in javascript_text

    rejected = await client.get("/", headers={"Host": "evil.example"})
    assert rejected.status == 400


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

    gateway.health_payload["status"] = "degraded"
    gateway.health_payload["maddy_write_enabled"] = False
    degraded = await client.get("/healthz")
    assert degraded.status == 503
    assert (await degraded.json())["status"] == "degraded"


@pytest.mark.asyncio
async def test_account_actions_are_separate_and_mailbox_delete_is_confirmed(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    token, page = await _get_token(client, "/accounts")
    assert "/password" in page
    assert "/append-limit" in page
    assert "/credentials/disable" in page
    assert "Permanently delete mailbox..." in page
    assert '<button class="danger" type="submit">Delete</button>' not in page

    origin = _origin(client)
    limit = await client.post(
        "/accounts/admin@example.test/append-limit",
        data={"_csrf": token, "limit": "0"},
        headers={"Origin": origin},
        allow_redirects=False,
    )
    assert limit.status == 303
    assert ("set_append_limit", "admin@example.test", 0) in gateway.operations

    token, confirmation_page = await _get_token(
        client,
        "/accounts/admin@example.test/delete",
    )
    assert "To continue, enter" in confirmation_page
    wrong = await client.post(
        "/accounts/admin@example.test/delete",
        data={"_csrf": token, "confirmation": "wrong@example.test"},
        headers={"Origin": origin},
        allow_redirects=False,
    )
    assert wrong.status == 400
    assert not any(operation[0] == "delete_mailbox" for operation in gateway.operations)

    token, _ = await _get_token(client, "/accounts/admin@example.test/delete")
    deleted = await client.post(
        "/accounts/admin@example.test/delete",
        data={"_csrf": token, "confirmation": "admin@example.test"},
        headers={"Origin": origin},
        allow_redirects=False,
    )
    assert deleted.status == 303
    assert ("delete_mailbox", "admin@example.test") in gateway.operations


@pytest.mark.asyncio
async def test_mail_requires_account_and_mailbox_context_and_has_two_delete_levels(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    response = await client.get("/mail")
    page = await response.text()
    assert "Select an account" in page
    assert not any(operation[0] == "list_messages" for operation in gateway.operations)

    context = urlencode({"account": "admin@example.test", "mailbox": "INBOX"})
    response = await client.get(f"/mail?{context}")
    page = await response.text()
    assert "Received message" in page
    assert ("list_messages", "admin@example.test", "INBOX", 20, 0) in gateway.operations

    detail = await client.get(f"/mail/42?{context}")
    detail_page = await detail.text()
    assert detail.status == 200
    assert 'sandbox=""' in detail_page
    assert 'sandbox=" allow-' not in detail_page
    assert "/mail/42/trash" in detail_page
    assert "/mail/42/delete?" in detail_page
    assert "account=admin%40example.test" in detail_page

    html_body = await client.get(f"/mail/42/html?{context}")
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
    assert "/mail/42/inline/0?account=admin%40example.test&amp;mailbox=INBOX" in rendered

    inline = await client.get(f"/mail/42/inline/0?{context}")
    assert inline.status == 200
    assert inline.content_type == "image/png"
    assert inline.headers["X-Content-Type-Options"] == "nosniff"
    assert await inline.read() == b"\x89PNG\r\n\x1a\ninline-image"

    attachment = await client.get(f"/mail/42/attachments/1?{context}")
    assert attachment.content_type == "application/octet-stream"
    assert attachment.headers["Content-Disposition"].startswith("attachment;")

    token, detail_form = await _get_token(client, f"/mail/42?{context}")
    trashed = await client.post(
        "/mail/42/trash",
        data={
            "_csrf": token,
            "account": "admin@example.test",
            "mailbox": "INBOX",
            "freshness": _hidden_value(detail_form, "freshness"),
        },
        headers={"Origin": _origin(client)},
        allow_redirects=False,
    )
    assert trashed.status == 303
    assert ("trash", "admin@example.test", "INBOX", "42") in gateway.operations

    token, confirm = await _get_token(client, f"/mail/42/delete?{context}")
    assert "bypasses Trash" in confirm
    rejected = await client.post(
        "/mail/42/delete",
        data={
            "_csrf": token,
            "account": "admin@example.test",
            "mailbox": "INBOX",
            "freshness": _hidden_value(confirm, "freshness"),
            "confirmation": "Delete",
        },
        headers={"Origin": _origin(client)},
        allow_redirects=False,
    )
    assert rejected.status == 400
    assert not any(operation[0] == "delete_message" for operation in gateway.operations)


@pytest.mark.asyncio
async def test_single_uid_and_freshness_are_required_for_destructive_mail_actions(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    context = urlencode({"account": "admin@example.test", "mailbox": "INBOX"})

    assert (await client.get(f"/mail/1:*/delete?{context}")).status == 400
    assert (await client.get(f"/mail/1,2/delete?{context}")).status == 400
    assert (await client.get(f"/mail/{'9' * 100}/delete?{context}")).status == 400
    assert (await client.get(f"/mail/\u0661/delete?{context}")).status == 400

    token, detail = await _get_token(client, f"/mail/42?{context}")
    freshness = _hidden_value(detail, "freshness")
    gateway.raw_message = gateway.raw_message.replace(b"Subject:", b"Subject: changed ", 1)
    stale = await client.post(
        "/mail/42/trash",
        data={
            "_csrf": token,
            "account": "admin@example.test",
            "mailbox": "INBOX",
            "freshness": freshness,
        },
        headers={"Origin": _origin(client)},
        allow_redirects=False,
    )
    assert stale.status == 409
    assert not any(operation[0] == "trash" for operation in gateway.operations)

    token, confirmation = await _get_token(client, f"/mail/42/delete?{context}")
    deleted = await client.post(
        "/mail/42/delete",
        data={
            "_csrf": token,
            "account": "admin@example.test",
            "mailbox": "INBOX",
            "freshness": _hidden_value(confirmation, "freshness"),
            "confirmation": "PERMANENTLY DELETE",
        },
        headers={"Origin": _origin(client)},
        allow_redirects=False,
    )
    assert deleted.status == 303
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
    response = await client.get(f"/mail?{context}")
    assert response.status == 200


@pytest.mark.asyncio
async def test_mailbox_pagination_is_bounded_and_preserves_context(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    gateway.message_rows = [
        {"id": str(index), "sender": "sender@example.test", "subject": f"Message {index}"}
        for index in range(20)
    ]
    gateway.message_initial_offset = 100
    gateway.message_next_offset = 80
    context = urlencode({"account": "admin@example.test", "mailbox": "INBOX"})
    first = await client.get(f"/mail?{context}")
    first_page = await first.text()
    assert "Next" in first_page
    next_href = _pagination_href(first_page, "next")
    assert "account=admin%40example.test&mailbox=INBOX&cursor=" in next_href
    assert "page=" not in next_href
    assert re.search(r"cursor=[A-Za-z0-9_-]{32}\Z", next_href) is not None

    gateway.message_next_offset = None
    second = await client.get(next_href)
    second_page = await second.text()
    assert "Previous" in second_page
    assert ("list_messages", "admin@example.test", "INBOX", 20, 80) in gateway.operations

    previous_href = _pagination_href(second_page, "prev")
    await client.get(previous_href)
    assert ("list_messages", "admin@example.test", "INBOX", 20, 100) in gateway.operations

    tampered = next_href.replace("mailbox=INBOX", "mailbox=Sent")
    assert (await client.get(tampered)).status == 409

    invalid = await client.get(f"/mail?{context}&page=1")
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
    truncated_page = await (await client.get(f"/mail?{context}")).text()
    assert "Next" in truncated_page
    continuation = _pagination_href(truncated_page, "next")

    gateway.message_rows = [{"id": "99", "sender": "sender@example.test", "subject": "Continued"}]
    gateway.message_next_offset = None
    continued_page = await (await client.get(continuation)).text()
    assert "Previous" in continued_page
    assert ("list_messages", "admin@example.test", "INBOX", 20, 99) in gateway.operations

    gateway.message_rows = [
        {"id": str(index), "sender": "sender@example.test", "subject": f"Message {index}"}
        for index in range(20)
    ]
    gateway.message_next_offset = None
    complete_page = await (await client.get(f"/mail?{context}")).text()
    assert "Next" not in complete_page


@pytest.mark.asyncio
async def test_oversized_preview_still_allows_streamed_raw_download(
    web_client: tuple[TestClient, FakeGateway],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, gateway = web_client
    monkeypatch.setattr("maddyweb.web.MAX_RAW_MESSAGE_BYTES", 64)
    gateway.raw_message = b"From: sender@example.test\r\n\r\n" + b"x" * (128 * 1024)
    context = urlencode({"account": "admin@example.test", "mailbox": "INBOX"})
    detail = await client.get(f"/mail/42?{context}")
    page = await detail.text()
    assert detail.status == 200
    assert "exceeds the safe preview limit" in page
    assert "Stream-download raw .eml" in page
    assert "mail-frame" not in page

    raw = await client.get(f"/mail/42/raw?{context}")
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
    first = asyncio.create_task(client.get(f"/mail/42?{context}"))
    second = asyncio.create_task(client.get(f"/mail/42?{context}"))
    try:
        await asyncio.wait_for(gateway.two_spools_started.wait(), timeout=1)
        health = await asyncio.wait_for(client.get("/healthz"), timeout=0.1)
        assert health.status == 200
        third = await client.get(f"/mail/42?{context}")
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
    detail_task = asyncio.create_task(client.get(f"/mail/42?{context}"))
    await asyncio.wait_for(started.wait(), timeout=1)
    health = await asyncio.wait_for(client.get("/healthz"), timeout=0.08)
    assert health.status == 200
    assert (await detail_task).status == 200


@pytest.mark.asyncio
async def test_compose_uses_enabled_sender_and_streams_cid_mime(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    token, page = await _get_token(client, "/compose")
    assert 'contenteditable="true"' in page
    assert '<select name="sender" required>' in page
    assert "admin@example.test" in page
    assert "disabled@example.test" not in page

    form = FormData()
    form.add_field("_csrf", token)
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
        "/send",
        data=form,
        headers={"Origin": _origin(client), "X-CSRF-Token": token},
        allow_redirects=False,
    )
    assert response.status == 303
    assert response.headers["Location"] == "/compose?status=sent"
    assert gateway.delivered == gateway.sent
    assert gateway.delivered is not None
    parsed = BytesParser(policy=policy.default).parsebytes(gateway.delivered)
    assert parsed["Bcc"] is None
    assert any(part.get("Content-ID") == "<logo@maddyweb.local>" for part in parsed.walk())


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
        token, _page = await _get_token(client, "/compose")
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
            "/send",
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
    token, _ = await _get_token(client, "/compose")
    duplicate = FormData()
    duplicate.add_field("_csrf", token)
    duplicate.add_field("sender", "admin@example.test")
    duplicate.add_field("sender", "admin@example.test")
    duplicate.add_field(
        "attachments",
        io.BytesIO(b"x"),
        filename="x.txt",
        content_type="text/plain",
    )
    response = await client.post(
        "/send",
        data=duplicate,
        headers={"Origin": _origin(client), "X-CSRF-Token": token},
    )
    assert response.status == 400

    token, _ = await _get_token(client, "/compose")
    oversized = FormData()
    oversized.add_field("_csrf", token)
    oversized.add_field("sender", "admin@example.test")
    oversized.add_field("password", "x" * 5000)
    oversized.add_field(
        "attachments",
        io.BytesIO(b"x"),
        filename="x.txt",
        content_type="text/plain",
    )
    response = await client.post(
        "/send",
        data=oversized,
        headers={"Origin": _origin(client), "X-CSRF-Token": token},
    )
    assert response.status == 413


@pytest.mark.asyncio
async def test_disabled_sender_is_rejected_server_side(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    token, _ = await _get_token(client, "/compose")
    form = FormData()
    for name, value in {
        "_csrf": token,
        "sender": "disabled@example.test",
        "to": "recipient@example.test",
        "subject": "x",
        "text": "x",
        "html": "",
    }.items():
        form.add_field(name, value)
    form.add_field("attachments", io.BytesIO(b"x"), filename="x.txt")
    response = await client.post(
        "/send",
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
    token, page = await _get_token(client, "/certificates")
    assert "/certificates/timer" in page
    assert "/certificates/dry-run" in page
    assert "/certificates/renew-if-due" in page
    assert "Source fingerprint" in page
    assert "Deployed fingerprint" in page
    assert "AA:BB" in page
    assert 'type="file"' not in page
    assert "/certificates/upload" not in page
    assert "/certificates/" + quote("mail.example.test") + "/delete" not in page

    response = await client.post(
        "/certificates/dry-run",
        data={"_csrf": token, "name": "mail.example.test"},
        headers={"Origin": _origin(client)},
        allow_redirects=False,
    )
    assert response.status == 303
    assert ("certificate_dry_run", "mail.example.test") in gateway.operations
    get_mutation = await client.get("/certificates/dry-run")
    assert get_mutation.status == 404

    token, _ = await _get_token(client, "/certificates")
    unknown = await client.post(
        "/certificates/dry-run",
        data={"_csrf": token, "name": "unknown.example.test"},
        headers={"Origin": _origin(client)},
        allow_redirects=False,
    )
    assert unknown.status == 400
    assert ("certificate_dry_run", "unknown.example.test") not in gateway.operations
