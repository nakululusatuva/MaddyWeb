from __future__ import annotations

import asyncio
import io
import json
import time
from collections.abc import Sequence
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlencode

import pytest
import pytest_asyncio
from aiohttp import CookieJar, FormData
from aiohttp.test_utils import TestClient, TestServer

from maddyweb.gateway import HelperCallError
from maddyweb.mail import (
    MAX_RENDERED_CID_BYTES,
    MAX_RENDERED_CID_IMAGES,
    MAX_RENDERED_CID_PIXELS,
    DeliveryRejected,
    MailError,
    ParsedAttachment,
    ParsedMessage,
    PreparedMessage,
)
from maddyweb.web import (
    _FRESHNESS_KEY,
    MessagePage,
    _eligible_inline_attachments,
    _FreshnessStore,
    _iframe_document,
    create_app,
)

FIXTURE_CREDENTIAL = "-".join(("account", "credential"))
ADMIN_ACCOUNT_ID = "a" * 32
DISABLED_ACCOUNT_ID = "d" * 32
ADMIN_SESSION_TOKEN = "S" * 43
VALID_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010804000000"
    "b51c0c020000000b4944415478da6364f80f00010501012718e3660000"
    "000049454e44ae426082"
)


def test_freshness_tokens_are_owner_bound_and_evict_without_global_failure() -> None:
    store = _FreshnessStore(ttl_seconds=60, capacity=4, per_owner_capacity=2)
    owner_a = "a" * 64
    owner_b = "b" * 64
    owner_c = "c" * 64

    first_a = store.issue(owner_a, ADMIN_ACCOUNT_ID, "INBOX", "1", "digest-1")
    second_a = store.issue(owner_a, ADMIN_ACCOUNT_ID, "INBOX", "2", "digest-2")
    third_a = store.issue(owner_a, ADMIN_ACCOUNT_ID, "INBOX", "3", "digest-3")
    assert store.consume(first_a, owner_a) is None
    assert store.consume(second_a, owner_b) is None
    assert store.consume(second_a, owner_a) is not None

    first_b = store.issue(owner_b, ADMIN_ACCOUNT_ID, "INBOX", "4", "digest-4")
    store.issue(owner_b, ADMIN_ACCOUNT_ID, "INBOX", "5", "digest-5")
    store.issue(owner_c, ADMIN_ACCOUNT_ID, "INBOX", "6", "digest-6")
    store.issue(owner_c, ADMIN_ACCOUNT_ID, "INBOX", "7", "digest-7")
    newest = store.issue(owner_c, ADMIN_ACCOUNT_ID, "INBOX", "8", "digest-8")

    assert len(store._entries) == 4
    assert store.consume(third_a, owner_a) is None
    assert store.consume(first_b, owner_b) is not None
    assert store.consume(newest, owner_c) is not None


def _message_with_attachments(
    attachments: tuple[ParsedAttachment, ...],
) -> ParsedMessage:
    return ParsedMessage(
        subject="fixture",
        sender="sender@example.test",
        to=("recipient@example.test",),
        cc=(),
        date="",
        message_id="<fixture@example.test>",
        text="body",
        html="<p>body</p>",
        attachments=attachments,
    )


def test_message_iframe_explains_when_sanitization_removes_all_visible_content() -> None:
    document = _iframe_document("<p></p>", {})

    assert "No safe visible HTML content remained after sanitization." in document
    assert "default-src 'none'" in document


def test_inline_cid_rendering_bounds_count_bytes_pixels_and_duplicates() -> None:
    count_limited = tuple(
        ParsedAttachment(
            str(index),
            f"image-{index}.png",
            "image/png",
            VALID_PNG,
            content_id=f"image-{index}",
            inline=True,
        )
        for index in range(MAX_RENDERED_CID_IMAGES + 2)
    )
    selected = _eligible_inline_attachments(_message_with_attachments(count_limited))
    assert len(selected) == MAX_RENDERED_CID_IMAGES

    one_megabyte = VALID_PNG + b"\0" * (1024 * 1024)
    byte_limited = tuple(
        ParsedAttachment(
            str(index),
            f"large-{index}.png",
            "image/png",
            one_megabyte,
            content_id=f"large-{index}",
            inline=True,
        )
        for index in range(5)
    )
    selected = _eligible_inline_attachments(_message_with_attachments(byte_limited))
    assert sum(item.size for item in selected) <= MAX_RENDERED_CID_BYTES
    assert len(selected) == 3

    large_pixels = bytearray(VALID_PNG)
    large_pixels[16:20] = (2000).to_bytes(4, "big")
    large_pixels[20:24] = (2000).to_bytes(4, "big")
    pixel_limited = tuple(
        ParsedAttachment(
            str(index),
            f"pixels-{index}.png",
            "image/png",
            bytes(large_pixels),
            content_id=f"pixels-{index}",
            inline=True,
        )
        for index in range(3)
    )
    selected = _eligible_inline_attachments(_message_with_attachments(pixel_limited))
    assert len(selected) == 2
    assert len(selected) * 2000 * 2000 == MAX_RENDERED_CID_PIXELS

    duplicates = (
        ParsedAttachment("0", "a.png", "image/png", VALID_PNG, "same", True),
        ParsedAttachment("1", "b.png", "image/png", VALID_PNG, "same", True),
    )
    assert _eligible_inline_attachments(_message_with_attachments(duplicates)) == ()


class FakeGateway:
    def __init__(self) -> None:
        self.accounts = [
            {
                "id": ADMIN_ACCOUNT_ID,
                "address": "admin@example.test",
                "has_credentials": True,
                "has_mailbox": True,
                "append_limit": 1024,
            },
            {
                "id": DISABLED_ACCOUNT_ID,
                "address": "disabled@example.test",
                "has_credentials": False,
                "has_mailbox": True,
            },
        ]
        self.operations: list[tuple[object, ...]] = []
        self.create_account_error: Exception | None = None
        self.change_password_error: Exception | None = None
        self.append_limit_error: Exception | None = None
        self.certificate_dry_run_error: Exception | None = None
        self.delete_error: Exception | None = None
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
        self.latest_message_uid_value = 42
        self.latest_message_uid_checked = asyncio.Event()
        self.delivered: bytes | None = None
        self.sent: bytes | None = None
        self.delivery_error: Exception | None = None
        self.bulk_delete_error: Exception | None = None
        self.mail_rule_error: Exception | None = None
        self.mail_rules: list[dict[str, object]] = []
        self.mail_rule_run: dict[str, object] | None = None
        self.step_up_until = 2_000_000_000
        self.spool_gate: asyncio.Event | None = None
        self.spool_active = 0
        self.spool_calls = 0
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
            VALID_PNG,
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
        self.raw_messages: dict[str, bytes] = {}

    async def health(self) -> dict[str, object]:
        return self.health_payload

    async def session(self, token: str) -> dict[str, object]:
        if token != ADMIN_SESSION_TOKEN:
            raise RuntimeError("invalid fixture session")
        return {
            "account_id": ADMIN_ACCOUNT_ID,
            "email": "admin@example.test",
            "role": "admin",
            "password_change_required": False,
            "enrollment_state": "active",
            "idle_expires_at": 2_000_000_000,
            "absolute_expires_at": 2_000_010_000,
            "step_up_until": self.step_up_until,
        }

    async def peek_session(self, token: str) -> dict[str, object]:
        self.operations.append(("peek_session", token))
        return await self.session(token)

    async def list_accounts(self) -> list[dict[str, object]]:
        return self.accounts

    async def create_account(self, username: str, password: str) -> object:
        if self.create_account_error is not None:
            raise self.create_account_error
        self.operations.append(("create_account", username, password))
        return {"address": username}

    async def change_password(self, account_id: str, password: str) -> None:
        if self.change_password_error is not None:
            raise self.change_password_error
        self.operations.append(("change_password", account_id, password))

    async def set_append_limit(self, account_id: str, limit: int) -> None:
        if self.append_limit_error is not None:
            raise self.append_limit_error
        self.operations.append(("set_append_limit", account_id, limit))

    async def disable_credentials(self, account_id: str) -> None:
        self.operations.append(("disable_credentials", account_id))

    async def delete_mailbox(self, account_id: str) -> None:
        self.operations.append(("delete_mailbox", account_id))

    async def list_mailboxes(self, account_id: str) -> list[dict[str, str]]:
        self.operations.append(("list_mailboxes", account_id))
        return [{"name": "INBOX"}, {"name": "Sent"}, {"name": "Trash"}]

    async def create_mailbox(self, account_id: str, mailbox: str) -> None:
        self.operations.append(("create_mailbox", account_id, mailbox))

    async def rename_mailbox(
        self,
        account_id: str,
        old_name: str,
        new_name: str,
    ) -> None:
        self.operations.append(("rename_mailbox", account_id, old_name, new_name))

    async def delete_named_mailbox(self, account_id: str, mailbox: str) -> None:
        self.operations.append(("delete_named_mailbox", account_id, mailbox))

    async def list_mail_rules(self, account_id: str) -> dict[str, object]:
        if self.mail_rule_error is not None:
            raise self.mail_rule_error
        self.operations.append(("list_mail_rules", account_id))
        return {"rules": list(self.mail_rules), "active_run": self.mail_rule_run}

    async def create_mail_rule(
        self,
        account_id: str,
        *,
        name: str,
        enabled: bool,
        match_condition: dict[str, object],
        target_mailbox: str,
        stop_processing: bool,
        apply_existing: bool,
    ) -> dict[str, object]:
        if self.mail_rule_error is not None:
            raise self.mail_rule_error
        self.operations.append(
            (
                "create_mail_rule",
                account_id,
                name,
                enabled,
                match_condition,
                target_mailbox,
                stop_processing,
                apply_existing,
            )
        )
        rule = {
            "rule_id": "b" * 32,
            "name": name,
            "enabled": enabled,
            "match": match_condition,
            "target_mailbox": target_mailbox,
            "stop_processing": stop_processing,
            "revision": 1,
        }
        self.mail_rules.append(rule)
        result: dict[str, object] = {"rule": rule}
        if apply_existing:
            self.mail_rule_run = {
                "run_id": "c" * 32,
                "rule_id": rule["rule_id"],
                "rule_name": name,
                "status": "queued",
                "processed": 0,
            }
            result["run"] = self.mail_rule_run
        return result

    async def update_mail_rule(
        self,
        account_id: str,
        rule_id: str,
        *,
        name: str,
        enabled: bool,
        match_condition: dict[str, object],
        target_mailbox: str,
        stop_processing: bool,
        expected_revision: int | None = None,
    ) -> dict[str, object]:
        if self.mail_rule_error is not None:
            raise self.mail_rule_error
        self.operations.append(
            (
                "update_mail_rule",
                account_id,
                rule_id,
                name,
                enabled,
                match_condition,
                target_mailbox,
                stop_processing,
                expected_revision,
            )
        )
        rule = {
            "rule_id": rule_id,
            "name": name,
            "enabled": enabled,
            "match": match_condition,
            "target_mailbox": target_mailbox,
            "stop_processing": stop_processing,
            "revision": (expected_revision or 1) + 1,
        }
        self.mail_rules = [rule]
        return {"rule": rule}

    async def delete_mail_rule(self, account_id: str, rule_id: str) -> None:
        if self.mail_rule_error is not None:
            raise self.mail_rule_error
        self.operations.append(("delete_mail_rule", account_id, rule_id))
        self.mail_rules = [rule for rule in self.mail_rules if rule["rule_id"] != rule_id]

    async def reorder_mail_rules(
        self,
        account_id: str,
        rule_ids: Sequence[str],
    ) -> dict[str, object]:
        if self.mail_rule_error is not None:
            raise self.mail_rule_error
        self.operations.append(("reorder_mail_rules", account_id, tuple(rule_ids)))
        return {"rules": list(self.mail_rules)}

    async def create_mail_rule_run(self, account_id: str, rule_id: str) -> dict[str, object]:
        if self.mail_rule_error is not None:
            raise self.mail_rule_error
        self.operations.append(("create_mail_rule_run", account_id, rule_id))
        self.mail_rule_run = {
            "run_id": "c" * 32,
            "rule_id": rule_id,
            "status": "queued",
            "processed": 0,
        }
        return {"run": self.mail_rule_run}

    async def get_mail_rule_run(self, account_id: str, run_id: str) -> dict[str, object]:
        if self.mail_rule_error is not None:
            raise self.mail_rule_error
        self.operations.append(("get_mail_rule_run", account_id, run_id))
        return {"run": self.mail_rule_run or {"run_id": run_id, "status": "completed"}}

    async def step_mail_rule_run(self, account_id: str, run_id: str) -> dict[str, object]:
        if self.mail_rule_error is not None:
            raise self.mail_rule_error
        self.operations.append(("step_mail_rule_run", account_id, run_id))
        self.mail_rule_run = {"run_id": run_id, "status": "completed", "processed": 2}
        return {"run": self.mail_rule_run}

    async def cancel_mail_rule_run(self, account_id: str, run_id: str) -> dict[str, object]:
        if self.mail_rule_error is not None:
            raise self.mail_rule_error
        self.operations.append(("cancel_mail_rule_run", account_id, run_id))
        self.mail_rule_run = {"run_id": run_id, "status": "cancelled", "processed": 0}
        return {"run": self.mail_rule_run}

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

    async def latest_message_uid(self, account_id: str, mailbox: str) -> int:
        self.operations.append(("latest_message_uid", account_id, mailbox))
        self.latest_message_uid_checked.set()
        return self.latest_message_uid_value

    async def spool_message(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
        destination_path: Path,
        *,
        max_bytes: int,
    ) -> int:
        self.spool_calls += 1
        self.operations.append(("spool_message", account_id, mailbox, message_id))
        if self.spool_gate is not None:
            self.spool_active += 1
            if self.spool_active == 2:
                self.two_spools_started.set()
            try:
                await self.spool_gate.wait()
            finally:
                self.spool_active -= 1
        raw_message = self.raw_messages.get(message_id, self.raw_message)
        if len(raw_message) > max_bytes:
            raise ValueError("message too large")
        return await asyncio.to_thread(destination_path.write_bytes, raw_message)

    async def move_message_to_trash(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
    ) -> str:
        self.operations.append(("trash", account_id, mailbox, message_id))
        return "Trash"

    async def move_message_to_archive(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
    ) -> str:
        self.operations.append(("archive", account_id, mailbox, message_id))
        return "Archive"

    async def move_message(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
        target: str,
    ) -> str:
        self.operations.append(("move", account_id, mailbox, message_id, target))
        return target

    async def set_messages_seen(
        self,
        account_id: str,
        mailbox: str,
        message_ids: Sequence[str] | None,
        *,
        seen: bool,
    ) -> None:
        self.operations.append(("set_messages_seen", account_id, mailbox, message_ids, seen))

    async def move_messages_to_trash(
        self,
        account_id: str,
        mailbox: str,
        message_ids: Sequence[str],
    ) -> str:
        self.operations.append(("trash_many", account_id, mailbox, tuple(message_ids)))
        return "Trash"

    async def move_messages_to_archive(
        self,
        account_id: str,
        mailbox: str,
        message_ids: Sequence[str],
    ) -> str:
        self.operations.append(("archive_many", account_id, mailbox, tuple(message_ids)))
        return "Archive"

    async def move_messages(
        self,
        account_id: str,
        mailbox: str,
        message_ids: Sequence[str],
        target: str,
    ) -> str:
        self.operations.append(("move_many", account_id, mailbox, tuple(message_ids), target))
        return target

    async def delete_message_permanently(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
    ) -> None:
        if self.delete_error is not None:
            raise self.delete_error
        self.operations.append(("delete_message", account_id, mailbox, message_id))

    async def delete_messages_permanently(
        self,
        account_id: str,
        mailbox: str,
        message_ids: Sequence[str],
    ) -> None:
        self.operations.append(("delete_messages", account_id, mailbox, tuple(message_ids)))
        if self.bulk_delete_error is not None:
            raise self.bulk_delete_error

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
        if self.certificate_dry_run_error is not None:
            raise self.certificate_dry_run_error
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
            "mail_event_poll_seconds": 0.25,
            "temp_dir": tmp_path,
        },
        "security": {
            "session_signing_key": b"k" * 32,
            "csrf_ttl_seconds": 300,
            "csrf_cookie_name": "maddyweb-csrf",
            "session_cookie_name": "maddyweb-session",
            "secure_cookies": False,
            "login_domain": "example.test",
        },
    }
    client = TestClient(
        TestServer(create_app(config, gateway)),
        cookie_jar=CookieJar(unsafe=True),
    )
    await client.start_server()
    client.session.cookie_jar.update_cookies(
        {"maddyweb-session": ADMIN_SESSION_TOKEN},
        response_url=client.make_url("/"),
    )
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


def _raw_spool_paths(temp_dir: Path) -> list[Path]:
    return list(temp_dir.glob("raw-message-*.eml"))


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
    assert 'href="/static/app.css?v=' in page
    assert 'src="/static/workspace.js?v=' in page
    assert 'src="/static/app.js?v=' not in page
    assert "__MADDYWEB_APP_ASSET_VERSION__" not in page
    assert 'id="new-mail-banner"' in page
    assert 'id="new-mail-notice"' in page
    assert 'id="new-mail-dismiss"' in page
    assert 'id="new-mail-announcer"' in page
    assert 'id="startup-recovery"' in page
    assert 'href="">Reload this page</a>' in page
    assert 'id="mail-bulk-permanent-delete"' in page
    assert 'id="compose-sender-name"' in page
    assert 'name="sender_name"' in page
    assert 'maxlength="256"' in page
    assert 'aria-describedby="sender-name-help"' in page
    assert 'id="body-write-tab"' in page
    assert 'id="body-write-panel"' in page
    assert 'id="message-editor"' in page
    assert 'contenteditable="true"' in page
    assert 'role="textbox"' in page
    assert 'aria-multiline="true"' in page
    assert 'role="toolbar" aria-label="Message formatting"' in page
    assert (
        'aria-selected="true" aria-controls="body-write-panel" tabindex="0" data-body-mode="write"'
    ) in page
    assert 'id="html-source"' in page
    assert 'name="html"' in page
    assert 'id="html-preview"' in page
    assert (
        'aria-selected="false" aria-controls="body-source-panel" tabindex="-1" '
        'data-body-mode="source"'
    ) in page
    assert (
        'aria-selected="false" aria-controls="body-preview-panel" tabindex="-1" '
        'data-body-mode="preview"'
    ) in page
    assert 'id="body-source-panel" class="body-mode-panel"' in page
    assert 'id="body-preview-panel" class="body-mode-panel"' in page
    assert 'id="html-source" class="html-source" name="html"' in page
    assert 'name="html" maxlength="2097152" required' not in page
    assert 'sandbox="allow-same-origin"' in page
    assert '<main id="main" class="app-main" tabindex="-1">' in page
    assert "admin@example.test" not in page
    assert "csrf_token" not in page
    assert "Access-Control-Allow-Origin" not in response.headers
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert "frame-src 'self' blob:" in response.headers["Content-Security-Policy"]
    assert "img-src 'self' blob:" in response.headers["Content-Security-Policy"]
    assert response.headers["Referrer-Policy"] == "same-origin"

    stylesheet = await client.get("/static/app.css")
    assert stylesheet.status == 200
    assert stylesheet.content_type == "text/css"
    stylesheet_bytes = await stylesheet.read()
    assert b"@import" not in stylesheet_bytes
    assert b"url(" not in stylesheet_bytes

    preview_stylesheet = await client.get("/static/preview.css")
    assert preview_stylesheet.status == 200
    assert preview_stylesheet.content_type == "text/css"
    preview_stylesheet_bytes = await preview_stylesheet.read()
    assert b"@import" not in preview_stylesheet_bytes
    assert b"url(" not in preview_stylesheet_bytes

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
        "insertHTML",
        "createContextualFragment",
        "setHTMLUnsafe",
        "document.write",
        "document.open",
        "srcdoc",
        "eval(",
    ):
        assert forbidden_sink not in javascript_text
    assert "serializePreviewNode" in javascript_text
    assert "new DOMParser()" in javascript_text
    assert "new Blob(" in javascript_text
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
    detail = await client.get(f"/mail/42?account={ADMIN_ACCOUNT_ID}&mailbox=INBOX")
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
    created_from_local_part = await _post_json(
        client,
        "/api/v1/accounts",
        token,
        {"username": "local-only", "password": "valid-password"},
    )
    assert created_from_local_part.status == 201
    assert ("create_account", "local-only@example.test", "valid-password") in gateway.operations

    token = await _get_token(client)
    changed = await _post_json(
        client,
        f"/api/v1/accounts/{ADMIN_ACCOUNT_ID}/password",
        token,
        {"password": "changed-password"},
    )
    assert changed.status == 200
    assert ("change_password", ADMIN_ACCOUNT_ID, "changed-password") in gateway.operations

    token = await _get_token(client)
    limit = await _post_json(
        client,
        f"/api/v1/accounts/{ADMIN_ACCOUNT_ID}/append-limit",
        token,
        {"limit": 0},
    )
    assert limit.status == 200
    assert ("set_append_limit", ADMIN_ACCOUNT_ID, 0) in gateway.operations

    token = await _get_token(client)
    disabled = await _post_json(
        client,
        f"/api/v1/accounts/{ADMIN_ACCOUNT_ID}/credentials/disable",
        token,
        {},
    )
    assert disabled.status == 200
    assert ("disable_credentials", ADMIN_ACCOUNT_ID) in gateway.operations

    token = await _get_token(client)
    wrong = await _post_json(
        client,
        f"/api/v1/accounts/{ADMIN_ACCOUNT_ID}/delete",
        token,
        {"confirmation": "wrong@example.test"},
    )
    assert wrong.status == 400
    assert not any(operation[0] == "delete_mailbox" for operation in gateway.operations)

    token = await _get_token(client)
    deleted = await _post_json(
        client,
        f"/api/v1/accounts/{ADMIN_ACCOUNT_ID}/delete",
        token,
        {"confirmation": "admin@example.test"},
    )
    assert deleted.status == 200
    assert ("delete_mailbox", ADMIN_ACCOUNT_ID) in gateway.operations


@pytest.mark.asyncio
async def test_account_creation_reports_fresh_admin_verification_requirement(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    gateway.create_account_error = HelperCallError(
        "step_up_required",
        "Fresh administrator authentication is required",
    )

    token = await _get_token(client)
    response = await _post_json(
        client,
        "/api/v1/accounts",
        token,
        {"username": "protected", "password": "valid-password"},
    )

    assert response.status == 403
    payload = await response.json()
    assert payload["error"]["code"] == "step_up_required"
    assert not any(operation[0] == "create_account" for operation in gateway.operations)


@pytest.mark.asyncio
async def test_sensitive_admin_mutations_report_fresh_verification_requirement(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    step_up_error = HelperCallError(
        "step_up_required",
        "Fresh authentication is required",
    )
    cases = (
        (
            "change_password_error",
            f"/api/v1/accounts/{ADMIN_ACCOUNT_ID}/password",
            {"password": "changed-password"},
        ),
        (
            "append_limit_error",
            f"/api/v1/accounts/{ADMIN_ACCOUNT_ID}/append-limit",
            {"limit": 0},
        ),
        (
            "certificate_dry_run_error",
            "/api/v1/certificates/dry-run",
            {"name": "mail.example.test"},
        ),
    )

    for attribute, path, body in cases:
        setattr(gateway, attribute, step_up_error)
        response = await _post_json(client, path, await _get_token(client), body)
        assert response.status == 403
        assert (await response.json())["error"]["code"] == "step_up_required"
        setattr(gateway, attribute, None)


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
async def test_mail_summary_boundary_removes_directional_controls(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    unsafe = "Invoice\u202ecod.exe\u2066\u200b"
    gateway.message_rows[0]["from"] = unsafe
    gateway.message_rows[0]["subject"] = unsafe
    gateway.message_rows[0]["date"] = unsafe
    context = urlencode({"account": ADMIN_ACCOUNT_ID, "mailbox": "INBOX"})

    response, data = await _api_data(client, f"/api/v1/mail?{context}")

    assert response.status == 200
    message = data["messages"][0]
    assert message["sender"] == "Invoicecod.exe"
    assert message["subject"] == "Invoicecod.exe"
    assert message["date"] == "Invoicecod.exe"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    (
        "/api/v1/me/mail-events",
        f"/api/v1/admin/mail-events?account={ADMIN_ACCOUNT_ID}",
    ),
)
async def test_mail_event_catch_up_is_ordered_private_unbuffered_and_metadata_free(
    web_client: tuple[TestClient, FakeGateway],
    path: str,
) -> None:
    client, gateway = web_client
    response = await client.get(path, headers={"Last-Event-ID": "41"})
    try:
        assert response.status == 200
        assert response.headers["Content-Type"] == "text/event-stream; charset=utf-8"
        assert response.headers["Cache-Control"] == ("private, no-store, no-cache, no-transform")
        assert response.headers["X-Accel-Buffering"] == "no"
        assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"
        assert response.headers["Content-Security-Policy"] == (
            "default-src 'none'; frame-ancestors 'none'"
        )

        ready = await response.content.readuntil(b"\n\n")
        new_mail = await response.content.readuntil(b"\n\n")
        payload = ready + new_mail
        assert ready == (b'retry: 15000\nevent: ready\ndata: {"mailbox":"INBOX"}\n\n')
        assert new_mail == (b'event: new_mail\nid: 42\ndata: {"mailbox":"INBOX"}\n\n')
        assert payload.count(b'data: {"mailbox":"INBOX"}\n') == 2
        for sensitive in (
            ADMIN_ACCOUNT_ID.encode(),
            b"admin@example.test",
            b"sender@example.test",
            b"Received message",
            b"message_id",
            b"subject",
        ):
            assert sensitive not in payload
    finally:
        response.close()

    assert ("latest_message_uid", ADMIN_ACCOUNT_ID, "INBOX") in gateway.operations
    assert ("peek_session", ADMIN_SESSION_TOKEN) in gateway.operations
    assert not any(operation[0] == "list_mailboxes" for operation in gateway.operations)
    assert not any(operation[0] == "list_messages" for operation in gateway.operations)


@pytest.mark.asyncio
async def test_mail_events_reject_invalid_resume_cursor_before_streaming(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    response = await client.get(
        "/api/v1/me/mail-events",
        headers={"Last-Event-ID": "-1"},
    )

    assert response.status == 400
    payload = await response.json()
    assert payload["error"] == {
        "code": "invalid_request",
        "message": "Invalid mail event cursor.",
    }
    assert not any(operation[0] == "latest_message_uid" for operation in gateway.operations)


@pytest.mark.asyncio
async def test_mail_event_tabs_share_one_per_session_backend_watcher(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    first = await client.get(
        "/api/v1/me/mail-events",
        headers={"Last-Event-ID": "42"},
    )
    second = None
    try:
        assert b"event: ready\n" in await first.content.readuntil(b"\n\n")
        second = await client.get(
            "/api/v1/me/mail-events",
            headers={"Last-Event-ID": "42"},
        )
        assert b"event: ready\n" in await second.content.readuntil(b"\n\n")
        assert (
            sum(
                operation == ("latest_message_uid", ADMIN_ACCOUNT_ID, "INBOX")
                for operation in gateway.operations
            )
            == 1
        )
        assert sum(operation[0] == "peek_session" for operation in gateway.operations) == 2
    finally:
        if second is not None:
            second.close()
        first.close()


@pytest.mark.asyncio
async def test_mail_event_notifies_after_inbox_uid_reset(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    gateway.latest_message_uid_value = 100
    response = await client.get(
        "/api/v1/me/mail-events",
        headers={"Last-Event-ID": "100"},
    )
    try:
        ready = await response.content.readuntil(b"\n\n")
        assert b"event: ready\n" in ready
        assert b"id: 100\n" in ready

        gateway.latest_message_uid_checked.clear()
        gateway.latest_message_uid_value = 0
        async with asyncio.timeout(1):
            await gateway.latest_message_uid_checked.wait()

        gateway.latest_message_uid_checked.clear()
        gateway.latest_message_uid_value = 1
        async with asyncio.timeout(2):
            while True:
                event = await response.content.readuntil(b"\n\n")
                if b"event: new_mail\n" in event:
                    break
        assert event == (b'event: new_mail\nid: 1\ndata: {"mailbox":"INBOX"}\n\n')
    finally:
        response.close()


@pytest.mark.asyncio
async def test_mail_defaults_to_admin_inbox_and_has_two_delete_levels(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    response, data = await _api_data(client, "/api/v1/mail")
    assert response.status == 200
    assert data["selected_account"] == ADMIN_ACCOUNT_ID
    assert data["selected_mailbox"] == "INBOX"
    assert data["selected_view"] == "mailbox"
    assert data["messages"][0]["uid"] == "42"
    assert ("list_messages", ADMIN_ACCOUNT_ID, "INBOX", 20, 0) in gateway.operations

    gateway.operations.clear()
    response, data = await _api_data(client, "/api/v1/mail?phase=context")
    assert response.status == 200
    assert data["selected_account"] == ADMIN_ACCOUNT_ID
    assert data["selected_mailbox"] == "INBOX"
    assert data["messages"] == []
    assert ("list_mailboxes", ADMIN_ACCOUNT_ID) in gateway.operations
    assert not any(operation[0] == "list_messages" for operation in gateway.operations)

    context = urlencode({"account": ADMIN_ACCOUNT_ID, "mailbox": "INBOX"})
    response, data = await _api_data(client, f"/api/v1/mail?{context}")
    assert response.status == 200
    assert data["messages"][0]["subject"] == "Received message"
    assert data["messages"][0]["uid"] == "42"
    assert "message_id" not in data["messages"][0]
    assert ("list_messages", ADMIN_ACCOUNT_ID, "INBOX", 20, 0) in gateway.operations

    detail, detail_data = await _api_data(client, f"/api/v1/mail/42?{context}")
    assert detail.status == 200
    assert detail_data["subject"] == "Received message"
    assert detail_data["has_html"] is True
    assert detail_data["html_url"].startswith("/api/v1/admin/mail/42/html?")
    assert "html_document" not in detail_data
    assert detail_data["raw_url"].startswith("/api/v1/admin/mail/42/raw?")
    assert detail_data["freshness_token"]

    html_body = await client.get(f"/api/v1/mail/42/html?{context}")
    rendered = await html_body.text()
    assert html_body.status == 200
    assert html_body.headers["Cache-Control"] == "private, no-store, no-transform"
    assert html_body.headers["Referrer-Policy"] == "no-referrer"
    iframe_csp = html_body.headers["Content-Security-Policy"]
    assert "sandbox allow-popups allow-popups-to-escape-sandbox" in iframe_csp
    assert "img-src data:" in iframe_csp
    assert "cid:" not in iframe_csp
    assert "tracker.test" not in rendered
    assert "script" not in rendered
    assert "data:image/png;base64," in rendered
    assert "cid:missing" not in rendered
    assert "cid:logo" not in rendered
    assert "/inline/" not in rendered

    inline = await client.get(f"/api/v1/mail/42/inline/0?{context}")
    assert inline.status == 200
    assert inline.content_type == "image/png"
    assert inline.headers["X-Content-Type-Options"] == "nosniff"
    assert await inline.read() == VALID_PNG

    attachment = await client.get(f"/api/v1/mail/42/attachments/1?{context}")
    assert attachment.content_type == "application/octet-stream"
    assert attachment.headers["Content-Disposition"].startswith("attachment;")

    token = await _get_token(client)
    trashed = await _post_json(
        client,
        "/api/v1/mail/42/trash",
        token,
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "INBOX",
            "freshness": detail_data["freshness_token"],
        },
    )
    assert trashed.status == 200
    assert ("trash", ADMIN_ACCOUNT_ID, "INBOX", "42") in gateway.operations

    _response, fresh_detail = await _api_data(client, f"/api/v1/mail/42?{context}")
    token = await _get_token(client)
    rejected = await _post_json(
        client,
        "/api/v1/mail/42/delete",
        token,
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "INBOX",
            "freshness": fresh_detail["freshness_token"],
            "confirmation": "Delete",
        },
    )
    assert rejected.status == 400
    assert not any(operation[0] == "delete_message" for operation in gateway.operations)


@pytest.mark.asyncio
async def test_account_only_mail_context_selects_authoritative_inbox(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client

    async def case_variant_mailboxes(account_id: str) -> list[dict[str, str]]:
        gateway.operations.append(("list_mailboxes", account_id))
        return [{"name": "Inbox"}, {"name": "Sent"}, {"name": "Trash"}]

    gateway.list_mailboxes = case_variant_mailboxes  # type: ignore[method-assign]
    response, data = await _api_data(
        client,
        f"/api/v1/mail?account={ADMIN_ACCOUNT_ID}",
    )
    assert response.status == 200
    assert data["selected_account"] == ADMIN_ACCOUNT_ID
    assert data["selected_mailbox"] == "Inbox"
    assert data["messages"][0]["uid"] == "42"
    assert ("list_messages", ADMIN_ACCOUNT_ID, "Inbox", 20, 0) in gateway.operations


@pytest.mark.asyncio
async def test_account_only_mail_context_does_not_guess_missing_inbox(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client

    async def mailboxes_without_inbox(account_id: str) -> list[dict[str, str]]:
        gateway.operations.append(("list_mailboxes", account_id))
        return [{"name": "Sent"}, {"name": "Archive"}]

    gateway.list_mailboxes = mailboxes_without_inbox  # type: ignore[method-assign]
    response, data = await _api_data(
        client,
        f"/api/v1/mail?account={ADMIN_ACCOUNT_ID}",
    )
    assert response.status == 200
    assert data["selected_mailbox"] == ""
    assert data["messages"] == []
    assert not any(operation[0] == "list_messages" for operation in gateway.operations)


@pytest.mark.asyncio
async def test_mailbox_payload_exposes_validated_special_use_flags(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client

    async def special_use_mailboxes(account_id: str) -> list[object]:
        gateway.operations.append(("list_mailboxes", account_id))
        return [
            "Inbox",
            {"name": "Deleted Items", "attributes": [r"\Trash", r"\HasNoChildren"]},
            {"name": "Stored Mail", "attributes": [r"\ARCHIVE"]},
        ]

    gateway.list_mailboxes = special_use_mailboxes  # type: ignore[method-assign]
    response, data = await _api_data(
        client,
        f"/api/v1/mail?account={ADMIN_ACCOUNT_ID}",
    )

    assert response.status == 200
    assert data["mailboxes"] == [
        {"name": "Inbox", "is_trash": False, "is_archive": False},
        {"name": "Deleted Items", "is_trash": True, "is_archive": False},
        {"name": "Stored Mail", "is_trash": False, "is_archive": True},
    ]
    assert data["trash_available"] is True
    assert data["archive_available"] is True


@pytest.mark.asyncio
async def test_all_mail_excludes_resolved_special_folders_and_keeps_source_identity(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client

    async def special_use_mailboxes(account_id: str) -> list[object]:
        gateway.operations.append(("list_mailboxes", account_id))
        return [
            {"name": "INBOX"},
            {"name": "Receipts"},
            {"name": "Deleted Items", "attributes": [r"\Trash"]},
            {"name": "Old Deleted Items", "attributes": [r"\Trash"]},
            {"name": "Stored Mail", "attributes": [r"\Archive"]},
            {"name": "Old Stored Mail", "attributes": [r"\Archive"]},
        ]

    rows = {
        "INBOX": [
            {
                "uid": 42,
                "from": "inbox@example.test",
                "subject": "Inbox message",
                "internal_date_unix": 100,
            }
        ],
        "Receipts": [
            {
                "uid": 42,
                "from": "billing@example.test",
                "subject": "Receipt",
                "internal_date_unix": 200,
            }
        ],
    }

    async def mailbox_messages(
        account_id: str,
        mailbox: str,
        *,
        limit: int,
        offset: int,
    ) -> MessagePage:
        gateway.operations.append(("list_messages", account_id, mailbox, limit, offset))
        values = rows.get(mailbox, [])
        initial_offset = int(values[0]["uid"]) if values else 0
        return MessagePage(values, False, None, offset or initial_offset)

    gateway.list_mailboxes = special_use_mailboxes  # type: ignore[method-assign]
    gateway.list_messages = mailbox_messages  # type: ignore[method-assign]
    response, data = await _api_data(
        client,
        f"/api/v1/admin/mail?account={ADMIN_ACCOUNT_ID}&view=all",
    )

    assert response.status == 200
    assert data["selected_view"] == "all"
    assert data["selected_mailbox"] == ""
    assert [(item["mailbox"], item["uid"]) for item in data["messages"]] == [
        ("Receipts", "42"),
        ("INBOX", "42"),
    ]
    listed = {
        operation[2]
        for operation in gateway.operations
        if operation[0] == "list_messages"
    }
    assert listed == {"INBOX", "Receipts"}
    assert all(
        operation[3] <= 20
        for operation in gateway.operations
        if operation[0] == "list_messages"
    )

    mixed_context = await client.get(
        f"/api/v1/admin/mail?account={ADMIN_ACCOUNT_ID}&view=all&mailbox=INBOX"
    )
    assert mixed_context.status == 400


@pytest.mark.asyncio
async def test_all_mail_cursor_resumes_each_source_without_uid_collisions(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    mailbox_names = ["INBOX", "Sent", "Trash"]
    rows = {
        "INBOX": [
            {"uid": uid, "subject": f"Inbox {uid}", "internal_date_unix": uid + 200}
            for uid in range(100, 0, -1)
        ],
        "Sent": [
            {"uid": uid, "subject": f"Sent {uid}", "internal_date_unix": uid + 90}
            for uid in range(200, 100, -1)
        ],
    }

    async def listed_mailboxes(account_id: str) -> list[dict[str, str]]:
        gateway.operations.append(("list_mailboxes", account_id))
        return [{"name": mailbox} for mailbox in mailbox_names]

    async def mailbox_messages(
        account_id: str,
        mailbox: str,
        *,
        limit: int,
        offset: int,
    ) -> MessagePage:
        gateway.operations.append(("list_messages", account_id, mailbox, limit, offset))
        mailbox_rows = rows[mailbox]
        start = 0
        if offset:
            start = next(index for index, row in enumerate(mailbox_rows) if row["uid"] == offset)
        items = mailbox_rows[start : start + limit]
        next_offset = (
            int(mailbox_rows[start + limit]["uid"])
            if start + limit < len(mailbox_rows)
            else None
        )
        return MessagePage(
            items,
            next_offset is not None,
            next_offset,
            offset or int(items[0]["uid"]),
        )

    gateway.list_mailboxes = listed_mailboxes  # type: ignore[method-assign]
    gateway.list_messages = mailbox_messages  # type: ignore[method-assign]
    base = f"/api/v1/admin/mail?account={ADMIN_ACCOUNT_ID}&view=all"
    _response, first = await _api_data(client, base)
    next_cursor = str(first["next_cursor"])
    first_identities = {
        (str(item["mailbox"]), str(item["uid"])) for item in first["messages"]
    }

    assert len(first_identities) == 20
    assert next_cursor
    gateway.operations.clear()
    _response, second = await _api_data(client, f"{base}&cursor={next_cursor}")
    second_identities = {
        (str(item["mailbox"]), str(item["uid"])) for item in second["messages"]
    }
    assert len(second_identities) == 20
    assert first_identities.isdisjoint(second_identities)
    assert second["previous_cursor"]
    resumed_offsets = {
        operation[2]: operation[4]
        for operation in gateway.operations
        if operation[0] == "list_messages"
    }
    assert resumed_offsets.keys() == {"INBOX", "Sent"}
    assert all(offset > 0 for offset in resumed_offsets.values())

    mailbox_names.insert(2, "Drafts")
    changed = await client.get(f"{base}&cursor={next_cursor}")
    assert changed.status == 409


@pytest.mark.asyncio
async def test_all_mail_fills_a_page_from_one_busy_folder_with_bounded_fanout(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    mailbox_names = ["INBOX", *(f"Empty {index:02d}" for index in range(63))]
    rows = [
        {"uid": uid, "subject": f"Inbox {uid}", "internal_date_unix": uid}
        for uid in range(50, 0, -1)
    ]

    async def listed_mailboxes(account_id: str) -> list[dict[str, str]]:
        gateway.operations.append(("list_mailboxes", account_id))
        return [{"name": mailbox} for mailbox in mailbox_names]

    async def mailbox_messages(
        account_id: str,
        mailbox: str,
        *,
        limit: int,
        offset: int,
    ) -> MessagePage:
        gateway.operations.append(("list_messages", account_id, mailbox, limit, offset))
        if mailbox != "INBOX":
            return MessagePage((), False, None, 0)
        start = 0
        if offset:
            start = next(index for index, row in enumerate(rows) if row["uid"] == offset)
        items = rows[start : start + limit]
        next_offset = (
            int(rows[start + limit]["uid"]) if start + limit < len(rows) else None
        )
        return MessagePage(
            items,
            next_offset is not None,
            next_offset,
            offset or int(items[0]["uid"]),
        )

    gateway.list_mailboxes = listed_mailboxes  # type: ignore[method-assign]
    gateway.list_messages = mailbox_messages  # type: ignore[method-assign]
    base = f"/api/v1/admin/mail?account={ADMIN_ACCOUNT_ID}&view=all"
    _response, first = await _api_data(client, base)

    assert len(first["messages"]) == 20
    assert {item["mailbox"] for item in first["messages"]} == {"INBOX"}
    list_calls = [
        operation for operation in gateway.operations if operation[0] == "list_messages"
    ]
    assert len(list_calls) <= 65
    assert all(1 <= int(operation[3]) <= 20 for operation in list_calls)

    gateway.operations.clear()
    mailbox_names.reverse()
    _response, second = await _api_data(
        client,
        f"{base}&cursor={first['next_cursor']}",
    )
    assert len(second["messages"]) == 20
    assert {
        (str(item["mailbox"]), str(item["uid"])) for item in first["messages"]
    }.isdisjoint(
        (str(item["mailbox"]), str(item["uid"])) for item in second["messages"]
    )
    _response, previous = await _api_data(
        client,
        f"{base}&cursor={second['previous_cursor']}",
    )
    assert [
        (str(item["mailbox"]), str(item["uid"])) for item in previous["messages"]
    ] == [
        (str(item["mailbox"]), str(item["uid"])) for item in first["messages"]
    ]

    wrong_account = await client.get(
        "/api/v1/admin/mail?"
        + urlencode(
            {
                "account": DISABLED_ACCOUNT_ID,
                "view": "all",
                "cursor": str(first["next_cursor"]),
            }
        )
    )
    assert wrong_account.status == 409

    personal_override = await client.get(
        "/api/v1/me/mail?"
        + urlencode({"account": DISABLED_ACCOUNT_ID, "view": "all"})
    )
    assert personal_override.status == 400


@pytest.mark.asyncio
async def test_folder_mutation_endpoints_are_account_scoped_and_confirm_delete(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client

    created = await _post_json(
        client,
        "/api/v1/admin/mailboxes",
        await _get_token(client),
        {"account": ADMIN_ACCOUNT_ID, "name": "Projects/2026"},
    )
    assert created.status == 201
    assert ("create_mailbox", ADMIN_ACCOUNT_ID, "Projects/2026") in gateway.operations

    renamed = await _post_json(
        client,
        "/api/v1/admin/mailboxes/rename",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "old_name": "Projects/2026",
            "new_name": "Projects/Current",
        },
    )
    assert renamed.status == 200
    assert (
        "rename_mailbox",
        ADMIN_ACCOUNT_ID,
        "Projects/2026",
        "Projects/Current",
    ) in gateway.operations

    rejected = await _post_json(
        client,
        "/api/v1/admin/mailboxes/delete",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "name": "Projects/Current",
            "confirmation": "Projects",
        },
    )
    assert rejected.status == 400
    assert not any(operation[0] == "delete_named_mailbox" for operation in gateway.operations)

    deleted = await _post_json(
        client,
        "/api/v1/admin/mailboxes/delete",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "name": "Projects/Current",
            "confirmation": "Projects/Current",
        },
    )
    assert deleted.status == 200
    assert ("delete_named_mailbox", ADMIN_ACCOUNT_ID, "Projects/Current") in gateway.operations

    personal_cross_account = await _post_json(
        client,
        "/api/v1/me/mailboxes",
        await _get_token(client),
        {"account": ADMIN_ACCOUNT_ID, "name": "Should not exist"},
    )
    assert personal_cross_account.status == 400
    assert not any(
        operation[:2] == ("create_mailbox", ADMIN_ACCOUNT_ID)
        and operation[-1] == "Should not exist"
        for operation in gateway.operations
    )

    async def referenced_folder(*_args: object) -> None:
        raise HelperCallError("conflict", "internal rule reference")

    gateway.rename_mailbox = referenced_folder  # type: ignore[method-assign]
    referenced = await _post_json(
        client,
        "/api/v1/admin/mailboxes/rename",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "old_name": "Receipts",
            "new_name": "Filed",
        },
    )
    assert referenced.status == 409
    assert (await referenced.json())["error"]["message"] == (
        "The folder is used by a mail rule and cannot be changed."
    )


@pytest.mark.asyncio
async def test_mail_rule_spa_and_admin_api_match_frontend_contract(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    shell = await client.get("/rules")
    assert shell.status == 200
    assert 'id="rules-view"' in await shell.text()

    listed = await client.get(f"/api/v1/admin/mail-rules?account={ADMIN_ACCOUNT_ID}")
    assert listed.status == 200
    listed_payload = await listed.json()
    assert listed_payload["data"] == {"rules": [], "active_run": None}

    condition = {
        "op": "and",
        "conditions": [
            {"field": "subject", "operator": "contains", "value": "receipt"},
            {"field": "from", "operator": "ends_with", "value": "@shop.example"},
        ],
    }
    created = await _post_json(
        client,
        "/api/v1/admin/mail-rules",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "name": "Receipts",
            "enabled": True,
            "match": condition,
            "target_mailbox": "Receipts",
            "stop_processing": True,
            "apply_existing": True,
        },
    )
    assert created.status == 201
    created_data = (await created.json())["data"]
    rule_id = created_data["rule"]["rule_id"]
    run_id = created_data["run"]["run_id"]
    assert created_data["rule"]["match"] == condition
    assert created_data["run"]["rule_name"] == "Receipts"

    updated = await _post_json(
        client,
        f"/api/v1/admin/mail-rules/{rule_id}/update",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "name": "Shop receipts",
            "enabled": True,
            "match": condition,
            "target_mailbox": "Receipts",
            "stop_processing": False,
            "expected_revision": 1,
        },
    )
    assert updated.status == 200
    update_operation = next(
        operation for operation in gateway.operations if operation[0] == "update_mail_rule"
    )
    assert update_operation[-1] == 1

    alias_updated = await _post_json(
        client,
        f"/api/v1/admin/mail-rules/{rule_id}/update",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "name": "Shop receipts",
            "enabled": True,
            "match": condition,
            "target_mailbox": "Receipts",
            "stop_processing": False,
            "revision": 2,
        },
    )
    assert alias_updated.status == 200
    assert [
        operation for operation in gateway.operations if operation[0] == "update_mail_rule"
    ][-1][-1] == 2

    duplicate_revision = await _post_json(
        client,
        f"/api/v1/admin/mail-rules/{rule_id}/update",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "name": "Shop receipts",
            "enabled": True,
            "match": condition,
            "target_mailbox": "Receipts",
            "stop_processing": False,
            "expected_revision": 2,
            "revision": 2,
        },
    )
    assert duplicate_revision.status == 400

    missing_revision = await _post_json(
        client,
        f"/api/v1/admin/mail-rules/{rule_id}/update",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "name": "Shop receipts",
            "enabled": True,
            "match": condition,
            "target_mailbox": "Receipts",
            "stop_processing": False,
        },
    )
    assert missing_revision.status == 400

    reordered = await _post_json(
        client,
        "/api/v1/admin/mail-rules/reorder",
        await _get_token(client),
        {"account": ADMIN_ACCOUNT_ID, "rule_ids": [rule_id]},
    )
    assert reordered.status == 200

    started = await _post_json(
        client,
        "/api/v1/admin/mail-rule-runs",
        await _get_token(client),
        {"account": ADMIN_ACCOUNT_ID, "rule_id": rule_id},
    )
    assert started.status == 201

    status = await client.get(
        f"/api/v1/admin/mail-rule-runs/{run_id}?account={ADMIN_ACCOUNT_ID}"
    )
    assert status.status == 200

    stepped = await _post_json(
        client,
        f"/api/v1/admin/mail-rule-runs/{run_id}/step",
        await _get_token(client),
        {"account": ADMIN_ACCOUNT_ID},
    )
    assert stepped.status == 200
    assert (await stepped.json())["data"]["run"]["processed"] == 2

    cancelled = await _post_json(
        client,
        f"/api/v1/admin/mail-rule-runs/{run_id}/cancel",
        await _get_token(client),
        {"account": ADMIN_ACCOUNT_ID},
    )
    assert cancelled.status == 200

    deleted = await _post_json(
        client,
        f"/api/v1/admin/mail-rules/{rule_id}/delete",
        await _get_token(client),
        {"account": ADMIN_ACCOUNT_ID},
    )
    assert deleted.status == 200

    personal_cross_account = await client.get(
        f"/api/v1/me/mail-rules?account={ADMIN_ACCOUNT_ID}"
    )
    assert personal_cross_account.status == 400


@pytest.mark.asyncio
async def test_mail_rule_mutations_require_recent_verification_but_reads_and_cancel_do_not(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    gateway.step_up_until = 0
    rule_id = "b" * 32
    run_id = "c" * 32
    condition = {"field": "subject", "operator": "exists"}
    cases = (
        (
            "/api/v1/admin/mail-rules",
            {
                "account": ADMIN_ACCOUNT_ID,
                "name": "Receipts",
                "enabled": True,
                "match": condition,
                "target_mailbox": "Receipts",
                "stop_processing": True,
                "apply_existing": False,
            },
        ),
        (
            f"/api/v1/admin/mail-rules/{rule_id}/update",
            {
                "account": ADMIN_ACCOUNT_ID,
                "name": "Receipts",
                "enabled": True,
                "match": condition,
                "target_mailbox": "Receipts",
                "stop_processing": True,
                "expected_revision": 1,
            },
        ),
        (
            f"/api/v1/admin/mail-rules/{rule_id}/delete",
            {"account": ADMIN_ACCOUNT_ID},
        ),
        (
            "/api/v1/admin/mail-rules/reorder",
            {"account": ADMIN_ACCOUNT_ID, "rule_ids": [rule_id]},
        ),
        (
            "/api/v1/admin/mail-rule-runs",
            {"account": ADMIN_ACCOUNT_ID, "rule_id": rule_id},
        ),
        (
            f"/api/v1/admin/mail-rule-runs/{run_id}/step",
            {"account": ADMIN_ACCOUNT_ID},
        ),
    )

    operation_start = len(gateway.operations)
    for path, body in cases:
        response = await _post_json(client, path, await _get_token(client), body)
        assert response.status == 403
        assert (await response.json())["error"] == {
            "code": "step_up_required",
            "message": "Fresh authentication is required.",
        }
    assert not any(
        operation[0]
        in {
            "create_mail_rule",
            "update_mail_rule",
            "delete_mail_rule",
            "reorder_mail_rules",
            "create_mail_rule_run",
            "step_mail_rule_run",
        }
        for operation in gateway.operations[operation_start:]
    )

    listed = await client.get(f"/api/v1/admin/mail-rules?account={ADMIN_ACCOUNT_ID}")
    status = await client.get(
        f"/api/v1/admin/mail-rule-runs/{run_id}?account={ADMIN_ACCOUNT_ID}"
    )
    assert listed.status == 200
    assert status.status == 200

    cancelled = await _post_json(
        client,
        f"/api/v1/admin/mail-rule-runs/{run_id}/cancel",
        await _get_token(client),
        {"account": ADMIN_ACCOUNT_ID},
    )
    assert cancelled.status == 200
    assert ("cancel_mail_rule_run", ADMIN_ACCOUNT_ID, run_id) in gateway.operations


@pytest.mark.asyncio
async def test_mail_rule_conflicts_are_public_safe_409_responses(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    gateway.mail_rule_error = HelperCallError("conflict", "sensitive helper details")
    response = await _post_json(
        client,
        f"/api/v1/admin/mail-rules/{'b' * 32}/update",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "name": "Stale rule",
            "enabled": True,
            "match": {"field": "subject", "operator": "exists"},
            "target_mailbox": "INBOX",
            "stop_processing": True,
            "expected_revision": 1,
        },
    )
    assert response.status == 409
    payload = await response.json()
    assert payload["error"] == {
        "code": "conflict",
        "message": "The mail rule state conflicts with this operation.",
    }
    assert "sensitive" not in repr(payload)

    gateway.mail_rule_error = HelperCallError(
        "step_up_required",
        "sensitive helper verification details",
    )
    step_up = await _post_json(
        client,
        "/api/v1/admin/mail-rules",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "name": "Protected rule",
            "enabled": True,
            "match": {"field": "subject", "operator": "exists"},
            "target_mailbox": "INBOX",
            "stop_processing": True,
            "apply_existing": False,
        },
    )
    assert step_up.status == 403
    step_up_payload = await step_up.json()
    assert step_up_payload["error"] == {
        "code": "step_up_required",
        "message": "Fresh authentication is required.",
    }
    assert "sensitive" not in repr(step_up_payload)


@pytest.mark.asyncio
async def test_bulk_message_actions_validate_selection_and_use_fixed_mailbox_scope(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    token = await _get_token(client)
    base = {
        "account": ADMIN_ACCOUNT_ID,
        "mailbox": "INBOX",
    }

    marked = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        token,
        {**base, "action": "mark_read", "uids": ["42", "43"]},
    )
    assert marked.status == 200
    assert (
        "set_messages_seen",
        ADMIN_ACCOUNT_ID,
        "INBOX",
        ("42", "43"),
        True,
    ) in gateway.operations

    token = await _get_token(client)
    mark_all = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        token,
        {**base, "action": "mark_all_read"},
    )
    assert mark_all.status == 200
    assert (
        "set_messages_seen",
        ADMIN_ACCOUNT_ID,
        "INBOX",
        None,
        True,
    ) in gateway.operations

    token = await _get_token(client)
    archive_freshness = await _message_action_token(client, "42", mailbox="INBOX")
    archived = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        token,
        {
            **base,
            "action": "archive",
            "uids": ["42"],
            "freshness": [{"uid": "42", "token": archive_freshness}],
        },
    )
    assert archived.status == 200
    assert ("archive_many", ADMIN_ACCOUNT_ID, "INBOX", ("42",)) in gateway.operations

    token = await _get_token(client)
    move_freshness = {
        uid: await _message_action_token(client, uid, mailbox="INBOX")
        for uid in ("42", "43")
    }
    moved = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        token,
        {
            **base,
            "action": "move",
            "target_mailbox": "Sent",
            "uids": ["42", "43"],
            "freshness": [
                {"uid": uid, "token": move_freshness[uid]} for uid in ("42", "43")
            ],
        },
    )
    moved_payload = await moved.json()
    assert moved.status == 200
    assert moved_payload["data"]["target_mailbox"] == "Sent"
    assert (
        "move_many",
        ADMIN_ACCOUNT_ID,
        "INBOX",
        ("42", "43"),
        "Sent",
    ) in gateway.operations

    token = await _get_token(client)
    invalid_target = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        token,
        {
            **base,
            "action": "move",
            "target_mailbox": "Unknown",
            "uids": ["42"],
        },
    )
    assert invalid_target.status == 400
    assert not any(operation[-1] == "Unknown" for operation in gateway.operations)

    token = await _get_token(client)
    duplicate = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        token,
        {**base, "action": "trash", "uids": ["42", "42"]},
    )
    assert duplicate.status == 400
    assert not any(operation[0] == "trash_many" for operation in gateway.operations)


@pytest.mark.asyncio
async def test_bulk_relocation_requires_fresh_proof_before_any_write(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    body = {
        "account": ADMIN_ACCOUNT_ID,
        "mailbox": "INBOX",
        "action": "move",
        "target_mailbox": "Sent",
        "uids": ["42"],
    }

    missing = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        await _get_token(client),
        body,
    )
    assert missing.status == 400
    assert not any(operation[0] == "move_many" for operation in gateway.operations)

    proof = await _message_action_token(client, "42", mailbox="INBOX")
    gateway.raw_message = gateway.raw_message.replace(b"Subject:", b"Subject: changed ", 1)
    stale = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        await _get_token(client),
        {**body, "freshness": [{"uid": "42", "token": proof}]},
    )
    assert stale.status == 409
    assert not any(operation[0] == "move_many" for operation in gateway.operations)


async def _message_action_token(
    client: TestClient,
    uid: str,
    *,
    mailbox: str = "Trash",
) -> str:
    context = urlencode({"account": ADMIN_ACCOUNT_ID, "mailbox": mailbox})
    response, payload = await _api_data(
        client,
        f"/api/v1/mail/{uid}/action-snapshot?{context}",
    )
    assert response.status == 200
    return str(payload["freshness_token"])


@pytest.mark.asyncio
async def test_single_message_can_move_to_an_authoritative_folder(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    freshness = await _message_action_token(client, "42", mailbox="INBOX")

    moved = await _post_json(
        client,
        "/api/v1/admin/mail/42/move",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "INBOX",
            "target_mailbox": "Sent",
            "freshness": freshness,
        },
    )

    assert moved.status == 200
    assert ("move", ADMIN_ACCOUNT_ID, "INBOX", "42", "Sent") in gateway.operations


@pytest.mark.asyncio
async def test_single_permanent_delete_preserves_proof_until_recent_verification(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    freshness = await _message_action_token(client, "42")
    body = {
        "account": ADMIN_ACCOUNT_ID,
        "mailbox": "Trash",
        "freshness": freshness,
        "confirmation": "PERMANENTLY DELETE",
    }
    initial_spools = gateway.spool_calls
    gateway.step_up_until = int(time.time()) + 4

    rejected = await _post_json(
        client,
        "/api/v1/admin/mail/42/delete",
        await _get_token(client),
        body,
    )

    assert rejected.status == 403
    assert (await rejected.json())["error"]["code"] == "step_up_required"
    assert gateway.spool_calls == initial_spools
    assert not any(operation[0] == "delete_message" for operation in gateway.operations)

    gateway.step_up_until = int(time.time()) + 300
    retried = await _post_json(
        client,
        "/api/v1/admin/mail/42/delete",
        await _get_token(client),
        body,
    )

    assert retried.status == 200
    assert ("delete_message", ADMIN_ACCOUNT_ID, "Trash", "42") in gateway.operations


@pytest.mark.asyncio
async def test_bulk_permanent_delete_preserves_proofs_until_recent_verification(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    freshness = await _message_action_token(client, "42")
    body = {
        "account": ADMIN_ACCOUNT_ID,
        "mailbox": "Trash",
        "action": "permanent_delete",
        "uids": ["42"],
        "confirmation": "PERMANENTLY DELETE",
        "freshness": [{"uid": "42", "token": freshness}],
    }
    initial_spools = gateway.spool_calls
    gateway.step_up_until = 0

    rejected = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        await _get_token(client),
        body,
    )

    assert rejected.status == 403
    assert (await rejected.json())["error"]["code"] == "step_up_required"
    assert gateway.spool_calls == initial_spools
    assert not any(operation[0] == "delete_messages" for operation in gateway.operations)

    gateway.step_up_until = int(time.time()) + 300
    retried = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        await _get_token(client),
        body,
    )

    assert retried.status == 200
    assert (
        "delete_messages",
        ADMIN_ACCOUNT_ID,
        "Trash",
        ("42",),
    ) in gateway.operations


@pytest.mark.asyncio
async def test_permanent_delete_routes_surface_helper_step_up_requirement(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    step_up_error = HelperCallError("step_up_required", "verification expired")

    single_proof = await _message_action_token(client, "42")
    gateway.delete_error = step_up_error
    single = await _post_json(
        client,
        "/api/v1/admin/mail/42/delete",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "Trash",
            "freshness": single_proof,
            "confirmation": "PERMANENTLY DELETE",
        },
    )
    assert single.status == 403
    assert (await single.json())["error"]["code"] == "step_up_required"

    bulk_proof = await _message_action_token(client, "43")
    gateway.bulk_delete_error = step_up_error
    bulk = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "Trash",
            "action": "permanent_delete",
            "uids": ["43"],
            "confirmation": "PERMANENTLY DELETE",
            "freshness": [{"uid": "43", "token": bulk_proof}],
        },
    )
    assert bulk.status == 403
    assert (await bulk.json())["error"]["code"] == "step_up_required"


@pytest.mark.asyncio
async def test_bulk_permanent_delete_preflights_every_snapshot_then_calls_gateway_once(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    proofs = {
        uid: await _message_action_token(client, uid) for uid in ("42", "43", "44", "45", "46")
    }
    gateway.spool_gate = asyncio.Event()
    token = await _get_token(client)
    request = asyncio.create_task(
        _post_json(
            client,
            "/api/v1/admin/mail-actions",
            token,
            {
                "account": ADMIN_ACCOUNT_ID,
                "mailbox": "Trash",
                "action": "permanent_delete",
                "uids": ["46", "42", "45", "43", "44"],
                "confirmation": "PERMANENTLY DELETE",
                "freshness": [
                    {"uid": uid, "token": proofs[uid]} for uid in ("44", "42", "46", "43", "45")
                ],
            },
        )
    )
    await asyncio.wait_for(gateway.two_spools_started.wait(), timeout=1)
    assert not any(operation[0] == "delete_messages" for operation in gateway.operations)
    assert gateway.spool_active <= 2
    gateway.spool_gate.set()

    response = await request
    assert response.status == 200
    assert [operation for operation in gateway.operations if operation[0] == "delete_messages"] == [
        (
            "delete_messages",
            ADMIN_ACCOUNT_ID,
            "Trash",
            ("42", "43", "44", "45", "46"),
        )
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [
        {"confirmation": "permanently delete"},
        {"freshness": []},
        {
            "uids": ["\u0661"],
            "freshness": [{"uid": "\u0661", "token": "T" * 43}],
        },
        {
            "uids": ["42", "43"],
            "freshness": [
                {"uid": "42", "token": "T" * 43},
                {"uid": "44", "token": "X" * 43},
            ],
        },
        {
            "uids": ["42", "43"],
            "freshness": [
                {"uid": "42", "token": "T" * 43},
                {"uid": "42", "token": "X" * 43},
            ],
        },
        {"freshness": [{"uid": "42", "token": "T" * 43, "extra": True}]},
        {
            "uids": ["42", "43"],
            "freshness": [
                {"uid": "42", "token": "T" * 43},
                {"uid": "43", "token": "T" * 43},
            ],
        },
    ],
)
async def test_bulk_permanent_delete_rejects_invalid_confirmation_and_proof_sets(
    web_client: tuple[TestClient, FakeGateway],
    changes: dict[str, object],
) -> None:
    client, gateway = web_client
    token = await _get_token(client)
    body: dict[str, object] = {
        "account": ADMIN_ACCOUNT_ID,
        "mailbox": "Trash",
        "action": "permanent_delete",
        "uids": ["42"],
        "confirmation": "PERMANENTLY DELETE",
        "freshness": [{"uid": "42", "token": "T" * 43}],
    }
    body.update(changes)

    response = await _post_json(client, "/api/v1/admin/mail-actions", token, body)
    assert response.status in {400, 409}
    assert not any(operation[0] == "delete_messages" for operation in gateway.operations)


@pytest.mark.asyncio
async def test_bulk_permanent_delete_requires_authoritative_trash_and_fresh_content(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    inbox_token = await _message_action_token(client, "42", mailbox="INBOX")
    csrf = await _get_token(client)
    wrong_mailbox = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        csrf,
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "INBOX",
            "action": "permanent_delete",
            "uids": ["42"],
            "confirmation": "PERMANENTLY DELETE",
            "freshness": [{"uid": "42", "token": inbox_token}],
        },
    )
    assert wrong_mailbox.status == 400

    stale_token = await _message_action_token(client, "42")
    gateway.raw_message = gateway.raw_message.replace(b"Subject:", b"Subject: changed ", 1)
    csrf = await _get_token(client)
    stale = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        csrf,
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "Trash",
            "action": "permanent_delete",
            "uids": ["42"],
            "confirmation": "PERMANENTLY DELETE",
            "freshness": [{"uid": "42", "token": stale_token}],
        },
    )
    assert stale.status == 409
    assert not any(operation[0] == "delete_messages" for operation in gateway.operations)


@pytest.mark.asyncio
async def test_bulk_permanent_delete_mixed_stale_set_completes_preflight_without_a_write(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    proofs = {uid: await _message_action_token(client, uid) for uid in ("42", "43")}
    gateway.raw_messages["43"] = gateway.raw_message.replace(
        b"Subject:",
        b"Subject: changed ",
        1,
    )
    operation_start = len(gateway.operations)
    csrf = await _get_token(client)
    response = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        csrf,
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "Trash",
            "action": "permanent_delete",
            "uids": ["42", "43"],
            "confirmation": "PERMANENTLY DELETE",
            "freshness": [{"uid": uid, "token": proofs[uid]} for uid in ("42", "43")],
        },
    )

    assert response.status == 409
    verification_operations = gateway.operations[operation_start:]
    assert sorted(
        operation[3] for operation in verification_operations if operation[0] == "spool_message"
    ) == ["42", "43"]
    assert not any(operation[0] == "delete_messages" for operation in gateway.operations)


@pytest.mark.asyncio
async def test_bulk_permanent_delete_backend_failure_is_not_retried(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    freshness = await _message_action_token(client, "42")
    gateway.bulk_delete_error = ConnectionError("ambiguous transport outcome")
    token = await _get_token(client)
    response = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        token,
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "Trash",
            "action": "permanent_delete",
            "uids": ["42"],
            "confirmation": "PERMANENTLY DELETE",
            "freshness": [{"uid": "42", "token": freshness}],
        },
    )
    assert response.status == 502
    assert sum(operation[0] == "delete_messages" for operation in gateway.operations) == 1


@pytest.mark.asyncio
async def test_other_bulk_actions_reject_permanent_delete_fields(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    token = await _get_token(client)
    response = await _post_json(
        client,
        "/api/v1/admin/mail-actions",
        token,
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "INBOX",
            "action": "trash",
            "uids": ["42"],
            "confirmation": "PERMANENTLY DELETE",
            "freshness": [],
        },
    )
    assert response.status == 400
    assert not any(operation[0] == "trash_many" for operation in gateway.operations)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mailboxes", "expected_mailboxes", "trash_available", "archive_available"),
    [
        (
            [
                {"name": "Deleted Items", "attributes": [r"\Trash"]},
                {"name": "Stored Mail", "attributes": [r"\Archive"]},
                {"name": "Trash", "attributes": []},
                {"name": "Archive", "attributes": []},
            ],
            [
                {"name": "Deleted Items", "is_trash": True, "is_archive": False},
                {"name": "Stored Mail", "is_trash": False, "is_archive": True},
                {"name": "Trash", "is_trash": False, "is_archive": False},
                {"name": "Archive", "is_trash": False, "is_archive": False},
            ],
            True,
            True,
        ),
        (
            ["INBOX", "Saved"],
            [
                {"name": "INBOX", "is_trash": False, "is_archive": False},
                {"name": "Saved", "is_trash": False, "is_archive": False},
            ],
            False,
            False,
        ),
        (
            [
                {"name": "Trash One", "attributes": [r"\Trash"]},
                {"name": "Trash Two", "attributes": [r"\Trash"]},
                {"name": "Archive One", "attributes": [r"\Archive"]},
                {"name": "Archive Two", "attributes": [r"\Archive"]},
            ],
            [
                {"name": "Trash One", "is_trash": False, "is_archive": False},
                {"name": "Trash Two", "is_trash": False, "is_archive": False},
                {"name": "Archive One", "is_trash": False, "is_archive": False},
                {"name": "Archive Two", "is_trash": False, "is_archive": False},
            ],
            False,
            False,
        ),
        (
            ["INBOX", "Trash", {"name": "Archive", "attributes": []}],
            [
                {"name": "INBOX", "is_trash": False, "is_archive": False},
                {"name": "Trash", "is_trash": True, "is_archive": False},
                {"name": "Archive", "is_trash": False, "is_archive": True},
            ],
            True,
            True,
        ),
    ],
    ids=("unique-flags", "missing", "ambiguous-flags", "exact-name-fallback"),
)
async def test_mailbox_special_targets_match_helper_resolution_semantics(
    web_client: tuple[TestClient, FakeGateway],
    mailboxes: list[object],
    expected_mailboxes: list[dict[str, object]],
    trash_available: bool,
    archive_available: bool,
) -> None:
    client, gateway = web_client

    async def listed_mailboxes(account_id: str) -> list[object]:
        gateway.operations.append(("list_mailboxes", account_id))
        return mailboxes

    gateway.list_mailboxes = listed_mailboxes  # type: ignore[method-assign]
    _response, data = await _api_data(
        client,
        f"/api/v1/mail?account={ADMIN_ACCOUNT_ID}",
    )

    assert data["mailboxes"] == expected_mailboxes
    assert data["trash_available"] is trash_available
    assert data["archive_available"] is archive_available


@pytest.mark.asyncio
async def test_mailbox_payload_rejects_invalid_special_use_attributes(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client

    async def invalid_mailboxes(account_id: str) -> list[dict[str, object]]:
        gateway.operations.append(("list_mailboxes", account_id))
        return [{"name": "Trash", "attributes": r"\Trash"}]

    gateway.list_mailboxes = invalid_mailboxes  # type: ignore[method-assign]
    response = await client.get(f"/api/v1/mail?account={ADMIN_ACCOUNT_ID}")
    payload = await response.json()

    assert response.status == 502
    assert payload["error"]["code"] == "invalid_backend_response"


@pytest.mark.asyncio
async def test_message_detail_reuses_bounded_parsing_but_issues_fresh_action_tokens(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    context = urlencode({"account": ADMIN_ACCOUNT_ID, "mailbox": "INBOX"})
    _first_response, first = await _api_data(client, f"/api/v1/mail/42?{context}")
    _second_response, second = await _api_data(client, f"/api/v1/mail/42?{context}")

    assert gateway.spool_calls == 1
    assert second["subject"] == first["subject"]
    assert second["freshness_token"] != first["freshness_token"]


@pytest.mark.asyncio
async def test_archive_requires_and_consumes_a_fresh_message_snapshot(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    context = urlencode({"account": ADMIN_ACCOUNT_ID, "mailbox": "INBOX"})
    _response, detail = await _api_data(client, f"/api/v1/mail/42?{context}")
    body = {
        "account": ADMIN_ACCOUNT_ID,
        "mailbox": "INBOX",
        "freshness": detail["freshness_token"],
    }

    token = await _get_token(client)
    archived = await _post_json(client, "/api/v1/mail/42/archive", token, body)
    assert archived.status == 200
    payload = await archived.json()
    assert payload["data"] == {
        "account": ADMIN_ACCOUNT_ID,
        "mailbox": "Archive",
    }
    assert ("archive", ADMIN_ACCOUNT_ID, "INBOX", "42") in gateway.operations

    token = await _get_token(client)
    replayed = await _post_json(client, "/api/v1/mail/42/archive", token, body)
    assert replayed.status == 409
    assert sum(operation[0] == "archive" for operation in gateway.operations) == 1


@pytest.mark.asyncio
async def test_action_snapshot_does_not_require_mime_preview(
    web_client: tuple[TestClient, FakeGateway],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    client, gateway = web_client

    def reject_preview(_raw: bytes) -> object:
        raise MailError("fixture parser rejection")

    monkeypatch.setattr("maddyweb.web.parse_message", reject_preview)
    context = urlencode({"account": ADMIN_ACCOUNT_ID, "mailbox": "INBOX"})

    detail = await client.get(f"/api/v1/mail/42?{context}")
    assert detail.status == 422

    snapshot_response, snapshot = await _api_data(
        client,
        f"/api/v1/mail/42/action-snapshot?{context}",
    )
    assert snapshot_response.status == 200
    assert set(snapshot) == {
        "uid",
        "account",
        "mailbox",
        "size",
        "freshness_token",
    }
    assert snapshot["uid"] == "42"
    assert snapshot["account"] == ADMIN_ACCOUNT_ID
    assert snapshot["mailbox"] == "INBOX"
    assert snapshot["size"] == len(gateway.raw_message)
    assert snapshot["freshness_token"]
    assert not await asyncio.to_thread(_raw_spool_paths, tmp_path)

    token = await _get_token(client)
    archived = await _post_json(
        client,
        "/api/v1/mail/42/archive",
        token,
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "INBOX",
            "freshness": snapshot["freshness_token"],
        },
    )
    assert archived.status == 200
    assert ("archive", ADMIN_ACCOUNT_ID, "INBOX", "42") in gateway.operations
    assert not await asyncio.to_thread(_raw_spool_paths, tmp_path)


@pytest.mark.asyncio
async def test_batch_action_snapshots_are_ordered_bounded_and_issued_together(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    selected = ["46", "42", "45", "43", "44"]
    gateway.spool_gate = asyncio.Event()
    pending = asyncio.create_task(
        _post_json(
            client,
            "/api/v1/admin/mail/action-snapshots",
            await _get_token(client),
            {
                "account": ADMIN_ACCOUNT_ID,
                "mailbox": "INBOX",
                "uids": selected,
            },
        )
    )

    await asyncio.wait_for(gateway.two_spools_started.wait(), timeout=1)
    assert gateway.spool_active == 2
    assert not pending.done()
    store = client.server.app[_FRESHNESS_KEY]
    assert isinstance(store, _FreshnessStore)
    assert not store._entries

    gateway.spool_gate.set()
    response = await pending
    assert response.status == 200
    data = (await response.json())["data"]
    assert data["account"] == ADMIN_ACCOUNT_ID
    assert data["mailbox"] == "INBOX"
    assert [item["uid"] for item in data["freshness"]] == selected
    assert len({item["token"] for item in data["freshness"]}) == len(selected)
    assert gateway.spool_calls == len(selected)
    assert not any(
        operation[0] in {"archive_many", "trash_many", "move_many", "delete_messages"}
        for operation in gateway.operations
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"account": ADMIN_ACCOUNT_ID, "mailbox": "INBOX", "uids": ["42", "42"]},
        {"account": ADMIN_ACCOUNT_ID, "mailbox": "INBOX", "uids": ["\u0661"]},
        {"account": ADMIN_ACCOUNT_ID, "mailbox": "INBOX", "uids": []},
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "INBOX",
            "uids": [str(uid) for uid in range(1, 52)],
        },
        {"account": ADMIN_ACCOUNT_ID, "mailbox": "Unknown", "uids": ["42"]},
    ],
)
async def test_batch_action_snapshots_reject_invalid_selection_before_spooling(
    web_client: tuple[TestClient, FakeGateway],
    payload: dict[str, object],
) -> None:
    client, gateway = web_client
    response = await _post_json(
        client,
        "/api/v1/admin/mail/action-snapshots",
        await _get_token(client),
        payload,
    )

    assert response.status == 400
    assert gateway.spool_calls == 0


@pytest.mark.asyncio
async def test_batch_action_snapshots_require_csrf_and_isolate_personal_accounts(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client

    missing_csrf = await client.post(
        "/api/v1/admin/mail/action-snapshots",
        json={
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "INBOX",
            "uids": ["42"],
        },
        headers={"Origin": _origin(client)},
    )
    assert missing_csrf.status == 403
    assert gateway.spool_calls == 0

    async def ordinary_session(token: str) -> dict[str, object]:
        assert token == ADMIN_SESSION_TOKEN
        return {
            "account_id": DISABLED_ACCOUNT_ID,
            "email": "ordinary@example.test",
            "role": "user",
            "password_change_required": False,
            "enrollment_state": "active",
            "idle_expires_at": 2_000_000_000,
            "absolute_expires_at": 2_000_010_000,
            "step_up_until": 2_000_000_000,
        }

    gateway.session = ordinary_session  # type: ignore[method-assign]
    personal = await _post_json(
        client,
        "/api/v1/me/mail/action-snapshots",
        await _get_token(client),
        {"mailbox": "INBOX", "uids": ["42"]},
    )
    assert personal.status == 200
    personal_data = (await personal.json())["data"]
    assert personal_data["account"] == DISABLED_ACCOUNT_ID
    assert (
        "spool_message",
        DISABLED_ACCOUNT_ID,
        "INBOX",
        "42",
    ) in gateway.operations

    initial_spools = gateway.spool_calls
    override = await _post_json(
        client,
        "/api/v1/me/mail/action-snapshots",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "INBOX",
            "uids": ["43"],
        },
    )
    assert override.status == 400
    assert gateway.spool_calls == initial_spools


@pytest.mark.asyncio
async def test_batch_action_snapshot_failure_issues_no_partial_tokens(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    original_spool = gateway.spool_message

    async def fail_one_snapshot(
        account_id: str,
        mailbox: str,
        message_id: str,
        destination_path: Path,
        *,
        max_bytes: int,
    ) -> int:
        if message_id == "43":
            raise OSError("synthetic spool failure")
        return await original_spool(
            account_id,
            mailbox,
            message_id,
            destination_path,
            max_bytes=max_bytes,
        )

    gateway.spool_message = fail_one_snapshot  # type: ignore[method-assign]
    response = await _post_json(
        client,
        "/api/v1/admin/mail/action-snapshots",
        await _get_token(client),
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "INBOX",
            "uids": ["42", "43", "44"],
        },
    )

    assert response.status == 502
    store = client.server.app[_FRESHNESS_KEY]
    assert isinstance(store, _FreshnessStore)
    assert not store._entries


@pytest.mark.asyncio
async def test_single_uid_and_freshness_are_required_for_destructive_mail_actions(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    context = urlencode({"account": ADMIN_ACCOUNT_ID, "mailbox": "INBOX"})

    for invalid_uid in ("1:*", "1,2", "9" * 100, "\u0661"):
        token = await _get_token(client)
        invalid = await _post_json(
            client,
            f"/api/v1/mail/{invalid_uid}/delete",
            token,
            {
                "account": ADMIN_ACCOUNT_ID,
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
            "account": ADMIN_ACCOUNT_ID,
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
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "INBOX",
            "freshness": changed_detail["freshness_token"],
            "confirmation": "PERMANENTLY DELETE",
        },
    )
    assert deleted.status == 200
    assert ("delete_message", ADMIN_ACCOUNT_ID, "INBOX", "42") in gateway.operations


@pytest.mark.asyncio
async def test_nested_mailbox_name_is_allowed_when_returned_by_maddy(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client

    async def nested_mailboxes(account_id: str) -> list[dict[str, str]]:
        gateway.operations.append(("list_mailboxes", account_id))
        return [{"name": "INBOX"}, {"name": "Projects/2026"}]

    gateway.list_mailboxes = nested_mailboxes  # type: ignore[method-assign]
    context = urlencode({"account": ADMIN_ACCOUNT_ID, "mailbox": "Projects/2026"})
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
    context = urlencode({"account": ADMIN_ACCOUNT_ID, "mailbox": "INBOX"})
    first, first_data = await _api_data(client, f"/api/v1/mail?{context}")
    assert first.status == 200
    next_cursor = str(first_data["next_cursor"])
    assert next_cursor
    assert first_data["previous_cursor"] is None
    next_query = urlencode(
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "INBOX",
            "cursor": next_cursor,
        }
    )
    next_href = f"/api/v1/mail?{next_query}"

    gateway.message_next_offset = None
    second, second_data = await _api_data(client, next_href)
    assert second.status == 200
    assert second_data["previous_cursor"]
    assert ("list_messages", ADMIN_ACCOUNT_ID, "INBOX", 20, 80) in gateway.operations

    previous_query = urlencode(
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "INBOX",
            "cursor": str(second_data["previous_cursor"]),
        }
    )
    previous_href = f"/api/v1/mail?{previous_query}"
    await client.get(previous_href)
    assert ("list_messages", ADMIN_ACCOUNT_ID, "INBOX", 20, 100) in gateway.operations

    tampered = next_href.replace("mailbox=INBOX", "mailbox=Sent")
    assert (await client.get(tampered)).status == 409

    invalid = await client.get(f"/api/v1/mail?{context}&page=1")
    assert invalid.status == 400


@pytest.mark.asyncio
async def test_mailbox_uses_authoritative_continuation_not_page_length(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    context = urlencode({"account": ADMIN_ACCOUNT_ID, "mailbox": "INBOX"})

    gateway.message_initial_offset = 100
    gateway.message_rows = [{"id": "100", "sender": "sender@example.test", "subject": "Truncated"}]
    gateway.message_next_offset = 99
    _response, truncated_data = await _api_data(client, f"/api/v1/mail?{context}")
    continuation_query = urlencode(
        {
            "account": ADMIN_ACCOUNT_ID,
            "mailbox": "INBOX",
            "cursor": str(truncated_data["next_cursor"]),
        }
    )
    continuation = f"/api/v1/mail?{continuation_query}"

    gateway.message_rows = [{"id": "99", "sender": "sender@example.test", "subject": "Continued"}]
    gateway.message_next_offset = None
    _response, continued_data = await _api_data(client, continuation)
    assert continued_data["previous_cursor"]
    assert ("list_messages", ADMIN_ACCOUNT_ID, "INBOX", 20, 99) in gateway.operations

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
    context = urlencode({"account": ADMIN_ACCOUNT_ID, "mailbox": "INBOX"})
    detail, data = await _api_data(client, f"/api/v1/mail/42?{context}")
    assert detail.status == 200
    assert data["preview_too_large"] is True
    assert data["size"] == len(gateway.raw_message)
    assert data["raw_url"].startswith("/api/v1/admin/mail/42/raw?")
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
    context = urlencode({"account": ADMIN_ACCOUNT_ID, "mailbox": "INBOX"})
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
    context = urlencode({"account": ADMIN_ACCOUNT_ID, "mailbox": "INBOX"})
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
    assert data["senders"] == [{"id": ADMIN_ACCOUNT_ID, "address": "admin@example.test"}]
    assert data["max_upload_bytes"] == 4 * 1024 * 1024
    token = await _get_token(client)

    form = FormData()
    form.add_field("sender_account_id", ADMIN_ACCOUNT_ID)
    form.add_field("sender", "admin@example.test")
    form.add_field("sender_name", "Web Console")
    form.add_field("password", FIXTURE_CREDENTIAL)
    form.add_field("to", "recipient@example.test")
    form.add_field("cc", "")
    form.add_field("bcc", "hidden@example.test")
    form.add_field("subject", "Rich text")
    form.add_field("text", "")
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
    assert parsed["From"].addresses[0].display_name == "Web Console"
    assert parsed["From"].addresses[0].addr_spec == "admin@example.test"
    assert parsed.get_body(("plain",)).get_content().strip() == "rich"
    expected_delivery = (
        "deliver",
        "admin@example.test",
        ("recipient@example.test", "hidden@example.test"),
    )
    assert expected_delivery in gateway.operations
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
        "sender_account_id": ADMIN_ACCOUNT_ID,
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
        "sender_account_id": ADMIN_ACCOUNT_ID,
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
        "sender_account_id": ADMIN_ACCOUNT_ID,
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
            "csrf_cookie_name": "maddyweb-csrf",
            "session_cookie_name": "maddyweb-session",
            "secure_cookies": False,
        },
    }
    client = TestClient(
        TestServer(create_app(config, gateway)),
        cookie_jar=CookieJar(unsafe=True),
    )
    await client.start_server()
    client.session.cookie_jar.update_cookies(
        {"maddyweb-session": ADMIN_SESSION_TOKEN},
        response_url=client.make_url("/"),
    )
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
async def test_sender_name_rejects_duplicates_and_enforces_both_size_bounds(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    token = await _get_token(client)
    duplicate = FormData()
    duplicate.add_field("sender_name", "First")
    duplicate.add_field("sender_name", "Second")
    duplicate.add_field("attachments", io.BytesIO(b"x"), filename="x.txt")
    response = await client.post(
        "/api/v1/send",
        data=duplicate,
        headers={"Origin": _origin(client), "X-CSRF-Token": token},
    )
    assert response.status == 400

    token = await _get_token(client)
    byte_oversized = FormData()
    byte_oversized.add_field("sender_name", "x" * 1025)
    byte_oversized.add_field("attachments", io.BytesIO(b"x"), filename="x.txt")
    response = await client.post(
        "/api/v1/send",
        data=byte_oversized,
        headers={"Origin": _origin(client), "X-CSRF-Token": token},
    )
    assert response.status == 413

    token = await _get_token(client)
    character_oversized = FormData()
    for name, value in {
        "sender_account_id": ADMIN_ACCOUNT_ID,
        "sender": "admin@example.test",
        "sender_name": "x" * 257,
        "password": FIXTURE_CREDENTIAL,
        "to": "recipient@example.test",
        "subject": "Sender name bound",
        "html": "<p>body</p>",
    }.items():
        character_oversized.add_field(name, value)
    character_oversized.add_field("attachments", io.BytesIO(b"x"), filename="x.txt")
    response = await client.post(
        "/api/v1/send",
        data=character_oversized,
        headers={"Origin": _origin(client), "X-CSRF-Token": token},
    )
    payload = await response.json()
    assert response.status == 400
    assert payload["error"]["message"] == (
        "Sender name must be 256 characters or fewer and cannot contain control characters."
    )
    assert gateway.delivered is None


@pytest.mark.asyncio
async def test_disabled_sender_is_rejected_server_side(
    web_client: tuple[TestClient, FakeGateway],
) -> None:
    client, gateway = web_client
    token = await _get_token(client)
    form = FormData()
    for name, value in {
        "sender_account_id": DISABLED_ACCOUNT_ID,
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
