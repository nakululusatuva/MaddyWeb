"""Live loopback fixtures for Chromium SPA and security tests."""

from __future__ import annotations

import asyncio
import os
import secrets
import socket
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from aiohttp import web

from maddyweb.web import MessagePage, create_app

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    from maddyweb.mail import PreparedMessage


ACCOUNT = "admin@example.test"
NEW_ACCOUNT = "new-user@example.test"
MAILBOX = "INBOX"
TRASH_MAILBOX = "Custom Trash"
MESSAGE_ID = "42"
CERTIFICATE_NAME = "mx.example.test"
CERTIFICATE_FINGERPRINT = ":".join(f"{value:02X}" for value in range(32))
COOKIE_NAME = "__Host-maddyweb-browser-csrf"


class BrowserSecurityGateway:
    """Mutable observable gateway with no external services or sockets."""

    def __init__(self) -> None:
        message = EmailMessage()
        message["From"] = "attacker@example.test"
        message["To"] = ACCOUNT
        message["Subject"] = "Browser security fixture"
        message.set_content("plain fallback")
        message.add_alternative(
            '<script>document.body.dataset.xss="executed"</script>'
            '<img id="remote-image" src="https://tracker.invalid/pixel">'
            '<img id="data-image" src="data:image/png;base64,iVBORw0KGgo=">'
            '<img id="inline-image" src="cid:logo">'
            '<b id="safe-content">Safe body</b>',
            subtype="html",
        )
        html_part = message.get_payload()[-1]
        assert isinstance(html_part, EmailMessage)
        html_part.add_related(
            b"\x89PNG\r\n\x1a\nfixture",
            maintype="image",
            subtype="png",
            cid="<logo>",
            filename="logo.png",
            disposition="inline",
        )
        message.add_attachment(
            b"attachment",
            maintype="text",
            subtype="html",
            filename="../../evil.html",
        )
        self.raw = message.as_bytes(policy=policy.SMTP)
        self.accounts: list[dict[str, object]] = [
            {
                "id": ACCOUNT,
                "address": ACCOUNT,
                "has_credentials": True,
                "has_mailbox": True,
                "append_limit": 1_048_576,
            }
        ]
        self.created_accounts: list[tuple[str, str]] = []
        self.password_changes: list[tuple[str, str]] = []
        self.append_limit_changes: list[tuple[str, int]] = []
        self.disabled_accounts: list[str] = []
        self.deleted_accounts: list[str] = []
        self.message_location: str | None = MAILBOX
        self.trash_moves: list[tuple[str, str, str]] = []
        self.permanent_deletions: list[tuple[str, str, str]] = []
        self.delivery_started = asyncio.Event()
        self.delivery_release = asyncio.Event()
        self.delivery_release.set()
        self.deliveries: list[dict[str, object]] = []
        self.sent_saves = 0
        self.timer_enabled = True
        self.timer_changes: list[bool] = []
        self.certificate_dry_runs: list[str] = []
        self.certificate_renewals: list[str] = []

    def _account(self, account_id: str) -> dict[str, object]:
        return next(item for item in self.accounts if item["id"] == account_id)

    async def health(self) -> dict[str, object]:
        return {
            "status": "ok",
            "version": "0.1.0",
            "maddy_version": "0.9.5",
            "maddy_write_enabled": True,
            "storage_available": True,
            "certbot_available": True,
            "certificate_management_enabled": True,
        }

    async def list_accounts(self) -> list[dict[str, object]]:
        return [dict(account) for account in self.accounts]

    async def create_account(self, username: str, password: str) -> None:
        self.created_accounts.append((username, password))
        self.accounts.append(
            {
                "id": username,
                "address": username,
                "has_credentials": True,
                "has_mailbox": True,
                "append_limit": None,
            }
        )

    async def change_password(self, account_id: str, password: str) -> None:
        self._account(account_id)
        self.password_changes.append((account_id, password))

    async def set_append_limit(self, account_id: str, limit: int) -> None:
        self._account(account_id)["append_limit"] = limit
        self.append_limit_changes.append((account_id, limit))

    async def disable_credentials(self, account_id: str) -> None:
        self._account(account_id)["has_credentials"] = False
        self.disabled_accounts.append(account_id)

    async def delete_mailbox(self, account_id: str) -> None:
        self._account(account_id)
        self.accounts = [item for item in self.accounts if item["id"] != account_id]
        self.deleted_accounts.append(account_id)

    async def list_mailboxes(self, _account: str) -> list[dict[str, object]]:
        return [
            {"name": MAILBOX, "attributes": []},
            {"name": TRASH_MAILBOX, "attributes": ["\\Trash"]},
        ]

    async def list_messages(self, _account: str, mailbox: str, **_kwargs: object) -> MessagePage:
        items: list[dict[str, object]] = []
        if self.message_location == mailbox:
            items.append(
                {
                    "id": MESSAGE_ID,
                    "sender": "attacker@example.test",
                    "subject": (
                        '<img src=x onerror="document.body.dataset.listXss=1">'
                        "Security fixture"
                    ),
                    "date": "2026-07-23 12:00 UTC",
                    "unread": True,
                }
            )
        return MessagePage(items, False)

    async def spool_message(
        self,
        _account: str,
        _mailbox: str,
        _uid: str,
        destination: Path,
        *,
        max_bytes: int,
    ) -> int:
        if len(self.raw) > max_bytes:
            raise ValueError("fixture exceeds limit")
        await asyncio.to_thread(destination.write_bytes, self.raw)
        await asyncio.to_thread(os.chmod, destination, 0o600)
        return len(self.raw)

    async def move_message_to_trash(
        self,
        account: str,
        mailbox: str,
        message_id: str,
    ) -> str:
        self.trash_moves.append((account, mailbox, message_id))
        self.message_location = TRASH_MAILBOX
        return TRASH_MAILBOX

    async def delete_message_permanently(
        self,
        account: str,
        mailbox: str,
        message_id: str,
    ) -> None:
        self.permanent_deletions.append((account, mailbox, message_id))
        self.message_location = None

    async def deliver_message(
        self,
        message: PreparedMessage,
        envelope_from: str,
        recipients: Sequence[str],
        submission_password: str,
    ) -> str:
        self.delivery_started.set()
        await self.delivery_release.wait()
        self.deliveries.append(
            {
                "envelope_from": envelope_from,
                "recipients": tuple(recipients),
                "password": submission_password,
                "raw": await asyncio.to_thread(message.path.read_bytes),
            }
        )
        return "browser-fixture-delivery"

    async def save_sent(self, _message: PreparedMessage) -> None:
        self.sent_saves += 1

    async def certificate_status(self) -> dict[str, object]:
        return {
            "timer_enabled": self.timer_enabled,
            "timer_active": self.timer_enabled,
            "timer_state": "Enabled" if self.timer_enabled else "Disabled",
            "timer_enable_safe": True,
            "certificates": [
                {
                    "name": CERTIFICATE_NAME,
                    "expires": "2026-10-21T00:00:00Z",
                    "source_fingerprint": CERTIFICATE_FINGERPRINT,
                    "deployed_fingerprint": CERTIFICATE_FINGERPRINT,
                    "fingerprints_match": True,
                    "automation_safe": True,
                }
            ],
        }

    async def set_certificate_timer(self, enabled: bool) -> None:
        self.timer_enabled = enabled
        self.timer_changes.append(enabled)

    async def certificate_dry_run(self, certificate_name: str) -> None:
        self.certificate_dry_runs.append(certificate_name)

    async def renew_certificate_if_due(self, certificate_name: str) -> None:
        self.certificate_renewals.append(certificate_name)


@dataclass(frozen=True, slots=True)
class LiveApplication:
    base_url: str
    port: int
    gateway: BrowserSecurityGateway


def _listening_socket() -> tuple[socket.socket, int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(socket.SOMAXCONN)
    listener.setblocking(False)
    return listener, int(listener.getsockname()[1])


@pytest.fixture
async def live_application(tmp_path: Path) -> AsyncIterator[LiveApplication]:
    gateway = BrowserSecurityGateway()
    app = create_app(  # type: ignore[arg-type]
        {
            "server": {
                "allowed_hosts": ("127.0.0.1",),
                "concurrency": 4,
                "max_upload_bytes": 4 * 1024 * 1024,
                "request_body_timeout_seconds": 5,
                "page_size": 20,
                "temp_dir": tmp_path,
            },
            "security": {
                "session_signing_key": secrets.token_bytes(32),
                "csrf_ttl_seconds": 300,
                "cookie_name": COOKIE_NAME,
                "secure_cookies": True,
            },
        },
        gateway,
    )
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    listener, port = _listening_socket()
    site = web.SockSite(runner, listener)
    await site.start()
    try:
        yield LiveApplication(f"http://127.0.0.1:{port}", port, gateway)
    finally:
        await runner.cleanup()


@pytest.fixture
async def attacker_url(live_application: LiveApplication) -> AsyncIterator[str]:
    async def attack_page(_request: web.Request) -> web.Response:
        return web.Response(
            text=(
                '<!doctype html><html><body><form id="cross-origin" method="post" action="'
                f'{live_application.base_url}/api/v1/mail/{MESSAGE_ID}/delete">'
                f'<input name="account" value="{ACCOUNT}">'
                f'<input name="mailbox" value="{MAILBOX}">'
                '<input name="confirmation" value="PERMANENTLY DELETE">'
                '<button type="submit">attack</button></form></body></html>'
            ),
            content_type="text/html",
        )

    app = web.Application()
    app.router.add_get("/", attack_page)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    listener, port = _listening_socket()
    site = web.SockSite(runner, listener)
    await site.start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        await runner.cleanup()
