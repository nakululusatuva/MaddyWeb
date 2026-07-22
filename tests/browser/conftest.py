"""Live loopback fixtures for Chromium security tests."""

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
    from collections.abc import AsyncIterator


ACCOUNT = "admin@example.test"
MAILBOX = "INBOX"
MESSAGE_ID = "42"
COOKIE_NAME = "__Host-maddyweb-browser-csrf"


class BrowserSecurityGateway:
    """Small observable gateway; no external services or sockets are used."""

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
        self.permanent_deletions: list[tuple[str, str, str]] = []

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
        return [
            {
                "id": ACCOUNT,
                "address": ACCOUNT,
                "has_credentials": True,
                "has_mailbox": True,
            }
        ]

    async def list_mailboxes(self, _account: str) -> list[dict[str, object]]:
        return [
            {"name": MAILBOX, "attributes": []},
            {"name": "Custom Trash", "attributes": ["\\Trash"]},
        ]

    async def list_messages(self, *_args: object, **_kwargs: object) -> MessagePage:
        return MessagePage(
            [{"id": MESSAGE_ID, "sender": "attacker@example.test", "subject": "Security fixture"}],
            False,
        )

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

    async def delete_message_permanently(
        self,
        account: str,
        mailbox: str,
        message_id: str,
    ) -> None:
        self.permanent_deletions.append((account, mailbox, message_id))


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
                f'{live_application.base_url}/mail/{MESSAGE_ID}/delete">'
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
