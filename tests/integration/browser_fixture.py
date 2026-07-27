"""Loopback-only browser security fixture; never included in production."""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path

from aiohttp import web

from maddyweb.web import MessagePage, create_app

ACCOUNT_ID = "a" * 32
ACCOUNT_ADDRESS = "admin@example.test"
SESSION_COOKIE_NAME = "__Host-maddyweb-browser-session"
SESSION_TOKEN = "S" * 43


class BrowserGateway:
    def __init__(self) -> None:
        definitions = (
            (
                "105",
                "MaddyWeb Operations <operations@example.test>",
                "Welcome to your private mail workspace",
                "2026-07-27T08:25:00+00:00",
                False,
                (
                    "<h2>Your private mail workspace is ready</h2>"
                    "<p>MaddyWeb keeps mailbox access and administration behind one "
                    "authenticated interface.</p>"
                    "<ul><li>Read, reply, forward, archive, and organize mail.</li>"
                    "<li>Manage accounts and certificates with protected actions.</li>"
                    "<li>Keep the application isolated on its loopback listener.</li></ul>"
                ),
            ),
            (
                "104",
                "TLS Automation <certificates@example.test>",
                "Certificate renewal completed",
                "2026-07-27T07:40:00+00:00",
                False,
                "<p>The scheduled certificate renewal check completed successfully.</p>",
            ),
            (
                "103",
                "Postmaster <postmaster@example.test>",
                "Weekly delivery summary",
                "2026-07-26T18:30:00+00:00",
                False,
                "<p>Your weekly delivery summary is ready for review.</p>",
            ),
            (
                "102",
                "Alex Morgan <alex@example.test>",
                "Re: Migration checklist",
                "2026-07-26T14:05:00+00:00",
                True,
                "<p>The mailbox migration checklist is complete.</p>",
            ),
            (
                "101",
                "Security Bot <security@example.test>",
                "Account security review",
                "2026-07-25T21:18:00+00:00",
                False,
                "<p>No account security issues were detected during the review.</p>",
            ),
        )
        self.messages: list[dict[str, object]] = []
        self.raw_by_uid: dict[str, bytes] = {}
        for uid, sender, subject, date, unread, html in definitions:
            message = EmailMessage()
            message["From"] = sender
            message["To"] = ACCOUNT_ADDRESS
            message["Subject"] = subject
            message["Date"] = formatdate(
                datetime.fromisoformat(date).timestamp(),
                localtime=False,
                usegmt=True,
            )
            message.set_content("Open the HTML view to read this fixture message.")
            message.add_alternative(html, subtype="html")
            self.raw_by_uid[uid] = message.as_bytes(policy=policy.SMTP)
            self.messages.append(
                {
                    "id": uid,
                    "sender": sender,
                    "subject": subject,
                    "date": date,
                    "unread": unread,
                }
            )

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

    async def session(self, token: str) -> dict[str, object]:
        if token != SESSION_TOKEN:
            raise RuntimeError("invalid browser fixture session")
        now = int(time.time())
        return {
            "account_id": ACCOUNT_ID,
            "email": ACCOUNT_ADDRESS,
            "role": "admin",
            "password_change_required": False,
            "enrollment_state": "active",
            "idle_expires_at": now + 30 * 60,
            "absolute_expires_at": now + 12 * 60 * 60,
            "recovery_codes_remaining": 10,
        }

    async def list_accounts(self) -> list[dict[str, object]]:
        return [
            {
                "id": ACCOUNT_ID,
                "address": ACCOUNT_ADDRESS,
                "has_credentials": True,
                "has_mailbox": True,
            }
        ]

    async def list_mailboxes(self, _account: str) -> list[dict[str, object]]:
        return [
            {"name": "INBOX", "attributes": []},
            {"name": "Archive", "attributes": ["\\Archive"]},
            {"name": "Sent", "attributes": ["\\Sent"]},
            {"name": "Trash", "attributes": ["\\Trash"]},
        ]

    async def list_messages(
        self,
        _account: str,
        mailbox: str,
        **_kwargs: object,
    ) -> MessagePage:
        return MessagePage(self.messages if mailbox == "INBOX" else [], False)

    async def spool_message(
        self,
        _account: str,
        _mailbox: str,
        uid: str,
        destination: Path,
        *,
        max_bytes: int,
    ) -> int:
        raw = self.raw_by_uid.get(str(uid))
        if raw is None:
            raise ValueError("unknown fixture message")
        if len(raw) > max_bytes:
            raise ValueError("fixture exceeds limit")
        await asyncio.to_thread(destination.write_bytes, raw)
        await asyncio.to_thread(os.chmod, destination, 0o600)
        return len(raw)

    async def move_message_to_trash(self, *_args: object) -> str:
        return "Custom Trash"

    async def move_message_to_archive(self, *_args: object) -> str:
        return "Custom Archive"

    async def set_messages_seen(self, *_args: object, **_kwargs: object) -> None:
        return None

    async def move_messages_to_trash(self, *_args: object) -> str:
        return "Custom Trash"

    async def move_messages_to_archive(self, *_args: object) -> str:
        return "Custom Archive"

    async def delete_message_permanently(self, *_args: object) -> None:
        return None


@web.middleware
async def _fixture_session_cookie(
    request: web.Request,
    handler: web.RequestHandler,
) -> web.StreamResponse:
    """Add the fixture session before production authentication middleware."""

    if SESSION_COOKIE_NAME in request.cookies:
        return await handler(request)
    headers = request.headers.copy()
    existing = headers.get("Cookie", "")
    injected = f"{SESSION_COOKIE_NAME}={SESSION_TOKEN}"
    headers["Cookie"] = f"{existing}; {injected}" if existing else injected
    return await handler(request.clone(headers=headers))


def main() -> None:
    temp_dir = Path("/tmp/maddyweb-browser-fixture")  # noqa: S108
    temp_dir.mkdir(mode=0o700, exist_ok=True)
    config = {
        "server": {
            "allowed_hosts": ("127.0.0.1", "localhost"),
            "concurrency": 4,
            "max_upload_bytes": 4 * 1024 * 1024,
            "request_body_timeout_seconds": 5,
            "page_size": 20,
            "temp_dir": temp_dir,
        },
        "security": {
            "session_signing_key": b"browser-fixture-process-key-0001",
            "csrf_ttl_seconds": 300,
            "csrf_cookie_name": "__Host-maddyweb-browser-csrf",
            "session_cookie_name": SESSION_COOKIE_NAME,
            "secure_cookies": True,
            "login_domain": "example.test",
        },
    }
    app = create_app(config, BrowserGateway())  # type: ignore[arg-type]
    app.middlewares.insert(0, _fixture_session_cookie)
    web.run_app(
        app,
        host="127.0.0.1",
        port=8790,
        access_log=None,
        print=None,
    )


if __name__ == "__main__":
    main()
