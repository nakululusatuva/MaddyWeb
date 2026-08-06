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
        self.passkeys: list[dict[str, object]] = []
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
        self.message_mailboxes: dict[str, str] = {}
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
            self.message_mailboxes[uid] = "INBOX"
            self.messages.append(
                {
                    "id": uid,
                    "sender": sender,
                    "subject": subject,
                    "date": date,
                    "unread": unread,
                }
            )
        self.mailboxes: list[dict[str, object]] = [
            {"name": "INBOX", "attributes": []},
            {"name": "Archive", "attributes": ["\\Archive"]},
            {"name": "Sent", "attributes": ["\\Sent"]},
            {"name": "Trash", "attributes": ["\\Trash"]},
            {"name": "Projects", "attributes": []},
        ]

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
            "session_id": "d" * 32,
            "step_up_until": now + 5 * 60,
            "idle_expires_at": now + 72 * 60 * 60,
            "absolute_expires_at": now + 30 * 24 * 60 * 60,
            "recovery_codes_remaining": 10,
        }

    async def peek_session(self, token: str) -> dict[str, object]:
        return await self.session(token)

    async def list_passkeys(self) -> dict[str, object]:
        return {"passkeys": [dict(item) for item in self.passkeys]}

    async def list_sessions(self) -> dict[str, object]:
        now = int(time.time())
        return {
            "sessions": [
                {
                    "id": "d" * 32,
                    "current": True,
                    "client_ip": "127.0.0.1",
                    "user_agent": "Chromium fixture",
                    "created_at": now - 60,
                    "last_seen_at": now,
                    "idle_expires_at": now + 72 * 60 * 60,
                    "absolute_expires_at": now + 30 * 24 * 60 * 60,
                }
            ]
        }

    async def revoke_session(self, session_id: str) -> dict[str, object]:
        assert session_id != "d" * 32
        return {"revoked": True}

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
        return [dict(mailbox) for mailbox in self.mailboxes]

    async def rename_mailbox(
        self,
        _account: str,
        old_name: str,
        new_name: str,
    ) -> None:
        mailbox = next(
            (item for item in self.mailboxes if item["name"] == old_name),
            None,
        )
        if mailbox is None:
            raise ValueError("unknown fixture mailbox")
        if any(
            str(item["name"]).casefold() == new_name.casefold()
            for item in self.mailboxes
            if item is not mailbox
        ):
            raise ValueError("fixture mailbox already exists")
        mailbox["name"] = new_name
        for uid, location in tuple(self.message_mailboxes.items()):
            if location == old_name:
                self.message_mailboxes[uid] = new_name

    async def delete_named_mailbox(
        self,
        _account: str,
        mailbox: str,
        *,
        disposition: str,
        target_mailbox: str | None = None,
    ) -> str:
        target = target_mailbox if disposition == "move" else "Trash"
        if target is None:
            raise ValueError("fixture deletion target is required")
        if not any(item["name"] == mailbox for item in self.mailboxes):
            raise ValueError("unknown fixture mailbox")
        self.mailboxes = [item for item in self.mailboxes if item["name"] != mailbox]
        for uid, location in tuple(self.message_mailboxes.items()):
            if location == mailbox:
                self.message_mailboxes[uid] = target
        return target

    async def list_messages(
        self,
        _account: str,
        mailbox: str,
        **_kwargs: object,
    ) -> MessagePage:
        items = [
            message
            for message in self.messages
            if self.message_mailboxes.get(str(message["id"])) == mailbox
        ]
        return MessagePage(items, False)

    async def latest_message_uid(self, _account: str, mailbox: str) -> int:
        uids = [
            int(str(message["id"]))
            for message in self.messages
            if self.message_mailboxes.get(str(message["id"])) == mailbox
        ]
        if not uids:
            return 0
        return max(uids)

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

    def _move_messages(self, mailbox: str, message_ids: tuple[str, ...], target: str) -> None:
        for message_id in message_ids:
            if self.message_mailboxes.get(message_id) != mailbox:
                raise ValueError("unknown fixture message location")
        for message_id in message_ids:
            self.message_mailboxes[message_id] = target

    async def move_message_to_trash(
        self,
        _account: str,
        mailbox: str,
        message_id: str,
    ) -> str:
        self._move_messages(mailbox, (message_id,), "Trash")
        return "Trash"

    async def move_message_to_archive(
        self,
        _account: str,
        mailbox: str,
        message_id: str,
    ) -> str:
        self._move_messages(mailbox, (message_id,), "Archive")
        return "Archive"

    async def move_message(
        self,
        _account: str,
        mailbox: str,
        message_id: str,
        target: str,
    ) -> str:
        self._move_messages(mailbox, (message_id,), target)
        return target

    async def set_messages_seen(
        self,
        _account: str,
        mailbox: str,
        message_ids: tuple[str, ...] | None,
        *,
        seen: bool,
    ) -> None:
        selected = (
            {
                str(message["id"])
                for message in self.messages
                if self.message_mailboxes.get(str(message["id"])) == mailbox
            }
            if message_ids is None
            else set(message_ids)
        )
        if any(self.message_mailboxes.get(message_id) != mailbox for message_id in selected):
            raise ValueError("unknown fixture message location")
        for message in self.messages:
            if str(message["id"]) in selected:
                message["unread"] = not seen

    async def set_message_seen(
        self,
        _account: str,
        mailbox: str,
        message_id: str,
        *,
        seen: bool,
    ) -> None:
        if self.message_mailboxes.get(message_id) != mailbox:
            raise ValueError("unknown fixture message location")
        message = next(
            (item for item in self.messages if str(item["id"]) == message_id),
            None,
        )
        if message is None:
            raise ValueError("unknown fixture message")
        message["unread"] = not seen

    async def move_messages_to_trash(
        self,
        _account: str,
        mailbox: str,
        message_ids: tuple[str, ...],
    ) -> str:
        self._move_messages(mailbox, message_ids, "Trash")
        return "Trash"

    async def move_messages_to_archive(
        self,
        _account: str,
        mailbox: str,
        message_ids: tuple[str, ...],
    ) -> str:
        self._move_messages(mailbox, message_ids, "Archive")
        return "Archive"

    async def move_messages(
        self,
        _account: str,
        mailbox: str,
        message_ids: tuple[str, ...],
        target: str,
    ) -> str:
        self._move_messages(mailbox, message_ids, target)
        return target

    async def delete_message_permanently(
        self,
        _account: str,
        mailbox: str,
        message_id: str,
    ) -> None:
        if self.message_mailboxes.get(message_id) != mailbox:
            raise ValueError("unknown fixture message location")
        self.message_mailboxes.pop(message_id)

    async def delete_messages_permanently(
        self,
        _account: str,
        mailbox: str,
        message_ids: tuple[str, ...],
    ) -> None:
        for message_id in message_ids:
            if self.message_mailboxes.get(message_id) != mailbox:
                raise ValueError("unknown fixture message location")
        for message_id in message_ids:
            self.message_mailboxes.pop(message_id)


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
