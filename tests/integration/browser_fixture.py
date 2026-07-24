"""Loopback-only browser security fixture; never included in production."""

from __future__ import annotations

import asyncio
import os
from email import policy
from email.message import EmailMessage
from pathlib import Path

from aiohttp import web

from maddyweb.web import MessagePage, create_app

ACCOUNT_ID = "a" * 32
ACCOUNT_ADDRESS = "admin@example.test"
SESSION_COOKIE_NAME = "__Host-maddyweb-browser-session"
SESSION_TOKEN = "S" * 43


class BrowserGateway:
    def __init__(self) -> None:
        message = EmailMessage()
        message["From"] = "attacker@example.test"
        message["To"] = ACCOUNT_ADDRESS
        message["Subject"] = "Browser security fixture"
        message.set_content("plain fallback")
        message.add_alternative(
            '<script>document.body.dataset.xss="executed"</script>'
            '<img id="remote" src="https://tracker.invalid/pixel">'
            '<img id="inline" src="cid:logo"><b id="safe">Safe body</b>',
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
        return {
            "account_id": ACCOUNT_ID,
            "email": ACCOUNT_ADDRESS,
            "role": "admin",
            "password_change_required": False,
            "enrollment_state": "active",
            "idle_expires_at": 2_000_000_000,
            "absolute_expires_at": 2_000_010_000,
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
            {"name": "Custom Trash", "attributes": ["\\Trash"]},
            {"name": "Custom Sent", "attributes": ["\\Sent"]},
            {"name": "Custom Archive", "attributes": ["\\Archive"]},
        ]

    async def list_messages(self, *_args: object, **_kwargs: object) -> MessagePage:
        return MessagePage(
            [{"id": "42", "sender": "attacker@example.test", "subject": "Security fixture"}],
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

    async def move_message_to_trash(self, *_args: object) -> str:
        return "Custom Trash"

    async def move_message_to_archive(self, *_args: object) -> str:
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
