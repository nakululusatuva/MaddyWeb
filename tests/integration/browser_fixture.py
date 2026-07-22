"""Loopback-only browser security fixture; never included in production."""

from __future__ import annotations

import asyncio
import os
from email import policy
from email.message import EmailMessage
from pathlib import Path

from aiohttp import web

from maddyweb.web import MessagePage, create_app


class BrowserGateway:
    def __init__(self) -> None:
        message = EmailMessage()
        message["From"] = "attacker@example.test"
        message["To"] = "admin@example.test"
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

    async def list_accounts(self) -> list[dict[str, object]]:
        return [
            {
                "id": "admin@example.test",
                "address": "admin@example.test",
                "has_credentials": True,
                "has_mailbox": True,
            }
        ]

    async def list_mailboxes(self, _account: str) -> list[dict[str, object]]:
        return [
            {"name": "INBOX", "attributes": []},
            {"name": "Custom Trash", "attributes": ["\\Trash"]},
            {"name": "Custom Sent", "attributes": ["\\Sent"]},
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

    async def delete_message_permanently(self, *_args: object) -> None:
        return None


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
            "cookie_name": "__Host-maddyweb",
            "secure_cookies": True,
        },
    }
    web.run_app(
        create_app(config, BrowserGateway()),  # type: ignore[arg-type]
        host="127.0.0.1",
        port=8790,
        access_log=None,
        print=None,
    )


if __name__ == "__main__":
    main()
