"""Loopback-only fake backend used to measure real Web rendering in CI/WSL."""

from __future__ import annotations

import asyncio
import os
import secrets
from email import policy
from email.message import EmailMessage
from pathlib import Path

from aiohttp import web

import maddyweb.cli  # noqa: F401 - mirror production entry-point import cost
from maddyweb.web import MessagePage, create_app


class PerformanceGateway:
    def __init__(self) -> None:
        message = EmailMessage()
        message["From"] = "sender@example.test"
        message["To"] = "user@example.test"
        message["Subject"] = "Performance fixture"
        message.set_content("plain fallback")
        message.add_alternative("<p>Safe HTML body.</p>", subtype="html")
        self.raw_message = message.as_bytes(policy=policy.SMTP)

    async def health(self) -> dict[str, object]:
        return {
            "status": "ok",
            "version": "0.1.0",
            "maddy_version": "0.9.5",
            "maddy_write_enabled": True,
            "storage_available": True,
            "certbot_available": False,
            "certificate_management_enabled": False,
        }

    async def list_accounts(self) -> list[dict[str, object]]:
        return [
            {
                "id": f"user{index:02d}@example.test",
                "address": f"user{index:02d}@example.test",
                "has_credentials": True,
                "has_mailbox": True,
            }
            for index in range(50)
        ]

    async def list_mailboxes(self, _account: str) -> list[dict[str, object]]:
        return [
            {"name": "INBOX", "attributes": []},
            {"name": "Sent", "attributes": ["\\Sent"]},
            {"name": "Trash", "attributes": ["\\Trash"]},
        ]

    async def list_messages(self, *_args: object, **_kwargs: object) -> MessagePage:
        return MessagePage(
            [
                {
                    "id": str(index),
                    "sender": f"sender{index:02d}@example.test",
                    "subject": f"Performance message {index:02d}",
                    "date": "2026-07-22 12:00:00 +0000",
                }
                for index in range(50, 0, -1)
            ],
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
        if len(self.raw_message) > max_bytes:
            raise ValueError("performance fixture exceeds the message limit")
        await asyncio.to_thread(destination.write_bytes, self.raw_message)
        await asyncio.to_thread(os.chmod, destination, 0o600)
        return len(self.raw_message)


def main() -> None:
    temp_dir = Path("/tmp/maddyweb-performance-fixture")  # noqa: S108
    temp_dir.mkdir(mode=0o700, exist_ok=True)
    config = {
        "session_signing_key": secrets.token_bytes(48),
        "server": {
            "allowed_hosts": ("127.0.0.1",),
            "concurrency": 8,
            "max_upload_bytes": 20 * 1024 * 1024,
            "page_size": 50,
            "temp_dir": temp_dir,
        },
        "security": {
            "csrf_ttl_seconds": 900,
            "cookie_name": "__Host-maddyweb",
            "secure_cookies": True,
        },
    }
    web.run_app(
        create_app(config, PerformanceGateway()),  # type: ignore[arg-type]
        host="127.0.0.1",
        port=8787,
        backlog=16,
        keepalive_timeout=5.0,
        access_log=None,
        print=None,
        reuse_port=False,
    )


if __name__ == "__main__":
    main()
