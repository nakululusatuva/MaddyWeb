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

from maddyweb.gateway import HelperCallError
from maddyweb.web import MessagePage, create_app

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    from maddyweb.mail import PreparedMessage


ACCOUNT = "a" * 32
ACCOUNT_ADDRESS = "admin@example.test"
NORMAL_ACCOUNT = "c" * 32
NORMAL_ACCOUNT_ADDRESS = "tornado@custom.example.test"
NEW_ACCOUNT = "new-user@example.test"
NEW_ACCOUNT_ID = "b" * 32
MAILBOX = "INBOX"
SENT_MAILBOX = "Sent"
TRASH_MAILBOX = "Custom Trash"
ARCHIVE_MAILBOX = "Custom Archive"
MESSAGE_ID = "42"
CERTIFICATE_NAME = "mx.example.test"
CERTIFICATE_FINGERPRINT = ":".join(f"{value:02X}" for value in range(32))
COOKIE_NAME = "__Host-maddyweb-browser-csrf"
SESSION_COOKIE_NAME = "maddyweb-browser-session"
SESSION_TOKEN = "S" * 43
LOGIN_CHALLENGE = "C" * 43
LOGIN_PASSWORD = "fixture-mail-password"  # noqa: S105 - synthetic browser fixture
LOGIN_TOTP = "123456"
VALID_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010804000000"
    "b51c0c020000000b4944415478da6364f80f00010501012718e3660000"
    "000049454e44ae426082"
)


class BrowserSecurityGateway:
    """Mutable observable gateway with no external services or sockets."""

    def __init__(self) -> None:
        message = EmailMessage()
        message["From"] = "attacker@example.test"
        message["To"] = ACCOUNT_ADDRESS
        message["Subject"] = "Browser security fixture"
        message.set_content("plain fallback")
        message.add_alternative(
            '<script>document.body.dataset.xss="executed"</script>'
            '<meta http-equiv="refresh" content="0;url=https://meta.invalid/">'
            '<style>@import "https://style.invalid/x";</style>'
            '<form action="https://form.invalid/"><input autofocus name="token"></form>'
            "<svg><foreignObject><script>window.top.svgXss=true</script></foreignObject></svg>"
            '<math><annotation-xml encoding="text/html"><script>window.top.mathXss=true'
            "</script></annotation-xml></math>"
            '<iframe src="https://frame.invalid/"></iframe>'
            '<object data="https://object.invalid/x"></object>'
            '<embed src="https://embed.invalid/x">'
            '<img id="remote-image" src="https://tracker.invalid/pixel" '
            'srcset="https://srcset.invalid/pixel 1x" onerror="window.top.imageXss=true">'
            '<img id="data-image" src="data:image/png;base64,iVBORw0KGgo=">'
            '<img id="inline-image" src="cid:logo">'
            '<table width="640" height="120" align="center" bgcolor="#f5f7fa" '
            'border="2" cellpadding="8" cellspacing="0" '
            'style="color:#123456;background-color:#f5f7fa;border:2px solid #345678;'
            'font-family:Arial,sans-serif;font-size:16px;width:640px;min-width:320px;'
            'height:120px;text-align:center;vertical-align:middle;border-collapse:collapse">'
            '<tr><td style="border:1px solid #789abc;padding:8px;text-align:right;'
            'vertical-align:middle">Quarterly summary</td></tr></table>'
            '<div style="position:fixed;color:#112233">Position probe</div>'
            '<div style="background-image:url(https://style.invalid/pixel);color:#445566">'
            "CSS network probe</div>"
            '<span style="width:expression(alert(1));color:#778899">Expression probe</span>'
            '<a id="unsafe-link" href="javascript:window.top.linkXss=true">Unsafe link</a>'
            '<a id="safe-link" href="https://example.test/path" target="_self">Safe link</a>'
            '<b id="safe-content">Safe body</b>',
            subtype="html",
        )
        html_part = message.get_payload()[-1]
        assert isinstance(html_part, EmailMessage)
        html_part.add_related(
            VALID_PNG,
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
                "address": ACCOUNT_ADDRESS,
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
        self.archive_moves: list[tuple[str, str, str]] = []
        self.permanent_deletions: list[tuple[str, str, str]] = []
        self.bulk_permanent_deletions: list[tuple[str, str, tuple[str, ...]]] = []
        self.message_read_started = asyncio.Event()
        self.message_read_release = asyncio.Event()
        self.message_read_release.set()
        self.trash_move_started = asyncio.Event()
        self.trash_move_release = asyncio.Event()
        self.trash_move_release.set()
        self.trash_move_finished = asyncio.Event()
        self.archive_move_started = asyncio.Event()
        self.archive_move_release = asyncio.Event()
        self.archive_move_release.set()
        self.archive_move_finished = asyncio.Event()
        self.delivery_started = asyncio.Event()
        self.delivery_release = asyncio.Event()
        self.delivery_release.set()
        self.deliveries: list[dict[str, object]] = []
        self.sent_saves = 0
        self.timer_enabled = True
        self.timer_changes: list[bool] = []
        self.certificate_dry_runs: list[str] = []
        self.certificate_renewals: list[str] = []
        self.logout_attempts = 0
        self.logout_fails = False
        self.password_login_attempts: list[tuple[str, str, str]] = []
        self.totp_login_attempts: list[tuple[str, str, str]] = []
        self.step_up_attempts: list[tuple[str, str, str]] = []
        self.passkey_login_attempts = 0
        self.passkeys: list[dict[str, object]] = []
        self.revoked_session_ids: list[str] = []
        self.require_create_step_up = False
        self.step_up_granted = False
        self.bulk_seen_changes: list[tuple[str, str, tuple[str, ...] | None, bool]] = []
        self.bulk_moves: list[tuple[str, str, tuple[str, ...], str]] = []
        self.message_unread = True
        self.notification_uid = int(MESSAGE_ID)
        self.notification_checks = 0

        self.principal: dict[str, object] = {
            "account_id": ACCOUNT,
            "email": ACCOUNT_ADDRESS,
            "role": "admin",
            "password_change_required": False,
            "enrollment_state": "active",
            "step_up_until": 2_000_000_300,
            "idle_expires_at": 2_000_000_000,
            "absolute_expires_at": 2_000_010_000,
            "recovery_codes_remaining": 10,
        }

    def _principal(self) -> dict[str, object]:
        return dict(self.principal)

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

    async def session(self, token: str) -> dict[str, object]:
        if token != SESSION_TOKEN:
            raise RuntimeError("invalid browser fixture session")
        return self._principal()

    async def peek_session(self, token: str) -> dict[str, object]:
        return await self.session(token)

    async def begin_password_login(
        self,
        email: str,
        password: str,
        *,
        client_ip: str,
    ) -> dict[str, object]:
        self.password_login_attempts.append((email, password, client_ip))
        if email != ACCOUNT_ADDRESS or password != LOGIN_PASSWORD:
            raise RuntimeError("invalid browser fixture credentials")
        return {"challenge": LOGIN_CHALLENGE, "next": "totp"}

    async def complete_totp_login(
        self,
        challenge: str,
        code: str,
        *,
        client_ip: str,
        user_agent: str,
    ) -> dict[str, object]:
        assert user_agent
        self.totp_login_attempts.append((challenge, code, client_ip))
        if challenge != LOGIN_CHALLENGE or code != LOGIN_TOTP:
            raise RuntimeError("invalid browser fixture second factor")
        return {
            "session_token": SESSION_TOKEN,
            "principal": self._principal(),
            "recovery_codes": [],
        }

    @staticmethod
    def _passkey_options() -> dict[str, object]:
        return {
            "challenge": "Q" * 43,
            "rpId": "127.0.0.1",
            "timeout": 300_000,
            "userVerification": "required",
        }

    async def begin_passkey_login(self, *, client_ip: str) -> dict[str, object]:
        assert client_ip
        self.passkey_login_attempts += 1
        return {"challenge": LOGIN_CHALLENGE, "options": self._passkey_options()}

    async def complete_passkey_login(
        self,
        challenge: str,
        credential: dict[str, object],
        *,
        client_ip: str,
        user_agent: str,
    ) -> dict[str, object]:
        assert challenge == LOGIN_CHALLENGE
        assert credential
        assert client_ip
        assert user_agent
        return {
            "session_token": SESSION_TOKEN,
            "principal": self._principal(),
            "recovery_codes": [],
        }

    async def list_passkeys(self) -> dict[str, object]:
        return {"passkeys": [dict(item) for item in self.passkeys]}

    async def begin_passkey_registration(self) -> dict[str, object]:
        options = self._passkey_options()
        options.update(
            {
                "rp": {"id": "127.0.0.1", "name": "MaddyWeb"},
                "user": {
                    "id": "Y" * 43,
                    "name": ACCOUNT_ADDRESS,
                    "displayName": ACCOUNT_ADDRESS,
                },
                "pubKeyCredParams": [{"alg": -7, "type": "public-key"}],
                "authenticatorSelection": {
                    "residentKey": "required",
                    "requireResidentKey": True,
                    "userVerification": "required",
                },
                "attestation": "none",
            }
        )
        return {"challenge": LOGIN_CHALLENGE, "options": options}

    async def complete_passkey_registration(
        self,
        challenge: str,
        credential: dict[str, object],
        *,
        name: str,
    ) -> dict[str, object]:
        assert challenge == LOGIN_CHALLENGE
        assert credential
        record = {
            "id": "e" * 32,
            "name": name,
            "backed_up": False,
            "created_at": 1_900_000_000,
            "last_used_at": None,
        }
        self.passkeys.append(record)
        return {"passkey": dict(record)}

    async def delete_passkey(self, passkey_id: str) -> dict[str, object]:
        before = len(self.passkeys)
        self.passkeys = [item for item in self.passkeys if item["id"] != passkey_id]
        return {"deleted": len(self.passkeys) != before}

    async def begin_passkey_step_up(self) -> dict[str, object]:
        return {"challenge": LOGIN_CHALLENGE, "options": self._passkey_options()}

    async def complete_passkey_step_up(
        self,
        challenge: str,
        credential: dict[str, object],
    ) -> dict[str, object]:
        assert challenge == LOGIN_CHALLENGE
        assert credential
        self.step_up_granted = True
        return {"step_up_expires_at": 2_000_000_300}

    async def list_sessions(self) -> dict[str, object]:
        return {
            "sessions": [
                {
                    "id": "d" * 32,
                    "current": True,
                    "client_ip": "127.0.0.1",
                    "user_agent": "Chromium fixture",
                    "created_at": 1_900_000_000,
                    "last_seen_at": 1_900_000_100,
                    "idle_expires_at": 2_000_000_000,
                    "absolute_expires_at": 2_000_010_000,
                }
            ]
        }

    async def revoke_session(self, session_id: str) -> dict[str, object]:
        self.revoked_session_ids.append(session_id)
        return {"revoked": True}

    async def logout(self, token: str) -> None:
        assert token == SESSION_TOKEN
        self.logout_attempts += 1
        if self.logout_fails:
            raise RuntimeError("fixture logout failure")

    async def step_up(
        self,
        password: str,
        code: str,
        *,
        client_ip: str,
    ) -> dict[str, object]:
        self.step_up_attempts.append((password, code, client_ip))
        if password != LOGIN_PASSWORD or code != LOGIN_TOTP:
            raise HelperCallError("invalid_second_factor", "invalid fixture verification")
        self.step_up_granted = True
        return {"step_up_expires_at": 2_000_000_300}

    async def list_accounts(self) -> list[dict[str, object]]:
        return [dict(account) for account in self.accounts]

    async def create_account(self, username: str, password: str) -> dict[str, object]:
        if self.require_create_step_up and not self.step_up_granted:
            raise HelperCallError(
                "step_up_required",
                "Fresh administrator authentication is required",
            )
        self.created_accounts.append((username, password))
        self.accounts.append(
            {
                "id": NEW_ACCOUNT_ID,
                "address": username,
                "has_credentials": True,
                "has_mailbox": True,
                "append_limit": None,
            }
        )
        return {
            "id": NEW_ACCOUNT_ID,
            "address": username,
            "role": "user",
            "totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "totp_uri": (
                "otpauth://totp/MaddyWeb%3Anew-user%40example.test?"
                "secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=MaddyWeb"
            ),
            "recovery_codes": ["fixture-recovery-code"],
        }

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
            {"name": SENT_MAILBOX, "attributes": ["\\Sent"]},
            {"name": TRASH_MAILBOX, "attributes": ["\\Trash"]},
            {"name": ARCHIVE_MAILBOX, "attributes": ["\\Archive"]},
        ]

    async def list_messages(self, _account: str, mailbox: str, **_kwargs: object) -> MessagePage:
        items: list[dict[str, object]] = []
        if self.message_location == mailbox:
            items.append(
                {
                    "id": MESSAGE_ID,
                    "sender": "attacker@example.test",
                    "subject": (
                        '<img src=x onerror="document.body.dataset.listXss=1">Security fixture'
                    ),
                    "date": "2026-07-23 12:00 UTC",
                    "unread": self.message_unread,
                }
            )
        return MessagePage(items, False)

    async def latest_message_uid(self, _account: str, _mailbox: str) -> int:
        self.notification_checks += 1
        return self.notification_uid

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
        self.message_read_started.set()
        await self.message_read_release.wait()
        await asyncio.to_thread(destination.write_bytes, self.raw)
        await asyncio.to_thread(os.chmod, destination, 0o600)
        return len(self.raw)

    async def move_message_to_trash(
        self,
        account: str,
        mailbox: str,
        message_id: str,
    ) -> str:
        self.trash_move_started.set()
        await self.trash_move_release.wait()
        self.trash_moves.append((account, mailbox, message_id))
        self.message_location = TRASH_MAILBOX
        self.trash_move_finished.set()
        return TRASH_MAILBOX

    async def move_message_to_archive(
        self,
        account: str,
        mailbox: str,
        message_id: str,
    ) -> str:
        self.archive_move_started.set()
        await self.archive_move_release.wait()
        self.archive_moves.append((account, mailbox, message_id))
        self.message_location = ARCHIVE_MAILBOX
        self.archive_move_finished.set()
        return ARCHIVE_MAILBOX

    async def set_messages_seen(
        self,
        account: str,
        mailbox: str,
        message_ids: Sequence[str] | None,
        *,
        seen: bool,
    ) -> None:
        selected = None if message_ids is None else tuple(message_ids)
        self.bulk_seen_changes.append((account, mailbox, selected, seen))
        self.message_unread = not seen

    async def move_messages_to_trash(
        self,
        account: str,
        mailbox: str,
        message_ids: Sequence[str],
    ) -> str:
        self.trash_move_started.set()
        await self.trash_move_release.wait()
        self.bulk_moves.append((account, mailbox, tuple(message_ids), TRASH_MAILBOX))
        self.message_location = TRASH_MAILBOX
        self.trash_move_finished.set()
        return TRASH_MAILBOX

    async def move_messages_to_archive(
        self,
        account: str,
        mailbox: str,
        message_ids: Sequence[str],
    ) -> str:
        self.archive_move_started.set()
        await self.archive_move_release.wait()
        self.bulk_moves.append((account, mailbox, tuple(message_ids), ARCHIVE_MAILBOX))
        self.message_location = ARCHIVE_MAILBOX
        self.archive_move_finished.set()
        return ARCHIVE_MAILBOX

    async def delete_message_permanently(
        self,
        account: str,
        mailbox: str,
        message_id: str,
    ) -> None:
        self.permanent_deletions.append((account, mailbox, message_id))
        self.message_location = None

    async def delete_messages_permanently(
        self,
        account: str,
        mailbox: str,
        message_ids: Sequence[str],
    ) -> None:
        self.bulk_permanent_deletions.append((account, mailbox, tuple(message_ids)))
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
                "mail_event_poll_seconds": 0.25,
            },
            "security": {
                "session_signing_key": secrets.token_bytes(32),
                "csrf_ttl_seconds": 300,
                "csrf_cookie_name": COOKIE_NAME,
                "session_cookie_name": SESSION_COOKIE_NAME,
                "secure_cookies": True,
                "login_domain": "example.test",
            },
        },
        gateway,
    )
    runner = web.AppRunner(app, access_log=None, shutdown_timeout=0.25)
    await runner.setup()
    listener, port = _listening_socket()
    site = web.SockSite(runner, listener)
    await site.start()
    try:
        yield LiveApplication(f"http://127.0.0.1:{port}", port, gateway)
    finally:
        await runner.cleanup()


@pytest.fixture(autouse=True)
async def authenticated_browser_page(
    page: object,
    live_application: LiveApplication,
) -> None:
    """Install the fixture session before a real browser test starts."""

    await page.context.add_cookies(
        [
            {
                "name": SESSION_COOKIE_NAME,
                "value": SESSION_TOKEN,
                "url": live_application.base_url,
                "httpOnly": True,
                "secure": False,
                "sameSite": "Strict",
            }
        ]
    )


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
