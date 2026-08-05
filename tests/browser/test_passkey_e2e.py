"""Real Chromium WebAuthn registration and discoverable sign-in checks."""

from __future__ import annotations

import secrets
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import pytest
from aiohttp import web
from conftest import LiveApplication, _listening_socket
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from maddyweb.auth import AuthStore, IssuedSession, PasskeyCredential, SessionPrincipal, totp_code
from maddyweb.web import create_app

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping

    from playwright.async_api import Page, Route


pytestmark = pytest.mark.asyncio
PASSKEY_ACCOUNT = "passkey-user@example.test"
PASSKEY_SESSION_COOKIE = "maddyweb-passkey-session"
PASSKEY_CSRF_COOKIE = "maddyweb-passkey-csrf"


async def _allow_loopback_only(route: Route) -> None:
    if urlsplit(route.request.url).hostname in {"127.0.0.1", "localhost"}:
        await route.continue_()
    else:
        await route.abort()


@pytest.fixture
async def page() -> AsyncIterator[Page]:
    async_api = pytest.importorskip(
        "playwright.async_api",
        reason="install the 'browser' extra to run Chromium passkey tests",
        exc_type=ImportError,
    )
    async with async_api.async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=["--no-proxy-server"],
        )
        context = await browser.new_context(ignore_https_errors=True)
        await context.route("**/*", _allow_loopback_only)
        browser_page = await context.new_page()
        try:
            yield browser_page
        finally:
            await context.close()
            await browser.close()


def _principal_payload(principal: SessionPrincipal) -> dict[str, object]:
    return {
        "account_id": principal.account_id,
        "email": principal.email,
        "role": principal.role.value,
        "password_change_required": principal.password_change_required,
        "enrollment_state": principal.enrollment_state.value,
        "idle_expires_at": principal.idle_expires_at,
        "absolute_expires_at": principal.absolute_expires_at,
        "step_up_until": principal.step_up_until,
        "session_id": principal.session_id,
        "client_ip": principal.client_ip,
        "user_agent": principal.user_agent,
        "recovery_codes_remaining": 10,
    }


def _issued_payload(issued: IssuedSession) -> dict[str, object]:
    return {
        "session_token": issued.token,
        "principal": _principal_payload(issued.principal),
        "recovery_codes": [],
    }


def _passkey_payload(passkey: PasskeyCredential) -> dict[str, object]:
    return {
        "id": passkey.public_id,
        "name": passkey.name,
        "device_type": passkey.device_type,
        "backed_up": passkey.backed_up,
        "transports": list(passkey.transports),
        "created_at": passkey.created_at,
        "last_used_at": passkey.last_used_at,
    }


class AuthStoreBrowserGateway:
    """Minimal gateway that keeps the browser ceremony backed by the real AuthStore."""

    def __init__(self, store: AuthStore, account_id: str) -> None:
        self.store = store
        self.account_id = account_id
        self.current_token = ""

    async def session(self, token: str) -> dict[str, object]:
        self.current_token = token
        return _principal_payload(self.store.authenticate_session(token))

    async def peek_session(self, token: str) -> dict[str, object]:
        self.current_token = token
        return _principal_payload(self.store.authenticate_session(token, touch=False))

    async def logout(self, token: str) -> None:
        self.store.revoke_session(token)

    async def list_passkeys(self) -> dict[str, object]:
        return {
            "passkeys": [
                _passkey_payload(value) for value in self.store.list_passkeys(self.account_id)
            ]
        }

    async def begin_passkey_registration(self) -> dict[str, object]:
        ceremony = self.store.begin_passkey_registration(self.current_token)
        return {"challenge": ceremony.challenge_token, "options": ceremony.options}

    async def complete_passkey_registration(
        self,
        challenge: str,
        credential: Mapping[str, object],
        *,
        name: str,
    ) -> dict[str, object]:
        passkey = self.store.complete_passkey_registration(
            self.current_token,
            challenge,
            credential,
            name=name,
        )
        return {"passkey": _passkey_payload(passkey)}

    async def delete_passkey(self, passkey_id: str) -> dict[str, object]:
        return {"deleted": self.store.delete_passkey(self.account_id, passkey_id)}

    async def list_sessions(self) -> dict[str, object]:
        records = self.store.list_sessions(
            self.account_id,
            current_session_token=self.current_token,
        )
        return {
            "sessions": [
                {
                    "id": record.session_id,
                    "current": record.current,
                    "client_ip": record.client_ip,
                    "user_agent": record.user_agent,
                    "created_at": record.created_at,
                    "last_seen_at": record.last_seen_at,
                    "idle_expires_at": record.idle_expires_at,
                    "absolute_expires_at": record.absolute_expires_at,
                    "step_up_until": record.step_up_until,
                }
                for record in records
            ]
        }

    async def begin_passkey_login(self, *, client_ip: str) -> dict[str, object]:
        assert client_ip
        ceremony = self.store.begin_passkey_login()
        return {"challenge": ceremony.challenge_token, "options": ceremony.options}

    async def complete_passkey_login(
        self,
        challenge: str,
        credential: Mapping[str, object],
        *,
        client_ip: str,
        user_agent: str,
    ) -> dict[str, object]:
        issued = self.store.complete_passkey_login(
            challenge,
            credential,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        self.current_token = issued.token
        return _issued_payload(issued)


@dataclass(frozen=True, slots=True)
class PasskeyApplication:
    live: LiveApplication
    store: AuthStore
    initial_session_token: str
    account_id: str


def _localhost_tls_context(tmp_path: Path) -> ssl.SSLContext:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path = tmp_path / "localhost-key.pem"
    certificate_path = tmp_path / "localhost-certificate.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_path, key_path)
    return context


@pytest.fixture
async def passkey_application(tmp_path: Path) -> AsyncIterator[PasskeyApplication]:
    listener, port = _listening_socket()
    origin = f"https://localhost:{port}"
    store = AuthStore(
        (tmp_path / "passkey-browser.sqlite3").resolve(),
        secrets.token_bytes(32),
        "MaddyWeb Browser Test",
        webauthn_rp_id="localhost",
        webauthn_origin=origin,
    )
    account, enrollment, _recovery_codes = store.provision_active_account(PASSKEY_ACCOUNT)
    challenge = store.create_pending_challenge(account.email)
    issued = store.complete_totp_challenge(
        challenge,
        totp_code(enrollment.secret),
        client_ip="127.0.0.1",
        user_agent="Initial Chromium session",
    )
    store.mark_step_up(issued.token)
    gateway = AuthStoreBrowserGateway(store, account.account_id)
    app = create_app(  # type: ignore[arg-type]
        {
            "server": {
                "allowed_hosts": ("localhost",),
                "concurrency": 4,
                "max_upload_bytes": 4 * 1024 * 1024,
                "request_body_timeout_seconds": 5,
                "page_size": 20,
                "temp_dir": tmp_path,
                "mail_event_poll_seconds": 60,
            },
            "security": {
                "session_signing_key": secrets.token_bytes(32),
                "csrf_ttl_seconds": 300,
                "csrf_cookie_name": PASSKEY_CSRF_COOKIE,
                "session_cookie_name": PASSKEY_SESSION_COOKIE,
                "secure_cookies": False,
                "login_domain": "example.test",
                "public_origin": origin,
            },
        },
        gateway,
    )
    runner = web.AppRunner(app, access_log=None, shutdown_timeout=0.25)
    await runner.setup()
    site = web.SockSite(runner, listener, ssl_context=_localhost_tls_context(tmp_path))
    await site.start()
    live = LiveApplication(origin, port, gateway)  # type: ignore[arg-type]
    try:
        yield PasskeyApplication(live, store, issued.token, account.account_id)
    finally:
        await runner.cleanup()
        store.close()


async def test_virtual_platform_passkey_registers_and_signs_in_without_email(
    page: Page,
    passkey_application: PasskeyApplication,
) -> None:
    application = passkey_application
    await page.context.set_extra_http_headers(
        {"X-Forwarded-Proto": "https", "X-Real-IP": "127.0.0.1"}
    )
    cdp = await page.context.new_cdp_session(page)
    await cdp.send("WebAuthn.enable")
    authenticator = await cdp.send(
        "WebAuthn.addVirtualAuthenticator",
        {
            "options": {
                "protocol": "ctap2",
                "transport": "internal",
                "hasResidentKey": True,
                "hasUserVerification": True,
                "isUserVerified": True,
                "automaticPresenceSimulation": True,
            }
        },
    )
    await page.context.add_cookies(
        [
            {
                "name": PASSKEY_SESSION_COOKIE,
                "value": application.initial_session_token,
                "url": application.live.base_url,
                "httpOnly": True,
                "secure": False,
                "sameSite": "Strict",
            }
        ]
    )
    try:
        await page.goto(application.live.base_url + "/security")
        await page.locator('#passkey-registration-form input[name="name"]').fill(
            "Virtual platform passkey"
        )
        await page.locator("#passkey-registration-button").click()
        await page.locator(
            "#security-passkey-state",
            has_text="1 registered",
        ).wait_for(state="visible")
        assert len(application.store.list_passkeys(application.account_id)) == 1

        await page.context.clear_cookies()
        await page.goto(application.live.base_url + "/login")
        assert await page.locator("#login-address").input_value() == ""
        await page.locator("#passkey-login-panel").wait_for(state="visible")
        await page.locator("#passkey-login").click()
        await page.wait_for_url(application.live.base_url + "/mail")

        credentials = application.store.list_passkeys(application.account_id)
        assert len(credentials) == 1
        assert credentials[0].last_used_at is not None
        assert len(application.store.list_sessions(application.account_id)) == 2
    finally:
        await cdp.send(
            "WebAuthn.removeVirtualAuthenticator",
            {"authenticatorId": authenticator["authenticatorId"]},
        )
        await cdp.send("WebAuthn.disable")
