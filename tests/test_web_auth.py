from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest
import pytest_asyncio
from aiohttp import CookieJar
from aiohttp.test_utils import TestClient, TestServer

from maddyweb.gateway import HelperCallError
from maddyweb.web import MessagePage, create_app

USER_ID = "1" * 32
ADMIN_ID = "2" * 32
TARGET_ID = "3" * 32
CHALLENGE = "C" * 43
USER_TOKEN = "U" * 43
ADMIN_TOKEN = "A" * 43
RECOVERY_TOKEN = "R" * 43
ENROLLMENT_TOKEN = "E" * 43
AUTHENTICATOR_KEY = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


def _principal(
    *,
    account_id: str = USER_ID,
    email: str = "user@example.test",
    role: str = "user",
    password_change_required: bool = False,
) -> dict[str, object]:
    return {
        "account_id": account_id,
        "email": email,
        "role": role,
        "password_change_required": password_change_required,
        "enrollment_state": "active",
        "idle_expires_at": 2_000_000_000,
        "absolute_expires_at": 2_000_010_000,
    }


class AuthGateway:
    def __init__(self) -> None:
        self.next_step = "totp"
        self.login_principal = _principal()
        self.login_token = USER_TOKEN
        self.sessions: dict[str, dict[str, object]] = {}
        self.operations: list[tuple[object, ...]] = []
        self.password_error: HelperCallError | None = None
        self.session_error: HelperCallError | None = None
        self.logout_error: HelperCallError | None = None
        self.enrollment_uri = (
            "otpauth://totp/MaddyWeb%3Auser%40example.test?"
            f"secret={AUTHENTICATOR_KEY}&issuer=MaddyWeb&algorithm=SHA1&digits=6&period=30"
        )
        self.accounts = [
            {
                "id": ADMIN_ID,
                "address": "admin@example.test",
                "has_credentials": True,
                "has_mailbox": True,
                "append_limit": None,
            },
            {
                "id": TARGET_ID,
                "address": "target@example.test",
                "has_credentials": True,
                "has_mailbox": True,
                "append_limit": None,
            },
        ]

    def configure_login(
        self,
        *,
        principal: Mapping[str, object],
        token: str,
        next_step: str = "totp",
    ) -> None:
        self.login_principal = dict(principal)
        self.login_token = token
        self.next_step = next_step

    def _issue_session(
        self,
        *,
        token: str | None = None,
        recovery_codes: Sequence[str] = (),
    ) -> dict[str, object]:
        issued = token or self.login_token
        principal = dict(self.login_principal)
        self.sessions[issued] = principal
        return {
            "session_token": issued,
            "principal": principal,
            "recovery_codes": list(recovery_codes),
        }

    async def begin_password_login(
        self,
        email: str,
        password: str,
        *,
        client_ip: str,
    ) -> Mapping[str, object]:
        self.operations.append(("password", email, password, client_ip))
        if self.password_error is not None:
            raise self.password_error
        return {"challenge": CHALLENGE, "next": self.next_step}

    async def begin_totp_enrollment(self, challenge: str) -> Mapping[str, object]:
        self.operations.append(("enrollment", challenge))
        return {
            "secret": AUTHENTICATOR_KEY,
            "provisioning_uri": self.enrollment_uri,
        }

    async def complete_totp_enrollment(
        self,
        challenge: str,
        code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, object]:
        self.operations.append(("enrollment_confirm", challenge, code, client_ip))
        return self._issue_session(
            token=ENROLLMENT_TOKEN,
            recovery_codes=("recovery-one", "recovery-two"),
        )

    async def complete_totp_login(
        self,
        challenge: str,
        code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, object]:
        self.operations.append(("totp", challenge, code, client_ip))
        return self._issue_session()

    async def complete_recovery_login(
        self,
        challenge: str,
        recovery_code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, object]:
        self.operations.append(("recovery", challenge, recovery_code, client_ip))
        return self._issue_session(token=RECOVERY_TOKEN)

    async def session(self, token: str) -> Mapping[str, object]:
        self.operations.append(("session", token))
        if self.session_error is not None:
            raise self.session_error
        try:
            return dict(self.sessions[token])
        except KeyError as exc:
            raise HelperCallError("unauthorized") from exc

    async def logout(self, token: str) -> None:
        self.operations.append(("logout", token))
        if self.logout_error is not None:
            raise self.logout_error
        self.sessions.pop(token, None)

    async def change_own_password(
        self,
        current_password: str,
        new_password: str,
        *,
        client_ip: str,
    ) -> Mapping[str, object]:
        self.operations.append(("change_own_password", current_password, new_password, client_ip))
        self.sessions.clear()
        return {"changed": True}

    async def regenerate_recovery_codes(
        self,
        password: str,
        code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, object]:
        self.operations.append(("regenerate_recovery", password, code, client_ip))
        self.sessions.clear()
        return {"recovery_codes": ["new-recovery-one", "new-recovery-two"]}

    async def step_up(
        self,
        password: str,
        code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, object]:
        self.operations.append(("step_up", password, code, client_ip))
        return {"step_up_expires_at": 2_000_000_300}

    async def rotate_account_totp(self, account_id: str) -> Mapping[str, object]:
        self.operations.append(("rotate_totp", account_id))
        return {
            "secret": AUTHENTICATOR_KEY,
            "recovery_codes": ["reset-recovery-one"],
        }

    async def health(self) -> Mapping[str, object]:
        return {
            "status": "ok",
            "version": "0.1.0",
            "maddy_version": "0.9.5",
            "maddy_write_enabled": True,
            "storage_available": True,
            "certbot_available": True,
            "certificate_management_enabled": True,
        }

    async def list_accounts(self) -> Sequence[object]:
        self.operations.append(("list_accounts",))
        return self.accounts

    async def list_mailboxes(self, account_id: str) -> Sequence[object]:
        self.operations.append(("list_mailboxes", account_id))
        return [
            {"name": "INBOX"},
            {"name": "Archive", "attributes": [r"\Archive"]},
            {"name": "Trash", "attributes": [r"\Trash"]},
        ]

    async def list_messages(
        self,
        account_id: str,
        mailbox: str,
        *,
        limit: int,
        offset: int,
    ) -> MessagePage:
        self.operations.append(("list_messages", account_id, mailbox, limit, offset))
        return MessagePage((), False, None, offset)


def _config(
    temp_dir: Path,
    *,
    public: bool = False,
    secure_cookies: bool = False,
    login_domain: str = "",
) -> dict[str, object]:
    security: dict[str, object] = {
        "session_signing_key": b"k" * 32,
        "csrf_ttl_seconds": 300,
        "csrf_cookie_name": ("__Host-maddyweb-csrf" if secure_cookies else "maddyweb-csrf"),
        "session_cookie_name": (
            "__Host-maddyweb-session" if secure_cookies else "maddyweb-session"
        ),
        "secure_cookies": secure_cookies,
        "login_domain": login_domain,
    }
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost")
    if public:
        allowed_hosts += ("maddy.example.test",)
        security["public_origin"] = "https://maddy.example.test"
    return {
        "server": {
            "allowed_hosts": allowed_hosts,
            "concurrency": 4,
            "max_upload_bytes": 4 * 1024 * 1024,
            "page_size": 20,
            "temp_dir": temp_dir,
        },
        "security": security,
    }


@pytest_asyncio.fixture
async def auth_client(tmp_path: Path) -> tuple[TestClient, AuthGateway]:
    gateway = AuthGateway()
    client = TestClient(
        TestServer(create_app(_config(tmp_path), gateway)),
        cookie_jar=CookieJar(unsafe=True),
    )
    await client.start_server()
    try:
        yield client, gateway
    finally:
        await client.close()


def _origin(client: TestClient) -> str:
    return str(client.make_url("/").origin())


async def _csrf(
    client: TestClient,
    *,
    headers: Mapping[str, str] | None = None,
) -> str:
    response = await client.get("/api/v1/auth/csrf", headers=headers)
    assert response.status == 200
    payload = await response.json()
    return str(payload["data"]["csrf_token"])


async def _post_json(
    client: TestClient,
    path: str,
    token: str,
    payload: Mapping[str, object],
    *,
    headers: Mapping[str, str] | None = None,
) -> Any:
    request_headers = {
        "Origin": _origin(client),
        "X-CSRF-Token": token,
    }
    if headers:
        request_headers.update(headers)
    return await client.post(
        path,
        json=dict(payload),
        headers=request_headers,
        allow_redirects=False,
    )


def _rotated_csrf(response: Any) -> str:
    token = response.headers.get("X-CSRF-Token")
    assert token
    return str(token)


async def _password_challenge(
    client: TestClient,
    *,
    email: str = "user@example.test",
) -> tuple[str, str]:
    csrf = await _csrf(client)
    response = await _post_json(
        client,
        "/api/v1/auth/password",
        csrf,
        {"email": email, "password": "mailbox-password"},
    )
    assert response.status == 200
    payload = await response.json()
    return str(payload["data"]["challenge"]), _rotated_csrf(response)


async def _login_totp(
    client: TestClient,
    gateway: AuthGateway,
    *,
    principal: Mapping[str, object] | None = None,
    token: str = USER_TOKEN,
) -> tuple[Any, str]:
    gateway.configure_login(
        principal=principal or _principal(),
        token=token,
        next_step="totp",
    )
    challenge, csrf = await _password_challenge(
        client,
        email=str(gateway.login_principal["email"]),
    )
    response = await _post_json(
        client,
        "/api/v1/auth/totp",
        csrf,
        {"challenge": challenge, "code": "123456"},
    )
    assert response.status == 200
    return response, _rotated_csrf(response)


@pytest.mark.asyncio
async def test_short_login_identifier_uses_the_configured_local_domain(tmp_path: Path) -> None:
    gateway = AuthGateway()
    client = TestClient(
        TestServer(create_app(_config(tmp_path, login_domain="example.test"), gateway)),
        cookie_jar=CookieJar(unsafe=True),
    )
    await client.start_server()
    try:
        challenge, _csrf_token = await _password_challenge(client, email="User.Name")
        assert challenge == CHALLENGE
        assert gateway.operations == [
            ("password", "user.name@example.test", "mailbox-password", "127.0.0.1")
        ]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_configured_login_domain_restricts_and_canonicalizes_identifiers(
    tmp_path: Path,
) -> None:
    gateway = AuthGateway()
    client = TestClient(
        TestServer(create_app(_config(tmp_path, login_domain="example.test"), gateway)),
        cookie_jar=CookieJar(unsafe=True),
    )
    await client.start_server()
    try:
        await _password_challenge(client, email="User.Name")
        await _password_challenge(client, email="USER.NAME@EXAMPLE.TEST")
        assert gateway.operations == [
            ("password", "user.name@example.test", "mailbox-password", "127.0.0.1"),
            ("password", "user.name@example.test", "mailbox-password", "127.0.0.1"),
        ]

        csrf = await _csrf(client)
        response = await _post_json(
            client,
            "/api/v1/auth/password",
            csrf,
            {"email": "user@outside.test", "password": "mailbox-password"},
        )
        assert response.status == 401
        assert (await response.json())["error"] == {
            "code": "invalid_credentials",
            "message": "Authentication failed.",
        }
        assert gateway.operations == [
            ("password", "user.name@example.test", "mailbox-password", "127.0.0.1"),
            ("password", "user.name@example.test", "mailbox-password", "127.0.0.1"),
        ]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_short_login_identifier_is_disabled_without_a_configured_domain(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    csrf = await _csrf(client)
    response = await _post_json(
        client,
        "/api/v1/auth/password",
        csrf,
        {"email": "user", "password": "mailbox-password"},
    )
    assert response.status == 401
    assert not gateway.operations


@pytest.mark.asyncio
async def test_active_normal_user_login_redirects_to_mail(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    await _login_totp(client, gateway)
    response = await client.get("/login", allow_redirects=False)
    assert response.status == 302
    assert response.headers["Location"] == "/mail"


@pytest.mark.asyncio
async def test_unauthenticated_browser_is_confined_to_login_surface(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client

    login = await client.get("/login")
    assert login.status == 200
    login_html = await login.text()
    asset_paths = re.findall(
        r'(?:href|src)="(/static/login\.(?:css|js)\?v=[0-9a-f]{16})"',
        login_html,
    )
    assert len(asset_paths) == 2
    for path in asset_paths:
        public_asset = await client.get(path)
        assert public_asset.status == 200
        assert "Set-Cookie" not in public_asset.headers
        assert public_asset.headers["Cache-Control"] == ("public, max-age=31536000, immutable")
    assert (await client.get("/static/login.css")).status == 404
    assert (await client.get("/static/login.js?v=incorrect")).status == 404
    assert (await client.get("/api/v1/auth/csrf")).status == 200

    for path in ("/", "/mail", "/compose", "/accounts", "/certificates", "/security"):
        response = await client.get(path, allow_redirects=False)
        assert response.status == 302
        assert response.headers["Location"] == "/login"

    for path in (
        "/api/v1/health",
        "/api/v1/accounts",
        "/api/v1/me/mail",
        "/api/v1/admin/accounts",
        "/static/app.css",
        "/static/app.js",
    ):
        response = await client.get(path, allow_redirects=False)
        assert response.status == 401

    health = await client.get("/healthz")
    assert health.status == 200
    assert "accounts" not in await health.json()
    assert ("list_accounts",) not in gateway.operations


@pytest.mark.asyncio
async def test_versioned_login_assets_ignore_session_cookies_and_helper_outage(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    login_html = await (await client.get("/login")).text()
    asset_paths = re.findall(
        r'(?:href|src)="(/static/login\.(?:css|js)\?v=[0-9a-f]{16})"',
        login_html,
    )
    assert len(asset_paths) == 2
    gateway.session_error = HelperCallError("backend_failure")

    for cookie in ("maddyweb-session=malformed", f"maddyweb-session={'Z' * 43}"):
        for path in asset_paths:
            asset = await client.get(path, headers={"Cookie": cookie})
            assert asset.status == 200
            assert "Set-Cookie" not in asset.headers
            assert asset.headers["Cache-Control"] == ("public, max-age=31536000, immutable")

    assert not any(operation[0] == "session" for operation in gateway.operations)


@pytest.mark.asyncio
async def test_password_totp_login_rotates_csrf_and_sets_session_cookie(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client

    response, rotated = await _login_totp(client, gateway)
    payload = await response.json()
    cookies = client.session.cookie_jar.filter_cookies(client.make_url("/"))

    assert cookies["maddyweb-session"].value == USER_TOKEN
    assert cookies["maddyweb-csrf"].value == rotated
    assert payload["data"]["principal"]["email"] == "user@example.test"
    assert payload["data"]["csrf_token"] == rotated
    set_cookie = "\n".join(response.headers.getall("Set-Cookie", []))
    assert "maddyweb-session=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=Strict" in set_cookie
    assert "Path=/" in set_cookie
    assert ("totp", CHALLENGE, "123456", "127.0.0.1") in gateway.operations

    session = await client.get("/api/v1/auth/session")
    assert session.status == 200
    session_payload = await session.json()
    assert session_payload["data"]["principal"]["account_id"] == USER_ID


@pytest.mark.asyncio
async def test_authenticated_application_bundle_is_never_publicly_cacheable(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    await _login_totp(client, gateway)

    for path in ("/static/app.css", "/static/app.js", "/static/preview.css"):
        response = await client.get(path)
        assert response.status == 200
        directives = {
            directive.strip().casefold()
            for directive in response.headers["Cache-Control"].split(",")
        }
        assert "no-store" in directives
        assert "public" not in directives

    versioned = await client.get("/static/app.js?v=23")
    assert versioned.status == 200
    directives = {
        directive.strip().casefold() for directive in versioned.headers["Cache-Control"].split(",")
    }
    assert "private" in directives
    assert "immutable" in directives
    assert "public" not in directives


@pytest.mark.asyncio
async def test_first_login_enrollment_and_recovery_login_flows(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    gateway.configure_login(
        principal=_principal(),
        token=ENROLLMENT_TOKEN,
        next_step="enrollment",
    )

    challenge, csrf = await _password_challenge(client)
    enrollment = await _post_json(
        client,
        "/api/v1/auth/enrollment",
        csrf,
        {"challenge": challenge},
    )
    assert enrollment.status == 200
    enrollment_data = (await enrollment.json())["data"]
    assert enrollment_data["secret"] == AUTHENTICATOR_KEY
    assert enrollment_data["issuer"] == "MaddyWeb"
    assert enrollment_data["provisioning_uri"].startswith("otpauth://totp/")
    qr_svg = enrollment_data["qr_svg"]
    assert qr_svg.startswith("<svg ")
    assert len(qr_svg) < 256 * 1024
    assert AUTHENTICATOR_KEY not in qr_svg
    assert "otpauth://" not in qr_svg
    assert "<script" not in qr_svg.casefold()
    assert "href=" not in qr_svg.casefold()

    confirmed = await _post_json(
        client,
        "/api/v1/auth/enrollment/confirm",
        _rotated_csrf(enrollment),
        {"challenge": challenge, "code": "654321"},
    )
    assert confirmed.status == 200
    confirmed_data = (await confirmed.json())["data"]
    assert confirmed_data["recovery_codes"] == ["recovery-one", "recovery-two"]
    assert (
        "enrollment_confirm",
        CHALLENGE,
        "654321",
        "127.0.0.1",
    ) in gateway.operations

    gateway.sessions.clear()
    client.session.cookie_jar.clear()
    challenge, csrf = await _password_challenge(client)
    recovered = await _post_json(
        client,
        "/api/v1/auth/recovery",
        csrf,
        {"challenge": challenge, "recovery_code": "recovery-one"},
    )
    assert recovered.status == 200
    assert (
        "recovery",
        CHALLENGE,
        "recovery-one",
        "127.0.0.1",
    ) in gateway.operations
    cookies = client.session.cookie_jar.filter_cookies(client.make_url("/"))
    assert cookies["maddyweb-session"].value == RECOVERY_TOKEN


@pytest.mark.asyncio
async def test_enrollment_rejects_a_mismatched_totp_issuer(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    gateway.enrollment_uri = gateway.enrollment_uri.replace(
        "issuer=MaddyWeb",
        "issuer=Unexpected",
    )
    challenge, csrf = await _password_challenge(client)

    response = await _post_json(
        client,
        "/api/v1/auth/enrollment",
        csrf,
        {"challenge": challenge},
    )

    assert response.status == 502
    assert (await response.json())["error"]["code"] == "invalid_backend_response"


@pytest.mark.asyncio
async def test_authentication_failure_is_non_enumerating_and_rate_limit_is_bounded(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    gateway.password_error = HelperCallError(
        "invalid_credentials",
        "mailbox user@example.test does not exist",
    )
    csrf = await _csrf(client)
    denied = await _post_json(
        client,
        "/api/v1/auth/password",
        csrf,
        {"email": "user@example.test", "password": "wrong-password"},
    )
    denied_body = await denied.text()
    assert denied.status == 401
    assert "Authentication failed." in denied_body
    assert "does not exist" not in denied_body
    assert "user@example.test" not in denied_body
    assert "wrong-password" not in denied_body

    gateway.password_error = HelperCallError("rate_limited", "internal rate details")
    limited = await _post_json(
        client,
        "/api/v1/auth/password",
        _rotated_csrf(denied),
        {"email": "user@example.test", "password": "wrong-password"},
    )
    assert limited.status == 429
    assert limited.headers["Retry-After"] == "60"
    assert "internal rate details" not in await limited.text()


@pytest.mark.asyncio
async def test_csrf_rejects_missing_cross_origin_and_reused_tokens(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    token = await _csrf(client)

    missing = await client.post(
        "/api/v1/auth/password",
        json={"email": "user@example.test", "password": "mailbox-password"},
        headers={"Origin": _origin(client)},
    )
    assert missing.status == 403
    assert (await missing.json())["error"]["code"] == "csrf_failed"
    assert not gateway.operations

    token = _rotated_csrf(missing)
    cross_origin = await _post_json(
        client,
        "/api/v1/auth/password",
        token,
        {"email": "user@example.test", "password": "mailbox-password"},
        headers={"Origin": "https://attacker.example"},
    )
    assert cross_origin.status == 403
    assert (await cross_origin.json())["error"]["code"] == "cross_site_rejected"
    assert not gateway.operations

    token = await _csrf(client)
    accepted = await _post_json(
        client,
        "/api/v1/auth/password",
        token,
        {"email": "user@example.test", "password": "mailbox-password"},
    )
    assert accepted.status == 200
    replayed = await _post_json(
        client,
        "/api/v1/auth/password",
        token,
        {"email": "user@example.test", "password": "mailbox-password"},
    )
    assert replayed.status == 403
    assert (await replayed.json())["error"]["code"] in {"csrf_failed", "csrf_reused"}
    assert sum(operation[0] == "password" for operation in gateway.operations) == 1


@pytest.mark.asyncio
async def test_unauthenticated_protected_posts_do_not_rotate_or_consume_csrf(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    csrf = await _csrf(client)
    for _index in range(12):
        denied = await _post_json(
            client,
            "/api/v1/admin/accounts",
            csrf,
            {},
        )
        assert denied.status == 401
        assert "X-CSRF-Token" not in denied.headers
        cookies = client.session.cookie_jar.filter_cookies(client.make_url("/"))
        assert cookies["maddyweb-csrf"].value == csrf

    accepted = await _post_json(
        client,
        "/api/v1/auth/password",
        csrf,
        {"email": "user@example.test", "password": "mailbox-password"},
    )
    assert accepted.status == 200
    assert sum(operation[0] == "password" for operation in gateway.operations) == 1


@pytest.mark.asyncio
async def test_normal_user_cannot_select_or_reach_another_account(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    _response, csrf = await _login_totp(client, gateway)
    gateway.operations.clear()

    query = urlencode({"account": TARGET_ID, "mailbox": "INBOX"})
    injected = await client.get(f"/api/v1/me/mail?{query}")
    assert injected.status == 400
    assert (await injected.json())["error"]["message"] == (
        "Personal mailbox APIs do not accept an account field."
    )
    assert not any(operation[0] == "list_messages" for operation in gateway.operations)

    admin_api = await client.get(f"/api/v1/admin/mail?{query}")
    assert admin_api.status == 403
    assert not any(operation[0] == "list_messages" for operation in gateway.operations)

    legacy_admin_api = await client.get(f"/api/v1/mail?{query}")
    assert legacy_admin_api.status == 403
    assert not any(operation[0] == "list_messages" for operation in gateway.operations)

    message_injection = await client.get(
        f"/api/v1/me/mail/42?{urlencode({'account': TARGET_ID, 'mailbox': 'INBOX'})}"
    )
    assert message_injection.status == 400
    assert not any(operation[0] == "spool_message" for operation in gateway.operations)

    state_injection = await _post_json(
        client,
        "/api/v1/me/mail/42/read-state",
        csrf,
        {
            "account": TARGET_ID,
            "mailbox": "INBOX",
            "freshness": "not-relevant",
            "seen": True,
        },
    )
    assert state_injection.status == 400
    assert not any(operation[0] == "set_message_seen" for operation in gateway.operations)

    folder_injection = await _post_json(
        client,
        "/api/v1/me/mailboxes",
        _rotated_csrf(state_injection),
        {"account": TARGET_ID, "name": "Injected"},
    )
    assert folder_injection.status == 400
    assert not any(operation[0] == "create_mailbox" for operation in gateway.operations)

    gateway.operations.clear()
    context = await client.get("/api/v1/me/mail?phase=context")
    assert context.status == 200
    context_data = (await context.json())["data"]
    assert context_data["selected_account"] == USER_ID
    assert context_data["selected_mailbox"] == "INBOX"
    assert context_data["messages"] == []
    assert ("list_mailboxes", USER_ID) in gateway.operations
    assert not any(operation[0] == "list_messages" for operation in gateway.operations)

    gateway.operations.clear()
    own = await client.get("/api/v1/me/mail")
    assert own.status == 200
    own_data = (await own.json())["data"]
    assert own_data["selected_account"] == USER_ID
    assert own_data["selected_mailbox"] == "INBOX"
    assert ("list_messages", USER_ID, "INBOX", 20, 0) in gateway.operations


@pytest.mark.asyncio
async def test_admin_uses_opaque_target_and_unknown_target_is_rejected(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    _response, csrf = await _login_totp(
        client,
        gateway,
        principal=_principal(
            account_id=ADMIN_ID,
            email="admin@example.test",
            role="admin",
        ),
        token=ADMIN_TOKEN,
    )
    gateway.operations.clear()

    target = urlencode({"account": TARGET_ID, "mailbox": "INBOX"})
    allowed = await client.get(f"/api/v1/admin/mail?{target}")
    assert allowed.status == 200
    assert ("list_mailboxes", TARGET_ID) in gateway.operations
    assert ("list_messages", TARGET_ID, "INBOX", 20, 0) in gateway.operations

    gateway.operations.clear()
    unknown_id = "f" * 32
    unknown = await client.get(
        f"/api/v1/admin/mail?{urlencode({'account': unknown_id, 'mailbox': 'INBOX'})}"
    )
    assert unknown.status == 400
    assert ("list_accounts",) in gateway.operations
    assert not any(operation[0] == "list_mailboxes" for operation in gateway.operations)

    gateway.operations.clear()
    address_target = urlencode({"account": "target@example.test", "mailbox": "INBOX"})
    non_opaque = await client.get(f"/api/v1/admin/mail?{address_target}")
    assert non_opaque.status == 400
    assert ("list_accounts",) not in gateway.operations
    assert not any(operation[0] == "list_mailboxes" for operation in gateway.operations)

    gateway.operations.clear()
    uppercase_target = urlencode({"account": "A" * 32, "mailbox": "INBOX"})
    uppercase = await client.get(f"/api/v1/admin/mail?{uppercase_target}")
    assert uppercase.status == 400
    assert ("list_accounts",) not in gateway.operations
    assert not any(operation[0] == "list_mailboxes" for operation in gateway.operations)

    route_address = await _post_json(
        client,
        "/api/v1/admin/accounts/target@example.test/password",
        csrf,
        {"password": "replacement-mailbox-password"},
    )
    assert route_address.status == 400
    assert not any(operation[0] == "change_password" for operation in gateway.operations)


@pytest.mark.asyncio
async def test_forced_password_change_gate_only_allows_security_flow(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    response, csrf = await _login_totp(
        client,
        gateway,
        principal=_principal(password_change_required=True),
    )
    assert response.status == 200

    page = await client.get("/mail", allow_redirects=False)
    assert page.status == 302
    assert page.headers["Location"] == "/security"
    mail = await client.get("/api/v1/me/mail")
    assert mail.status == 403
    assert (await mail.json())["error"]["code"] == "password_change_required"
    assert (await client.get("/api/v1/auth/session")).status == 200
    assert (await client.get("/security")).status == 200

    changed = await _post_json(
        client,
        "/api/v1/auth/password/change",
        csrf,
        {
            "current_password": "old-mailbox-password",
            "new_password": "new-mailbox-password",
        },
    )
    assert changed.status == 200
    assert (
        "change_own_password",
        "old-mailbox-password",
        "new-mailbox-password",
        "127.0.0.1",
    ) in gateway.operations
    assert "Max-Age=0" in "\n".join(changed.headers.getall("Set-Cookie", []))
    assert (await client.get("/api/v1/auth/session")).status == 401


@pytest.mark.asyncio
async def test_public_proxy_host_and_origin_are_exactly_validated(tmp_path: Path) -> None:
    gateway = AuthGateway()
    client = TestClient(
        TestServer(create_app(_config(tmp_path, public=True), gateway)),
        cookie_jar=CookieJar(unsafe=True),
    )
    await client.start_server()
    proxy_headers = {
        "Host": "maddy.example.test",
        "X-Forwarded-Proto": "https",
        "X-Real-IP": "203.0.113.8",
    }
    try:
        assert (await client.get("/login", headers={"Host": "invalid.example.test"})).status == 400
        assert (await client.get("/login", headers={"Host": "maddy.example.test"})).status == 400
        assert (
            await client.get(
                "/login",
                headers={**proxy_headers, "X-Forwarded-For": "203.0.113.8"},
            )
        ).status == 400
        assert (await client.get("/login", headers=proxy_headers)).status == 200
        assert (await client.get("/healthz", headers=proxy_headers)).status == 404

        csrf = await _csrf(client, headers=proxy_headers)
        bad_origin = await _post_json(
            client,
            "/api/v1/auth/password",
            csrf,
            {"email": "user@example.test", "password": "mailbox-password"},
            headers={**proxy_headers, "Origin": "http://maddy.example.test"},
        )
        assert bad_origin.status == 403
        assert not gateway.operations

        csrf = await _csrf(client, headers=proxy_headers)
        accepted = await _post_json(
            client,
            "/api/v1/auth/password",
            csrf,
            {"email": "user@example.test", "password": "mailbox-password"},
            headers={**proxy_headers, "Origin": "https://maddy.example.test"},
        )
        assert accepted.status == 200
        assert ("password", "user@example.test", "mailbox-password", "203.0.113.8") in (
            gateway.operations
        )
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_logout_revokes_session_and_expired_session_fails_closed(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    _response, csrf = await _login_totp(client, gateway)

    logout = await _post_json(client, "/api/v1/auth/logout", csrf, {})
    assert logout.status == 200
    assert ("logout", USER_TOKEN) in gateway.operations
    assert "Max-Age=0" in "\n".join(logout.headers.getall("Set-Cookie", []))
    assert (await client.get("/api/v1/auth/session")).status == 401
    protected = await client.get("/api/v1/me/mail")
    assert protected.status == 401


@pytest.mark.asyncio
async def test_logout_failure_keeps_cookie_and_reports_unrevoked_session(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    _response, csrf = await _login_totp(client, gateway)
    gateway.logout_error = HelperCallError("internal_error")

    failed = await _post_json(client, "/api/v1/auth/logout", csrf, {})
    assert failed.status == 503
    assert (await failed.json())["error"]["code"] == "logout_failed"
    assert "Max-Age=0" not in "\n".join(failed.headers.getall("Set-Cookie", []))
    assert (await client.get("/api/v1/auth/session")).status == 200

    gateway.logout_error = None
    succeeded = await _post_json(
        client,
        "/api/v1/auth/logout",
        _rotated_csrf(failed),
        {},
    )
    assert succeeded.status == 200
    assert "Max-Age=0" in "\n".join(succeeded.headers.getall("Set-Cookie", []))

    await _login_totp(client, gateway)
    gateway.sessions.pop(USER_TOKEN)
    expired = await client.get("/api/v1/me/mail")
    assert expired.status == 401
    assert "Max-Age=0" in "\n".join(expired.headers.getall("Set-Cookie", []))


@pytest.mark.asyncio
async def test_session_helper_outage_preserves_cookie_and_returns_503(
    auth_client: tuple[TestClient, AuthGateway],
) -> None:
    client, gateway = auth_client
    await _login_totp(client, gateway)
    gateway.session_error = HelperCallError("internal_error")

    api_response = await client.get("/api/v1/auth/session")
    assert api_response.status == 503
    assert (await api_response.json())["error"]["code"] == "authentication_unavailable"
    assert "Max-Age=0" not in "\n".join(api_response.headers.getall("Set-Cookie", []))

    page_response = await client.get("/", allow_redirects=False)
    assert page_response.status == 503
    assert "Max-Age=0" not in "\n".join(page_response.headers.getall("Set-Cookie", []))

    gateway.session_error = None
    assert (await client.get("/api/v1/auth/session")).status == 200


@pytest.mark.asyncio
async def test_host_prefixed_session_cookie_is_secure_and_securely_deleted(
    tmp_path: Path,
) -> None:
    gateway = AuthGateway()
    app = create_app(_config(tmp_path, public=True, secure_cookies=True), gateway)
    client = TestClient(TestServer(app))
    await client.start_server()
    proxy_headers = {
        "Host": "maddy.example.test",
        "Origin": "https://maddy.example.test",
        "X-Forwarded-Proto": "https",
        "X-Real-IP": "203.0.113.9",
    }
    try:
        csrf_response = await client.get(
            "/api/v1/auth/csrf",
            headers={key: value for key, value in proxy_headers.items() if key != "Origin"},
        )
        csrf_payload = await csrf_response.json()
        csrf = str(csrf_payload["data"]["csrf_token"])
        cookie_header = f"__Host-maddyweb-csrf={csrf}"
        password = await client.post(
            "/api/v1/auth/password",
            json={"email": "user@example.test", "password": "mailbox-password"},
            headers={
                **proxy_headers,
                "Cookie": cookie_header,
                "X-CSRF-Token": csrf,
            },
        )
        assert password.status == 200
        challenge = str((await password.json())["data"]["challenge"])
        rotated = _rotated_csrf(password)
        totp = await client.post(
            "/api/v1/auth/totp",
            json={"challenge": challenge, "code": "123456"},
            headers={
                **proxy_headers,
                "Cookie": f"__Host-maddyweb-csrf={rotated}",
                "X-CSRF-Token": rotated,
            },
        )
        assert totp.status == 200
        set_cookie = "\n".join(totp.headers.getall("Set-Cookie", []))
        assert "__Host-maddyweb-session=" in set_cookie
        assert "Secure" in set_cookie
        assert "HttpOnly" in set_cookie
        assert "SameSite=Strict" in set_cookie

        session_token = gateway.login_token
        next_csrf = _rotated_csrf(totp)
        logout = await client.post(
            "/api/v1/auth/logout",
            json={},
            headers={
                **proxy_headers,
                "Cookie": (
                    f"__Host-maddyweb-csrf={next_csrf}; __Host-maddyweb-session={session_token}"
                ),
                "X-CSRF-Token": next_csrf,
            },
        )
        assert logout.status == 200
        deletion_headers = [
            value
            for value in logout.headers.getall("Set-Cookie", [])
            if value.startswith("__Host-maddyweb-session=")
        ]
        assert len(deletion_headers) == 1
        assert "Secure" in deletion_headers[0]
        assert "HttpOnly" in deletion_headers[0]
        assert "SameSite=Strict" in deletion_headers[0]
        assert "Path=/" in deletion_headers[0]
        assert "Max-Age=0" in deletion_headers[0]
    finally:
        await client.close()
