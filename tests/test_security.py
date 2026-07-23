from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp import CookieJar, web
from aiohttp.test_utils import TestClient, TestServer

from maddyweb.security import (
    SecurityConfig,
    bounded_concurrency_middleware,
    csrf_token_for_request,
    host_is_allowed,
    new_csrf_token,
    normalize_origin,
    security_middleware,
    verify_csrf_token,
)
from maddyweb.web import _session_key

KEY = b"s" * 32
COOKIE = "maddyweb-csrf"


@pytest_asyncio.fixture
async def security_client() -> TestClient:
    config = SecurityConfig(
        allowed_hosts=("127.0.0.1", "localhost"),
        session_signing_key=KEY,
        secure_cookies=False,
        csrf_cookie_name=COOKIE,
        csrf_max_age=300,
    )
    app = web.Application(middlewares=[security_middleware(config)])

    async def token(request: web.Request) -> web.Response:
        return web.Response(text=csrf_token_for_request(request))

    async def write(request: web.Request) -> web.Response:
        return web.Response(text="written", headers={"Access-Control-Allow-Origin": "*"})

    async def fail(request: web.Request) -> web.Response:
        return web.Response(text="invalid", status=400)

    app.add_routes([web.get("/token", token), web.post("/write", write), web.post("/fail", fail)])
    client = TestClient(TestServer(app), cookie_jar=CookieJar(unsafe=True))
    await client.start_server()
    try:
        yield client
    finally:
        await client.close()


def _cookie(client: TestClient) -> str:
    return client.session.cookie_jar.filter_cookies(client.make_url("/"))[COOKIE].value


def test_signed_csrf_token_authenticates_and_expires() -> None:
    token = new_csrf_token(KEY, now=1_000)
    verified = verify_csrf_token(token, KEY, max_age=300, now=1_200)
    assert verified is not None
    assert verified[1] == 1_000
    assert verify_csrf_token(token + "x", KEY, max_age=300, now=1_200) is None
    assert verify_csrf_token(token, KEY, max_age=300, now=1_301) is None
    assert verify_csrf_token(token, b"x" * 32, max_age=300, now=1_200) is None


def test_host_and_origin_normalization_is_exact() -> None:
    assert host_is_allowed("EXAMPLE.test:8443", ("example.test",))
    assert host_is_allowed("example.test:8443", ("example.test:8443",))
    assert not host_is_allowed("example.test.evil", ("example.test",))
    assert not host_is_allowed("user@example.test", ("example.test",))
    assert normalize_origin("HTTPS://EXAMPLE.test:443/") == "https://example.test"


def test_session_key_file_is_bounded_regular_and_private(tmp_path: Path) -> None:
    key_file = tmp_path / "session.key"
    key_file.write_bytes(b"z" * 32)
    if os.name == "posix":
        key_file.chmod(0o600)
    assert _session_key({"security": {"session_key_file": key_file}}) == b"z" * 32

    key_file.write_bytes(b"short")
    with pytest.raises(ValueError, match="32 to 128"):
        _session_key({"security": {"session_key_file": key_file}})


def test_session_key_rejects_symlink_and_posix_public_mode(tmp_path: Path) -> None:
    target = tmp_path / "target.key"
    target.write_bytes(b"z" * 32)
    if os.name == "posix":
        target.chmod(0o600)
    link = tmp_path / "link.key"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("this platform does not permit creating a test symlink")
    with pytest.raises(ValueError, match="non-symlink"):
        _session_key({"security": {"session_key_file": link}})

    if os.name == "posix":
        target.chmod(0o640)
        with pytest.raises(ValueError, match="group/world"):
            _session_key({"security": {"session_key_file": target}})


@pytest.mark.asyncio
async def test_cookie_and_response_security_headers(security_client: TestClient) -> None:
    response = await security_client.get("/token")
    assert response.status == 200
    token = await response.text()
    # Middleware tokens are additionally bound to a random process lifetime,
    # so the persistent session key alone cannot validate/replay them.
    assert verify_csrf_token(token, KEY, max_age=300) is None
    set_cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in set_cookie
    assert "SameSite=Strict" in set_cookie
    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp
    assert response.headers["X-Frame-Options"] == "DENY"


@pytest.mark.asyncio
async def test_invalid_host_and_cross_origin_are_rejected(security_client: TestClient) -> None:
    invalid_host = await security_client.get("/token", headers={"Host": "evil.example"})
    assert invalid_host.status == 400

    await security_client.get("/token")
    token = _cookie(security_client)
    missing_origin = await security_client.post("/write", data={"_csrf": token})
    assert missing_origin.status == 403
    cross_origin = await security_client.post(
        "/write",
        data={"_csrf": token},
        headers={"Origin": "https://evil.example"},
    )
    assert cross_origin.status == 403


@pytest.mark.asyncio
async def test_referer_fallback_and_no_cors(security_client: TestClient) -> None:
    await security_client.get("/token")
    token = _cookie(security_client)
    response = await security_client.post(
        "/write",
        data={"_csrf": token},
        headers={"Referer": str(security_client.make_url("/form"))},
        allow_redirects=False,
    )
    assert response.status == 200
    assert "Access-Control-Allow-Origin" not in response.headers


@pytest.mark.asyncio
async def test_successful_write_consumes_nonce_and_rotates_cookie(
    security_client: TestClient,
) -> None:
    await security_client.get("/token")
    old_token = _cookie(security_client)
    origin = str(security_client.make_url("/"))
    response = await security_client.post(
        "/write",
        data={"_csrf": old_token},
        headers={"Origin": origin},
    )
    assert response.status == 200
    replacement = _cookie(security_client)
    assert replacement != old_token
    assert response.headers["X-CSRF-Token"] == replacement

    replay = await security_client.post(
        "/write",
        data={"_csrf": old_token},
        headers={"Origin": origin, "Cookie": f"{COOKIE}={old_token}"},
    )
    assert replay.status == 403
    assert re.search("token|CSRF", await replay.text())


@pytest.mark.asyncio
async def test_failed_write_consumes_nonce_and_rotates_cookie(
    security_client: TestClient,
) -> None:
    await security_client.get("/token")
    old_token = _cookie(security_client)
    origin = str(security_client.make_url("/"))
    failed = await security_client.post(
        "/fail",
        data={"_csrf": old_token},
        headers={"Origin": origin},
    )
    assert failed.status == 400
    replacement = _cookie(security_client)
    assert replacement != old_token
    assert failed.headers["X-CSRF-Token"] == replacement

    replay = await security_client.post(
        "/write",
        data={"_csrf": old_token},
        headers={"Origin": origin, "Cookie": f"{COOKIE}={old_token}"},
    )
    assert replay.status == 403
    assert re.search("token|CSRF", await replay.text())


@pytest.mark.asyncio
async def test_bounded_concurrency_returns_429_with_retry_after() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    app = web.Application(middlewares=[bounded_concurrency_middleware(1, wait_timeout=0.02)])

    async def slow(_request: web.Request) -> web.Response:
        entered.set()
        await release.wait()
        return web.Response(text="ok")

    app.router.add_get("/slow", slow)
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        first = asyncio.create_task(client.get("/slow"))
        await entered.wait()
        rejected = await client.get("/slow")
        assert rejected.status == 429
        assert rejected.headers["Retry-After"] == "1"
        release.set()
        assert (await first).status == 200
    finally:
        release.set()
        await client.close()


@pytest.mark.asyncio
async def test_slow_csrf_body_times_out_and_releases_concurrency_slot() -> None:
    config = SecurityConfig(
        allowed_hosts=("127.0.0.1",),
        session_signing_key=KEY,
        secure_cookies=False,
        csrf_cookie_name=COOKIE,
        csrf_max_age=300,
        request_body_timeout_seconds=0.05,
    )
    app = web.Application(
        middlewares=[
            bounded_concurrency_middleware(1, wait_timeout=0.02),
            security_middleware(config),
        ]
    )

    async def endpoint(_request: web.Request) -> web.Response:
        return web.Response(text="ok")

    app.add_routes([web.get("/", endpoint), web.post("/", endpoint)])
    client = TestClient(TestServer(app), cookie_jar=CookieJar(unsafe=True))
    await client.start_server()
    try:
        await client.get("/")
        token = _cookie(client)

        async def slow_form():
            yield f"_csrf={token}".encode()
            await asyncio.sleep(0.2)

        timed_out = await client.post(
            "/",
            data=slow_form(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": str(client.make_url("/")),
            },
        )
        assert timed_out.status == 408
        assert (await client.get("/")).status == 200
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_missing_csrf_cookie_is_rejected_without_reading_body() -> None:
    config = SecurityConfig(
        allowed_hosts=("127.0.0.1",),
        session_signing_key=KEY,
        secure_cookies=False,
        csrf_cookie_name=COOKIE,
        request_body_timeout_seconds=1,
    )
    app = web.Application(middlewares=[security_middleware(config)])

    async def unexpected(_request: web.Request) -> web.Response:
        return web.Response(text="unexpected")

    app.router.add_post("/", unexpected)
    client = TestClient(TestServer(app), cookie_jar=CookieJar(unsafe=True))
    await client.start_server()
    try:

        async def unread_body():
            yield b"_"
            await asyncio.sleep(0.5)
            yield b"csrf=invalid"

        response = await asyncio.wait_for(
            client.post(
                "/",
                data=unread_body(),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": str(client.make_url("/")),
                },
            ),
            timeout=0.2,
        )
        assert response.status == 403
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_non_send_multipart_is_rejected_before_a_slow_body_is_read() -> None:
    config = SecurityConfig(
        allowed_hosts=("127.0.0.1",),
        session_signing_key=KEY,
        secure_cookies=False,
        csrf_cookie_name=COOKIE,
        request_body_timeout_seconds=1,
    )
    app = web.Application(middlewares=[security_middleware(config)])

    async def endpoint(_request: web.Request) -> web.Response:
        return web.Response(text="unexpected")

    app.add_routes([web.get("/", endpoint), web.post("/account", endpoint)])
    client = TestClient(TestServer(app), cookie_jar=CookieJar(unsafe=True))
    await client.start_server()
    try:
        await client.get("/")
        token = _cookie(client)

        async def slow_multipart():
            yield b"--slow\r\n"
            await asyncio.sleep(0.5)
            yield b"--slow--\r\n"

        response = await asyncio.wait_for(
            client.post(
                "/account",
                data=slow_multipart(),
                headers={
                    "Content-Type": "multipart/form-data; boundary=slow",
                    "Origin": str(client.make_url("/")),
                    "X-CSRF-Token": token,
                },
            ),
            timeout=0.2,
        )
        assert response.status == 415
    finally:
        await client.close()
