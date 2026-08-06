"""Real-Chromium SPA, workflow, and loopback security checks."""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import time
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlencode, urlsplit

import pytest
from aiohttp import web
from conftest import (
    ACCOUNT,
    ACCOUNT_ADDRESS,
    ARCHIVE_MAILBOX,
    CERTIFICATE_FINGERPRINT,
    CERTIFICATE_NAME,
    COOKIE_NAME,
    LOGIN_CHALLENGE,
    LOGIN_PASSWORD,
    LOGIN_TOTP,
    MAILBOX,
    MESSAGE_ID,
    NEW_ACCOUNT,
    NEW_ACCOUNT_ID,
    NORMAL_ACCOUNT,
    NORMAL_ACCOUNT_ADDRESS,
    SENT_MAILBOX,
    SESSION_COOKIE_NAME,
    SESSION_TOKEN,
    TRASH_MAILBOX,
    BrowserSecurityGateway,
    LiveApplication,
    _listening_socket,
)

from maddyweb.web import MessagePage, create_app

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from playwright.async_api import Page, Route

pytestmark = pytest.mark.asyncio
CLIENT_SOURCE_PATH = Path(__file__).resolve().parents[2] / "src" / "maddyweb" / "static" / "app.js"
TOUCH_TARGET_GEOMETRY_TOLERANCE_PX = 0.01


async def _allow_loopback_only(route: Route) -> None:
    hostname = urlsplit(route.request.url).hostname
    if hostname in {"127.0.0.1", "localhost", "unlisted.invalid"}:
        await route.continue_()
    else:
        await route.abort()


@pytest.fixture
async def page() -> AsyncIterator[Page]:
    async_api = pytest.importorskip(
        "playwright.async_api",
        reason="install the 'browser' extra to run Chromium security tests",
        exc_type=ImportError,
    )
    async with async_api.async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=[
                "--no-proxy-server",
                "--host-resolver-rules=MAP unlisted.invalid 127.0.0.1",
            ],
        )
        context = await browser.new_context(accept_downloads=True)
        await context.route("**/*", _allow_loopback_only)
        browser_page = await context.new_page()
        try:
            yield browser_page
        finally:
            await context.close()
            await browser.close()


@pytest.fixture
async def normal_user_application(tmp_path: Path) -> AsyncIterator[LiveApplication]:
    gateway = BrowserSecurityGateway()
    gateway.principal = {
        "account_id": NORMAL_ACCOUNT,
        "email": NORMAL_ACCOUNT_ADDRESS,
        "role": "user",
        "password_change_required": False,
        "enrollment_state": "active",
        "idle_expires_at": 2_000_000_000,
        "absolute_expires_at": 2_000_010_000,
        "recovery_codes_remaining": 10,
    }
    gateway.accounts = [
        {
            "id": NORMAL_ACCOUNT,
            "address": NORMAL_ACCOUNT_ADDRESS,
            "has_credentials": True,
            "has_mailbox": True,
            "append_limit": None,
        }
    ]
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


async def _install_session(page: Page, application: LiveApplication) -> None:
    await page.context.add_cookies(
        [
            {
                "name": SESSION_COOKIE_NAME,
                "value": SESSION_TOKEN,
                "url": application.base_url,
                "httpOnly": True,
                "secure": False,
                "sameSite": "Strict",
            }
        ]
    )


def _api_request_paths(requests: list[str]) -> list[str]:
    return [urlsplit(url).path for url in requests if urlsplit(url).path.startswith("/api/v1/")]


async def test_normal_user_mail_defaults_to_own_inbox_with_minimal_requests(
    page: Page,
    normal_user_application: LiveApplication,
) -> None:
    await _install_session(page, normal_user_application)
    requests: list[str] = []
    page.on("request", lambda request: requests.append(request.url))

    await page.goto(normal_user_application.base_url + "/mail")
    await page.locator("#message-list-body tr").wait_for()

    assert await page.locator("#mail-account-field").is_hidden()
    assert await page.locator("#mail-account").input_value() == NORMAL_ACCOUNT
    assert await page.locator("#mail-mailbox").input_value() == MAILBOX
    assert await page.locator("#current-mailbox-identity").inner_text() == NORMAL_ACCOUNT_ADDRESS
    assert _api_request_paths(requests) == [
        "/api/v1/auth/session",
        "/api/v1/me/mail",
        "/api/v1/me/mail-events",
    ]


async def test_normal_user_hides_administrator_ui_before_session_resolution(
    page: Page,
    normal_user_application: LiveApplication,
) -> None:
    await _install_session(page, normal_user_application)
    session_requested = asyncio.Event()
    release_session = asyncio.Event()

    async def pause_session(route: Route) -> None:
        session_requested.set()
        await release_session.wait()
        await route.continue_()

    await page.route("**/api/v1/auth/session", pause_session)
    navigation = asyncio.create_task(
        page.goto(normal_user_application.base_url + "/mail", wait_until="domcontentloaded")
    )
    try:
        await asyncio.wait_for(session_requested.wait(), timeout=2)
        assert await page.locator("#mail-account-field").is_hidden()
        assert await page.locator("#admin-workspace-indicator").is_hidden()
        assert await page.locator('[data-role="admin"]').evaluate_all(
            "nodes => nodes.every(node => node.hidden)"
        )
    finally:
        release_session.set()
        await navigation


async def test_session_bootstrap_timeout_exits_connecting_with_retryable_error(
    page: Page,
    normal_user_application: LiveApplication,
) -> None:
    await _install_session(page, normal_user_application)
    session_requested = asyncio.Event()
    release_session = asyncio.Event()

    async def pause_session(route: Route) -> None:
        session_requested.set()
        await release_session.wait()
        await route.continue_()

    await page.clock.install()
    await page.route("**/api/v1/auth/session", pause_session)
    await page.goto(normal_user_application.base_url + "/mail", wait_until="domcontentloaded")
    try:
        await asyncio.wait_for(session_requested.wait(), timeout=2)
        assert await page.locator("html").get_attribute("data-auth-state") == "checking"
        assert await page.locator("#runtime-badge").inner_text() == "CONNECTING"

        await page.clock.fast_forward(12_001)

        alert = page.locator("#global-alert")
        await alert.wait_for(state="visible", timeout=2_000)
        assert await page.locator("html").get_attribute("data-auth-state") == "error"
        assert await page.locator("#runtime-badge").inner_text() == "CONNECTION FAILED"
        assert await page.locator("#startup-recovery").is_visible()
        assert await page.locator("#startup-recovery a").get_attribute("href") == ""
        assert await alert.inner_text() == (
            "The secure session request timed out. Reload the page to retry."
        )
    finally:
        release_session.set()


async def test_failed_workspace_script_exposes_reload_recovery_without_business_data(
    page: Page,
    normal_user_application: LiveApplication,
) -> None:
    await _install_session(page, normal_user_application)
    workspace_attempts = 0
    api_requests: list[str] = []

    async def fail_first_workspace_load(route: Route) -> None:
        nonlocal workspace_attempts
        workspace_attempts += 1
        if workspace_attempts == 1:
            await route.abort("failed")
            return
        await route.continue_()

    page.on(
        "request",
        lambda request: api_requests.append(urlsplit(request.url).path)
        if urlsplit(request.url).path.startswith("/api/v1/")
        else None,
    )
    await page.route("**/static/workspace.js?*", fail_first_workspace_load)
    await page.goto(normal_user_application.base_url + "/mail", wait_until="domcontentloaded")

    assert workspace_attempts == 1
    assert api_requests == []
    assert await page.locator("html").get_attribute("data-auth-state") == "checking"
    assert await page.locator("#runtime-badge").inner_text() == "CONNECTING"
    assert await page.locator('[data-role="admin"]').evaluate_all(
        "nodes => nodes.every(node => node.hidden)"
    )

    await page.locator("#startup-recovery").evaluate(
        "node => { node.style.animationDelay = '0s'; }"
    )
    recovery = page.locator("#startup-recovery")
    await recovery.wait_for(state="visible", timeout=2_000)
    assert "This page did not finish opening" in await recovery.inner_text()

    async with page.expect_navigation(wait_until="domcontentloaded"):
        await recovery.get_by_role("link", name="Reload this page").click()
    await page.locator("#message-list-body tr").wait_for()

    assert workspace_attempts == 2
    assert await page.locator("html").get_attribute("data-auth-state") == "active"
    assert await page.locator("#runtime-badge").inner_text() == "CONNECTED"
    assert await recovery.is_hidden()


async def test_bfcache_restore_reloads_a_failed_session_bootstrap(
    page: Page,
    normal_user_application: LiveApplication,
) -> None:
    await _install_session(page, normal_user_application)
    session_attempts = 0

    async def fail_first_session_load(route: Route) -> None:
        nonlocal session_attempts
        session_attempts += 1
        if session_attempts == 1:
            await route.fulfill(
                status=503,
                content_type="application/json",
                body=(
                    '{"api_version":"v1","ok":false,"error":'
                    '{"code":"authentication_unavailable",'
                    '"message":"Authentication is temporarily unavailable."}}'
                ),
            )
            return
        await route.continue_()

    await page.route("**/api/v1/auth/session", fail_first_session_load)
    await page.goto(normal_user_application.base_url + "/mail", wait_until="domcontentloaded")
    recovery = page.locator("#startup-recovery")
    await recovery.wait_for(state="visible", timeout=2_000)

    assert session_attempts == 1
    assert await page.locator("html").get_attribute("data-auth-state") == "error"

    async with page.expect_navigation(wait_until="domcontentloaded"):
        await page.evaluate(
            "window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}))"
        )
    await page.locator("#message-list-body tr").wait_for()

    assert session_attempts == 2
    assert await page.locator("html").get_attribute("data-auth-state") == "active"
    assert await page.locator("#runtime-badge").inner_text() == "CONNECTED"
    assert await recovery.is_hidden()


async def test_bfcache_restore_keeps_cached_mail_covered_when_revalidation_fails(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _load_inbox(page, live_application)

    async def fail_session_recheck(route: Route) -> None:
        await route.fulfill(
            status=503,
            content_type="application/json",
            body=json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "authentication_unavailable",
                        "message": "Authentication is temporarily unavailable.",
                    },
                }
            ),
        )

    await page.route("**/api/v1/auth/session", fail_session_recheck)
    await page.evaluate(
        """() => {
          window.dispatchEvent(new PageTransitionEvent("pagehide", {persisted: true}));
          window.dispatchEvent(new PageTransitionEvent("pageshow", {persisted: true}));
        }"""
    )

    guard = page.locator("#session-resume-guard")
    await guard.wait_for(state="visible")
    await page.locator("#session-resume-reload").wait_for(state="visible")
    assert await guard.get_attribute("role") == "alert"
    assert "Session check interrupted" in await guard.inner_text()
    assert await page.locator(".workspace").evaluate("node => node.inert")
    assert await page.locator("#message-list-body tr").count() == 1


async def test_required_password_change_opens_security_without_overview_flicker(
    page: Page,
    live_application: LiveApplication,
) -> None:
    live_application.gateway.principal["password_change_required"] = True
    await page.add_init_script(
        """(() => {
            window.__overviewWasVisible = false;
            const inspect = () => {
                const overview = document.getElementById("overview-view");
                if (overview && !overview.hidden) window.__overviewWasVisible = true;
            };
            new MutationObserver(inspect).observe(document, {
                subtree: true,
                attributes: true,
                attributeFilter: ["hidden"],
            });
            document.addEventListener("DOMContentLoaded", inspect);
        })();"""
    )

    await page.goto(live_application.base_url + "/")
    await page.wait_for_url("**/security")
    await page.get_by_role("heading", name="Security", exact=True).wait_for()

    assert await page.evaluate("window.__overviewWasVisible") is False
    assert await page.locator("#overview-view").is_hidden()
    assert await page.locator('a[data-section="security"]').is_visible()
    assert await page.locator('a[data-section="overview"]').is_hidden()


async def test_unconfigured_passkeys_are_not_offered(
    page: Page,
    live_application: LiveApplication,
) -> None:
    requested_paths: list[str] = []
    page.on("request", lambda request: requested_paths.append(urlsplit(request.url).path))

    await page.goto(live_application.base_url + "/security")
    await page.get_by_role("heading", name="Security", exact=True).wait_for()

    assert await page.locator("#passkey-registration-form").is_hidden()
    assert await page.locator("#security-passkey-state").inner_text() == "UNAVAILABLE"
    assert "/api/v1/auth/passkeys" not in requested_paths


async def test_session_timer_and_visibility_changes_do_not_extend_inactivity(
    page: Page,
    live_application: LiveApplication,
) -> None:
    now = int(time.time())
    live_application.gateway.principal["idle_expires_at"] = now + 10 * 60
    live_application.gateway.principal["absolute_expires_at"] = now + 60 * 60
    await page.add_init_script(
        """(() => {
            window.__sessionTestNow = Date.now();
            Date.now = () => window.__sessionTestNow;
            const originalSetInterval = window.setInterval.bind(window);
            window.setInterval = (callback, delay, ...args) => originalSetInterval(
                callback,
                delay === 30000 ? 25 : delay,
                ...args,
            );
        })();"""
    )
    session_requests: list[str] = []
    page.on(
        "request",
        lambda request: session_requests.append(urlsplit(request.url).path),
    )

    async def serve_login(route: Route) -> None:
        await route.fulfill(
            status=200,
            content_type="text/html",
            body="<!doctype html><title>Signed out</title>",
        )

    await page.route("**/login", serve_login)
    await page.goto(live_application.base_url + "/security")
    await page.get_by_role("heading", name="Security", exact=True).wait_for()
    assert session_requests.count("/api/v1/auth/session") == 1

    await page.evaluate(
        """() => {
            window.__sessionTestNow += 6 * 60 * 1000;
            document.dispatchEvent(new Event("visibilitychange"));
        }"""
    )
    await page.wait_for_timeout(100)
    assert session_requests.count("/api/v1/auth/session") == 1

    await page.evaluate("window.__sessionTestNow += 5 * 60 * 1000")
    await page.wait_for_url("**/login", timeout=2_000)
    assert session_requests.count("/api/v1/auth/session") == 1


async def test_session_countdown_includes_days_hours_and_minutes(
    page: Page,
    live_application: LiveApplication,
) -> None:
    now = int(time.time())
    live_application.gateway.principal["idle_expires_at"] = now + (
        2 * 24 * 60 * 60 + 3 * 60 * 60 + 4 * 60
    )
    live_application.gateway.principal["absolute_expires_at"] = now + 7 * 24 * 60 * 60
    await page.add_init_script(f"Date.now = () => {now * 1000};")

    await page.goto(live_application.base_url + "/security")
    await page.get_by_role("heading", name="Security", exact=True).wait_for()

    assert await page.locator("#session-expiry").inner_text() == (
        "Session expires in 2 d 3 h 4 mins"
    )


async def test_admin_mail_defaults_to_the_admins_own_inbox(
    page: Page,
    live_application: LiveApplication,
) -> None:
    requests: list[str] = []
    page.on("request", lambda request: requests.append(request.url))

    await page.goto(live_application.base_url + "/mail")
    await page.locator("#message-list-body tr").wait_for()

    assert await page.locator("#mail-account").input_value() == ACCOUNT
    assert await page.locator("#mail-mailbox").input_value() == MAILBOX
    assert await page.locator("#admin-workspace-indicator").is_visible()
    assert _api_request_paths(requests) == [
        "/api/v1/auth/session",
        "/api/v1/admin/mail",
        "/api/v1/admin/mail-events",
    ]


async def test_new_mail_notice_is_server_pushed_without_frontend_mailbox_polling(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.set_viewport_size({"width": 1280, "height": 800})
    requests: list[str] = []
    page.on("request", lambda request: requests.append(urlsplit(request.url).path))
    await _load_inbox(page, live_application)

    for _ in range(40):
        if live_application.gateway.notification_checks:
            break
        await asyncio.sleep(0.05)
    else:
        pytest.fail("the browser did not establish the mail event stream")

    mailbox_loads = requests.count("/api/v1/admin/mail")
    event_streams = requests.count("/api/v1/admin/mail-events")
    assert mailbox_loads >= 1
    assert event_streams == 1

    live_application.gateway.notification_uid += 1
    banner = page.locator("#new-mail-banner")
    notice = page.locator("#new-mail-notice")
    await banner.wait_for(state="visible", timeout=3_000)
    assert await page.locator("#new-mail-title").inner_text() == "New mail"
    assert await page.locator("#new-mail-summary").inner_text() == (
        "A new message arrived in Inbox."
    )
    assert await page.locator("#new-mail-time").count() == 0
    assert await page.locator("#new-mail-announcer").inner_text() == ("New mail arrived in Inbox.")
    assert await page.locator("#toast").is_hidden()
    assert await notice.get_attribute("href") == _mailbox_path()
    visible_notice = await banner.inner_text()
    assert "attacker@example.test" not in visible_notice
    assert "Browser security fixture" not in visible_notice

    bounds = await banner.bounding_box()
    assert bounds is not None
    assert abs((bounds["x"] + bounds["width"] / 2) - 640) <= 2
    assert bounds["y"] <= 28
    assert await banner.evaluate("node => getComputedStyle(node).borderRadius") == "20px"

    await asyncio.sleep(0.65)
    assert requests.count("/api/v1/admin/mail") == mailbox_loads
    assert requests.count("/api/v1/admin/mail-events") == event_streams

    requests_before_dismiss = list(requests)
    await page.locator("#new-mail-dismiss").click()
    await banner.wait_for(state="hidden")
    assert requests == requests_before_dismiss

    live_application.gateway.notification_uid += 1
    await banner.wait_for(state="visible", timeout=3_000)
    await page.evaluate(
        """() => {
          history.pushState(null, "", "/security");
          window.dispatchEvent(new PopStateEvent("popstate"));
        }"""
    )
    await page.get_by_role("heading", name="Security", exact=True).wait_for()
    assert await banner.is_visible()
    await notice.click()
    await page.wait_for_url(f"**{_mailbox_path()}")
    await page.locator("#message-list-body tr").wait_for()
    assert await banner.is_hidden()

    event_streams_before_restore = requests.count("/api/v1/admin/mail-events")
    session_requests_before_restore = requests.count("/api/v1/auth/session")
    session_recheck_started = asyncio.Event()
    release_session_recheck = asyncio.Event()

    async def pause_restored_session_recheck(route: Route) -> None:
        session_recheck_started.set()
        await release_session_recheck.wait()
        await route.continue_()

    await page.route("**/api/v1/auth/session", pause_restored_session_recheck)
    await page.evaluate(
        """() => {
          window.dispatchEvent(new PageTransitionEvent("pagehide", {persisted: true}));
          window.dispatchEvent(new PageTransitionEvent("pageshow", {persisted: true}));
        }"""
    )
    await asyncio.wait_for(session_recheck_started.wait(), timeout=2)
    guard = page.locator("#session-resume-guard")
    assert await guard.is_visible()
    assert await page.locator(".workspace").evaluate("node => node.inert")
    assert await page.locator(".app-header").evaluate("node => node.inert")
    release_session_recheck.set()
    await guard.wait_for(state="hidden")
    assert requests.count("/api/v1/auth/session") == session_requests_before_restore + 1
    for _ in range(40):
        if requests.count("/api/v1/admin/mail-events") > event_streams_before_restore:
            break
        await asyncio.sleep(0.05)
    else:
        pytest.fail("the mail event stream did not reconnect after a BFCache restore")


async def test_mailbox_placeholder_cannot_be_selected(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.goto(live_application.base_url + "/mail")
    await page.locator("#message-list-body tr").wait_for()

    mailbox = page.locator("#mail-mailbox")
    placeholder = mailbox.locator('option[value=""]')
    assert await mailbox.input_value() == MAILBOX
    assert await mailbox.is_enabled()
    assert await mailbox.is_hidden()
    assert await placeholder.get_attribute("disabled") is not None
    assert await placeholder.get_attribute("hidden") is not None
    assert await page.locator(".mail-select-shell .mail-account-mark").count() == 0

    folder_pane = await page.locator("#mail-folder-pane").bounding_box()
    account_select = await page.locator("#mail-account").bounding_box()
    assert folder_pane is not None
    assert account_select is not None
    assert account_select["x"] >= folder_pane["x"]
    assert account_select["x"] + account_select["width"] <= (
        folder_pane["x"] + folder_pane["width"] + 1
    )


async def test_mailbox_switch_shows_a_scoped_loading_state(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _load_inbox(page, live_application)
    request_started = asyncio.Event()
    release_request = asyncio.Event()

    async def pause_sent_mailbox(route: Route) -> None:
        if "mailbox=Sent" not in route.request.url:
            await route.continue_()
            return
        request_started.set()
        await release_request.wait()
        await route.continue_()

    await page.route("**/api/v1/admin/mail?*", pause_sent_mailbox)
    try:
        await page.locator('#mail-folder-list a[data-kind="sent"]').click()
        await asyncio.wait_for(request_started.wait(), timeout=2)

        loader = page.locator("#mail-switch-loader")
        assert await loader.is_visible()
        assert await page.locator("#mail-view").get_attribute("aria-busy") == "true"
        assert await page.locator("#mail-switch-title").inner_text() == "Opening Sent"
        assert await page.locator("#message-list-body tr").count() == 1
        assert (
            await page.locator('#mail-folder-list a[data-kind="sent"]').get_attribute(
                "aria-current"
            )
            == "page"
        )
    finally:
        release_request.set()

    await page.locator("#mail-switch-loader").wait_for(state="hidden")
    assert await page.locator("#mail-view").get_attribute("aria-busy") is None
    assert await page.locator("#mail-title").inner_text() == "Sent"
    assert await page.locator("#mail-mailbox").input_value() == "Sent"


async def test_failed_mailbox_switch_keeps_old_rows_covered_until_retry(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _load_inbox(page, live_application)
    sent_attempts = 0

    async def fail_first_sent_mailbox(route: Route) -> None:
        nonlocal sent_attempts
        if "mailbox=Sent" not in route.request.url:
            await route.continue_()
            return
        sent_attempts += 1
        if sent_attempts == 1:
            await route.fulfill(
                status=503,
                content_type="application/json",
                body=json.dumps(
                    {
                        "ok": False,
                        "error": {
                            "code": "mailbox_unavailable",
                            "message": "The requested mailbox is temporarily unavailable.",
                        },
                    }
                ),
            )
            return
        await route.continue_()

    await page.route("**/api/v1/admin/mail?*", fail_first_sent_mailbox)
    await page.locator('#mail-folder-list a[data-kind="sent"]').click()

    loader = page.locator("#mail-switch-loader")
    await loader.wait_for(state="visible")
    await page.locator("#mail-switch-retry").wait_for(state="visible")
    assert await loader.get_attribute("role") == "alert"
    assert await page.locator("#mail-view").get_attribute("aria-busy") is None
    assert "Previously loaded messages are hidden" in await loader.inner_text()
    assert await page.locator("#message-list-body tr").count() == 1
    assert "mailbox=Sent" in page.url

    loader_bounds = await loader.bounding_box()
    table_bounds = await page.locator(".mail-list-table").bounding_box()
    assert loader_bounds is not None
    assert table_bounds is not None
    assert loader_bounds["x"] <= table_bounds["x"] + 1
    assert loader_bounds["y"] <= table_bounds["y"] + 1
    assert loader_bounds["x"] + loader_bounds["width"] >= (
        table_bounds["x"] + table_bounds["width"] - 1
    )
    assert loader_bounds["y"] + loader_bounds["height"] >= (
        table_bounds["y"] + table_bounds["height"] - 1
    )

    await page.locator("#mail-switch-retry").click()
    await loader.wait_for(state="hidden")
    assert sent_attempts == 2
    assert await page.locator("#mail-title").inner_text() == "Sent"


@pytest.mark.parametrize("action", ["read", "move"])
async def test_row_mutations_expose_a_busy_state_on_slow_links(
    page: Page,
    live_application: LiveApplication,
    action: str,
) -> None:
    await _load_inbox(page, live_application)
    request_started = asyncio.Event()
    release_request = asyncio.Event()

    async def pause_mail_action(route: Route) -> None:
        request_started.set()
        await release_request.wait()
        await route.continue_()

    await page.route("**/api/v1/admin/mail-actions", pause_mail_action)
    row = page.locator("#message-list-body tr")
    try:
        if action == "move":
            await _message_menu_move(page, row, "Sent")
        else:
            await _message_menu_action(page, row, "mark-read")
        await asyncio.wait_for(request_started.wait(), timeout=2)
        assert await page.locator("#mail-bulk-toolbar").evaluate(
            "node => node.classList.contains('is-busy')"
        )
        assert await page.locator("#mail-select-page").is_disabled()
        assert await row.locator(".message-select-checkbox").is_disabled()
    finally:
        release_request.set()

    if action == "move":
        await page.locator("#message-empty").wait_for()
    else:
        await page.wait_for_function(
            "() => document.querySelector('.message-read-status')?.textContent === 'Read'"
        )


async def test_mailbox_read_state_and_bulk_selection_actions(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _load_inbox(page, live_application)
    row = page.locator("#message-list-body tr")
    assert await row.locator(".message-read-status").text_content() == "Unread"

    await row.locator(".message-select-checkbox").check()
    assert await page.locator("#mail-selection-count").inner_text() == "1 selected"
    assert await page.locator("#mail-select-page").is_checked()
    assert await page.locator("#mail-mark-read").count() == 0
    assert await page.locator("#mail-bulk-archive").count() == 0
    assert await page.locator("#mail-bulk-move-target").count() == 0
    await _message_menu_action(page, row, "mark-read")
    await page.wait_for_function(
        "() => document.querySelector('.message-read-status')?.textContent === 'Read'"
    )
    assert live_application.gateway.bulk_seen_changes[-1] == (
        ACCOUNT,
        MAILBOX,
        (MESSAGE_ID,),
        True,
    )

    await _message_menu_action(page, row, "mark-unread")
    await page.wait_for_function(
        "() => document.querySelector('.message-read-status')?.textContent === 'Unread'"
    )
    await page.locator("#mail-mark-all-read").click()
    await page.locator("#confirm-action").click()
    await page.wait_for_function(
        "() => document.querySelector('.message-read-status')?.textContent === 'Read'"
    )
    assert live_application.gateway.bulk_seen_changes[-1] == (
        ACCOUNT,
        MAILBOX,
        None,
        True,
    )

    await page.locator(".message-select-checkbox").check()
    await _message_menu_action(page, row, "archive")
    await page.locator("#message-empty").wait_for(state="visible")
    assert live_application.gateway.bulk_moves[-1] == (
        ACCOUNT,
        MAILBOX,
        (MESSAGE_ID,),
        ARCHIVE_MAILBOX,
    )


async def test_mail_selection_checkboxes_remain_compact_after_deselect(
    page: Page,
    live_application: LiveApplication,
) -> None:
    geometry_script = """
        node => {
          const bounds = node.getBoundingClientRect();
          const style = getComputedStyle(node);
          return {
            width: bounds.width,
            height: bounds.height,
            boxShadow: style.boxShadow,
          };
        }
    """
    for viewport_width in (1440, 390):
        await page.set_viewport_size({"width": viewport_width, "height": 844})
        await _load_mailbox(page, live_application, MAILBOX)
        row = page.locator("#message-list-body tr").first
        message_checkbox = row.locator(".message-select-checkbox")

        await message_checkbox.check()
        assert await page.locator("#mail-selection-count").inner_text() == "1 selected"
        await message_checkbox.uncheck()
        assert await message_checkbox.is_checked() is False
        assert await page.locator("#mail-selection-count").inner_text() == "0 selected"
        assert await row.evaluate(
            "node => node.classList.contains('is-bulk-selected')"
        ) is False
        message_geometry = await message_checkbox.evaluate(geometry_script)
        assert message_geometry["width"] <= 20
        assert message_geometry["height"] <= 20
        assert message_geometry["boxShadow"] == "none"

        page_checkbox = page.locator("#mail-select-page")
        await page_checkbox.check()
        await page_checkbox.uncheck()
        assert await page_checkbox.is_checked() is False
        assert await page.locator("#mail-selection-count").inner_text() == "0 selected"
        assert await row.evaluate(
            "node => node.classList.contains('is-bulk-selected')"
        ) is False
        page_geometry = await page_checkbox.evaluate(geometry_script)
        assert page_geometry["width"] <= 20
        assert page_geometry["height"] <= 20
        assert page_geometry["boxShadow"] == "none"


async def test_opening_an_unread_message_marks_it_read(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _load_inbox(page, live_application)
    row = page.locator("#message-list-body tr")
    assert await row.locator(".message-read-status").text_content() == "Unread"

    async with page.expect_response(
        lambda response: urlsplit(response.url).path.endswith("/mail-actions")
    ) as read_response:
        await row.locator(".message-subject-cell a").click()
    await page.get_by_role(
        "heading",
        name="Browser security fixture",
        exact=True,
    ).wait_for()
    await page.wait_for_function(
        "() => document.querySelector('.message-read-status')?.textContent === 'Read'"
    )

    assert (await read_response.value).status == 200
    assert await row.locator(".message-unread-dot").count() == 0
    menu = await _open_message_menu(page, row)
    assert await menu.locator(
        '[role="menuitem"][data-action="mark-unread"]'
    ).count() == 1
    assert live_application.gateway.bulk_seen_changes[-1] == (
        ACCOUNT,
        MAILBOX,
        (MESSAGE_ID,),
        True,
    )


def _message_path() -> str:
    query = urlencode({"account": ACCOUNT, "mailbox": MAILBOX})
    return f"/mail/{MESSAGE_ID}?{query}"


def _mailbox_path(mailbox: str = MAILBOX) -> str:
    query = urlencode({"account": ACCOUNT, "mailbox": mailbox})
    return f"/mail?{query}"


async def _load_inbox(page: Page, live_application: LiveApplication) -> None:
    await page.goto(live_application.base_url + "/mail")
    await page.locator("#mail-account").select_option(ACCOUNT)
    message_link = page.locator("#message-list-body a")
    await message_link.first.wait_for()
    assert await page.locator("#mail-account").input_value() == ACCOUNT
    assert await page.locator("#mail-mailbox").input_value() == MAILBOX
    await page.wait_for_url(f"**{_mailbox_path()}")
    assert await page.locator("#message-list-body img").count() == 0
    assert await page.locator("body").get_attribute("data-list-xss") is None


async def _load_mailbox(
    page: Page,
    live_application: LiveApplication,
    mailbox: str,
) -> None:
    query = urlencode({"account": ACCOUNT, "mailbox": mailbox})
    await page.goto(f"{live_application.base_url}/mail?{query}")
    await page.locator("#message-list-body tr").first.wait_for()
    assert await page.locator("#mail-mailbox").input_value() == mailbox


def _folder_item(page: Page, mailbox: str):
    return page.locator(f'.mail-folder-item[data-mailbox="{mailbox}"]')


async def _open_folder_menu(page: Page, mailbox: str):
    item = _folder_item(page, mailbox)
    button = item.locator(".mail-folder-menu-button")
    await button.scroll_into_view_if_needed()
    await page.wait_for_timeout(25)
    await button.click()
    menu = page.locator("#mail-folder-menu")
    await menu.wait_for(state="visible")
    return menu


async def _open_message_menu(page: Page, row, *, keyboard: bool = False):
    if keyboard:
        await row.focus()
        await row.press("Shift+F10")
    else:
        await row.click(button="right")
    menu = page.locator("#message-context-menu")
    await menu.wait_for(state="visible")
    return menu


async def _message_menu_action(
    page: Page,
    row,
    action: str,
    *,
    keyboard: bool = False,
) -> None:
    menu = await _open_message_menu(page, row, keyboard=keyboard)
    await menu.locator(f'[role="menuitem"][data-action="{action}"]').click()


async def _message_menu_move(page: Page, row, target_mailbox: str) -> None:
    menu = await _open_message_menu(page, row)
    await menu.locator('[role="menuitem"][data-action="move-to"]').click()
    await menu.locator(
        f'[role="menuitem"][data-target-mailbox="{target_mailbox}"]'
    ).click()


async def _open_message(page: Page, live_application: LiveApplication) -> None:
    await _load_inbox(page, live_application)
    message_link = page.locator("#message-list-body a")
    await message_link.click()
    await page.get_by_role(
        "heading",
        name="Browser security fixture",
        exact=True,
    ).wait_for()


async def _fill_write_body(page: Page, text: str) -> None:
    editor = page.locator("#message-editor")
    await editor.fill(text)
    assert await page.locator("#body-write-tab").get_attribute("aria-selected") == "true"


async def test_spa_navigation_loads_each_operational_view_without_document_reload(
    page: Page,
    live_application: LiveApplication,
) -> None:
    document_requests: list[str] = []

    def capture_documents(request: object) -> None:
        if getattr(request, "is_navigation_request", lambda: False)():
            document_requests.append(getattr(request, "url", ""))

    page.on("request", capture_documents)
    await page.goto(live_application.base_url + "/")
    await page.get_by_role(
        "heading",
        name="Administration overview",
        exact=True,
    ).wait_for()
    await page.locator("#health-application").get_by_text("Ready", exact=True).wait_for()
    assert await page.locator("#health-maddy").inner_text() == "Maddy 0.9.5"

    await page.locator('a[data-section="accounts"]').click()
    await page.wait_for_url("**/accounts")
    await page.locator("#accounts-body").get_by_text(ACCOUNT_ADDRESS, exact=True).wait_for()

    await page.locator('a[data-section="mail"]').click()
    await page.wait_for_url("**/mail")
    await page.get_by_role("heading", name=MAILBOX, exact=True).wait_for()
    await page.locator("#message-list-body tr").wait_for()

    await page.locator(".compose-action").click()
    await page.wait_for_url("**/compose")
    await page.locator("#compose-sender").select_option(ACCOUNT)

    await page.locator('a[data-section="certificates"]').click()
    await page.wait_for_url("**/certificates")
    await page.get_by_text(CERTIFICATE_NAME, exact=True).wait_for()
    assert await page.locator('a[data-section="certificates"][aria-current="page"]').count() == 1

    await page.go_back()
    await page.get_by_role("heading", name="Compose", exact=True).wait_for()
    assert len(document_requests) == 1


async def test_anonymous_browser_loads_only_login_then_completes_password_and_totp(
    page: Page,
    tmp_path: Path,
) -> None:
    gateway = BrowserSecurityGateway()
    app = create_app(  # type: ignore[arg-type]
        {
            "server": {
                "allowed_hosts": ("localhost",),
                "concurrency": 4,
                "max_upload_bytes": 4 * 1024 * 1024,
                "request_body_timeout_seconds": 5,
                "page_size": 20,
                "temp_dir": tmp_path,
            },
            "security": {
                "session_signing_key": secrets.token_bytes(32),
                "csrf_ttl_seconds": 300,
                "csrf_cookie_name": "__Host-maddyweb-login-csrf",
                "session_cookie_name": "__Host-maddyweb-login-session",
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
    requested_paths: list[str] = []

    def capture_request(request: object) -> None:
        requested_paths.append(urlsplit(getattr(request, "url", "")).path)

    page.on("request", capture_request)
    await page.context.clear_cookies()
    base_url = f"http://localhost:{port}"
    try:
        await page.goto(base_url + "/")
        await page.wait_for_url("**/login")
        await page.get_by_role("heading", name="Sign in to MaddyWeb", exact=True).wait_for()
        assert await page.locator("#passkey-login-panel").is_hidden()
        assert "/static/login.js" in requested_paths
        assert "/static/app.js" not in requested_paths
        unauthorized = await page.evaluate(
            """async () => {
                const response = await fetch("/api/v1/admin/accounts");
                return response.status;
            }"""
        )
        assert unauthorized == 401

        await page.locator("#login-address").fill(ACCOUNT_ADDRESS)
        await page.locator("#login-password").fill(LOGIN_PASSWORD)
        await page.locator("#login-submit").click()
        await page.locator("#totp-code").wait_for()
        await page.locator("#totp-code").fill(LOGIN_TOTP)
        totp_started = asyncio.Event()
        release_totp = asyncio.Event()

        async def pause_totp(route: Route) -> None:
            totp_started.set()
            await release_totp.wait()
            await route.continue_()

        await page.route("**/api/v1/auth/totp", pause_totp)
        await page.evaluate(
            """() => {
                window.__pendingLoginNavigation = null;
                window.requestAnimationFrame = callback => {
                    window.__pendingLoginNavigation = callback;
                    return 1;
                };
            }"""
        )
        totp_submit = page.locator("#totp-submit")
        initial_color = await totp_submit.evaluate("node => getComputedStyle(node).backgroundColor")
        try:
            await totp_submit.click()
            await asyncio.wait_for(totp_started.wait(), timeout=2)
            assert "is-verifying" in (await totp_submit.get_attribute("class") or "")
            assert await totp_submit.inner_text() == "Verifying..."
            assert await totp_submit.get_attribute("aria-busy") == "true"
            assert (
                await totp_submit.evaluate("node => getComputedStyle(node).backgroundColor")
                != initial_color
            )
        finally:
            release_totp.set()

        await page.wait_for_function("() => typeof window.__pendingLoginNavigation === 'function'")
        assert "is-verified" in (await totp_submit.get_attribute("class") or "")
        assert "is-verifying" not in (await totp_submit.get_attribute("class") or "")
        assert await totp_submit.inner_text() == "Verified. Signing in..."
        assert await totp_submit.get_attribute("aria-busy") == "true"
        assert (
            await totp_submit.evaluate("node => getComputedStyle(node).backgroundColor")
            != initial_color
        )
        assert "is-success" in (await page.locator("#auth-notice").get_attribute("class") or "")
        await page.evaluate(
            """() => {
                const callback = window.__pendingLoginNavigation;
                window.__pendingLoginNavigation = null;
                callback(performance.now());
            }"""
        )

        await page.wait_for_url(base_url + "/")
        await page.get_by_role(
            "heading",
            name="Administration overview",
            exact=True,
        ).wait_for()
        cookies = {cookie["name"]: cookie for cookie in await page.context.cookies(base_url)}
        session_cookie = cookies["__Host-maddyweb-login-session"]
        assert session_cookie["httpOnly"] is True
        assert session_cookie["secure"] is True
        assert session_cookie["sameSite"] == "Strict"
        assert session_cookie["path"] == "/"
        assert gateway.password_login_attempts == [(ACCOUNT_ADDRESS, LOGIN_PASSWORD, "127.0.0.1")]
        assert gateway.totp_login_attempts == [(LOGIN_CHALLENGE, LOGIN_TOTP, "127.0.0.1")]
    finally:
        await runner.cleanup()


async def test_failed_logout_retains_session_and_stays_in_application(
    page: Page,
    live_application: LiveApplication,
) -> None:
    live_application.gateway.logout_fails = True
    await page.goto(live_application.base_url + "/security")
    await page.locator("#security-logout-button").click()

    alert = page.locator("#global-alert")
    await alert.wait_for(state="visible")
    assert "Session revocation failed" in await alert.inner_text()
    assert page.url.endswith("/security")
    assert await page.locator("#security-logout-button").is_enabled()
    assert live_application.gateway.logout_attempts == 1
    cookies = await page.context.cookies(live_application.base_url)
    assert any(cookie["name"] == SESSION_COOKIE_NAME for cookie in cookies)


async def test_account_workflows_use_json_mutations_and_typed_deletion(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.goto(live_application.base_url + "/accounts")
    await page.locator("#accounts-body").get_by_text(ACCOUNT_ADDRESS, exact=True).wait_for()
    assert await page.locator("#runtime-badge").inner_text() == "CONNECTED"

    create_form = page.locator("#create-account-form")
    username_input = create_form.locator('input[name="username"]')
    assert await page.locator("#create-account-domain").inner_text() == "@example.test"
    assert await username_input.get_attribute("maxlength") == "64"
    await username_input.fill(NEW_ACCOUNT.split("@", 1)[0])
    await create_form.locator('input[name="password"]').fill("fixture-password-123")
    live_application.gateway.require_create_step_up = True
    await create_form.get_by_role("button", name="Create account").click()
    step_up_dialog = page.locator("#step-up-dialog")
    await step_up_dialog.wait_for(state="visible")
    assert await page.locator("#step-up-title").inner_text() == "Verify your identity"
    assert await page.locator("#step-up-passkey").is_hidden()
    assert await page.locator("#step-up-divider").is_hidden()
    await step_up_dialog.get_by_role("button", name="Cancel").click()
    await step_up_dialog.wait_for(state="hidden")
    assert live_application.gateway.created_accounts == []
    await create_form.locator('input[name="password"]').fill("fixture-password-123")
    await create_form.get_by_role("button", name="Create account").click()
    await step_up_dialog.wait_for(state="visible")
    await step_up_dialog.locator('input[name="password"]').fill(LOGIN_PASSWORD)
    await step_up_dialog.locator('input[name="code"]').fill(LOGIN_TOTP)
    await page.locator("#step-up-submit").click()
    await step_up_dialog.wait_for(state="hidden")
    new_row = page.locator("#accounts-body tr").filter(has_text=NEW_ACCOUNT)
    await new_row.wait_for()
    assert len(live_application.gateway.step_up_attempts) == 1
    assert live_application.gateway.step_up_attempts[0][:2] == (LOGIN_PASSWORD, LOGIN_TOTP)
    assert live_application.gateway.created_accounts == [(NEW_ACCOUNT, "fixture-password-123")]
    disclosure = page.locator("#credential-disclosure-dialog")
    await disclosure.wait_for(state="visible")
    assert await page.locator("#credential-disclosure-account").inner_text() == NEW_ACCOUNT
    assert (await page.locator("#credential-secret").inner_text()).replace(" ", "") == (
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    )
    assert await page.locator("#credential-recovery-codes li").all_inner_texts() == [
        "fixture-recovery-code"
    ]
    continue_button = page.locator("#credential-disclosure-continue")
    assert await continue_button.is_disabled()
    await page.locator("#credential-disclosure-acknowledged").check()
    assert await continue_button.is_enabled()
    await continue_button.click()
    await disclosure.wait_for(state="hidden")

    await new_row.get_by_role("button", name="Manage").click()
    password_form = page.locator("#change-password-form")
    await password_form.locator('input[name="password"]').fill("replacement-password-456")
    await password_form.get_by_role("button", name="Change password").click()
    await page.locator("#account-dialog").wait_for(state="hidden")
    assert live_application.gateway.password_changes == [
        (NEW_ACCOUNT_ID, "replacement-password-456")
    ]

    await new_row.get_by_role("button", name="Manage").click()
    limit_form = page.locator("#append-limit-form")
    await limit_form.locator('input[name="limit"]').fill("2097152")
    await limit_form.get_by_role("button", name="Set limit").click()
    await page.locator("#account-dialog").wait_for(state="hidden")
    await new_row.get_by_text("2,097,152", exact=True).wait_for()
    assert live_application.gateway.append_limit_changes == [(NEW_ACCOUNT_ID, 2_097_152)]

    await new_row.get_by_role("button", name="Manage").click()
    await page.locator("#disable-credentials").click()
    await page.locator("#confirm-dialog").wait_for(state="visible")
    await page.locator("#confirm-action").click()
    await page.locator("#confirm-dialog").wait_for(state="hidden")
    await new_row.get_by_text("Credentials disabled", exact=True).wait_for()
    assert live_application.gateway.disabled_accounts == [NEW_ACCOUNT_ID]

    await new_row.get_by_role("button", name="Manage").click()
    await page.locator("#delete-account").click()
    typed_dialog = page.locator("#typed-confirm-dialog")
    await typed_dialog.wait_for(state="visible")
    typed_input = page.locator("#typed-confirm-input")
    typed_action = page.locator("#typed-confirm-action")
    await typed_input.fill("wrong")
    assert await typed_action.is_disabled()
    await typed_input.fill(NEW_ACCOUNT)
    assert await typed_action.is_enabled()
    await typed_action.click()
    await typed_dialog.wait_for(state="hidden")
    await new_row.wait_for(state="detached")
    assert live_application.gateway.deleted_accounts == [NEW_ACCOUNT_ID]


async def test_certificate_controls_serialize_writes_and_refresh_status(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.goto(live_application.base_url + "/certificates")
    await page.get_by_text(CERTIFICATE_NAME, exact=True).wait_for()
    assert await page.locator("#timer-state").inner_text() == "Enabled"

    await page.locator("#timer-action").click()
    await page.locator("#confirm-action").click()
    await page.locator("#confirm-dialog").wait_for(state="hidden")
    await page.locator("#timer-state").get_by_text("Disabled", exact=True).wait_for()
    assert live_application.gateway.timer_changes == [False]

    certificate_row = page.locator("#certificates-body tr").filter(has_text=CERTIFICATE_NAME)
    await certificate_row.get_by_role("button", name="Dry-run").click()
    await page.locator("#confirm-action").click()
    await page.locator("#confirm-dialog").wait_for(state="hidden")
    assert live_application.gateway.certificate_dry_runs == [CERTIFICATE_NAME]

    await certificate_row.get_by_role("button", name="Renew if due").click()
    await page.locator("#confirm-action").click()
    await page.locator("#confirm-dialog").wait_for(state="hidden")
    assert live_application.gateway.certificate_renewals == [CERTIFICATE_NAME]


async def test_certificate_table_shows_full_fingerprints_and_contains_overflow(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.set_viewport_size({"width": 1280, "height": 900})
    await page.goto(live_application.base_url + "/certificates")
    certificate_row = page.locator("#certificates-body tr").filter(has_text=CERTIFICATE_NAME)
    await certificate_row.wait_for()

    fingerprints = certificate_row.locator(".certificate-fingerprint")
    assert await fingerprints.all_inner_texts() == [
        CERTIFICATE_FINGERPRINT,
        CERTIFICATE_FINGERPRINT,
    ]
    assert await fingerprints.evaluate_all("nodes => nodes.map((node) => node.title)") == [
        CERTIFICATE_FINGERPRINT,
        CERTIFICATE_FINGERPRINT,
    ]
    assert all("..." not in value for value in await fingerprints.all_inner_texts())

    values = certificate_row.locator("td:not(.certificate-actions) .certificate-cell-value")
    for index in range(await values.count()):
        assert (
            await values.nth(index).evaluate("node => getComputedStyle(node).whiteSpace")
            == "nowrap"
        )
    assert (
        await certificate_row.locator(".certificate-actions .button-row").evaluate(
            "node => getComputedStyle(node).flexWrap"
        )
        == "wrap"
    )

    table_scroll = page.locator("#certificates-view .table-scroll")
    assert await table_scroll.evaluate("node => node.scrollWidth > node.clientWidth")
    assert await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

    await page.set_viewport_size({"width": 2048, "height": 900})
    await page.wait_for_timeout(50)
    wide_metrics = await table_scroll.evaluate(
        "node => ({scrollWidth: node.scrollWidth, clientWidth: node.clientWidth})"
    )
    assert wide_metrics["scrollWidth"] <= wide_metrics["clientWidth"] + 1, wide_metrics
    assert await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

    await page.set_viewport_size({"width": 320, "height": 844})
    await page.wait_for_timeout(50)
    assert await table_scroll.evaluate("node => node.scrollWidth <= node.clientWidth + 1")
    assert await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert await certificate_row.locator(".certificate-mobile-label:visible").all_inner_texts() == [
        "NAME",
        "EXPIRATION",
        "SOURCE",
        "DEPLOYED",
        "MATCH",
        "ACTIONS",
    ]
    assert (
        await page.get_by_role(
            "columnheader",
            name="Source fingerprint",
        ).count()
        == 1
    )


async def test_rejects_unlisted_host(
    page: Page,
    live_application: LiveApplication,
) -> None:
    response = await page.goto(
        f"http://unlisted.invalid:{live_application.port}/",
        wait_until="domcontentloaded",
    )

    assert response is not None
    assert response.status == 400
    assert "Invalid Host" in await page.locator("body").inner_text()


async def test_rejects_cross_origin_form_submission(
    page: Page,
    live_application: LiveApplication,
    attacker_url: str,
) -> None:
    submitted_origins: list[str | None] = []

    def capture_origin(request: object) -> None:
        if getattr(request, "method", "") == "POST":
            submitted_origins.append(getattr(request, "headers", {}).get("origin"))

    page.on("request", capture_origin)
    await page.goto(live_application.base_url + "/")
    await page.goto(attacker_url)

    async with page.expect_navigation() as navigation:
        await page.locator("#cross-origin button").click()
    response = await navigation.value

    assert response is not None
    assert response.status == 403
    body = await page.locator("body").inner_text()
    assert "cross_site_rejected" in body
    assert submitted_origins == [attacker_url.rstrip("/")]
    assert live_application.gateway.permanent_deletions == []


async def test_rejects_missing_and_replayed_header_csrf(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.goto(live_application.base_url + "/")
    token = await page.evaluate(
        """async () => {
            const response = await fetch("/api/v1/auth/session");
            return (await response.json()).data.csrf_token;
        }"""
    )
    post_url = f"/api/v1/admin/mail/{MESSAGE_ID}/delete"
    body = {
        "account": ACCOUNT,
        "mailbox": MAILBOX,
        "freshness": "not-used-for-invalid-confirmation",
        "confirmation": "wrong",
    }

    missing = await page.evaluate(
        """async ({url, body}) => {
            const response = await fetch(url, {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify(body),
            });
            return {
                status: response.status,
                payload: await response.json(),
                replacement: response.headers.get("X-CSRF-Token"),
            };
        }""",
        {"url": post_url, "body": body},
    )
    assert missing["status"] == 403
    assert missing["payload"]["error"]["code"] == "csrf_failed"
    assert missing["replacement"]
    token = missing["replacement"]

    attempted = await page.evaluate(
        """async ({url, body, token}) => {
            const response = await fetch(url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": token,
                },
                body: JSON.stringify(body),
            });
            return {
                status: response.status,
                payload: await response.json(),
                replacement: response.headers.get("X-CSRF-Token"),
            };
        }""",
        {"url": post_url, "body": body, "token": token},
    )
    assert attempted["status"] == 400
    assert attempted["payload"]["error"]["code"] == "invalid_request"
    assert attempted["replacement"]
    assert attempted["replacement"] != token

    replayed = await page.evaluate(
        """async ({url, body, token}) => {
            const response = await fetch(url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": token,
                },
                body: JSON.stringify(body),
            });
            return {status: response.status, payload: await response.json()};
        }""",
        {"url": post_url, "body": body, "token": token},
    )
    assert replayed["status"] == 403
    assert replayed["payload"]["error"]["code"] in {"csrf_failed", "csrf_reused"}
    assert live_application.gateway.permanent_deletions == []


async def test_mailbox_auto_opens_inbox_and_rows_support_pointer_and_keyboard_navigation(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _load_inbox(page, live_application)
    assert await page.get_by_role("button", name="Open", exact=True).count() == 0
    row = page.locator("#message-list-body tr")
    assert await row.get_attribute("tabindex") == "0"

    await row.locator("td").first.click()
    await page.wait_for_url(f"**{_message_path()}")
    expected_summary = f"{ACCOUNT_ADDRESS} / {MAILBOX} / UID {MESSAGE_ID}"
    await page.wait_for_function(
        "expected => document.querySelector('#message-summary')?.textContent === expected",
        arg=expected_summary,
    )
    assert await page.locator("#message-summary").inner_text() == expected_summary
    await page.go_back()
    await page.locator("#message-list-body tr").wait_for()

    row = page.locator("#message-list-body tr")
    await row.focus()
    await row.press(" ")
    await page.wait_for_url(f"**{_message_path()}")

    await page.set_viewport_size({"width": 320, "height": 844})
    await _load_mailbox(page, live_application, MAILBOX)
    quick_actions = page.locator(".message-quick-actions")
    assert await quick_actions.is_visible()
    assert await quick_actions.locator(
        ".message-row-action:not(.message-more-button)"
    ).evaluate_all("nodes => nodes.every(node => getComputedStyle(node).display === 'none')")
    more = page.locator(".message-more-button")
    assert await more.is_visible()
    assert await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    bounds = await more.bounding_box()
    assert bounds is not None
    assert bounds["height"] >= 44 - TOUCH_TARGET_GEOMETRY_TOLERANCE_PX
    assert bounds["width"] >= 44 - TOUCH_TARGET_GEOMETRY_TOLERANCE_PX


async def test_mailbox_rows_fit_the_desktop_message_pane(
    page: Page,
    live_application: LiveApplication,
) -> None:
    for width in (1440, 1074, 1024):
        await page.set_viewport_size({"width": width, "height": 900})
        await _load_inbox(page, live_application)
        await page.mouse.move(0, 0)

        pane = page.locator("#mail-view")
        pane_bounds = await pane.bounding_box()
        row = page.locator("#message-list-body tr")
        row_before = await row.bounding_box()
        subject = row.locator(".message-subject-cell")
        subject_bounds = await subject.bounding_box()
        quick_actions = row.locator(".message-quick-actions")
        assert pane_bounds is not None
        assert row_before is not None
        assert subject_bounds is not None
        assert await page.locator(".mail-list-table").evaluate(
            "node => node.scrollWidth <= node.clientWidth"
        )
        assert await quick_actions.evaluate(
            "node => getComputedStyle(node).opacity === '0'"
        )
        assert await quick_actions.evaluate(
            "node => getComputedStyle(node).pointerEvents === 'none'"
        )

        await row.hover()
        await page.wait_for_function(
            "() => getComputedStyle(document.querySelector("
            "'.message-quick-actions')).opacity === '1'"
        )
        row_after = await row.bounding_box()
        quick_bounds = await quick_actions.bounding_box()
        assert row_after is not None
        assert quick_bounds is not None
        assert abs(row_after["height"] - row_before["height"]) <= 1
        assert await quick_actions.evaluate(
            "node => getComputedStyle(node).flexWrap === 'nowrap'"
        )
        for action in await quick_actions.locator("button").all():
            bounds = await action.bounding_box()
            assert bounds is not None
            assert bounds["x"] >= pane_bounds["x"]
            assert bounds["x"] + bounds["width"] <= pane_bounds["x"] + pane_bounds["width"] + 1
        if width == 1024:
            assert quick_bounds["x"] < subject_bounds["x"] + subject_bounds["width"]


async def test_message_actions_switch_from_hover_to_touch_at_the_mobile_boundary(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.set_viewport_size({"width": 901, "height": 900})
    await _load_inbox(page, live_application)
    row = page.locator("#message-list-body tr")
    quick_actions = row.locator(".message-quick-actions")
    assert await quick_actions.evaluate(
        "node => getComputedStyle(node).opacity === '0'"
    )
    await row.hover()
    await page.wait_for_function(
        "() => getComputedStyle(document.querySelector("
        "'.message-quick-actions')).opacity === '1'"
    )

    await page.set_viewport_size({"width": 900, "height": 900})
    assert await quick_actions.is_visible()
    assert await quick_actions.locator(
        ".message-row-action:not(.message-more-button)"
    ).evaluate_all("nodes => nodes.every(node => getComputedStyle(node).display === 'none')")
    more = row.locator(".message-more-button")
    assert await more.is_visible()
    bounds = await more.bounding_box()
    assert bounds is not None
    assert bounds["height"] >= 44 - TOUCH_TARGET_GEOMETRY_TOLERANCE_PX


async def test_message_actions_do_not_cover_read_status_badges(
    page: Page,
    live_application: LiveApplication,
) -> None:
    async def messages_with_both_read_states(
        _account: str,
        mailbox: str,
        **_kwargs: object,
    ) -> MessagePage:
        if mailbox != MAILBOX:
            return MessagePage([], False)
        return MessagePage(
            [
                {
                    "id": MESSAGE_ID,
                    "sender": "read@example.test",
                    "subject": "Read message",
                    "date": "2026-08-06 12:00 UTC",
                    "unread": False,
                },
                {
                    "id": "43",
                    "sender": "unread@example.test",
                    "subject": "Unread message",
                    "date": "2026-08-06 11:00 UTC",
                    "unread": True,
                },
            ],
            False,
        )

    live_application.gateway.list_messages = (  # type: ignore[method-assign]
        messages_with_both_read_states
    )
    for viewport_width in (1440, 1024, 901, 900, 390):
        await page.set_viewport_size({"width": viewport_width, "height": 844})
        await _load_mailbox(page, live_application, MAILBOX)
        rows = page.locator("#message-list-body tr")
        assert await rows.count() == 2

        for row in await rows.all():
            status = row.locator(".message-read-status")
            quick_actions = row.locator(".message-quick-actions")
            more = row.locator(".message-more-button")
            if viewport_width > 900:
                await row.hover()
                await page.wait_for_function(
                    "node => getComputedStyle(node.querySelector("
                    "'.message-quick-actions')).opacity === '1'",
                    arg=await row.element_handle(),
                )
            assert await status.is_visible()
            assert await quick_actions.is_visible()
            assert await more.is_visible()

            geometry = await status.evaluate(
                """node => {
                    const bounds = node.getBoundingClientRect();
                    const range = document.createRange();
                    range.selectNodeContents(node);
                    const textBounds = range.getBoundingClientRect();
                    const actions = node.closest('tr')
                        .querySelector('.message-quick-actions')
                        .getBoundingClientRect();
                    const more = node.closest('tr')
                        .querySelector('.message-more-button')
                        .getBoundingClientRect();
                    return {
                        bounds: {
                            left: bounds.left,
                            right: bounds.right,
                            width: bounds.width,
                        },
                        textBounds: {
                            left: textBounds.left,
                            right: textBounds.right,
                            width: textBounds.width,
                        },
                        actions: {left: actions.left, right: actions.right},
                        more: {left: more.left, right: more.right},
                        clientWidth: node.clientWidth,
                        scrollWidth: node.scrollWidth,
                    };
                }"""
            )
            assert geometry["scrollWidth"] <= geometry["clientWidth"] + 1
            assert geometry["textBounds"]["left"] >= geometry["bounds"]["left"] - 1
            assert geometry["textBounds"]["right"] <= geometry["bounds"]["right"] + 1
            assert (
                geometry["bounds"]["right"] <= geometry["actions"]["left"] + 1
                or geometry["actions"]["right"] <= geometry["bounds"]["left"] + 1
            )
            assert (
                geometry["bounds"]["right"] <= geometry["more"]["left"] + 1
                or geometry["more"]["right"] <= geometry["bounds"]["left"] + 1
            )


async def test_hover_quick_actions_are_compact_and_do_not_open_the_message(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.set_viewport_size({"width": 1440, "height": 900})
    await _load_inbox(page, live_application)
    row = page.locator("#message-list-body tr")
    quick_actions = row.locator(".message-quick-actions")
    await row.hover()
    await page.wait_for_function(
        "() => getComputedStyle(document.querySelector("
        "'.message-quick-actions')).opacity === '1'"
    )

    labels = set(
        await quick_actions.locator("button[aria-label]").evaluate_all(
            "nodes => nodes.map(node => node.getAttribute('aria-label'))"
        )
    )
    assert {"Mark as read", "Archive", "Move to Trash", "Move to folder"}.issubset(
        labels
    )
    assert not {"Reply", "Reply all", "Forward", "Forward as attachment"}.intersection(
        labels
    )
    more = row.locator(".message-more-button")
    assert await more.count() == 1
    more_style = await more.evaluate(
        """node => {
            const style = getComputedStyle(node);
            const iconStyle = getComputedStyle(node.querySelector("svg"));
            return {
                borderTopWidth: style.borderTopWidth,
                borderRightWidth: style.borderRightWidth,
                borderBottomWidth: style.borderBottomWidth,
                borderLeftWidth: style.borderLeftWidth,
                boxShadow: style.boxShadow,
                iconWidth: Number.parseFloat(iconStyle.width),
                iconHeight: Number.parseFloat(iconStyle.height),
                iconStrokeWidth: Number.parseFloat(iconStyle.strokeWidth),
            };
        }"""
    )
    assert {
        key: value
        for key, value in more_style.items()
        if key not in {"iconWidth", "iconHeight", "iconStrokeWidth"}
    } == {
        "borderTopWidth": "0px",
        "borderRightWidth": "0px",
        "borderBottomWidth": "0px",
        "borderLeftWidth": "0px",
        "boxShadow": "none",
    }
    regular_stroke_width = await quick_actions.locator(
        ".message-row-action:not(.message-more-button) svg"
    ).first.evaluate("node => Number.parseFloat(getComputedStyle(node).strokeWidth)")
    assert more_style["iconWidth"] >= 20
    assert more_style["iconHeight"] >= 20
    assert more_style["iconStrokeWidth"] >= 4.5
    assert more_style["iconStrokeWidth"] >= regular_stroke_width + 2
    controls = await quick_actions.locator("button").all()
    control_rows = []
    for control in controls:
        bounds = await control.bounding_box()
        assert bounds is not None
        control_rows.append(round(bounds["y"]))
    assert max(control_rows) - min(control_rows) <= 1

    await quick_actions.get_by_role("button", name="Mark as read", exact=True).click()
    await page.wait_for_function(
        "() => document.querySelector('.message-read-status')?.textContent === 'Read'"
    )
    assert urlsplit(page.url).path == "/mail"


async def test_all_mail_keeps_each_messages_source_mailbox_context(
    page: Page,
    live_application: LiveApplication,
) -> None:
    query = urlencode({"account": ACCOUNT, "view": "all"})
    await page.goto(f"{live_application.base_url}/mail?{query}")

    await page.get_by_role("heading", name="All Mail", exact=True).wait_for()
    assert await page.locator("#mail-mailbox").input_value() == "__all__"
    assert await page.locator(
        '.mail-folder-link[data-kind="all"]'
    ).get_attribute("aria-current") == "page"
    row = page.locator("#message-list-body tr")
    await row.wait_for()
    assert await row.get_attribute("data-mailbox") == MAILBOX
    assert await row.locator(".message-mailbox-label").inner_text() == MAILBOX

    await row.locator(".message-subject-cell a").click()
    await page.wait_for_url(
        f"**/mail/{MESSAGE_ID}?account={ACCOUNT}&mailbox={MAILBOX}&view=all"
    )
    await page.get_by_role(
        "heading", name="Browser security fixture", exact=True
    ).wait_for()
    back_href = ""
    for _ in range(50):
        back_href = await page.locator("#message-back").get_attribute("href") or ""
        if "view=all" in back_href:
            break
        await asyncio.sleep(0.02)
    back_url = urlsplit(back_href)
    assert back_url.path == "/mail"
    assert "view=all" in back_url.query


async def test_desktop_hover_actions_do_not_cover_all_mail_badges(
    page: Page,
    live_application: LiveApplication,
) -> None:
    query = urlencode({"account": ACCOUNT, "view": "all"})
    for viewport_width in (1440, 1024, 901):
        await page.set_viewport_size({"width": viewport_width, "height": 844})
        await page.goto(f"{live_application.base_url}/mail?{query}")
        row = page.locator("#message-list-body tr")
        await row.wait_for()
        await row.hover()
        await page.wait_for_function(
            "node => getComputedStyle(node.querySelector("
            "'.message-quick-actions')).opacity === '1'",
            arg=await row.element_handle(),
        )

        geometry = await row.evaluate(
            """node => {
                const bounds = selector => {
                    const box = node.querySelector(selector).getBoundingClientRect();
                    return {left: box.left, right: box.right, width: box.width};
                };
                return {
                    actions: bounds('.message-quick-actions'),
                    status: bounds('.message-read-status'),
                    mailbox: bounds('.message-mailbox-label'),
                };
            }"""
        )
        assert geometry["actions"]["right"] <= geometry["status"]["left"] + 1
        assert geometry["actions"]["right"] <= geometry["mailbox"]["left"] + 1
        assert geometry["status"]["width"] > 0
        assert geometry["mailbox"]["width"] > 0


async def test_all_mail_batches_freshness_once_per_source_before_any_move(
    page: Page,
    live_application: LiveApplication,
) -> None:
    source_messages = {
        MAILBOX: ("42", "43"),
        SENT_MAILBOX: ("44", "45"),
    }

    async def messages_by_source(
        _account: str,
        mailbox: str,
        **_kwargs: object,
    ) -> MessagePage:
        return MessagePage(
            [
                {
                    "id": uid,
                    "sender": f"sender-{uid}@example.test",
                    "subject": f"Grouped message {uid}",
                    "date": f"2026-07-23 12:{uid} UTC",
                    "unread": True,
                }
                for uid in source_messages.get(mailbox, ())
            ],
            False,
        )

    live_application.gateway.list_messages = messages_by_source  # type: ignore[method-assign]
    second_preflight_ready = asyncio.Event()
    release_second_preflight = asyncio.Event()
    snapshot_requests: list[dict[str, object]] = []

    async def hold_second_snapshot(route: Route) -> None:
        payload = route.request.post_data_json
        assert isinstance(payload, dict)
        snapshot_requests.append(payload)
        response = await route.fetch()
        if len(snapshot_requests) == 2:
            second_preflight_ready.set()
            await release_second_preflight.wait()
        await route.fulfill(response=response)

    await page.route(
        "**/api/v1/admin/mail/action-snapshots",
        hold_second_snapshot,
    )
    await page.goto(
        live_application.base_url
        + "/mail?"
        + urlencode({"account": ACCOUNT, "view": "all"})
    )
    await page.get_by_role("heading", name="All Mail", exact=True).wait_for()
    await page.locator("#message-list-body tr").nth(3).wait_for()
    await page.locator("#mail-select-page").check()
    await _message_menu_move(
        page,
        page.locator("#message-list-body tr").first,
        ARCHIVE_MAILBOX,
    )

    await asyncio.wait_for(second_preflight_ready.wait(), timeout=2)
    assert live_application.gateway.bulk_moves == []
    assert len(snapshot_requests) == 2
    by_mailbox = {str(payload["mailbox"]): payload for payload in snapshot_requests}
    assert by_mailbox == {
        mailbox: {
            "account": ACCOUNT,
            "mailbox": mailbox,
            "uids": list(uids),
        }
        for mailbox, uids in source_messages.items()
    }

    release_second_preflight.set()
    for _attempt in range(100):
        if len(live_application.gateway.bulk_moves) == 2:
            break
        await asyncio.sleep(0.02)
    assert live_application.gateway.bulk_moves == [
        (ACCOUNT, MAILBOX, source_messages[MAILBOX], ARCHIVE_MAILBOX),
        (ACCOUNT, SENT_MAILBOX, source_messages[SENT_MAILBOX], ARCHIVE_MAILBOX),
    ]


async def test_normal_user_batch_snapshot_never_sends_an_account_override(
    page: Page,
    normal_user_application: LiveApplication,
) -> None:
    await _install_session(page, normal_user_application)
    requests: list[object] = []

    def capture_request(request: object) -> None:
        path = urlsplit(getattr(request, "url", "")).path
        if path.endswith(("/action-snapshots", "/mail-actions")):
            requests.append(request)

    page.on("request", capture_request)
    await page.goto(normal_user_application.base_url + "/mail")
    row = page.locator("#message-list-body tr")
    await row.wait_for()
    await _message_menu_action(page, row, "archive")
    await page.locator("#message-empty").wait_for()

    assert [
        (getattr(request, "method", ""), urlsplit(getattr(request, "url", "")).path)
        for request in requests
    ] == [
        ("POST", "/api/v1/me/mail/action-snapshots"),
        ("POST", "/api/v1/me/mail-actions"),
    ]
    assert all("account" not in getattr(request, "post_data_json", {}) for request in requests)
    assert normal_user_application.gateway.bulk_moves == [
        (NORMAL_ACCOUNT, MAILBOX, (MESSAGE_ID,), ARCHIVE_MAILBOX)
    ]


async def test_row_bulk_and_detail_move_controls_target_existing_folders(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _load_inbox(page, live_application)
    row = page.locator("#message-list-body tr")
    await _message_menu_move(page, row, "Sent")
    await page.locator("#message-empty").wait_for()
    assert live_application.gateway.bulk_moves[-1] == (
        ACCOUNT,
        MAILBOX,
        (MESSAGE_ID,),
        "Sent",
    )

    live_application.gateway.message_location = MAILBOX
    await page.goto(live_application.base_url + _mailbox_path())
    await page.locator("#message-list-body tr").wait_for()
    selected_row = page.locator("#message-list-body tr")
    await selected_row.locator(".message-select-checkbox").check()
    await _message_menu_move(page, selected_row, "Sent")
    await page.locator("#message-empty").wait_for()
    assert live_application.gateway.bulk_moves[-1] == (
        ACCOUNT,
        MAILBOX,
        (MESSAGE_ID,),
        "Sent",
    )

    live_application.gateway.message_location = MAILBOX
    await page.goto(live_application.base_url + _message_path())
    await page.get_by_role(
        "heading", name="Browser security fixture", exact=True
    ).wait_for()
    await page.locator("#message-move-target").select_option("Sent")
    await page.locator("#message-move").click()
    await page.wait_for_url(f"**{_mailbox_path()}")
    assert live_application.gateway.bulk_moves[-1] == (
        ACCOUNT,
        MAILBOX,
        (MESSAGE_ID,),
        "Sent",
    )


async def test_message_context_menu_scopes_single_and_bulk_actions(
    page: Page,
    live_application: LiveApplication,
) -> None:
    second_message_id = "43"

    async def two_messages(
        _account: str,
        mailbox: str,
        **_kwargs: object,
    ) -> MessagePage:
        if mailbox != MAILBOX:
            return MessagePage([], False)
        return MessagePage(
            [
                {
                    "id": uid,
                    "sender": f"sender-{uid}@example.test",
                    "subject": f"Context message {uid}",
                    "date": "2026-08-06 12:00 UTC",
                    "unread": True,
                }
                for uid in (MESSAGE_ID, second_message_id)
            ],
            False,
        )

    live_application.gateway.list_messages = two_messages  # type: ignore[method-assign]
    await _load_inbox(page, live_application)
    rows = page.locator("#message-list-body tr")
    await rows.nth(1).wait_for()

    menu = await _open_message_menu(page, rows.nth(1))
    assert await rows.first.locator(".message-select-checkbox").is_checked() is False
    assert await rows.nth(1).locator(".message-select-checkbox").is_checked() is False
    assert await page.locator("#mail-selection-count").inner_text() == "0 selected"
    assert await menu.locator('[role="menuitem"][data-action="open"]').is_visible()
    await page.keyboard.press("Escape")

    await rows.first.locator(".message-select-checkbox").check()
    menu = await _open_message_menu(page, rows.first)
    assert await page.locator("#mail-selection-count").inner_text() == "1 selected"
    single_actions = set(
        await menu.locator('[role="menuitem"][data-action]').evaluate_all(
            "nodes => nodes.map(node => node.dataset.action)"
        )
    )
    assert {
        "open",
        "open-new-tab",
        "reply",
        "reply-all",
        "forward",
        "forward-attachment",
        "mark-read",
        "move-to",
        "archive",
        "trash",
    }.issubset(single_actions)
    await page.keyboard.press("Escape")

    menu = await _open_message_menu(page, rows.nth(1))
    assert await rows.first.locator(".message-select-checkbox").is_checked()
    assert await rows.nth(1).locator(".message-select-checkbox").is_checked() is False
    assert await page.locator("#mail-selection-count").inner_text() == "1 selected"
    unselected_row_actions = set(
        await menu.locator('[role="menuitem"][data-action]').evaluate_all(
            "nodes => nodes.map(node => node.dataset.action)"
        )
    )
    assert {"open", "reply", "reply-all", "forward"}.issubset(unselected_row_actions)
    await page.keyboard.press("Escape")

    await page.locator("#mail-select-page").check()
    menu = await _open_message_menu(page, rows.first)
    assert await rows.first.locator(".message-select-checkbox").is_checked()
    assert await rows.nth(1).locator(".message-select-checkbox").is_checked()
    assert await page.locator("#mail-selection-count").inner_text() == "2 selected"
    bulk_actions = set(
        await menu.locator('[role="menuitem"][data-action]').evaluate_all(
            "nodes => nodes.map(node => node.dataset.action)"
        )
    )
    assert {"mark-read", "mark-unread", "move-to", "archive", "trash"}.issubset(
        bulk_actions
    )
    assert not {"open", "reply", "reply-all", "forward"}.intersection(bulk_actions)
    await menu.locator('[role="menuitem"][data-action="mark-read"]').click()
    for _attempt in range(50):
        if live_application.gateway.bulk_seen_changes:
            break
        await asyncio.sleep(0.02)
    assert live_application.gateway.bulk_seen_changes[-1] == (
        ACCOUNT,
        MAILBOX,
        (MESSAGE_ID, second_message_id),
        True,
    )


async def test_message_context_menu_supports_keyboard_and_stays_in_the_viewport(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.set_viewport_size({"width": 1024, "height": 600})
    await _load_inbox(page, live_application)
    row = page.locator("#message-list-body tr")

    menu = await _open_message_menu(page, row, keyboard=True)
    assert await menu.locator('[role="menuitem"]').first.evaluate(
        "node => node === document.activeElement"
    )
    await page.keyboard.press("End")
    assert await menu.locator('[role="menuitem"]:not([disabled])').last.evaluate(
        "node => node === document.activeElement"
    )
    await page.keyboard.press("Home")
    assert await menu.locator('[role="menuitem"]:not([disabled])').first.evaluate(
        "node => node === document.activeElement"
    )
    await page.keyboard.press("Escape")
    await menu.wait_for(state="hidden")
    assert await row.evaluate("node => node === document.activeElement")

    await row.evaluate(
        """node => node.dispatchEvent(new MouseEvent("contextmenu", {
          bubbles: true,
          cancelable: true,
          clientX: window.innerWidth - 1,
          clientY: window.innerHeight - 1,
        }))"""
    )
    await menu.wait_for(state="visible")
    bounds = await menu.bounding_box()
    assert bounds is not None
    assert bounds["x"] >= 0
    assert bounds["y"] >= 0
    assert bounds["x"] + bounds["width"] <= 1024 + 1
    assert bounds["y"] + bounds["height"] <= 600 + 1

    await page.evaluate("document.dispatchEvent(new Event('scroll'))")
    await menu.wait_for(state="hidden")
    await _open_message_menu(page, row)
    await page.locator("#mail-title").click()
    await menu.wait_for(state="hidden")
    await _open_message_menu(page, row)
    await page.set_viewport_size({"width": 1000, "height": 600})
    await menu.wait_for(state="hidden")
    await _open_message_menu(page, row)
    await page.locator('a[data-section="security"]').click()
    await page.get_by_role("heading", name="Security", exact=True).wait_for()
    assert await menu.is_hidden()


async def test_message_context_menu_uses_icons_and_fits_a_tall_viewport(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.set_viewport_size({"width": 1280, "height": 1000})
    await _load_inbox(page, live_application)
    menu = await _open_message_menu(page, page.locator("#message-list-body tr"))
    items = menu.locator('[role="menuitem"]')

    assert await items.count() >= 8
    assert await items.evaluate_all(
        """nodes => nodes.every(node => (
            node.firstElementChild?.matches("svg[aria-hidden='true']")
            && node.lastElementChild?.matches(".context-menu-item-label")
        ))"""
    )
    assert await menu.evaluate("node => node.scrollHeight <= node.clientHeight")
    bounds = await menu.bounding_box()
    assert bounds is not None
    assert bounds["x"] >= 0
    assert bounds["y"] >= 0
    assert bounds["x"] + bounds["width"] <= 1280 + 1
    assert bounds["y"] + bounds["height"] <= 1000 + 1


async def test_message_context_menu_closes_on_browser_history_navigation(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _load_inbox(page, live_application)
    row = page.locator("#message-list-body tr")
    await page.evaluate("history.pushState(null, '', '/security')")
    menu = await _open_message_menu(page, row)
    assert await menu.is_visible()

    await page.go_back()
    await menu.wait_for(state="hidden")
    await page.get_by_role("heading", name=MAILBOX, exact=True).wait_for()


async def test_message_more_button_opens_the_full_menu_on_touch_layouts(
    page: Page,
    live_application: LiveApplication,
) -> None:
    for width in (390, 320):
        await page.set_viewport_size({"width": width, "height": 844})
        await _load_mailbox(page, live_application, MAILBOX)
        row = page.locator("#message-list-body tr")
        more = row.locator(".message-more-button")
        quick_actions = row.locator(".message-quick-actions")
        await more.scroll_into_view_if_needed()
        await page.wait_for_timeout(25)
        assert await quick_actions.evaluate(
            "node => getComputedStyle(node).backgroundColor"
        ) == await row.evaluate("node => getComputedStyle(node).backgroundColor")
        await more.click()
        menu = page.locator("#message-context-menu")
        await menu.wait_for(state="visible")
        assert await quick_actions.evaluate(
            "node => getComputedStyle(node).backgroundColor"
        ) == await row.evaluate("node => getComputedStyle(node).backgroundColor")
        assert await menu.locator(
            '[role="menuitem"][data-action="forward"]'
        ).is_visible()
        assert await menu.locator(
            '[role="menuitem"][data-action="move-to"]'
        ).is_visible()
        bounds = await more.bounding_box()
        assert bounds is not None
        assert bounds["height"] >= 44 - TOUCH_TARGET_GEOMETRY_TOLERANCE_PX
        assert bounds["width"] >= 44 - TOUCH_TARGET_GEOMETRY_TOLERANCE_PX
        await page.keyboard.press("Escape")


async def test_touch_more_button_applies_to_the_selected_message_set(
    page: Page,
    live_application: LiveApplication,
) -> None:
    second_message_id = "43"

    async def two_messages(
        _account: str,
        mailbox: str,
        **_kwargs: object,
    ) -> MessagePage:
        if mailbox != MAILBOX:
            return MessagePage([], False)
        return MessagePage(
            [
                {
                    "id": uid,
                    "sender": f"sender-{uid}@example.test",
                    "subject": f"Touch message {uid}",
                    "date": "2026-08-06 12:00 UTC",
                    "unread": True,
                }
                for uid in (MESSAGE_ID, second_message_id)
            ],
            False,
        )

    live_application.gateway.list_messages = two_messages  # type: ignore[method-assign]
    await page.set_viewport_size({"width": 390, "height": 844})
    await _load_mailbox(page, live_application, MAILBOX)
    await page.locator("#mail-select-page").check()
    rows = page.locator("#message-list-body tr")
    await rows.first.locator(".message-more-button").click()

    menu = page.locator("#message-context-menu")
    await menu.wait_for(state="visible")
    assert await menu.locator(".context-menu-heading").inner_text() == "2 selected"
    assert await menu.locator('[data-action="open"]').count() == 0
    await menu.locator('[data-action="mark-read"]').click()
    for _attempt in range(50):
        if live_application.gateway.bulk_seen_changes:
            break
        await asyncio.sleep(0.02)
    assert live_application.gateway.bulk_seen_changes[-1] == (
        ACCOUNT,
        MAILBOX,
        (MESSAGE_ID, second_message_id),
        True,
    )


async def test_message_menu_does_not_create_a_persistent_selection(
    page: Page,
    live_application: LiveApplication,
) -> None:
    second_message_id = "43"

    async def two_messages(
        _account: str,
        mailbox: str,
        **_kwargs: object,
    ) -> MessagePage:
        if mailbox != MAILBOX:
            return MessagePage([], False)
        return MessagePage(
            [
                {
                    "id": uid,
                    "sender": f"sender-{uid}@example.test",
                    "subject": f"Transient menu state {uid}",
                    "date": "2026-08-06 12:00 UTC",
                    "unread": True,
                }
                for uid in (MESSAGE_ID, second_message_id)
            ],
            False,
        )

    live_application.gateway.list_messages = two_messages  # type: ignore[method-assign]
    await page.set_viewport_size({"width": 900, "height": 844})
    await _load_mailbox(page, live_application, MAILBOX)
    row = page.locator("#message-list-body tr").nth(1)
    checkbox = row.locator(".message-select-checkbox")
    more = row.locator(".message-more-button")
    menu = page.locator("#message-context-menu")
    initial_background = await row.evaluate(
        "node => getComputedStyle(node).backgroundColor"
    )

    await more.click()
    await menu.wait_for(state="visible")
    assert await checkbox.is_checked() is False
    assert await page.locator("#mail-selection-count").inner_text() == "0 selected"
    assert await row.evaluate("node => node.classList.contains('is-context-open')")
    assert await row.evaluate("node => node.classList.contains('is-bulk-selected')") is False

    await page.keyboard.press("Escape")
    await menu.wait_for(state="hidden")
    await page.mouse.move(0, 0)
    await page.wait_for_timeout(150)
    assert await more.get_attribute("aria-expanded") == "false"
    assert await checkbox.is_checked() is False
    assert await page.locator("#mail-selection-count").inner_text() == "0 selected"
    assert await row.evaluate("node => node.classList.contains('is-context-open')") is False
    assert await row.evaluate("node => node.classList.contains('is-bulk-selected')") is False
    assert await row.evaluate(
        "node => getComputedStyle(node).backgroundColor"
    ) == initial_background

    await row.click(button="right")
    await menu.wait_for(state="visible")
    assert await checkbox.is_checked() is False
    assert await page.locator("#mail-selection-count").inner_text() == "0 selected"
    assert await row.evaluate("node => node.classList.contains('is-context-open')")
    assert await row.evaluate("node => node.classList.contains('is-bulk-selected')") is False

    await page.keyboard.press("Escape")
    await menu.wait_for(state="hidden")
    await page.mouse.move(0, 0)
    await page.wait_for_timeout(150)
    assert await row.evaluate("node => node.classList.contains('is-context-open')") is False
    assert await row.evaluate("node => node.classList.contains('is-bulk-selected')") is False
    assert await checkbox.is_checked() is False
    assert await page.locator("#mail-selection-count").inner_text() == "0 selected"
    assert await row.evaluate(
        "node => getComputedStyle(node).backgroundColor"
    ) == initial_background


async def test_same_message_menu_opener_toggles_closed_and_clears_transient_state(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.set_viewport_size({"width": 900, "height": 844})
    await _load_mailbox(page, live_application, MAILBOX)
    row = page.locator("#message-list-body tr")
    more = row.locator(".message-more-button")
    menu = page.locator("#message-context-menu")

    await more.scroll_into_view_if_needed()
    await page.wait_for_timeout(25)
    await more.click()
    await menu.wait_for(state="visible")
    assert await more.get_attribute("aria-expanded") == "true"
    assert await row.evaluate("node => node.classList.contains('is-context-open')")

    await more.evaluate("node => node.click()")
    await menu.wait_for(state="hidden")
    assert await more.get_attribute("aria-expanded") == "false"
    assert await row.evaluate("node => node.classList.contains('is-context-open')") is False
    assert await page.locator(
        '#message-list-body [aria-controls="message-context-menu"][aria-expanded="true"]'
    ).count() == 0


async def test_quick_action_background_tracks_normal_opened_and_bulk_row_fills(
    page: Page,
    live_application: LiveApplication,
) -> None:
    message_ids = (MESSAGE_ID, "43", "44")

    async def three_messages(
        _account: str,
        mailbox: str,
        **_kwargs: object,
    ) -> MessagePage:
        if mailbox != MAILBOX:
            return MessagePage([], False)
        return MessagePage(
            [
                {
                    "id": uid,
                    "sender": f"sender-{uid}@example.test",
                    "subject": f"Row fill state {uid}",
                    "date": "2026-08-06 12:00 UTC",
                    "unread": True,
                }
                for uid in message_ids
            ],
            False,
        )

    live_application.gateway.list_messages = three_messages  # type: ignore[method-assign]
    await page.set_viewport_size({"width": 900, "height": 844})
    await _load_mailbox(page, live_application, MAILBOX)
    rows = page.locator("#message-list-body tr")
    normal_row = rows.nth(2)
    normal_actions = normal_row.locator(".message-quick-actions")
    normal_background = await normal_row.evaluate(
        "node => getComputedStyle(node).backgroundColor"
    )
    assert await normal_actions.evaluate(
        "node => getComputedStyle(node).backgroundColor"
    ) == normal_background

    normal_more = normal_row.locator(".message-more-button")
    await normal_more.click()
    await page.locator("#message-context-menu").wait_for(state="visible")
    await page.keyboard.press("Escape")
    await page.locator("#message-context-menu").wait_for(state="hidden")
    await page.mouse.move(0, 0)
    await page.wait_for_timeout(150)
    assert await normal_row.evaluate(
        "node => getComputedStyle(node).backgroundColor"
    ) == normal_background
    assert await normal_actions.evaluate(
        "node => getComputedStyle(node).backgroundColor"
    ) == normal_background

    await rows.nth(1).locator(".message-select-checkbox").check()
    await rows.first.locator(".message-subject-cell a").click()
    await page.wait_for_url(f"**{_message_path()}")

    opened_row = page.locator(f'#message-list-body tr[data-uid="{MESSAGE_ID}"]')
    bulk_row = page.locator('#message-list-body tr[data-uid="43"]')
    normal_row = page.locator('#message-list-body tr[data-uid="44"]')
    assert await opened_row.evaluate("node => node.classList.contains('is-selected')")
    assert await bulk_row.evaluate("node => node.classList.contains('is-bulk-selected')")
    assert await normal_row.evaluate(
        "node => !node.classList.contains('is-selected') "
        "&& !node.classList.contains('is-bulk-selected')"
    )

    backgrounds: list[str] = []
    for row in (opened_row, bulk_row, normal_row):
        row_background = await row.evaluate(
            "node => getComputedStyle(node).backgroundColor"
        )
        action_background = await row.locator(".message-quick-actions").evaluate(
            "node => getComputedStyle(node).backgroundColor"
        )
        assert action_background == row_background
        backgrounds.append(row_background)
    assert len(set(backgrounds)) == 3


async def test_folder_creation_uses_a_bounded_inline_form_and_opens_the_folder(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _load_inbox(page, live_application)
    toggle = page.locator("#mail-folder-create-toggle")
    await toggle.click()
    assert await toggle.get_attribute("aria-expanded") == "true"
    await page.locator("#mail-folder-name").fill("Projects/2026")
    async with page.expect_response(
        lambda response: response.request.method == "POST"
        and response.url.endswith("/api/v1/admin/mailboxes")
    ) as created_response:
        await page.locator("#mail-folder-create-form").get_by_role(
            "button", name="Create", exact=True
        ).click()
    assert (await created_response.value).status == 201
    await page.wait_for_url("**/mail?account=*&mailbox=Projects%2F2026")
    assert live_application.gateway.created_mailboxes == [
        (ACCOUNT, "Projects/2026")
    ]
    for _ in range(50):
        if await page.locator("#mail-mailbox").input_value() == "Projects/2026":
            break
        await asyncio.sleep(0.02)
    assert await page.locator("#mail-mailbox").input_value() == "Projects/2026"


async def test_custom_folder_menu_renames_the_clicked_non_current_folder(
    page: Page,
    live_application: LiveApplication,
) -> None:
    live_application.gateway.extra_mailboxes.extend(["Projects", "Receipts"])
    await _load_inbox(page, live_application)

    menu = await _open_folder_menu(page, "Projects")
    await menu.locator('[role="menuitem"][data-action="rename"]').click()
    dialog = page.locator("#folder-rename-dialog")
    await dialog.wait_for(state="visible")
    name = page.locator("#folder-rename-name")
    assert await name.input_value() == "Projects"
    await name.fill("Client projects")
    async with page.expect_response(
        lambda response: response.request.method == "POST"
        and response.url.endswith("/api/v1/admin/mailboxes/rename")
    ) as renamed_response:
        await page.locator("#folder-rename-submit").click()

    assert (await renamed_response.value).status == 200
    await dialog.wait_for(state="hidden")
    assert live_application.gateway.renamed_mailboxes == [
        (ACCOUNT, "Projects", "Client projects")
    ]
    await _folder_item(page, "Client projects").wait_for()
    assert await _folder_item(page, "Projects").count() == 0
    assert await _folder_item(page, "Client projects").count() == 1
    assert await page.locator("#mail-mailbox").input_value() == MAILBOX
    assert f"mailbox={MAILBOX}" in page.url


async def test_folder_menu_and_rename_conflict_preserve_focus_and_context(
    page: Page,
    live_application: LiveApplication,
) -> None:
    live_application.gateway.extra_mailboxes.append("Projects")
    await _load_inbox(page, live_application)
    button = _folder_item(page, "Projects").locator(".mail-folder-menu-button")

    menu = await _open_folder_menu(page, "Projects")
    assert await button.get_attribute("aria-expanded") == "true"
    await page.keyboard.press("Escape")
    await menu.wait_for(state="hidden")
    assert await button.get_attribute("aria-expanded") == "false"
    assert await button.evaluate("node => node === document.activeElement")

    async def reject_referenced_folder(route: Route) -> None:
        await route.fulfill(
            status=409,
            content_type="application/json",
            body=json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "mailbox_in_use",
                        "message": "The folder is referenced by an enabled mail rule.",
                    },
                }
            ),
        )

    await page.route(
        "**/api/v1/admin/mailboxes/rename",
        reject_referenced_folder,
    )
    menu = await _open_folder_menu(page, "Projects")
    await menu.locator('[role="menuitem"][data-action="rename"]').click()
    await page.locator("#folder-rename-name").fill("Referenced projects")
    await page.locator("#folder-rename-submit").click()

    dialog = page.locator("#folder-rename-dialog")
    await dialog.get_by_text("enabled mail rule", exact=False).wait_for()
    assert await dialog.is_visible()
    assert live_application.gateway.renamed_mailboxes == []
    assert await page.locator("#mail-mailbox").input_value() == MAILBOX


async def test_same_folder_menu_opener_toggles_closed_and_clears_expanded_state(
    page: Page,
    live_application: LiveApplication,
) -> None:
    live_application.gateway.extra_mailboxes.append("Projects")
    await _load_inbox(page, live_application)
    item = _folder_item(page, "Projects")
    button = item.locator(".mail-folder-menu-button")
    menu = page.locator("#mail-folder-menu")

    await _open_folder_menu(page, "Projects")
    assert await button.get_attribute("aria-expanded") == "true"

    await button.evaluate("node => node.click()")
    await menu.wait_for(state="hidden")
    assert await button.get_attribute("aria-expanded") == "false"
    assert await page.locator(
        '#mail-folder-list [aria-controls="mail-folder-menu"][aria-expanded="true"]'
    ).count() == 0


async def test_custom_folder_delete_targets_the_clicked_non_current_folder(
    page: Page,
    live_application: LiveApplication,
) -> None:
    live_application.gateway.extra_mailboxes.append("Projects")
    await _load_inbox(page, live_application)

    menu = await _open_folder_menu(page, "Projects")
    await menu.locator('[role="menuitem"][data-action="delete"]').click()
    await page.locator(
        '#folder-delete-form input[name="disposition"][value="trash"]'
    ).check()
    await page.locator("#folder-delete-confirmation").fill("Projects")
    await page.locator("#folder-delete-submit").click()

    await page.locator("#folder-delete-dialog").wait_for(state="hidden")
    assert live_application.gateway.deleted_mailboxes == [
        (ACCOUNT, "Projects", "trash", None)
    ]
    assert await page.locator("#mail-mailbox").input_value() == MAILBOX
    assert f"mailbox={MAILBOX}" in page.url


async def test_custom_folder_delete_moves_messages_before_removing_the_folder(
    page: Page,
    live_application: LiveApplication,
) -> None:
    live_application.gateway.extra_mailboxes.append("Projects")
    live_application.gateway.message_location = "Projects"
    await page.goto(live_application.base_url + _mailbox_path("Projects"))
    folder_item = _folder_item(page, "Projects")
    await folder_item.wait_for()
    assert await page.locator("#mail-folder-delete").count() == 0
    item_bounds = await folder_item.bounding_box()
    button_bounds = await folder_item.locator(
        ".mail-folder-menu-button"
    ).bounding_box()
    assert item_bounds is not None
    assert button_bounds is not None
    assert button_bounds["x"] >= item_bounds["x"]
    assert button_bounds["x"] + button_bounds["width"] <= (
        item_bounds["x"] + item_bounds["width"] + 1
    )

    menu = await _open_folder_menu(page, "Projects")
    assert await menu.locator('[role="menuitem"][data-action="rename"]').count() == 1
    await menu.locator('[role="menuitem"][data-action="delete"]').click()
    dialog = page.locator("#folder-delete-dialog")
    await dialog.wait_for()
    assert await dialog.get_by_text(
        "Move messages to another folder", exact=True
    ).is_visible()
    await page.locator("#folder-delete-target").select_option(MAILBOX)
    await page.locator("#folder-delete-confirmation").fill("Project")
    assert await page.locator("#folder-delete-submit").is_disabled()
    await page.locator("#folder-delete-confirmation").fill("Projects")

    async with page.expect_response(
        lambda response: response.request.method == "POST"
        and response.url.endswith("/api/v1/admin/mailboxes/delete")
    ) as deleted_response:
        await page.locator("#folder-delete-submit").click()
    assert (await deleted_response.value).status == 200
    await page.wait_for_url(f"**{_mailbox_path(MAILBOX)}")
    assert live_application.gateway.deleted_mailboxes == [
        (ACCOUNT, "Projects", "move", MAILBOX)
    ]
    assert live_application.gateway.message_location == MAILBOX
    assert "Projects" not in live_application.gateway.extra_mailboxes


async def test_custom_folder_delete_can_move_every_message_to_trash(
    page: Page,
    live_application: LiveApplication,
) -> None:
    live_application.gateway.extra_mailboxes.append("Temporary")
    live_application.gateway.message_location = "Temporary"
    await page.goto(live_application.base_url + _mailbox_path("Temporary"))
    menu = await _open_folder_menu(page, "Temporary")
    await menu.locator('[role="menuitem"][data-action="delete"]').click()
    await page.locator(
        '#folder-delete-form input[name="disposition"][value="trash"]'
    ).check()
    assert await page.locator("#folder-delete-target").is_disabled()
    await page.locator("#folder-delete-confirmation").fill("Temporary")
    await page.locator("#folder-delete-submit").click()

    await page.wait_for_url(f"**{_mailbox_path(TRASH_MAILBOX)}")
    assert live_application.gateway.deleted_mailboxes == [
        (ACCOUNT, "Temporary", "trash", None)
    ]
    assert live_application.gateway.message_location == TRASH_MAILBOX


async def test_ambiguous_folder_delete_keeps_the_dialog_and_requires_refresh(
    page: Page,
    live_application: LiveApplication,
) -> None:
    live_application.gateway.extra_mailboxes.append("Temporary")
    await page.goto(live_application.base_url + _mailbox_path("Temporary"))

    async def fail_delete(route: Route) -> None:
        await route.fulfill(
            status=502,
            content_type="application/json",
            body=json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "helper_unavailable",
                        "message": "The folder operation could not be confirmed.",
                    },
                }
            ),
        )

    await page.route("**/api/v1/admin/mailboxes/delete", fail_delete)
    menu = await _open_folder_menu(page, "Temporary")
    await menu.locator('[role="menuitem"][data-action="delete"]').click()
    await page.locator("#folder-delete-confirmation").fill("Temporary")
    await page.locator("#folder-delete-submit").click()

    dialog = page.locator("#folder-delete-dialog")
    await dialog.get_by_text("The result may be unknown", exact=False).wait_for()
    assert await dialog.is_visible()
    assert "mailbox=Temporary" in page.url


async def test_folder_cards_and_message_header_keep_actions_scoped(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.set_viewport_size({"width": 1074, "height": 1000})
    live_application.gateway.extra_mailboxes.append("Projects")
    await _load_inbox(page, live_application)

    tools = await page.locator("#mail-folder-tools").bounding_box()
    selector = await page.locator("#mail-selector").bounding_box()
    assert tools is not None
    assert selector is not None
    assert selector["y"] >= tools["y"] + tools["height"] + 12
    assert await page.locator("#mail-folder-delete").count() == 0
    assert await _folder_item(page, MAILBOX).locator(
        ".mail-folder-menu-button"
    ).count() == 0
    assert await _folder_item(page, SENT_MAILBOX).locator(
        ".mail-folder-menu-button"
    ).count() == 0
    assert await _folder_item(page, "Projects").locator(
        ".mail-folder-menu-button"
    ).count() == 1

    assert await page.locator("#mail-select-page").is_visible()
    assert await page.locator("#mail-selection-count").is_visible()
    assert await page.locator("#mail-mark-all-read").is_visible()
    for removed in (
        "#mail-mark-read",
        "#mail-mark-unread",
        "#mail-bulk-archive",
        "#mail-bulk-trash",
        "#mail-bulk-move-target",
        "#mail-bulk-move",
    ):
        assert await page.locator(removed).count() == 0


async def test_folder_menu_uses_icons_and_danger_hover_feedback(
    page: Page,
    live_application: LiveApplication,
) -> None:
    live_application.gateway.extra_mailboxes.append("Projects")
    await _load_inbox(page, live_application)
    menu = await _open_folder_menu(page, "Projects")
    items = menu.locator('[role="menuitem"]')

    folder_more_icon = _folder_item(page, "Projects").locator(
        ".mail-folder-menu-button svg"
    )
    folder_more_style = await folder_more_icon.evaluate(
        """node => {
            const style = getComputedStyle(node);
            return {
                width: Number.parseFloat(style.width),
                height: Number.parseFloat(style.height),
                strokeWidth: Number.parseFloat(style.strokeWidth),
            };
        }"""
    )
    assert folder_more_style["width"] >= 20
    assert folder_more_style["height"] >= 20
    assert folder_more_style["strokeWidth"] >= 4.5

    assert await items.count() == 2
    assert await items.evaluate_all(
        """nodes => nodes.every(node => (
            node.firstElementChild?.matches("svg[aria-hidden='true']")
            && node.lastElementChild?.matches(".context-menu-item-label")
        ))"""
    )
    delete = menu.locator('[role="menuitem"][data-action="delete"]')
    assert await delete.get_attribute("class") == "context-menu-item is-danger"
    background_before = await delete.evaluate(
        "node => getComputedStyle(node).backgroundColor"
    )
    menu_background = await menu.evaluate(
        "node => getComputedStyle(node).backgroundColor"
    )
    await delete.hover()
    background_after = await delete.evaluate(
        "node => getComputedStyle(node).backgroundColor"
    )
    assert background_after != background_before
    assert background_after != menu_background
    assert background_after not in {"transparent", "rgba(0, 0, 0, 0)"}


async def test_trash_bulk_permanent_delete_is_available_from_the_context_menu(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.set_viewport_size({"width": 1440, "height": 1000})
    live_application.gateway.message_location = TRASH_MAILBOX
    await page.goto(live_application.base_url + _mailbox_path(TRASH_MAILBOX))
    row = page.locator("#message-list-body tr")
    await row.wait_for()
    await row.locator(".message-select-checkbox").check()
    menu = await _open_message_menu(page, row)
    assert await menu.locator(
        '[role="menuitem"][data-action="permanent-delete"]'
    ).is_enabled()
    assert await menu.locator('[role="menuitem"][data-action="trash"]').count() == 0


async def test_completed_folder_creation_does_not_hijack_a_newer_route(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _load_inbox(page, live_application)
    request_started = asyncio.Event()
    release_request = asyncio.Event()

    async def pause_folder_creation(route: Route) -> None:
        request_started.set()
        await release_request.wait()
        await route.continue_()

    await page.route("**/api/v1/admin/mailboxes", pause_folder_creation)
    await page.locator("#mail-folder-create-toggle").click()
    await page.locator("#mail-folder-name").fill("Slow folder")
    await page.locator("#mail-folder-create-form").get_by_role(
        "button", name="Create", exact=True
    ).click()
    await asyncio.wait_for(request_started.wait(), timeout=2)

    await page.locator('a[data-section="security"]').click()
    await page.get_by_role("heading", name="Security", exact=True).wait_for()
    release_request.set()
    for _ in range(50):
        if live_application.gateway.created_mailboxes:
            break
        await asyncio.sleep(0.02)

    assert live_application.gateway.created_mailboxes == [(ACCOUNT, "Slow folder")]
    assert urlsplit(page.url).path == "/security"


async def test_mail_rule_builder_posts_the_canonical_bounded_condition_tree(
    page: Page,
    live_application: LiveApplication,
) -> None:
    posted: list[dict[str, object]] = []
    stored_rules: list[dict[str, object]] = []
    first_save_started = asyncio.Event()
    release_first_save = asyncio.Event()

    async def mail_rules(route: Route) -> None:
        request = route.request
        if request.method == "GET":
            payload = {"ok": True, "data": {"rules": stored_rules}}
        else:
            body = json.loads(request.post_data or "{}")
            posted.append(body)
            if len(posted) == 1:
                first_save_started.set()
                await release_first_save.wait()
            rule = {
                "rule_id": "11111111111111111111111111111111",
                "name": body["name"],
                "enabled": body["enabled"],
                "match": body["match"],
                "target_mailbox": body["target_mailbox"],
                "stop_processing": body["stop_processing"],
                "revision": int(body.get("expected_revision", 0)) + 1,
            }
            stored_rules[:] = [rule]
            payload = {"ok": True, "data": {"rule": rule}, "message": "Rule created."}
        await route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(payload),
        )

    await page.route("**/api/v1/admin/mail-rules**", mail_rules)
    await _load_inbox(page, live_application)
    await page.locator('.nav-link[data-section="rules"]').click()
    await page.get_by_role("heading", name="Mail rules", exact=True).wait_for()

    await page.locator("#mail-rule-name").fill("File project reports")
    await page.locator("#mail-rule-target").select_option(ARCHIVE_MAILBOX)
    root_group = page.locator("#mail-rule-condition-tree > .rule-condition-group")
    await root_group.get_by_role("button", name="Add nested group").click()
    condition_values = page.locator(".rule-condition-value")
    await condition_values.nth(0).fill("reports@example.test")
    nested_group = page.locator('.rule-condition-group[data-depth="2"]')
    await nested_group.locator(".rule-operator-select").select_option("or")
    await condition_values.nth(1).fill("Quarterly")
    root_heading = root_group.locator(":scope > .rule-condition-group-heading")
    await root_heading.get_by_role("button", name="Add condition", exact=True).click()
    await root_heading.get_by_role("button", name="Add condition", exact=True).click()
    fields = page.locator(".rule-condition-field")
    comparisons = page.locator(".rule-condition-test")
    await fields.nth(2).select_option("size")
    await comparisons.nth(2).select_option("gt")
    await page.locator(".rule-condition-value").nth(2).fill("1048576")
    await fields.nth(3).select_option("has_attachment")
    await page.locator(".rule-condition-value").nth(3).select_option("true")

    await page.locator("#mail-rule-save").click()
    await asyncio.wait_for(first_save_started.wait(), timeout=2)
    try:
        for selector in [
            "#mail-rule-new",
            "#mail-rule-name",
            "#mail-rule-enabled",
            "#mail-rule-stop",
            "#mail-rule-target",
            "#mail-rule-apply-existing",
            "#mail-rule-save",
            "#mail-rule-reset",
            ".rule-condition-field",
            ".rule-condition-test",
            ".rule-condition-value",
        ]:
            assert await page.locator(selector).first.is_disabled()
    finally:
        release_first_save.set()
    for _ in range(50):
        if posted:
            break
        await asyncio.sleep(0.02)
    assert len(posted) == 1
    assert posted[0]["match"] == {
        "op": "and",
        "conditions": [
            {
                "field": "from",
                "operator": "contains",
                "value": "reports@example.test",
            },
            {
                "op": "or",
                "conditions": [
                    {
                        "field": "from",
                        "operator": "contains",
                        "value": "Quarterly",
                    }
                ],
            },
            {
                "field": "size",
                "operator": "gt",
                "value": 1048576,
            },
            {
                "field": "has_attachment",
                "operator": "eq",
                "value": True,
            },
        ],
    }
    assert "children" not in json.dumps(posted[0]["match"])
    await page.get_by_role("heading", name="File project reports", exact=True).wait_for()

    await page.get_by_role("button", name="Edit File project reports", exact=True).click()
    restored_values = page.locator(".rule-condition-value")
    assert await restored_values.nth(0).input_value() == "reports@example.test"
    assert await restored_values.nth(1).input_value() == "Quarterly"
    assert await restored_values.nth(2).input_value() == "1048576"
    assert await restored_values.nth(3).input_value() == "true"
    await page.locator("#mail-rule-name").fill("File updated project reports")
    await page.locator("#mail-rule-save").click()
    for _ in range(50):
        if len(posted) == 2:
            break
        await asyncio.sleep(0.02)
    assert len(posted) == 2, await page.locator("#mail-rule-form-status").inner_text()
    assert posted[1]["expected_revision"] == 1
    await page.get_by_role(
        "heading", name="File updated project reports", exact=True
    ).wait_for()


async def test_slow_cross_account_rule_load_never_exposes_previous_rules(
    page: Page,
    live_application: LiveApplication,
) -> None:
    second_account = "f" * 32
    second_address = "second@example.test"
    live_application.gateway.accounts.append(
        {
            "id": second_account,
            "address": second_address,
            "has_credentials": True,
            "has_mailbox": True,
            "append_limit": 1_048_576,
        }
    )
    second_load_started = asyncio.Event()
    release_second_load = asyncio.Event()

    def rule_payload(rule_id: str, name: str) -> dict[str, object]:
        return {
            "rule_id": rule_id,
            "name": name,
            "enabled": True,
            "match": {"field": "subject", "operator": "contains", "value": name},
            "target_mailbox": ARCHIVE_MAILBOX,
            "stop_processing": True,
            "revision": 1,
        }

    async def mail_rules(route: Route) -> None:
        if f"account={second_account}" in route.request.url:
            second_load_started.set()
            await release_second_load.wait()
            rule = rule_payload("2" * 32, "Second account rule")
        else:
            rule = rule_payload("1" * 32, "First account rule")
        await route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"ok": True, "data": {"rules": [rule]}}),
        )

    await page.route("**/api/v1/admin/mail-rules?*", mail_rules)
    await _load_inbox(page, live_application)
    await page.locator('a[data-section="rules"]').click()
    await page.get_by_role("heading", name="First account rule", exact=True).wait_for()

    await page.locator('a[data-section="mail"]').click()
    await page.locator("#message-list-body tr").wait_for()
    await page.locator("#mail-account").select_option(second_account)
    await page.wait_for_url(f"**/mail?account={second_account}*")
    await page.locator('a[data-section="rules"]').click()
    await asyncio.wait_for(second_load_started.wait(), timeout=2)
    try:
        assert await page.get_by_role(
            "heading", name="First account rule", exact=True
        ).count() == 0
        assert await page.locator("#mail-rules-loading").is_visible()
        assert await page.locator("#mail-rule-name").is_disabled()
        assert await page.locator("#mail-rule-new").is_disabled()
        assert second_address in await page.locator("#mail-rules-account").inner_text()
    finally:
        release_second_load.set()

    await page.get_by_role("heading", name="Second account rule", exact=True).wait_for()
    assert await page.locator("#mail-rule-name").is_enabled()


async def test_failed_rule_reload_clears_stale_rules_and_disables_editor(
    page: Page,
    live_application: LiveApplication,
) -> None:
    request_count = 0
    rule = {
        "rule_id": "3" * 32,
        "name": "Loaded before failure",
        "enabled": True,
        "match": {"field": "subject", "operator": "contains", "value": "Report"},
        "target_mailbox": ARCHIVE_MAILBOX,
        "stop_processing": True,
        "revision": 1,
    }

    async def mail_rules(route: Route) -> None:
        nonlocal request_count
        request_count += 1
        if request_count == 1:
            await route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({"ok": True, "data": {"rules": [rule]}}),
            )
            return
        await route.fulfill(
            status=503,
            content_type="application/json",
            body=json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "rules_unavailable",
                        "message": "Mail rules are temporarily unavailable.",
                    },
                }
            ),
        )

    await page.route("**/api/v1/admin/mail-rules?*", mail_rules)
    await _load_inbox(page, live_application)
    await page.locator('a[data-section="rules"]').click()
    await page.get_by_role("heading", name="Loaded before failure", exact=True).wait_for()
    await page.locator('a[data-section="mail"]').click()
    await page.locator("#message-list-body tr").wait_for()
    await page.locator('a[data-section="rules"]').click()

    await page.locator("#mail-rules-loading").get_by_text(
        "Mail rules are temporarily unavailable.", exact=True
    ).wait_for()
    assert await page.get_by_role(
        "heading", name="Loaded before failure", exact=True
    ).count() == 0
    assert await page.locator("#mail-rule-name").is_disabled()
    assert await page.locator("#mail-rule-new").is_disabled()
    assert await page.locator("#mail-rules-empty").is_hidden()


async def test_existing_mail_rule_run_advances_sequentially_until_completed(
    page: Page,
    live_application: LiveApplication,
) -> None:
    rule_id = "1" * 32
    run_id = "2" * 32
    run = {
        "run_id": run_id,
        "rule_id": rule_id,
        "rule_name": "File project reports",
        "status": "queued",
        "processed": 0,
        "total": 60,
    }
    rule = {
        "rule_id": rule_id,
        "name": "File project reports",
        "enabled": True,
        "match": {"field": "subject", "operator": "contains", "value": "Report"},
        "target_mailbox": ARCHIVE_MAILBOX,
        "stop_processing": True,
        "revision": 1,
    }
    step_results = [
        {**run, "status": "running", "processed": 20},
        {**run, "status": "running", "processed": 40},
        {**run, "status": "completed", "processed": 60},
    ]
    step_calls = 0
    in_flight = 0
    maximum_in_flight = 0

    async def mail_rules(route: Route) -> None:
        await route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {"ok": True, "data": {"rules": [rule], "active_run": run}}
            ),
        )

    async def mail_rule_run(route: Route) -> None:
        nonlocal step_calls, in_flight, maximum_in_flight
        if route.request.method == "GET":
            payload = {"ok": True, "data": {"run": run}}
        else:
            index = step_calls
            step_calls += 1
            in_flight += 1
            maximum_in_flight = max(maximum_in_flight, in_flight)
            try:
                await asyncio.sleep(0.02)
                result = step_results[min(index, len(step_results) - 1)]
                payload = {
                    "ok": True,
                    "data": {"run": result},
                    "message": "Rule batch processed.",
                }
            finally:
                in_flight -= 1
        await route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(payload),
        )

    await page.route("**/api/v1/admin/mail-rules?*", mail_rules)
    await page.route("**/api/v1/admin/mail-rule-runs/**", mail_rule_run)
    await page.goto(live_application.base_url + "/rules")
    await page.wait_for_function(
        "() => document.querySelector('#mail-rule-run-state')?.textContent === 'completed'"
    )
    await page.wait_for_timeout(100)

    assert step_calls == len(step_results)
    assert maximum_in_flight == 1
    assert await page.locator("#mail-rule-run-summary").inner_text() == (
        "60 of 60 messages processed."
    )
    assert await page.locator("#mail-rule-run-step").is_disabled()
    assert await page.locator("#mail-rule-run-cancel").is_disabled()


async def test_existing_mail_rule_run_stops_after_rules_route_is_aborted(
    page: Page,
    live_application: LiveApplication,
) -> None:
    rule_id = "3" * 32
    run_id = "4" * 32
    run = {
        "run_id": run_id,
        "rule_id": rule_id,
        "rule_name": "File project reports",
        "status": "running",
        "processed": 0,
        "total": 40,
    }
    rule = {
        "rule_id": rule_id,
        "name": "File project reports",
        "enabled": True,
        "match": {"field": "subject", "operator": "contains", "value": "Report"},
        "target_mailbox": ARCHIVE_MAILBOX,
        "stop_processing": True,
        "revision": 1,
    }
    step_started = asyncio.Event()
    release_step = asyncio.Event()
    step_calls = 0

    async def mail_rules(route: Route) -> None:
        await route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {"ok": True, "data": {"rules": [rule], "active_run": run}}
            ),
        )

    async def mail_rule_run(route: Route) -> None:
        nonlocal step_calls
        if route.request.method == "GET":
            result = run
        else:
            step_calls += 1
            step_started.set()
            await release_step.wait()
            result = {**run, "processed": 20}
        await route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"ok": True, "data": {"run": result}}),
        )

    await page.route("**/api/v1/admin/mail-rules?*", mail_rules)
    await page.route("**/api/v1/admin/mail-rule-runs/**", mail_rule_run)
    await page.goto(live_application.base_url + "/rules")
    await asyncio.wait_for(step_started.wait(), timeout=2)
    try:
        assert await page.locator("#mail-rule-run-cancel").is_enabled()
        assert "Processing" in await page.locator("#mail-rule-run-status").inner_text()
        await page.locator('a[data-section="security"]').click()
        await page.get_by_role("heading", name="Security", exact=True).wait_for()
    finally:
        release_step.set()
    await page.wait_for_timeout(100)

    assert step_calls == 1

async def test_mailbox_search_filters_sender_and_subject_on_the_loaded_page(
    page: Page,
    live_application: LiveApplication,
) -> None:
    async def searchable_messages(*_args: object, **_kwargs: object) -> MessagePage:
        return MessagePage(
            [
                {
                    "id": "44",
                    "sender": "reports@example.test",
                    "subject": "Quarterly summary",
                },
                {
                    "id": "43",
                    "sender": "alerts@example.test",
                    "subject": "Service notice",
                },
                {
                    "id": "42",
                    "sender": "attacker@example.test",
                    "subject": "Security fixture",
                },
            ],
            False,
        )

    live_application.gateway.list_messages = searchable_messages  # type: ignore[method-assign]
    await page.goto(live_application.base_url + _mailbox_path())
    await page.locator("#message-list-body tr").first.wait_for()
    search = page.locator("#mail-search-input")
    await search.fill("quarterly")

    rows = page.locator("#message-list-body tr")
    assert await rows.count() == 1
    assert "Quarterly summary" in await rows.locator(".message-subject-cell").inner_text()
    assert "search=quarterly" in page.url
    assert await page.locator("#mail-list-summary").inner_text() == (
        "1 of 3 messages match on this page"
    )
    assert await page.locator("#mail-search-clear").is_visible()

    await search.fill("ALERTS@EXAMPLE.TEST")
    assert await rows.count() == 1
    assert "alerts@example.test" in await rows.locator(".message-sender-cell").inner_text()

    await page.locator("#mail-search-clear").click()
    assert await rows.count() == 3
    assert "search=" not in page.url
    assert await page.locator("#mail-search-clear").is_hidden()


async def test_refresh_centers_the_open_message_in_the_independent_list_pane(
    page: Page,
    live_application: LiveApplication,
) -> None:
    async def long_message_page(*_args: object, **_kwargs: object) -> MessagePage:
        return MessagePage(
            [
                {
                    "id": str(uid),
                    "sender": f"sender-{uid}@example.test",
                    "subject": f"Message {uid}",
                }
                for uid in range(60, 45, -1)
            ],
            False,
        )

    live_application.gateway.list_messages = long_message_page  # type: ignore[method-assign]
    await page.set_viewport_size({"width": 1440, "height": 820})
    await page.goto(live_application.base_url + _mailbox_path())
    await page.locator("#message-list-body tr").first.wait_for()
    target = page.locator('#message-list-body tr[data-uid="53"]')
    await target.locator(".message-subject-cell a").click()
    await page.get_by_role(
        "heading",
        name="Browser security fixture",
        exact=True,
    ).wait_for()

    await page.reload()
    selected = page.locator('#message-list-body tr[data-uid="53"].is-selected')
    await selected.wait_for()
    await page.wait_for_function(
        """() => {
            const pane = document.querySelector(".mail-list-table");
            const row = document.querySelector('#message-list-body tr[data-uid="53"]');
            return pane && row && pane.scrollTop > 0;
        }"""
    )
    center_delta = await selected.evaluate(
        """row => {
            const pane = row.closest(".mail-list-table");
            const rowBounds = row.getBoundingClientRect();
            const paneBounds = pane.getBoundingClientRect();
            return Math.abs(
                (rowBounds.top + rowBounds.height / 2)
                - (paneBounds.top + paneBounds.height / 2)
            );
        }"""
    )
    assert center_delta <= 2


async def test_mail_workspace_fills_the_tall_desktop_viewport(
    page: Page,
    live_application: LiveApplication,
) -> None:
    viewport_height = 1400
    await page.set_viewport_size({"width": 2048, "height": viewport_height})
    await _load_inbox(page, live_application)

    workspace = await page.locator("#mail-workspace").bounding_box()
    assert workspace is not None
    assert workspace["height"] >= 1100
    assert viewport_height - (workspace["y"] + workspace["height"]) <= 26


async def test_desktop_mail_list_and_reading_pane_scroll_independently(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.set_viewport_size({"width": 1440, "height": 820})
    await _open_message(page, live_application)

    message_list = page.locator(".mail-list-table")
    reading_pane = page.locator("#message-view")
    await page.locator("#message-list-body").evaluate(
        """tbody => {
            const source = tbody.querySelector("tr");
            for (let index = 0; index < 16; index += 1) {
                const clone = source.cloneNode(true);
                clone.dataset.uid = `scroll-fixture-${index}`;
                clone.removeAttribute("aria-current");
                clone.classList.remove("is-selected");
                tbody.append(clone);
            }
        }"""
    )
    await page.locator(".message-preview-shell").evaluate(
        "node => { node.style.height = '1800px'; }"
    )
    await message_list.evaluate("node => { node.scrollTop = 0; }")
    await reading_pane.evaluate("node => { node.scrollTop = 0; }")
    await page.evaluate("window.scrollTo(0, 0)")

    assert await message_list.evaluate("node => node.scrollHeight > node.clientHeight")
    assert await reading_pane.evaluate("node => node.scrollHeight > node.clientHeight")
    assert await page.evaluate("document.documentElement.scrollHeight <= window.innerHeight")

    await message_list.hover()
    await page.mouse.wheel(0, 700)
    await page.wait_for_function("() => document.querySelector('.mail-list-table').scrollTop > 0")
    list_scroll_top = await message_list.evaluate("node => node.scrollTop")
    assert await reading_pane.evaluate("node => node.scrollTop") == 0
    assert await page.evaluate("window.scrollY") == 0

    await reading_pane.hover()
    await page.mouse.wheel(0, 700)
    await page.wait_for_function("() => document.querySelector('#message-view').scrollTop > 0")
    assert await message_list.evaluate("node => node.scrollTop") == list_scroll_top
    assert await page.evaluate("window.scrollY") == 0


async def test_message_navigation_updates_selection_and_hides_stale_content(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _open_message(page, live_application)
    old_heading = page.get_by_role(
        "heading",
        name="Browser security fixture",
        exact=True,
    )
    assert await old_heading.is_visible()

    await page.locator('a[data-section="security"]').click()
    await page.get_by_role("heading", name="Security", exact=True).wait_for()
    await page.locator('a[data-section="mail"]').click()
    await page.locator("#message-list-body tr").wait_for()
    await page.locator("#message-list-body").evaluate(
        """tbody => {
            const stale = document.createElement("tr");
            stale.dataset.uid = "999";
            stale.className = "is-selected";
            stale.setAttribute("aria-current", "true");
            tbody.append(stale);
        }"""
    )

    request_started = asyncio.Event()
    request_release = asyncio.Event()

    async def delay_message_response(route: Route) -> None:
        request_started.set()
        await request_release.wait()
        await route.continue_()

    message_api = f"**/api/v1/admin/mail/{MESSAGE_ID}?*"
    await page.route(message_api, delay_message_response)
    try:
        await page.locator("#message-list-body a").click()
        await asyncio.wait_for(
            request_started.wait(),
            timeout=2,
        )

        placeholder = page.locator("#message-placeholder")
        assert await placeholder.is_visible()
        assert await placeholder.get_by_role(
            "heading",
            name="Loading message",
            exact=True,
        ).is_visible()
        assert await page.locator("#message-view").is_hidden()
        assert await old_heading.is_hidden()
        selected_rows = page.locator("#message-list-body tr.is-selected")
        assert await selected_rows.count() == 1
        assert await selected_rows.get_attribute("data-uid") == MESSAGE_ID
        assert await selected_rows.get_attribute("aria-current") == "true"
        assert (
            await page.locator('#message-list-body tr[data-uid="999"][aria-current]').count() == 0
        )
    finally:
        request_release.set()

    await old_heading.wait_for(state="visible")
    await page.unroute(message_api, delay_message_response)


async def test_empty_sent_mailbox_explains_when_copies_are_created(
    page: Page,
    live_application: LiveApplication,
) -> None:
    query = urlencode({"account": ACCOUNT, "mailbox": "Sent"})
    await page.goto(f"{live_application.base_url}/mail?{query}")

    empty = page.locator("#message-empty")
    await page.wait_for_function(
        "() => document.querySelector('#message-empty').textContent.includes("
        "'MaddyWeb saves a copy after it sends')"
    )
    assert "MaddyWeb saves a copy after it sends" in await empty.inner_text()
    assert await page.locator("#mail-mailbox").input_value() == "Sent"


async def test_mailbox_forward_actions_prepare_safe_compose_drafts(
    page: Page,
    live_application: LiveApplication,
) -> None:
    requested_urls: list[str] = []
    page.on("request", lambda request: requested_urls.append(request.url))
    await _load_inbox(page, live_application)
    row = page.locator("#message-list-body tr")
    await _message_menu_action(page, row, "forward")
    await page.wait_for_url("**/compose?forward=inline*")
    await page.wait_for_function(
        "() => document.querySelector('#compose-subject').value.startsWith('Fwd:')"
    )

    assert await page.locator("#compose-sender").input_value() == ACCOUNT
    assert await page.locator("#compose-to").input_value() == ""
    assert await page.locator("#compose-password").input_value() == ""
    assert "plain fallback" in await page.locator("#message-editor").inner_text()
    assert "Forwarded message" in await page.locator("#message-editor").inner_text()
    forwarded_files = await page.locator("#attachments-input").evaluate(
        "input => Array.from(input.files, file => [file.name, file.type])"
    )
    assert forwarded_files == [
        ["logo.png", "image/png"],
        ["evil.html", "text/html"],
    ]
    assert not any("tracker.invalid" in url for url in requested_urls)

    await _load_inbox(page, live_application)
    row = page.locator("#message-list-body tr")
    await _message_menu_action(page, row, "forward-attachment")
    await page.wait_for_url("**/compose?forward=attachment*")
    await page.wait_for_function(
        "() => document.querySelector('#attachments-input').files.length === 1"
    )
    attached_files = await page.locator("#attachments-input").evaluate(
        "input => Array.from(input.files, file => [file.name, file.type])"
    )
    assert attached_files == [["forwarded-message-42.eml", "message/rfc822"]]
    assert await page.locator("#compose-subject").input_value() == (
        'Fwd: <img src=x onerror="document.body.dataset.listXss=1">Security fixture'
    )
    assert await page.locator("body").get_attribute("data-list-xss") is None
    assert "Forwarded message attached." in await page.locator("#message-editor").inner_text()
    assert await page.locator("#compose-to").input_value() == ""
    assert await page.locator("#compose-password").input_value() == ""

    await page.reload()
    await page.wait_for_function(
        "() => document.querySelector('#attachments-input').files.length === 1"
    )
    assert await page.locator("#compose-subject").input_value() == "Fwd: Forwarded message"


async def test_forward_as_attachment_does_not_require_a_parseable_message(
    page: Page,
    live_application: LiveApplication,
) -> None:
    malformed = EmailMessage()
    malformed["From"] = "sender@example.test"
    malformed["To"] = ACCOUNT_ADDRESS
    malformed["Subject"] = "Attachment limit fixture"
    malformed.set_content("Body")
    for index in range(65):
        malformed.add_attachment(
            b"",
            maintype="application",
            subtype="octet-stream",
            filename=f"part-{index}.bin",
        )
    live_application.gateway.raw = malformed.as_bytes(policy=policy.SMTP)

    await _load_inbox(page, live_application)
    context = urlencode({"account": ACCOUNT, "mailbox": MAILBOX})
    detail_status = await page.evaluate(
        """async url => (await fetch(url, {
          credentials: "same-origin",
          headers: {"Accept": "application/json"},
        })).status""",
        f"/api/v1/admin/mail/{MESSAGE_ID}?{context}",
    )
    assert detail_status == 422

    row = page.locator("#message-list-body tr")
    await _message_menu_action(page, row, "forward-attachment")
    await page.wait_for_url("**/compose?forward=attachment*")
    await page.wait_for_function(
        "() => document.querySelector('#attachments-input').files.length === 1"
    )
    attached = await page.locator("#attachments-input").evaluate(
        "input => [input.files[0].name, input.files[0].type, input.files[0].size]"
    )
    assert attached == [
        "forwarded-message-42.eml",
        "message/rfc822",
        len(live_application.gateway.raw),
    ]


async def test_mailbox_actions_preflight_freshness_and_close_pending_confirmations(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _load_inbox(page, live_application)
    live_application.gateway.message_read_started.clear()
    live_application.gateway.message_read_release.clear()
    row = page.locator("#message-list-body tr")
    live_application.gateway.archive_move_release.clear()
    await _message_menu_action(page, row, "archive")
    await asyncio.wait_for(live_application.gateway.message_read_started.wait(), timeout=2)
    assert not live_application.gateway.archive_move_started.is_set()
    live_application.gateway.message_read_release.set()
    await asyncio.wait_for(live_application.gateway.archive_move_started.wait(), timeout=2)
    await page.go_back()
    live_application.gateway.archive_move_release.set()
    await page.get_by_role("heading", name=MAILBOX, exact=True).wait_for()
    await asyncio.sleep(0.1)
    assert live_application.gateway.bulk_moves == [
        (ACCOUNT, MAILBOX, (MESSAGE_ID,), ARCHIVE_MAILBOX)
    ]

    live_application.gateway.message_location = MAILBOX
    await _load_inbox(page, live_application)
    live_application.gateway.message_read_started.clear()
    row = page.locator("#message-list-body tr")
    await _message_menu_action(page, row, "trash")
    await page.locator("#confirm-dialog").wait_for(state="visible")
    assert not live_application.gateway.message_read_started.is_set()
    await page.go_back()
    await page.locator("#confirm-dialog").wait_for(state="hidden")
    assert not any(move[-1] == TRASH_MAILBOX for move in live_application.gateway.bulk_moves)


async def test_special_use_mailboxes_disable_same_target_actions(
    page: Page,
    live_application: LiveApplication,
) -> None:
    live_application.gateway.message_location = TRASH_MAILBOX
    await _load_mailbox(page, live_application, TRASH_MAILBOX)
    trash_row = page.locator("#message-list-body tr")
    trash_menu = await _open_message_menu(page, trash_row)
    assert await trash_menu.locator(
        '[role="menuitem"][data-action="permanent-delete"]'
    ).is_enabled()
    assert await trash_menu.locator(
        '[role="menuitem"][data-action="trash"]'
    ).count() == 0
    assert await trash_menu.locator(
        '[role="menuitem"][data-action="archive"]'
    ).is_enabled()
    await page.keyboard.press("Escape")

    live_application.gateway.message_location = ARCHIVE_MAILBOX
    await _load_mailbox(page, live_application, ARCHIVE_MAILBOX)
    archive_row = page.locator("#message-list-body tr")
    archive_menu = await _open_message_menu(page, archive_row)
    assert await archive_menu.locator(
        '[role="menuitem"][data-action="archive"]'
    ).count() == 0
    assert await archive_menu.locator(
        '[role="menuitem"][data-action="trash"]'
    ).is_enabled()


async def test_trash_row_permanent_delete_requires_typed_confirmation_and_snapshot(
    page: Page,
    live_application: LiveApplication,
) -> None:
    live_application.gateway.message_location = TRASH_MAILBOX
    await _load_mailbox(page, live_application, TRASH_MAILBOX)
    live_application.gateway.message_read_started.clear()
    action_requests: list[tuple[str, str]] = []

    def capture_action_request(request: object) -> None:
        path = urlsplit(getattr(request, "url", "")).path
        if path.endswith(("/action-snapshot", "/delete")):
            action_requests.append((getattr(request, "method", ""), path))

    page.on("request", capture_action_request)
    row = page.locator("#message-list-body tr")
    await _message_menu_action(page, row, "permanent-delete")

    dialog = page.locator("#typed-confirm-dialog")
    await dialog.wait_for(state="visible")
    assert action_requests == []
    assert not live_application.gateway.message_read_started.is_set()
    typed_action = page.locator("#typed-confirm-action")
    await page.locator("#typed-confirm-input").fill("delete")
    assert await typed_action.is_disabled()
    await page.locator("#typed-confirm-input").fill("PERMANENTLY DELETE")
    assert await typed_action.is_enabled()
    await typed_action.click()

    await dialog.wait_for(state="hidden")
    await page.locator("#message-empty").wait_for(state="visible")
    assert live_application.gateway.message_read_started.is_set()
    assert action_requests == [
        ("GET", f"/api/v1/admin/mail/{MESSAGE_ID}/action-snapshot"),
        ("POST", f"/api/v1/admin/mail/{MESSAGE_ID}/delete"),
    ]
    assert live_application.gateway.permanent_deletions == [(ACCOUNT, TRASH_MAILBOX, MESSAGE_ID)]


async def test_trash_bulk_permanent_delete_requires_per_message_freshness_and_one_write(
    page: Page,
    live_application: LiveApplication,
) -> None:
    second_message_id = "43"

    async def two_messages(
        _account: str,
        mailbox: str,
        **_kwargs: object,
    ) -> MessagePage:
        if live_application.gateway.message_location != mailbox:
            return MessagePage([], False)
        return MessagePage(
            [
                {
                    "id": uid,
                    "sender": "attacker@example.test",
                    "subject": f"Security fixture {uid}",
                    "date": "2026-07-23 12:00 UTC",
                    "unread": True,
                }
                for uid in (MESSAGE_ID, second_message_id)
            ],
            False,
        )

    live_application.gateway.list_messages = two_messages  # type: ignore[method-assign]
    live_application.gateway.message_location = TRASH_MAILBOX
    await _load_mailbox(page, live_application, TRASH_MAILBOX)
    live_application.gateway.message_read_started.clear()
    action_requests: list[object] = []

    def capture_action_request(request: object) -> None:
        path = urlsplit(getattr(request, "url", "")).path
        if path.endswith("/action-snapshots") or path.endswith("/mail-actions"):
            action_requests.append(request)

    page.on("request", capture_action_request)
    assert await page.locator("#mail-bulk-permanent-delete").count() == 0
    assert await page.locator("#mail-bulk-trash").count() == 0

    await page.locator("#mail-select-page").check()
    assert await page.locator("#mail-selection-count").inner_text() == "2 selected"
    menu = await _open_message_menu(page, page.locator("#message-list-body tr").first)
    bulk_delete = menu.locator(
        '[role="menuitem"][data-action="permanent-delete"]'
    )
    assert await bulk_delete.is_enabled()
    await bulk_delete.click()

    dialog = page.locator("#typed-confirm-dialog")
    await dialog.wait_for(state="visible")
    assert await page.locator("#typed-confirm-title").inner_text() == (
        "Permanently delete 2 messages?"
    )
    assert "cannot be undone" in (await page.locator("#typed-confirm-message").inner_text()).lower()
    assert action_requests == []
    assert not live_application.gateway.message_read_started.is_set()

    typed_action = page.locator("#typed-confirm-action")
    assert await typed_action.inner_text() == "Delete 2 permanently"
    await page.locator("#typed-confirm-input").fill("PERMANENTLY DELETE ")
    assert await typed_action.is_disabled()
    await page.locator("#typed-confirm-input").fill("PERMANENTLY DELETE")
    assert await typed_action.is_enabled()
    await typed_action.click()

    await dialog.wait_for(state="hidden")
    await page.locator("#message-empty").wait_for(state="visible")
    assert live_application.gateway.message_read_started.is_set()
    action_records = [
        (getattr(request, "method", ""), urlsplit(getattr(request, "url", "")).path)
        for request in action_requests
    ]
    assert action_records[:-1] == [
        ("POST", "/api/v1/admin/mail/action-snapshots"),
    ]
    assert action_records[-1] == ("POST", "/api/v1/admin/mail-actions")
    snapshot_payload = getattr(action_requests[0], "post_data_json", None)
    assert snapshot_payload == {
        "account": ACCOUNT,
        "mailbox": TRASH_MAILBOX,
        "uids": [MESSAGE_ID, second_message_id],
    }
    payload = getattr(action_requests[-1], "post_data_json", None)
    assert isinstance(payload, dict)
    assert payload == {
        "account": ACCOUNT,
        "mailbox": TRASH_MAILBOX,
        "action": "permanent_delete",
        "uids": [MESSAGE_ID, second_message_id],
        "confirmation": "PERMANENTLY DELETE",
        "freshness": [
            {
                "uid": MESSAGE_ID,
                "token": payload["freshness"][0]["token"],
            },
            {
                "uid": second_message_id,
                "token": payload["freshness"][1]["token"],
            },
        ],
    }
    assert all(isinstance(item["token"], str) and item["token"] for item in payload["freshness"])
    assert live_application.gateway.permanent_deletions == []
    assert live_application.gateway.bulk_permanent_deletions == [
        (ACCOUNT, TRASH_MAILBOX, (MESSAGE_ID, second_message_id))
    ]


async def test_unknown_bulk_delete_result_locks_stale_mail_ui_when_reload_fails(
    page: Page,
    live_application: LiveApplication,
) -> None:
    second_message_id = "43"

    async def two_messages(
        _account: str,
        mailbox: str,
        **_kwargs: object,
    ) -> MessagePage:
        if live_application.gateway.message_location != mailbox:
            return MessagePage([], False)
        return MessagePage(
            [
                {
                    "id": uid,
                    "sender": "attacker@example.test",
                    "subject": f"Unknown delete result {uid}",
                    "date": "2026-08-06 12:00 UTC",
                    "unread": True,
                }
                for uid in (MESSAGE_ID, second_message_id)
            ],
            False,
        )

    live_application.gateway.list_messages = two_messages  # type: ignore[method-assign]
    live_application.gateway.message_location = TRASH_MAILBOX
    await _load_mailbox(page, live_application, TRASH_MAILBOX)
    mutation_requests = 0

    async def fail_delete(route: Route) -> None:
        nonlocal mutation_requests
        mutation_requests += 1
        await route.fulfill(
            status=502,
            content_type="application/json",
            body=json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "helper_failed",
                        "message": "The deletion result is unknown.",
                    },
                }
            ),
        )

    async def fail_mail_reload(route: Route) -> None:
        await route.fulfill(
            status=502,
            content_type="application/json",
            body=json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "mailbox_unavailable",
                        "message": "The mailbox could not be refreshed.",
                    },
                }
            ),
        )

    await page.route("**/api/v1/admin/mail-actions", fail_delete)
    await page.route("**/api/v1/admin/mail?*", fail_mail_reload)
    await page.locator("#mail-select-page").check()
    await _message_menu_action(
        page,
        page.locator("#message-list-body tr").first,
        "permanent-delete",
    )
    await page.locator("#typed-confirm-input").fill("PERMANENTLY DELETE")
    await page.locator("#typed-confirm-action").click()

    await page.locator("#typed-confirm-dialog").wait_for(state="hidden")
    empty = page.locator("#message-empty")
    await empty.wait_for(state="visible")
    assert "Reload this page" in await empty.inner_text()
    assert await page.locator("#message-list-body tr").count() == 0
    assert await page.locator("#mail-selection-count").inner_text() == "0 selected"
    assert await page.locator("#mail-select-page").is_disabled()
    assert await page.locator("#mail-mark-read").count() == 0
    assert await page.locator("#mail-mark-unread").count() == 0
    assert await page.locator("#mail-bulk-archive").count() == 0
    assert await page.locator("#mail-bulk-trash").count() == 0
    assert await page.locator("#mail-bulk-permanent-delete").count() == 0
    assert await page.locator("#mail-mark-all-read").is_disabled()
    assert await page.locator("#mail-search-input").is_disabled()
    assert mutation_requests == 1


async def test_trash_row_permanent_delete_confirmation_does_not_survive_navigation(
    page: Page,
    live_application: LiveApplication,
) -> None:
    live_application.gateway.message_location = TRASH_MAILBOX
    await _load_mailbox(page, live_application, TRASH_MAILBOX)
    action_requests: list[str] = []

    def capture_action_request(request: object) -> None:
        path = urlsplit(getattr(request, "url", "")).path
        if path.endswith(("/action-snapshot", "/delete")):
            action_requests.append(path)

    page.on("request", capture_action_request)
    await _message_menu_action(
        page,
        page.locator("#message-list-body tr"),
        "permanent-delete",
    )
    dialog = page.locator("#typed-confirm-dialog")
    await dialog.wait_for(state="visible")

    await page.evaluate(
        """() => {
          history.pushState(null, "", "/");
          window.dispatchEvent(new PopStateEvent("popstate"));
        }"""
    )
    await page.get_by_role(
        "heading",
        name="Administration overview",
        exact=True,
    ).wait_for()
    await dialog.wait_for(state="hidden")
    await page.go_back()
    await page.locator("#message-list-body tr").wait_for()

    assert urlsplit(page.url).path == "/mail"
    assert await dialog.is_hidden()
    assert action_requests == []
    assert live_application.gateway.permanent_deletions == []


async def test_missing_special_use_targets_omit_unavailable_actions(
    page: Page,
    live_application: LiveApplication,
) -> None:
    async def inbox_only(_account: str) -> list[dict[str, object]]:
        return [{"name": MAILBOX, "attributes": []}]

    live_application.gateway.list_mailboxes = inbox_only  # type: ignore[method-assign]
    await _load_inbox(page, live_application)
    row = page.locator("#message-list-body tr")
    menu = await _open_message_menu(page, row)
    assert await menu.locator(
        '[role="menuitem"][data-action="permanent-delete"]'
    ).count() == 0
    assert await menu.locator(
        '[role="menuitem"][data-action="archive"]'
    ).count() == 0
    assert await menu.locator(
        '[role="menuitem"][data-action="forward"]'
    ).is_enabled()
    assert await menu.locator(
        '[role="menuitem"][data-action="forward-attachment"]'
    ).is_enabled()


async def test_completed_move_posts_do_not_hijack_a_newer_route(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _load_inbox(page, live_application)
    live_application.gateway.archive_move_release.clear()
    row = page.locator("#message-list-body tr")
    await _message_menu_action(page, row, "archive")
    await asyncio.wait_for(live_application.gateway.archive_move_started.wait(), timeout=2)
    await page.evaluate(
        """() => {
          history.pushState(null, "", "/");
          window.dispatchEvent(new PopStateEvent("popstate"));
        }"""
    )
    await page.get_by_role("heading", name="Administration overview", exact=True).wait_for()
    live_application.gateway.archive_move_release.set()
    await asyncio.wait_for(live_application.gateway.archive_move_finished.wait(), timeout=2)
    await asyncio.sleep(0.1)
    assert urlsplit(page.url).path == "/"
    assert await page.locator("#toast").is_hidden()
    assert live_application.gateway.bulk_moves == [
        (ACCOUNT, MAILBOX, (MESSAGE_ID,), ARCHIVE_MAILBOX)
    ]

    live_application.gateway.message_location = MAILBOX
    await _load_inbox(page, live_application)
    live_application.gateway.trash_move_release.clear()
    row = page.locator("#message-list-body tr")
    await _message_menu_action(page, row, "trash")
    await page.locator("#confirm-action").click()
    await asyncio.wait_for(live_application.gateway.trash_move_started.wait(), timeout=2)
    await page.evaluate(
        """() => {
          history.pushState(null, "", "/");
          window.dispatchEvent(new PopStateEvent("popstate"));
        }"""
    )
    await page.get_by_role("heading", name="Administration overview", exact=True).wait_for()
    live_application.gateway.trash_move_release.set()
    await asyncio.wait_for(live_application.gateway.trash_move_finished.wait(), timeout=2)
    await asyncio.sleep(0.1)
    assert urlsplit(page.url).path == "/"
    assert await page.locator("#toast").is_hidden()
    assert live_application.gateway.bulk_moves[-1] == (
        ACCOUNT,
        MAILBOX,
        (MESSAGE_ID,),
        TRASH_MAILBOX,
    )


async def test_mailbox_delete_and_archive_actions_do_not_open_the_message(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _load_inbox(page, live_application)
    row = page.locator("#message-list-body tr")
    await _message_menu_action(page, row, "trash")
    await page.locator("#confirm-dialog").wait_for(state="visible")
    assert urlsplit(page.url).path == "/mail"
    assert live_application.gateway.trash_moves == []
    await page.locator("#confirm-action").click()
    await page.locator("#confirm-dialog").wait_for(state="hidden")
    await page.locator("#message-empty").wait_for(state="visible")
    assert live_application.gateway.bulk_moves == [(ACCOUNT, MAILBOX, (MESSAGE_ID,), TRASH_MAILBOX)]
    assert live_application.gateway.permanent_deletions == []

    live_application.gateway.message_location = MAILBOX
    await _load_inbox(page, live_application)
    row = page.locator("#message-list-body tr")
    await _message_menu_action(page, row, "archive", keyboard=True)
    await page.locator("#message-empty").wait_for(state="visible")
    assert urlsplit(page.url).path == "/mail"
    assert live_application.gateway.bulk_moves[-1] == (
        ACCOUNT,
        MAILBOX,
        (MESSAGE_ID,),
        ARCHIVE_MAILBOX,
    )
    assert live_application.gateway.message_location == ARCHIVE_MAILBOX


async def test_message_html_is_sandboxed_and_attachment_filename_is_safe(
    page: Page,
    live_application: LiveApplication,
) -> None:
    requested_urls: list[str] = []
    page.on("request", lambda request: requested_urls.append(request.url))
    await _open_message(page, live_application)

    preview = page.locator(".message-preview-shell")
    preview_bounds = await preview.bounding_box()
    assert preview_bounds is not None
    assert 250 <= preview_bounds["height"] <= 300
    assert await preview.evaluate("node => getComputedStyle(node).resize") == "none"
    resize_handle = page.get_by_role("button", name="Resize message body", exact=True)
    await resize_handle.scroll_into_view_if_needed()
    preview_bounds = await preview.bounding_box()
    assert preview_bounds is not None
    handle_bounds = await resize_handle.bounding_box()
    assert handle_bounds is not None
    await page.mouse.move(
        handle_bounds["x"] + handle_bounds["width"] / 2,
        handle_bounds["y"] + handle_bounds["height"] / 2,
    )
    await page.mouse.down()
    await page.mouse.move(
        handle_bounds["x"] + handle_bounds["width"] / 2,
        handle_bounds["y"] + handle_bounds["height"] / 2 + 118,
        steps=6,
    )
    await page.mouse.up()
    resized_bounds = await preview.bounding_box()
    assert resized_bounds is not None
    assert resized_bounds["height"] >= preview_bounds["height"] + 90
    await resize_handle.focus()
    await resize_handle.press("ArrowUp")
    keyboard_resized_bounds = await preview.bounding_box()
    assert keyboard_resized_bounds is not None
    assert keyboard_resized_bounds["height"] <= resized_bounds["height"] - 30

    frame_element = page.locator("iframe.message-frame")
    frame = page.frame_locator("iframe.message-frame")
    assert "Safe body" in await frame.locator("body").inner_text()
    assert await frame.locator("script").count() == 0
    for active_tag in (
        "meta",
        "style",
        "form",
        "input",
        "svg",
        "math",
        "iframe",
        "object",
        "embed",
    ):
        assert await frame.locator(f"body {active_tag}").count() == 0
    assert await frame.locator('head meta[charset="utf-8"]').count() == 1
    assert await frame.locator('head meta[http-equiv="Content-Security-Policy"]').count() == 1
    assert await frame.locator("head style").count() == 1
    assert await frame.locator("body").get_attribute("data-xss") is None
    assert await frame.locator("[onerror], [srcset]").count() == 0
    assert await frame.locator(
        '[style*="position"], [style*="background-image"], '
        '[style*="url("], [style*="expression("]'
    ).count() == 0
    assert await frame.locator("#unsafe-link").count() == 0
    assert await page.evaluate(
        "typeof window.svgXss === 'undefined' "
        "&& typeof window.mathXss === 'undefined' "
        "&& typeof window.imageXss === 'undefined' "
        "&& typeof window.linkXss === 'undefined'"
    )
    image_sources = await frame.locator("img").evaluate_all(
        "images => images.map(image => image.getAttribute('src'))"
    )
    assert len(image_sources) == 1
    assert image_sources[0].startswith("data:image/png;base64,")

    styled_table = frame.locator("table").filter(has_text="Quarterly summary")
    assert await styled_table.count() == 1
    assert await styled_table.get_attribute("width") == "640"
    assert await styled_table.get_attribute("height") == "120"
    assert await styled_table.get_attribute("align") == "center"
    assert await styled_table.get_attribute("bgcolor") == "#f5f7fa"
    assert await styled_table.get_attribute("border") == "2"
    assert await styled_table.get_attribute("cellpadding") == "8"
    assert await styled_table.get_attribute("cellspacing") == "0"
    table_styles = await styled_table.evaluate(
        """node => {
            const style = getComputedStyle(node);
            return {
                backgroundColor: style.backgroundColor,
                borderCollapse: style.borderCollapse,
                borderTopColor: style.borderTopColor,
                borderTopStyle: style.borderTopStyle,
                borderTopWidth: style.borderTopWidth,
                color: style.color,
                declaredWidth: node.style.width,
                fontFamily: style.fontFamily,
                fontSize: style.fontSize,
                height: style.height,
                minWidth: style.minWidth,
                textAlign: style.textAlign,
                width: style.width,
            };
        }"""
    )
    computed_width = table_styles.pop("width")
    assert table_styles == {
        "backgroundColor": "rgb(245, 247, 250)",
        "borderCollapse": "collapse",
        "borderTopColor": "rgb(52, 86, 120)",
        "borderTopStyle": "solid",
        "borderTopWidth": "2px",
        "color": "rgb(18, 52, 86)",
        "declaredWidth": "640px",
        "fontFamily": "Arial, sans-serif",
        "fontSize": "16px",
        "height": "120px",
        "minWidth": "320px",
        "textAlign": "center",
    }
    assert 320 <= float(computed_width.removesuffix("px")) <= 640
    styled_cell = styled_table.locator("td")
    assert await styled_cell.evaluate(
        """node => {
            const style = getComputedStyle(node);
            return style.borderTopWidth === "1px"
                && style.paddingTop === "8px"
                && style.textAlign === "right"
                && style.verticalAlign === "middle";
        }"""
    )
    position_probe = frame.get_by_text("Position probe", exact=True)
    assert await position_probe.evaluate("node => getComputedStyle(node).position") == "static"
    assert await position_probe.evaluate("node => getComputedStyle(node).color") == (
        "rgb(17, 34, 51)"
    )
    assert await frame.get_by_text("CSS network probe", exact=True).get_attribute("style") is None
    assert await frame.get_by_text("Expression probe", exact=True).get_attribute("style") is None
    assert await frame_element.get_attribute("sandbox") == (
        "allow-popups allow-popups-to-escape-sandbox"
    )
    safe_link = frame.get_by_role("link", name="Safe link", exact=True)
    assert await safe_link.get_attribute("href") == "https://example.test/path"
    assert await safe_link.get_attribute("target") == "_blank"
    assert await safe_link.get_attribute("rel") == "noopener noreferrer nofollow"

    async def serve_safe_destination(route: Route) -> None:
        await route.fulfill(
            status=200,
            content_type="text/html",
            body="<!doctype html><title>Safe destination</title>",
        )

    await page.context.route("https://example.test/path", serve_safe_destination)
    async with page.expect_popup() as popup_info:
        await safe_link.click()
    popup = await popup_info.value
    try:
        await popup.wait_for_load_state("domcontentloaded")
        assert popup.url == "https://example.test/path"
        assert await popup.evaluate("window.opener === null")
    finally:
        await popup.close()
    frame_source = await frame_element.get_attribute("src")
    assert frame_source is not None and "/api/v1/admin/mail/42/html?" in frame_source
    assert await frame_element.get_attribute("srcdoc") is None
    assert await frame_element.get_attribute("loading") is None
    assert len([url for url in requested_urls if "/html?" in url]) == 1
    assert await frame_element.get_attribute("referrerpolicy") == "no-referrer"
    assert not any(".invalid" in url or url.startswith("data:") for url in requested_urls)
    assert await page.get_by_text("Sanitized HTML body", exact=True).count() == 0

    source_toggle = page.get_by_role("button", name="View source", exact=True)
    assert await source_toggle.evaluate("node => node.parentElement?.id") == "message-toolbar"
    assert await source_toggle.get_attribute("aria-pressed") == "false"
    assert await frame_element.is_visible()
    assert not await page.locator("#message-source-body").is_visible()
    await source_toggle.click()
    assert not await frame_element.is_visible()
    assert await page.locator("#message-source-body").is_visible()
    assert "plain fallback" in await page.locator("#message-source-body").inner_text()
    html_toggle = page.get_by_role("button", name="View HTML", exact=True)
    assert await html_toggle.get_attribute("aria-pressed") == "true"
    await html_toggle.click()
    assert await frame_element.is_visible()
    assert not await page.locator("#message-source-body").is_visible()

    attachment = page.locator("#attachment-list li").filter(has_text="evil.html")
    assert await attachment.count() == 1
    async with page.expect_download() as download_info:
        await attachment.get_by_role("link", name="Download").click()
    download = await download_info.value
    assert download.suggested_filename == "evil.html"
    assert "/" not in download.suggested_filename
    assert "\\" not in download.suggested_filename

    await page.locator("#message-delete").click()
    typed_action = page.locator("#typed-confirm-action")
    await page.locator("#typed-confirm-input").fill("delete")
    assert await typed_action.is_disabled()
    await page.locator("#typed-confirm-input").fill("PERMANENTLY DELETE")
    assert await typed_action.is_enabled()
    await typed_action.click()
    await page.locator("#typed-confirm-dialog").wait_for(state="hidden")
    await page.wait_for_url(f"**{_mailbox_path()}")
    assert live_application.gateway.permanent_deletions == [(ACCOUNT, MAILBOX, MESSAGE_ID)]


async def test_message_preview_height_adapts_to_long_content(
    page: Page,
    live_application: LiveApplication,
) -> None:
    long_lines = [f"Preview line {index}: " + ("message content " * 8) for index in range(40)]
    message = EmailMessage()
    message["From"] = "attacker@example.test"
    message["To"] = ACCOUNT_ADDRESS
    message["Subject"] = "Browser security fixture"
    message.set_content("\n".join(long_lines))
    message.add_alternative(
        "".join(f"<p>{line}</p>" for line in long_lines),
        subtype="html",
    )
    live_application.gateway.raw = message.as_bytes(policy=policy.SMTP)

    await _open_message(page, live_application)

    preview_bounds = await page.locator(".message-preview-shell").bounding_box()
    assert preview_bounds is not None
    assert 1100 <= preview_bounds["height"] <= 1200


async def test_move_to_trash_requires_explicit_confirmation(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await _open_message(page, live_application)
    await page.locator("#message-trash").click()
    dialog = page.locator("#confirm-dialog")
    await dialog.wait_for(state="visible")
    assert "current verified identifier" in await page.locator("#confirm-message").inner_text()
    await page.locator("#confirm-action").click()
    await dialog.wait_for(state="hidden")
    await page.wait_for_url(f"**{_mailbox_path(TRASH_MAILBOX)}")
    assert live_application.gateway.trash_moves == [(ACCOUNT, MAILBOX, MESSAGE_ID)]
    assert live_application.gateway.message_location == TRASH_MAILBOX


async def test_compose_shows_spinner_blocks_duplicates_and_reports_success(
    page: Page,
    live_application: LiveApplication,
) -> None:
    gateway = live_application.gateway
    gateway.delivery_release.clear()
    post_count = 0

    def count_submission(request: object) -> None:
        nonlocal post_count
        if (
            getattr(request, "method", "") == "POST"
            and urlsplit(getattr(request, "url", "")).path == "/api/v1/admin/send"
        ):
            post_count += 1

    page.on("request", count_submission)
    await page.goto(live_application.base_url + "/compose")
    await page.locator("#compose-sender").select_option(ACCOUNT)
    form = page.locator("#compose-form")
    assert await page.locator("#body-write-tab").get_attribute("aria-selected") == "true"
    assert await page.locator("#body-write-panel").is_visible()
    assert await page.locator("#body-source-panel").is_hidden()
    assert await page.locator("#body-preview-panel").is_hidden()
    await form.locator('input[name="sender_name"]').fill("Browser Sender")
    await form.locator('input[name="password"]').fill("fixture-mail-password")
    await form.locator('input[name="to"]').fill("recipient@example.test")
    await form.locator('input[name="subject"]').fill("Browser delivery fixture")
    await _fill_write_body(page, "A short message.")
    await page.locator("#attachments-input").set_input_files(
        {
            "name": "notes.txt",
            "mimeType": "text/plain",
            "buffer": b"ordinary attachment",
        }
    )
    assert await page.locator("#attachment-chips").get_by_text("notes.txt").is_visible()
    await page.locator("#body-preview-tab").click()
    await page.frame_locator("#html-preview").get_by_text("A short message.", exact=True).wait_for()
    button = page.locator("#send-button")

    await button.click()
    try:
        await asyncio.wait_for(gateway.delivery_started.wait(), timeout=2)
        assert await button.is_disabled()
        assert await button.inner_text() == "Sending..."
        assert "is-sending" in (await button.get_attribute("class") or "")
        assert await form.get_attribute("aria-busy") == "true"
        assert "Keep this page open" in await page.locator("[data-send-progress]").inner_text()

        await form.evaluate(
            "node => node.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}))"
        )
        await page.wait_for_timeout(50)
        assert post_count == 1
    finally:
        gateway.delivery_release.set()

    progress = page.locator("[data-send-progress]")
    await progress.get_by_text("Maddy accepted the message", exact=False).wait_for()
    assert await button.is_enabled()
    assert await button.inner_text() == "Send"
    assert await form.get_attribute("aria-busy") is None
    assert await form.locator('input[name="password"]').input_value() == ""
    assert await form.locator('input[name="sender_name"]').input_value() == ""
    assert await form.locator('textarea[name="html"]').input_value() == ""
    assert await page.locator("#message-editor").inner_text() == ""
    assert await page.locator("#body-write-tab").get_attribute("aria-selected") == "true"
    assert await page.locator("#body-write-panel").is_visible()
    assert await page.locator("#compose-file-tray").is_hidden()
    assert post_count == 1
    assert len(gateway.deliveries) == 1
    delivered = gateway.deliveries[0]
    parsed = BytesParser(policy=policy.default).parsebytes(delivered["raw"])
    assert parsed["From"].addresses[0].display_name == "Browser Sender"
    assert parsed["From"].addresses[0].addr_spec == ACCOUNT_ADDRESS
    plain_body = parsed.get_body(preferencelist=("plain",))
    assert plain_body is not None
    assert plain_body.get_content().strip() == "A short message."
    attachment = next(parsed.iter_attachments())
    assert attachment.get_filename() == "notes.txt"
    assert attachment.get_payload(decode=True) == b"ordinary attachment"
    assert delivered["envelope_from"] == ACCOUNT_ADDRESS
    assert gateway.deliveries[0]["recipients"] == ("recipient@example.test",)
    assert gateway.sent_saves == 1


async def test_compose_recipient_chips_support_suggestions_keyboard_and_multiple_fields(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.goto(live_application.base_url + "/compose")
    await page.locator("#compose-sender").select_option(ACCOUNT)
    form = page.locator("#compose-form")
    to_input = page.locator("#compose-to")

    await to_input.fill("first@gm")
    to_suggestions = page.locator("#compose-to-suggestions")
    assert await to_suggestions.is_visible()
    await to_input.press("Tab")
    assert await page.locator("#compose-to-chips .recipient-chip").count() == 0
    assert await to_input.input_value() == "first@gm"
    await to_input.click()
    await to_input.press("ArrowDown")
    assert await to_input.get_attribute("aria-activedescendant") == (
        "compose-to-suggestion-0"
    )
    await to_input.press("Enter")
    assert await to_input.input_value() == ""
    assert await page.locator("#compose-to-chips .recipient-chip-value").all_inner_texts() == [
        "first@gmail.com"
    ]

    await to_input.fill("second@example.test")
    await to_input.press("Enter")
    first_chip = page.locator("#compose-to-chips .recipient-chip").first
    first_remove = first_chip.locator(".recipient-chip-remove")
    assert await first_remove.evaluate("node => getComputedStyle(node).opacity") == "0"
    await first_chip.hover()
    await page.wait_for_timeout(150)
    assert await first_remove.evaluate("node => getComputedStyle(node).opacity") == "1"
    await first_remove.click()
    assert await page.locator("#compose-to-chips .recipient-chip-value").all_inner_texts() == [
        "second@example.test"
    ]
    await to_input.fill("first@gmail.com")
    await to_input.press("Enter")

    await page.locator('[data-recipient-toggle="cc"]').click()
    cc_input = page.locator("#compose-cc")
    await cc_input.fill("copy@out")
    await page.get_by_role("option", name="copy@outlook.com", exact=True).click()
    await cc_input.fill("team@example.test; audit@example.test")
    await cc_input.press("Enter")

    await page.locator('[data-recipient-toggle="bcc"]').click()
    bcc_input = page.locator("#compose-bcc")
    await bcc_input.fill("hidden@ic")
    await bcc_input.press("ArrowDown")
    await bcc_input.press("Enter")

    assert await page.locator("#compose-to-chips .recipient-chip").count() == 2
    assert await page.locator("#compose-cc-chips .recipient-chip").count() == 3
    assert await page.locator("#compose-bcc-chips .recipient-chip").count() == 1
    assert await to_input.get_attribute("aria-expanded") == "false"

    await form.locator('input[name="password"]').fill("fixture-mail-password")
    await form.locator('input[name="subject"]').fill("Multiple recipient fixture")
    await _fill_write_body(page, "Recipient chip delivery.")
    await page.locator("#send-button").click()
    await page.locator("[data-send-progress]").get_by_text(
        "Maddy accepted the message",
        exact=False,
    ).wait_for()

    assert len(live_application.gateway.deliveries) == 1
    delivery = live_application.gateway.deliveries[0]
    assert delivery["recipients"] == (
        "second@example.test",
        "first@gmail.com",
        "copy@outlook.com",
        "team@example.test",
        "audit@example.test",
        "hidden@icloud.com",
    )
    parsed = BytesParser(policy=policy.default).parsebytes(delivery["raw"])
    assert [address.addr_spec for address in parsed["To"].addresses] == [
        "second@example.test",
        "first@gmail.com",
    ]
    assert [address.addr_spec for address in parsed["Cc"].addresses] == [
        "copy@outlook.com",
        "team@example.test",
        "audit@example.test",
    ]
    assert parsed["Bcc"] is None
    assert await page.locator(".recipient-chip").count() == 0
    assert await to_input.input_value() == ""


async def test_compose_write_source_preview_modes_and_formatting_stay_synchronized(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.goto(live_application.base_url + "/compose")
    editor = page.locator("#message-editor")
    source = page.locator("#html-source")

    await _fill_write_body(page, "Formatted message")
    await editor.press("Control+A")
    await page.get_by_role("button", name="Bold", exact=True).click()
    await page.locator("#body-source-tab").click()
    source_value = await source.input_value()
    assert "Formatted message" in source_value
    assert "<b>" in source_value or "<strong>" in source_value

    edited_source = "<p>Edited <em>source</em></p>"
    await source.fill(edited_source)
    await page.locator("#body-write-tab").click()
    assert await editor.inner_text() == "Edited source"
    assert await editor.locator("em").inner_text() == "source"
    assert await source.input_value() == edited_source

    write_tab = page.locator("#body-write-tab")
    await write_tab.focus()
    await write_tab.press("ArrowRight")
    assert await page.locator("#body-source-tab").get_attribute("aria-selected") == "true"
    assert await page.locator("#body-source-tab").evaluate(
        "node => node === document.activeElement"
    )
    await page.locator("#body-source-tab").press("End")
    assert await page.locator("#body-preview-tab").get_attribute("aria-selected") == "true"
    assert await page.locator("#body-preview-tab").evaluate(
        "node => node === document.activeElement"
    )
    await (
        page.frame_locator("#html-preview")
        .locator("em")
        .get_by_text("source", exact=True)
        .wait_for()
    )
    await page.locator("#body-preview-tab").press("Home")
    assert await write_tab.get_attribute("aria-selected") == "true"
    assert await write_tab.evaluate("node => node === document.activeElement")
    assert await source.input_value() == edited_source


async def test_compose_write_paste_treats_html_as_literal_text_without_network_access(
    page: Page,
    live_application: LiveApplication,
) -> None:
    remote_requests: list[str] = []

    def record_request(request: object) -> None:
        url = getattr(request, "url", "")
        if "tracker.invalid" in url:
            remote_requests.append(url)

    page.on("request", record_request)
    await page.goto(live_application.base_url + "/compose")
    editor = page.locator("#message-editor")
    literal = '<img src="https://tracker.invalid/pixel"><script>unsafe()</script>'
    await editor.focus()
    await editor.evaluate(
        """(node, value) => {
            const data = new DataTransfer();
            data.setData("text/html", value);
            data.setData("text/plain", value);
            node.dispatchEvent(new ClipboardEvent("paste", {
                bubbles: true,
                cancelable: true,
                clipboardData: data,
            }));
        }""",
        literal,
    )
    assert await editor.inner_text() == literal
    assert await editor.locator("img, script").count() == 0
    assert remote_requests == []
    await page.locator("#body-source-tab").click()
    assert "&lt;img" in await page.locator("#html-source").input_value()
    await page.locator("#body-preview-tab").click()
    assert await page.frame_locator("#html-preview").locator("body").inner_text() == literal
    assert remote_requests == []


async def test_compose_empty_body_reports_validation_on_visible_write_editor(
    page: Page,
    live_application: LiveApplication,
) -> None:
    post_count = 0

    def count_submission(request: object) -> None:
        nonlocal post_count
        if (
            getattr(request, "method", "") == "POST"
            and urlsplit(getattr(request, "url", "")).path == "/api/v1/admin/send"
        ):
            post_count += 1

    page.on("request", count_submission)
    await page.goto(live_application.base_url + "/compose")
    await page.locator("#compose-sender").select_option(ACCOUNT)
    form = page.locator("#compose-form")
    await form.locator('input[name="password"]').fill("fixture-mail-password")
    await form.locator('input[name="to"]').fill("recipient@example.test")
    await page.locator("#send-button").click()

    editor = page.locator("#message-editor")
    assert post_count == 0
    assert await page.locator("#body-write-tab").get_attribute("aria-selected") == "true"
    assert await editor.get_attribute("aria-invalid") == "true"
    assert await editor.evaluate("node => node === document.activeElement")
    assert await page.locator("#body-error").inner_text() == (
        "Write a message that contains visible, safe content."
    )


async def test_compose_html_source_preview_is_sandboxed_and_blocks_remote_content(
    page: Page,
    live_application: LiveApplication,
) -> None:
    remote_requests: list[str] = []

    def record_request(request: object) -> None:
        url = getattr(request, "url", "")
        if "tracker.invalid" in url:
            remote_requests.append(url)

    page.on("request", record_request)
    await page.goto(live_application.base_url + "/compose")
    assert await page.locator("#body-write-tab").get_attribute("aria-selected") == "true"
    await page.locator("#body-source-tab").click()
    source = page.locator("#html-source")
    html = (
        "<h1>Preview heading</h1>"
        "<script>window.top.previewCompromised=true</script>"
        '<img src="https://tracker.invalid/pixel" alt="remote">'
        '<a href="https://tracker.invalid/link">Safe link text</a>'
        '<form action="https://tracker.invalid/submit"><input value="unsafe"></form>'
    )
    await page.evaluate("window.previewCompromised = false")
    await source.fill(html)
    await page.locator("#body-preview-tab").click()

    frame = page.frame_locator("#html-preview")
    await frame.locator("h1").get_by_text("Preview heading", exact=True).wait_for()
    assert await page.locator("#html-preview").get_attribute("sandbox") == "allow-same-origin"
    assert await frame.locator("script, form, img").count() == 0
    preview_link = frame.locator("a")
    assert await preview_link.inner_text() == "Safe link text"
    assert (await preview_link.get_attribute("href") or "").endswith("#preview-link-disabled")
    assert await preview_link.get_attribute("title") == (
        "Preview only; destination: https://tracker.invalid/link"
    )
    assert await page.evaluate("window.previewCompromised") is False
    assert remote_requests == []
    assert await page.locator("#body-preview-tab").get_attribute("aria-selected") == "true"
    assert await page.locator("#body-source-panel").is_hidden()

    await page.locator("#body-source-tab").click()
    assert await source.input_value() == html
    assert await page.locator("#body-source-tab").get_attribute("aria-selected") == "true"
    assert await page.locator("#body-preview-panel").is_hidden()

    await page.locator("#body-write-tab").click()
    write = page.locator("#message-editor")
    assert await write.locator("script, form, img").count() == 0
    assert await write.locator("h1").inner_text() == "Preview heading"
    assert await write.locator("a").get_attribute("href") is None
    assert await source.input_value() == html
    assert remote_requests == []

    await page.locator("#inline-images").set_input_files(
        {
            "name": "logo.png",
            "mimeType": "image/png",
            "buffer": base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
                "+A8AAQUBAScY42YAAAAASUVORK5CYII="
            ),
        }
    )
    await page.locator("#body-source-tab").click()
    first_source = await source.input_value()
    assert 'src="cid:' in first_source
    first_cid = first_source.split('src="cid:', 1)[1].split('"', 1)[0]
    await source.fill(
        first_source.replace(
            f'<img src="cid:{first_cid}" alt="logo.png">',
            f'<img title="1 > 0" class="manual" src="cid:{first_cid}" alt="edited">',
        )
    )
    await page.locator("#inline-images").set_input_files(
        {
            "name": "replacement.png",
            "mimeType": "image/png",
            "buffer": base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
                "+A8AAQUBAScY42YAAAAASUVORK5CYII="
            ),
        }
    )
    replacement_source = await source.input_value()
    assert first_cid not in replacement_source
    assert ' 0">' not in replacement_source
    assert replacement_source.count('src="cid:') == 1
    await page.locator("#body-preview-tab").click()
    inline_preview = frame.locator("img")
    await inline_preview.wait_for()
    assert (await inline_preview.get_attribute("src") or "").startswith("blob:")
    await page.wait_for_function(
        "() => document.querySelector('#html-preview')?.contentDocument"
        "?.querySelector('img')?.naturalWidth > 0"
    )
    assert (
        await frame.locator("body").evaluate("node => getComputedStyle(node).paddingTop") == "16px"
    )
    assert remote_requests == []

    await page.locator("#body-source-tab").click()
    await page.locator("#inline-images").set_input_files([])
    assert 'src="cid:' not in await source.input_value()
    await page.locator("#body-preview-tab").click()
    assert await frame.locator("img").count() == 0
    assert remote_requests == []

    await page.locator("#body-source-tab").click()
    await source.fill('<img alt="missing source">')
    await page.locator("#body-preview-tab").click()
    assert await frame.locator(".empty").inner_text() == "Nothing to preview."


async def test_compose_resynchronizes_csrf_after_cookie_expiry(
    page: Page,
    live_application: LiveApplication,
) -> None:
    gateway = live_application.gateway
    post_count = 0

    def count_submission(request: object) -> None:
        nonlocal post_count
        if (
            getattr(request, "method", "") == "POST"
            and urlsplit(getattr(request, "url", "")).path == "/api/v1/admin/send"
        ):
            post_count += 1

    page.on("request", count_submission)
    await page.goto(live_application.base_url + "/compose")
    await page.locator("#compose-sender").select_option(ACCOUNT)
    form = page.locator("#compose-form")
    await form.locator('input[name="password"]').fill("fixture-mail-password")
    await form.locator('input[name="to"]').fill("recipient@example.test")
    await _fill_write_body(page, "body")

    await page.context.clear_cookies(name=COOKIE_NAME)
    await page.locator("#send-button").click()

    await (
        page.locator("[data-send-progress]")
        .get_by_text(
            "Maddy accepted the message",
            exact=False,
        )
        .wait_for()
    )
    assert post_count == 1
    assert len(gateway.deliveries) == 1
    assert gateway.sent_saves == 1


async def test_compose_resynchronizes_csrf_after_another_tab_rotates_cookie(
    page: Page,
    live_application: LiveApplication,
) -> None:
    gateway = live_application.gateway
    post_count = 0

    def count_submission(request: object) -> None:
        nonlocal post_count
        if (
            getattr(request, "method", "") == "POST"
            and urlsplit(getattr(request, "url", "")).path == "/api/v1/admin/send"
        ):
            post_count += 1

    page.on("request", count_submission)
    await page.goto(live_application.base_url + "/compose")
    await page.locator("#compose-sender").select_option(ACCOUNT)
    form = page.locator("#compose-form")
    await form.locator('input[name="password"]').fill("fixture-mail-password")
    await form.locator('input[name="to"]').fill("recipient@example.test")
    await _fill_write_body(page, "body")

    other_page = await page.context.new_page()
    try:
        await other_page.goto(live_application.base_url + "/")
        rotation = await other_page.evaluate(
            """async () => {
                const session = await fetch("/api/v1/auth/session");
                const token = (await session.json()).data.csrf_token;
                const response = await fetch("/api/v1/not-real", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRF-Token": token,
                    },
                    body: "{}",
                });
                return {
                    status: response.status,
                    replacement: response.headers.get("X-CSRF-Token"),
                };
            }"""
        )
        assert rotation["status"] == 404
        assert rotation["replacement"]
    finally:
        await other_page.close()

    await page.locator("#send-button").click()
    await (
        page.locator("[data-send-progress]")
        .get_by_text(
            "Maddy accepted the message",
            exact=False,
        )
        .wait_for()
    )
    assert post_count == 1
    assert len(gateway.deliveries) == 1
    assert gateway.sent_saves == 1


async def test_compose_recovers_from_same_cookie_name_on_another_loopback_port(
    page: Page,
    live_application: LiveApplication,
    tmp_path: Path,
) -> None:
    other_gateway = BrowserSecurityGateway()
    other_app = create_app(  # type: ignore[arg-type]
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
                "csrf_cookie_name": COOKIE_NAME,
                "session_cookie_name": SESSION_COOKIE_NAME,
                "secure_cookies": True,
            },
        },
        other_gateway,
    )
    other_runner = web.AppRunner(other_app, access_log=None)
    await other_runner.setup()
    listener, other_port = _listening_socket()
    other_site = web.SockSite(other_runner, listener)
    await other_site.start()

    post_count = 0

    def count_submission(request: object) -> None:
        nonlocal post_count
        if (
            getattr(request, "method", "") == "POST"
            and urlsplit(getattr(request, "url", "")).path == "/api/v1/admin/send"
        ):
            post_count += 1

    page.on("request", count_submission)
    try:
        await page.goto(live_application.base_url + "/compose")
        await page.locator("#compose-sender").select_option(ACCOUNT)
        form = page.locator("#compose-form")
        await form.locator('input[name="password"]').fill("fixture-mail-password")
        await form.locator('input[name="to"]').fill("recipient@example.test")
        await _fill_write_body(page, "body")

        other_page = await page.context.new_page()
        try:
            await other_page.goto(f"http://127.0.0.1:{other_port}/")
            await other_page.evaluate(
                """async () => {
                    const response = await fetch("/api/v1/auth/session");
                    return (await response.json()).data.csrf_token;
                }"""
            )
        finally:
            await other_page.close()

        await page.locator("#send-button").click()
        await (
            page.locator("[data-send-progress]")
            .get_by_text(
                "Maddy accepted the message",
                exact=False,
            )
            .wait_for()
        )
        assert post_count == 1
        assert len(live_application.gateway.deliveries) == 1
        assert live_application.gateway.sent_saves == 1
        assert other_gateway.deliveries == []
    finally:
        await other_runner.cleanup()


async def test_compose_never_retries_an_explicit_csrf_rejection(
    page: Page,
    live_application: LiveApplication,
) -> None:
    post_count = 0

    async def reject_submission(route: Route) -> None:
        nonlocal post_count
        post_count += 1
        await route.fulfill(
            status=403,
            content_type="application/json",
            body=json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "csrf_failed",
                        "message": "CSRF check failed; refresh.",
                    },
                }
            ),
        )

    await page.route("**/api/v1/admin/send", reject_submission)
    await page.goto(live_application.base_url + "/compose")
    await page.locator("#compose-sender").select_option(ACCOUNT)
    form = page.locator("#compose-form")
    await form.locator('input[name="password"]').fill("fixture-mail-password")
    await form.locator('input[name="to"]').fill("recipient@example.test")
    await _fill_write_body(page, "body")
    await page.locator("#send-button").click()

    alert = page.locator("#global-alert")
    await alert.get_by_text("This attempt did not send a message", exact=False).wait_for()
    await page.wait_for_timeout(50)
    assert post_count == 1
    assert live_application.gateway.deliveries == []
    assert await page.locator("#send-button").is_enabled()
    assert await form.locator('input[name="password"]').input_value() == ""


async def test_compose_locks_after_an_unverifiable_success_response(
    page: Page,
    live_application: LiveApplication,
) -> None:
    post_count = 0

    async def truncate_submission_response(route: Route) -> None:
        nonlocal post_count
        post_count += 1
        await route.fulfill(
            status=200,
            content_type="application/json",
            body='{"ok":true',
        )

    await page.route("**/api/v1/admin/send", truncate_submission_response)
    await page.goto(live_application.base_url + "/compose")
    await page.locator("#compose-sender").select_option(ACCOUNT)
    form = page.locator("#compose-form")
    await form.locator('input[name="password"]').fill("fixture-mail-password")
    await form.locator('input[name="to"]').fill("recipient@example.test")
    await _fill_write_body(page, "body")
    button = page.locator("#send-button")
    await button.click()

    alert = page.locator("#global-alert")
    await alert.get_by_text("The delivery result is unknown", exact=False).wait_for()
    await page.wait_for_timeout(50)
    assert post_count == 1
    assert await button.is_disabled()
    assert await button.inner_text() == "Sending locked"
    assert await form.locator('input[name="password"]').input_value() == ""


async def test_compose_locks_after_a_reused_csrf_token(
    page: Page,
    live_application: LiveApplication,
) -> None:
    post_count = 0

    async def reject_submission(route: Route) -> None:
        nonlocal post_count
        post_count += 1
        await route.fulfill(
            status=403,
            content_type="application/json",
            body=json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "csrf_reused",
                        "message": "CSRF token reused; refresh.",
                    },
                }
            ),
        )

    await page.route("**/api/v1/admin/send", reject_submission)
    await page.goto(live_application.base_url + "/compose")
    await page.locator("#compose-sender").select_option(ACCOUNT)
    form = page.locator("#compose-form")
    await form.locator('input[name="password"]').fill("fixture-mail-password")
    await form.locator('input[name="to"]').fill("recipient@example.test")
    await _fill_write_body(page, "body")
    button = page.locator("#send-button")
    await button.click()

    alert = page.locator("#global-alert")
    await alert.get_by_text("The delivery result is unknown", exact=False).wait_for()
    await page.wait_for_timeout(50)
    assert post_count == 1
    assert live_application.gateway.deliveries == []
    assert await button.is_disabled()
    assert await button.inner_text() == "Sending locked"


async def test_compose_network_failure_locks_ambiguous_submission(
    page: Page,
    live_application: LiveApplication,
) -> None:
    post_count = 0

    async def abort_submission(route: Route) -> None:
        nonlocal post_count
        post_count += 1
        await route.abort("connectionfailed")

    await page.route("**/api/v1/admin/send", abort_submission)
    await page.goto(live_application.base_url + "/compose")
    await page.locator("#compose-sender").select_option(ACCOUNT)
    form = page.locator("#compose-form")
    await form.locator('input[name="password"]').fill("fixture-mail-password")
    await form.locator('input[name="to"]').fill("recipient@example.test")
    await _fill_write_body(page, "body")
    button = page.locator("#send-button")
    await button.click()
    warning = page.locator("[data-send-progress]")
    await warning.get_by_text("The delivery result is unknown.", exact=False).wait_for()

    assert await button.is_disabled()
    assert await button.inner_text() == "Sending locked"
    assert await form.get_attribute("data-submitting") is None
    assert await form.get_attribute("aria-busy") is None
    assert "Do not resend" in await warning.inner_text()
    await form.evaluate(
        "node => node.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}))"
    )
    await page.wait_for_timeout(50)
    assert post_count == 1


async def test_theme_persists_and_mobile_navigation_has_safe_touch_targets(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.emulate_media(color_scheme="light")
    await page.goto(live_application.base_url + "/")
    root = page.locator("html")
    toggle = page.locator("#theme-toggle")
    initial_surface = await page.evaluate(
        "getComputedStyle(document.documentElement).getPropertyValue('--surface')"
    )

    assert await root.get_attribute("data-theme") == "light"
    assert await toggle.get_attribute("aria-pressed") is None
    await toggle.click()
    assert await root.get_attribute("data-theme") == "dark"
    assert await toggle.get_attribute("aria-label") == "Use light theme"
    assert (
        await page.evaluate(
            "getComputedStyle(document.documentElement).getPropertyValue('--surface')"
        )
        != initial_surface
    )
    assert await page.evaluate("localStorage.getItem('maddyweb-theme')") == "dark"
    await page.reload()
    assert await root.get_attribute("data-theme") == "dark"

    await page.set_viewport_size({"width": 320, "height": 844})
    await page.goto(live_application.base_url + "/compose")
    await page.get_by_role("heading", name="Compose", exact=True).wait_for()
    await page.locator('.compose-action[aria-current="page"]:visible').wait_for()
    visible_links = page.locator(".primary-nav a:visible")
    assert await visible_links.all_inner_texts() == [
        "Compose",
        "Mail",
        "Rules",
        "Security",
        "Overview",
        "Accounts",
        "Certificates",
    ]
    assert await page.locator('.compose-action[aria-current="page"]:visible').count() == 1
    assert await page.locator("#compose-sender").is_visible()
    assert await page.locator("#compose-sender-name").is_visible()
    assert await page.locator("#body-write-tab").is_visible()
    assert await page.locator("#body-source-tab").is_visible()
    assert await page.locator("#body-preview-tab").is_visible()
    assert await page.locator("#message-editor").is_visible()
    assert await page.get_by_role("toolbar", name="Message formatting").is_visible()
    assert await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    for index in range(await visible_links.count()):
        bounds = await visible_links.nth(index).bounding_box()
        assert bounds is not None
        assert bounds["height"] >= 44 - TOUCH_TARGET_GEOMETRY_TOLERANCE_PX
    theme_bounds = await toggle.bounding_box()
    assert theme_bounds is not None
    assert theme_bounds["height"] >= 44 - TOUCH_TARGET_GEOMETRY_TOLERANCE_PX
    assert theme_bounds["width"] >= 44 - TOUCH_TARGET_GEOMETRY_TOLERANCE_PX


async def test_folder_and_rule_builder_controls_have_mobile_touch_targets(
    page: Page,
    live_application: LiveApplication,
) -> None:
    async def empty_mail_rules(route: Route) -> None:
        await route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"ok": True, "data": {"rules": []}}),
        )

    await page.route("**/api/v1/admin/mail-rules?*", empty_mail_rules)
    await page.set_viewport_size({"width": 390, "height": 844})
    live_application.gateway.extra_mailboxes.append("Mobile folder")
    await page.goto(live_application.base_url + _mailbox_path("Mobile folder"))
    await page.get_by_role("heading", name="Mobile folder", exact=True).wait_for()
    await page.locator("#mobile-folders-button").click()
    folder_toggle = page.locator("#mail-folder-create-toggle")
    folder_menu_button = _folder_item(page, "Mobile folder").locator(
        ".mail-folder-menu-button"
    )
    menu_button_bounds = await folder_menu_button.bounding_box()
    assert menu_button_bounds is not None
    assert menu_button_bounds["height"] >= 44 - TOUCH_TARGET_GEOMETRY_TOLERANCE_PX
    assert menu_button_bounds["width"] >= 44 - TOUCH_TARGET_GEOMETRY_TOLERANCE_PX
    menu = await _open_folder_menu(page, "Mobile folder")
    for action in ("rename", "delete"):
        bounds = await menu.locator(
            f'[role="menuitem"][data-action="{action}"]'
        ).bounding_box()
        assert bounds is not None
        assert bounds["height"] >= 44 - TOUCH_TARGET_GEOMETRY_TOLERANCE_PX
    await page.keyboard.press("Escape")
    await folder_toggle.click()
    controls = [
        folder_toggle,
        page.locator("#mail-folder-create-form").get_by_role(
            "button", name="Create", exact=True
        ),
        page.locator("#mail-folder-create-cancel"),
    ]
    for control in controls:
        bounds = await control.bounding_box()
        assert bounds is not None
        assert bounds["height"] >= 44 - TOUCH_TARGET_GEOMETRY_TOLERANCE_PX

    await page.locator('a[data-section="rules"]').click()
    await page.get_by_role("heading", name="Mail rules", exact=True).wait_for()
    for control in await page.locator(".rule-node-button").all():
        bounds = await control.bounding_box()
        assert bounds is not None
        assert bounds["height"] >= 44 - TOUCH_TARGET_GEOMETRY_TOLERANCE_PX
    for selector in (
        "#mail-rule-enabled",
        "#mail-rule-stop",
        "#mail-rule-apply-existing",
    ):
        bounds = await page.locator(selector).bounding_box()
        assert bounds is not None
        assert 16 <= bounds["width"] <= 20
        assert 16 <= bounds["height"] <= 20
    assert await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


async def test_client_uses_safe_dom_construction_without_unsafe_html_sinks() -> None:
    source = await asyncio.to_thread(CLIENT_SOURCE_PATH.read_text, encoding="ascii")
    forbidden = (
        ".innerHTML",
        ".outerHTML",
        "insertAdjacentHTML",
        "insertHTML",
        "createContextualFragment",
        "setHTMLUnsafe",
        "document.write",
        "document.writeln",
        "eval(",
        "new Function",
    )

    for sink in forbidden:
        assert sink not in source
    assert "document.createElement" in source
    assert ".textContent" in source
    assert '"allow-popups allow-popups-to-escape-sandbox"' in source
