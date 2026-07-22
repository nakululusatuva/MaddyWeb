"""Real-Chromium security checks for the loopback administration UI."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode, urlsplit

import pytest
from conftest import ACCOUNT, MAILBOX, MESSAGE_ID, LiveApplication

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from playwright.async_api import Page, Route

pytestmark = pytest.mark.asyncio


async def _allow_loopback_only(route: Route) -> None:
    hostname = urlsplit(route.request.url).hostname
    if hostname in {"127.0.0.1", "unlisted.invalid"}:
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
        page = await context.new_page()
        try:
            yield page
        finally:
            await context.close()
            await browser.close()


def _message_path(suffix: str = "") -> str:
    query = urlencode({"account": ACCOUNT, "mailbox": MAILBOX})
    return f"/mail/{MESSAGE_ID}{suffix}?{query}"


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
    page.on(
        "request",
        lambda request: (
            submitted_origins.append(request.headers.get("origin"))
            if request.method == "POST"
            else None
        ),
    )
    await page.goto(live_application.base_url + "/")
    await page.goto(attacker_url)

    async with page.expect_navigation() as navigation:
        await page.locator("#cross-origin button").click()
    response = await navigation.value

    assert response is not None
    assert response.status == 403
    assert "Cross-site request rejected" in await page.locator("body").inner_text()
    assert submitted_origins == [attacker_url.rstrip("/")]
    assert live_application.gateway.permanent_deletions == []


async def test_rejects_missing_and_replayed_csrf(
    page: Page,
    live_application: LiveApplication,
) -> None:
    confirmation_url = live_application.base_url + _message_path("/delete")
    await page.goto(confirmation_url)
    token = await page.locator('input[name="_csrf"]').input_value()
    post_url = f"{live_application.base_url}/mail/{MESSAGE_ID}/delete"

    missing = await page.evaluate(
        """async ({url, account, mailbox}) => {
            const body = new URLSearchParams({account, mailbox, confirmation: "wrong"});
            const response = await fetch(url, {method: "POST", body});
            return {status: response.status, text: await response.text()};
        }""",
        {"url": post_url, "account": ACCOUNT, "mailbox": MAILBOX},
    )
    assert missing["status"] == 403
    assert "CSRF check failed" in missing["text"]

    attempted = await page.evaluate(
        """async ({url, token, account, mailbox}) => {
            const body = new URLSearchParams({
                _csrf: token, account, mailbox, confirmation: "wrong"
            });
            const response = await fetch(url, {method: "POST", body});
            return {status: response.status, text: await response.text()};
        }""",
        {"url": post_url, "token": token, "account": ACCOUNT, "mailbox": MAILBOX},
    )
    assert attempted["status"] == 400
    assert "Confirmation text mismatch" in attempted["text"]

    # The first validated attempt consumes the token and rotates the
    # process-bound Secure cookie.  Reusing the old DOM token must therefore
    # fail even though the browser automatically retained the replacement.
    replayed = await page.evaluate(
        """async ({url, token, account, mailbox}) => {
            const body = new URLSearchParams({
                _csrf: token, account, mailbox, confirmation: "wrong"
            });
            const response = await fetch(url, {method: "POST", body});
            return {status: response.status, text: await response.text()};
        }""",
        {"url": post_url, "token": token, "account": ACCOUNT, "mailbox": MAILBOX},
    )
    assert replayed["status"] == 403
    assert "CSRF check failed" in replayed["text"]
    assert live_application.gateway.permanent_deletions == []


async def test_sanitizes_html_and_attachment_filename(
    page: Page,
    live_application: LiveApplication,
) -> None:
    requested_urls: list[str] = []
    page.on("request", lambda request: requested_urls.append(request.url))
    await page.goto(live_application.base_url + _message_path())

    frame = page.frame_locator("iframe.mail-frame")
    assert "Safe body" in await frame.locator("body").inner_text()
    assert await frame.locator("script").count() == 0
    assert await frame.locator("body").get_attribute("data-xss") is None
    image_sources = await frame.locator("img").evaluate_all(
        "images => images.map(image => image.getAttribute('src'))"
    )
    assert all(
        source is None or (source.startswith("/mail/") and "/inline/" in source)
        for source in image_sources
    )
    assert await page.locator("iframe.mail-frame").get_attribute("sandbox") == ""
    assert not any("tracker.invalid" in url or url.startswith("data:") for url in requested_urls)

    unsafe_attachment = page.get_by_role("link", name="evil.html", exact=True)
    assert await unsafe_attachment.count() == 1
    async with page.expect_download() as download_info:
        await unsafe_attachment.click()
    download = await download_info.value
    assert download.suggested_filename == "evil.html"
    assert "/" not in download.suggested_filename
    assert "\\" not in download.suggested_filename


async def test_permanent_delete_requires_exact_confirmation(
    page: Page,
    live_application: LiveApplication,
) -> None:
    submitted_origins: list[str | None] = []
    page.on(
        "request",
        lambda request: (
            submitted_origins.append(request.headers.get("origin"))
            if request.method == "POST"
            else None
        ),
    )
    confirmation_url = live_application.base_url + _message_path("/delete")
    await page.goto(confirmation_url)
    await page.locator('input[name="confirmation"]').fill("delete")
    async with page.expect_navigation() as rejected_navigation:
        await page.get_by_role("button", name="Permanently delete message").click()
    rejected = await rejected_navigation.value

    assert rejected is not None
    assert rejected.status == 400
    assert "Confirmation text mismatch" in await page.locator("body").inner_text()
    assert live_application.gateway.permanent_deletions == []

    await page.goto(confirmation_url)
    await page.locator('input[name="confirmation"]').fill("PERMANENTLY DELETE")
    async with page.expect_navigation() as accepted_navigation:
        await page.get_by_role("button", name="Permanently delete message").click()
    accepted = await accepted_navigation.value

    assert accepted is not None
    assert accepted.status == 200
    assert "status=deleted" in page.url
    assert submitted_origins == [live_application.base_url, live_application.base_url]
    assert live_application.gateway.permanent_deletions == [(ACCOUNT, MAILBOX, MESSAGE_ID)]
