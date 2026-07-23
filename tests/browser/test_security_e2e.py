"""Real-Chromium SPA, workflow, and loopback security checks."""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlencode, urlsplit

import pytest
from aiohttp import web
from conftest import (
    ACCOUNT,
    CERTIFICATE_FINGERPRINT,
    CERTIFICATE_NAME,
    COOKIE_NAME,
    MAILBOX,
    MESSAGE_ID,
    NEW_ACCOUNT,
    TRASH_MAILBOX,
    BrowserSecurityGateway,
    LiveApplication,
    _listening_socket,
)

from maddyweb.web import create_app

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from playwright.async_api import Page, Route

pytestmark = pytest.mark.asyncio
CLIENT_SOURCE_PATH = Path(__file__).resolve().parents[2] / "src" / "maddyweb" / "static" / "app.js"


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
        browser_page = await context.new_page()
        try:
            yield browser_page
        finally:
            await context.close()
            await browser.close()


def _message_path() -> str:
    query = urlencode({"account": ACCOUNT, "mailbox": MAILBOX})
    return f"/mail/{MESSAGE_ID}?{query}"


async def _open_message(page: Page, live_application: LiveApplication) -> None:
    await page.goto(live_application.base_url + "/mail")
    await page.locator("#mail-account").select_option(ACCOUNT)
    await page.locator("#mail-mailbox").select_option(MAILBOX)
    await page.get_by_role("button", name="Open", exact=True).click()
    message_link = page.locator("#message-list-body a")
    await message_link.wait_for()
    assert await page.locator("#message-list-body img").count() == 0
    assert await page.locator("body").get_attribute("data-list-xss") is None
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
    await page.get_by_text(ACCOUNT, exact=True).wait_for()

    await page.locator('a[data-section="mail"]').click()
    await page.wait_for_url("**/mail")
    await page.get_by_role("heading", name="Mailboxes", exact=True).wait_for()

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


async def test_account_workflows_use_json_mutations_and_typed_deletion(
    page: Page,
    live_application: LiveApplication,
) -> None:
    await page.goto(live_application.base_url + "/accounts")
    await page.get_by_text(ACCOUNT, exact=True).wait_for()
    assert await page.locator("#runtime-badge").inner_text() == "MADDY 0.9.5"

    create_form = page.locator("#create-account-form")
    await create_form.locator('input[name="username"]').fill(NEW_ACCOUNT)
    await create_form.locator('input[name="password"]').fill("fixture-password-123")
    await create_form.get_by_role("button", name="Create account").click()
    new_row = page.locator("#accounts-body tr").filter(has_text=NEW_ACCOUNT)
    await new_row.wait_for()
    assert live_application.gateway.created_accounts == [(NEW_ACCOUNT, "fixture-password-123")]

    await new_row.get_by_role("button", name="Manage").click()
    password_form = page.locator("#change-password-form")
    await password_form.locator('input[name="password"]').fill("replacement-password-456")
    await password_form.get_by_role("button", name="Change password").click()
    await page.locator("#account-dialog").wait_for(state="hidden")
    assert live_application.gateway.password_changes == [(NEW_ACCOUNT, "replacement-password-456")]

    await new_row.get_by_role("button", name="Manage").click()
    limit_form = page.locator("#append-limit-form")
    await limit_form.locator('input[name="limit"]').fill("2097152")
    await limit_form.get_by_role("button", name="Set limit").click()
    await page.locator("#account-dialog").wait_for(state="hidden")
    await new_row.get_by_text("2,097,152", exact=True).wait_for()
    assert live_application.gateway.append_limit_changes == [(NEW_ACCOUNT, 2_097_152)]

    await new_row.get_by_role("button", name="Manage").click()
    await page.locator("#disable-credentials").click()
    await page.locator("#confirm-dialog").wait_for(state="visible")
    await page.locator("#confirm-action").click()
    await page.locator("#confirm-dialog").wait_for(state="hidden")
    await new_row.get_by_text("Credentials disabled", exact=True).wait_for()
    assert live_application.gateway.disabled_accounts == [NEW_ACCOUNT]

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
    assert live_application.gateway.deleted_accounts == [NEW_ACCOUNT]


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
    assert await fingerprints.evaluate_all(
        "nodes => nodes.map((node) => node.title)"
    ) == [
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
            const response = await fetch("/api/v1/session");
            return (await response.json()).data.csrf_token;
        }"""
    )
    post_url = f"/api/v1/mail/{MESSAGE_ID}/delete"
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


async def test_message_html_is_sandboxed_and_attachment_filename_is_safe(
    page: Page,
    live_application: LiveApplication,
) -> None:
    requested_urls: list[str] = []
    html_headers: list[dict[str, str]] = []
    page.on("request", lambda request: requested_urls.append(request.url))

    async def capture_html_response(response: object) -> None:
        url = getattr(response, "url", "")
        if "/api/v1/mail/" in url and "/html?" in url:
            html_headers.append(await response.all_headers())

    page.on("response", capture_html_response)
    await _open_message(page, live_application)

    frame_element = page.locator("iframe.message-frame")
    frame = page.frame_locator("iframe.message-frame")
    assert "Safe body" in await frame.locator("body").inner_text()
    assert await frame.locator("script").count() == 0
    assert await frame.locator("body").get_attribute("data-xss") is None
    image_sources = await frame.locator("img").evaluate_all(
        "images => images.map(image => image.getAttribute('src'))"
    )
    assert all(
        source is None or (source.startswith("/api/v1/mail/") and "/inline/" in source)
        for source in image_sources
    )
    assert await frame_element.get_attribute("sandbox") == ""
    assert await frame_element.get_attribute("referrerpolicy") == "no-referrer"
    assert not any("tracker.invalid" in url or url.startswith("data:") for url in requested_urls)
    assert html_headers
    assert "sandbox" in html_headers[0]["content-security-policy"]
    assert html_headers[0]["referrer-policy"] == "no-referrer"

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
    await page.wait_for_url("**/mail?account=admin%40example.test&mailbox=INBOX")
    assert live_application.gateway.permanent_deletions == [(ACCOUNT, MAILBOX, MESSAGE_ID)]


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
    await page.wait_for_url("**/mail?account=admin%40example.test&mailbox=Custom+Trash")
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
            and urlsplit(getattr(request, "url", "")).path == "/api/v1/send"
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
    await page.frame_locator("#html-preview").get_by_text(
        "A short message.", exact=True
    ).wait_for()
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
    assert parsed["From"].addresses[0].addr_spec == ACCOUNT
    plain_body = parsed.get_body(preferencelist=("plain",))
    assert plain_body is not None
    assert plain_body.get_content().strip() == "A short message."
    attachment = next(parsed.iter_attachments())
    assert attachment.get_filename() == "notes.txt"
    assert attachment.get_payload(decode=True) == b"ordinary attachment"
    assert delivered["envelope_from"] == ACCOUNT
    assert gateway.deliveries[0]["recipients"] == ("recipient@example.test",)
    assert gateway.sent_saves == 1


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
    await page.frame_locator("#html-preview").locator("em").get_by_text(
        "source", exact=True
    ).wait_for()
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
            and urlsplit(getattr(request, "url", "")).path == "/api/v1/send"
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
    assert (
        await page.locator("#html-preview").get_attribute("sandbox")
        == "allow-same-origin"
    )
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
    assert await frame.locator("body").evaluate(
        "node => getComputedStyle(node).paddingTop"
    ) == "16px"
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
            and urlsplit(getattr(request, "url", "")).path == "/api/v1/send"
        ):
            post_count += 1

    page.on("request", count_submission)
    await page.goto(live_application.base_url + "/compose")
    await page.locator("#compose-sender").select_option(ACCOUNT)
    form = page.locator("#compose-form")
    await form.locator('input[name="password"]').fill("fixture-mail-password")
    await form.locator('input[name="to"]').fill("recipient@example.test")
    await _fill_write_body(page, "body")

    await page.context.clear_cookies()
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
            and urlsplit(getattr(request, "url", "")).path == "/api/v1/send"
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
                const session = await fetch("/api/v1/session");
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
                "cookie_name": COOKIE_NAME,
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
            and urlsplit(getattr(request, "url", "")).path == "/api/v1/send"
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
                    const response = await fetch("/api/v1/session");
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

    await page.route("**/api/v1/send", reject_submission)
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

    await page.route("**/api/v1/send", truncate_submission_response)
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

    await page.route("**/api/v1/send", reject_submission)
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

    await page.route("**/api/v1/send", abort_submission)
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
        "Overview",
        "Mail",
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
        assert bounds["height"] >= 44
    theme_bounds = await toggle.bounding_box()
    assert theme_bounds is not None
    assert theme_bounds["height"] >= 44
    assert theme_bounds["width"] >= 44


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
    assert 'frame.setAttribute("sandbox", "")' in source
