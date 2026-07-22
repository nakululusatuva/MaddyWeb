from __future__ import annotations

import os
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

import pytest

from maddyweb.mail import (
    Attachment,
    DeliveryRejected,
    DeliveryUncertain,
    MailError,
    OutgoingMessage,
    PreparedMessage,
    attachment_download_headers,
    build_message,
    deliver_and_save,
    detect_safe_image_type,
    parse_message,
    prepare_message,
    rewrite_cid_images,
    safe_filename,
    sandboxed_html_document,
    sanitize_html_email,
)

FIXTURE_CREDENTIAL = "-".join(("account", "credential"))


def _message(**changes: object) -> OutgoingMessage:
    values: dict[str, object] = {
        "sender": "sender@example.test",
        "to": ("recipient@example.test",),
        "subject": "Test subject",
        "text": "Plain-text body",
    }
    values.update(changes)
    return OutgoingMessage(**values)  # type: ignore[arg-type]


def test_html_sanitizer_blocks_active_content_and_remote_images() -> None:
    cleaned = sanitize_html_email(
        "<style>body{background:url(https://tracker.test/x)}</style>"
        '<script>alert(1)</script><iframe src="https://evil.test"></iframe>'
        '<img src="https://tracker.test/pixel"><img src="//tracker.test/pixel">'
        '<img src="data:image/svg+xml,x"><img src="cid:logo.1">'
        '<a href="https://example.test/path">Link</a>'
    )
    assert "script" not in cleaned
    assert "iframe" not in cleaned
    assert "tracker.test" not in cleaned
    assert "data:image" not in cleaned
    assert 'src="cid:logo.1"' in cleaned
    assert "noopener" in cleaned


def test_sandbox_document_has_no_network_capability() -> None:
    document = sandboxed_html_document('<img src="https://tracker.test/x"><b>Body</b>')
    assert "tracker.test" not in document
    assert "default-src 'none'" in document
    assert "form-action 'none'" in document
    assert "img-src 'self'" in document
    assert "img-src cid:" not in document
    assert "img-src data:" not in document


def test_cid_rewriter_only_maps_exact_known_safe_url() -> None:
    sanitized = sanitize_html_email(
        '<img src="cid:known" alt="logo"><img src="cid:missing">'
        '<img src="data:image/png;base64,AAAA"><img src="https://tracker.test/x">'
    )
    rewritten = rewrite_cid_images(
        sanitized,
        {"known": "/mail/42/inline/0?account=a%40example.test&mailbox=INBOX"},
    )
    assert 'src="/mail/42/inline/0?account=a%40example.test&amp;mailbox=INBOX"' in rewritten
    assert "cid:" not in rewritten
    assert "data:" not in rewritten
    assert "tracker.test" not in rewritten
    assert rewritten.count("<img") == 1
    assert detect_safe_image_type(b"\x89PNG\r\n\x1a\nrest") == "image/png"
    assert detect_safe_image_type(b"<svg></svg>") is None


def test_attachment_filename_and_headers_are_download_only() -> None:
    assert safe_filename("../../evil\r\n.html") == "evil.html"
    headers = attachment_download_headers('../../bad"\r\n.html')
    assert headers["Content-Type"] == "application/octet-stream"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Content-Disposition"].startswith("attachment;")
    assert "\r" not in headers["Content-Disposition"]
    assert "\n" not in headers["Content-Disposition"]


def test_rich_mime_contains_alternative_cid_and_no_bcc_header() -> None:
    built = build_message(
        _message(
            cc=("copy@example.test",),
            bcc=("hidden@example.test",),
            html='<p>Rich text<img src="cid:logo"></p>',
            inline_images=(Attachment("logo.png", b"PNG", "image/png", "logo"),),
            attachments=(Attachment("notes.txt", b"notes", "text/plain"),),
        )
    )
    parsed = BytesParser(policy=policy.default).parsebytes(built.raw)
    assert parsed.get_content_type() == "multipart/mixed"
    assert parsed["Bcc"] is None
    assert "hidden@example.test" in built.recipients
    assert parsed.get_body(("plain",)).get_content().strip() == "Plain-text body"
    html_part = parsed.get_body(("html",))
    assert html_part is not None
    assert "cid:logo" in html_part.get_content()
    inline = next(part for part in parsed.walk() if part.get("Content-ID") == "<logo>")
    assert inline.get_content_disposition() == "inline"
    attachment = next(
        part for part in parsed.iter_attachments() if part.get_filename() == "notes.txt"
    )
    assert attachment.get_payload(decode=True) == b"notes"


def test_prepare_message_streams_path_to_private_spool(tmp_path: Path) -> None:
    source = tmp_path / "large.bin"
    source.write_bytes(b"a" * (2 * 1024 * 1024))
    prepared = prepare_message(
        _message(attachments=(Attachment("large.bin", source),)),
        spool_directory=tmp_path,
    )
    try:
        assert prepared.size > source.stat().st_size
        assert sum(len(chunk) for chunk in prepared.iter_chunks(32 * 1024)) == prepared.size
        if os.name != "nt":
            assert prepared.path.stat().st_mode & 0o777 == 0o600
        parsed = BytesParser(policy=policy.default).parsebytes(prepared.path.read_bytes())
        attachment = next(parsed.iter_attachments())
        assert attachment.get_payload(decode=True) == source.read_bytes()
    finally:
        path = prepared.path
        prepared.cleanup()
    assert not path.exists()


def test_header_injection_and_non_image_inline_are_rejected() -> None:
    with pytest.raises(MailError):
        build_message(_message(subject="hello\r\nBcc: attacker@example.test"))
    with pytest.raises(MailError):
        build_message(
            _message(
                html='<a href="cid:not-image">x</a>',
                inline_images=(Attachment("x.txt", b"x", "text/plain", "not-image"),),
            )
        )


def test_parse_received_message_sanitizes_html_and_attachment_name() -> None:
    source = EmailMessage()
    source["From"] = "sender@example.test"
    source["To"] = "recipient@example.test"
    source["Subject"] = "Incoming"
    source.set_content("plain")
    source.add_alternative(
        '<script>alert(1)</script><img src="https://tracker.test/pixel"><b>safe</b>',
        subtype="html",
    )
    source.add_attachment(
        b"<script>download</script>",
        maintype="text",
        subtype="html",
        filename="../../payload.html",
    )
    parsed = parse_message(source.as_bytes(policy=policy.SMTP))
    assert parsed.html is not None
    assert "script" not in parsed.html
    assert "tracker.test" not in parsed.html
    assert parsed.attachments[0].filename == "payload.html"


class _MailGateway:
    def __init__(self, delivery_error: Exception | None = None, *, fail_sent: bool = False):
        self.delivery_error = delivery_error
        self.fail_sent = fail_sent
        self.delivered_raw: bytes | None = None
        self.sent_raw: bytes | None = None
        self.spool_path: Path | None = None

    async def deliver_message(
        self,
        message: PreparedMessage,
        envelope_from: str,
        recipients: tuple[str, ...],
        submission_password: str,
    ) -> str:
        assert submission_password == FIXTURE_CREDENTIAL
        self.spool_path = message.path
        if self.delivery_error:
            raise self.delivery_error
        self.delivered_raw = b"".join(message.iter_chunks())
        return "delivery-1"

    async def save_sent(self, message: PreparedMessage) -> None:
        if self.fail_sent:
            raise RuntimeError("sent unavailable")
        self.sent_raw = b"".join(message.iter_chunks())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "safe_to_retry"),
    [
        (DeliveryRejected("rejected"), True),
        (DeliveryUncertain("connection reset"), False),
        (RuntimeError("unknown"), False),
    ],
)
async def test_delivery_failure_classification(error: Exception, safe_to_retry: bool) -> None:
    gateway = _MailGateway(error)
    result = await deliver_and_save(
        gateway,
        _message(),
        submission_password=FIXTURE_CREDENTIAL,
    )
    assert not result.delivered
    assert result.retry_delivery is safe_to_retry
    assert gateway.spool_path is not None
    assert not gateway.spool_path.exists()


@pytest.mark.asyncio
async def test_sent_copy_failure_is_partial_success_and_must_not_retry() -> None:
    gateway = _MailGateway(fail_sent=True)
    result = await deliver_and_save(
        gateway,
        _message(),
        submission_password=FIXTURE_CREDENTIAL,
    )
    assert result.delivered
    assert not result.saved_to_sent
    assert not result.retry_delivery
    assert "do not resend" in (result.error or "")
    assert gateway.delivered_raw is not None
    assert gateway.spool_path is not None and not gateway.spool_path.exists()
