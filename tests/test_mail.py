from __future__ import annotations

import os
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import unquote

import pytest

from maddyweb.mail import (
    MAX_ADDRESS_HEADER_CHARACTERS,
    MAX_HEADERS_PER_PART,
    MAX_INLINE_IMAGE_DIMENSION,
    MAX_MIME_DEPTH,
    MAX_MIME_PARTS,
    MAX_SANITIZED_HTML_DEPTH,
    MAX_SANITIZED_HTML_ELEMENTS,
    Attachment,
    DeliveryRejected,
    DeliveryUncertain,
    MailError,
    MailLimitError,
    MailValidationError,
    OutgoingMessage,
    PreparedMessage,
    attachment_download_headers,
    build_message,
    deliver_and_save,
    derive_reply_recipients,
    detect_safe_image_type,
    parse_message,
    prepare_message,
    reply_subject,
    reply_thread_headers,
    rewrite_cid_images,
    safe_display_header,
    safe_filename,
    safe_inline_image_metadata,
    sandboxed_html_document,
    sanitize_html_email,
)

FIXTURE_CREDENTIAL = "-".join(("account", "credential"))
VALID_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010804000000"
    "b51c0c020000000b4944415478da6364f80f00010501012718e3660000"
    "000049454e44ae426082"
)
VALID_GIF = bytes.fromhex(
    "47494638396101000100800000000000ffffff2c00000000010001000002014c003b"
)
VALID_WEBP = bytes.fromhex(
    "52494646220000005745425056503820160000003001009d012a0100010001402625"
    "a400037000feff3d58000000"
)
VALID_JPEG_HEADER = bytes.fromhex("ffd8ffc0000b080001000103011100")


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
        '<meta http-equiv="refresh" content="0;url=https://meta.test/">'
        '<base href="https://base.test/"><link rel="stylesheet" href="https://css.test/x">'
        '<form action="https://form.test/"><input autofocus name="token"></form>'
        '<svg><foreignObject><script>alert(2)</script></foreignObject></svg>'
        "<math><annotation-xml encoding=\"text/html\"><script>alert(3)</script>"
        "</annotation-xml></math>"
        '<object data="https://object.test/x"></object>'
        '<embed src="https://embed.test/x"><video poster="https://video.test/x"></video>'
        '<img src="https://tracker.test/pixel"><img src="//tracker.test/pixel">'
        '<img src="data:image/svg+xml,x" srcset="https://srcset.test/x 1x">'
        '<img src="cid:logo.1" onerror="alert(4)" style="background:url(https://style.test/x)">'
        '<a href="javascript:alert(5)" ping="https://ping.test/x">Unsafe link</a>'
        '<a href="https://example.test/path">Link</a>'
    )
    assert "script" not in cleaned
    assert "iframe" not in cleaned
    assert "foreignObject" not in cleaned
    assert "http-equiv" not in cleaned
    assert "srcset" not in cleaned
    assert "onerror" not in cleaned
    assert "style=" not in cleaned
    assert "javascript:" not in cleaned
    assert "ping=" not in cleaned
    assert "tracker.test" not in cleaned
    assert "data:image" not in cleaned
    assert 'src="cid:logo.1"' in cleaned
    assert "noopener" in cleaned


def test_sandbox_document_has_no_network_capability() -> None:
    document = sandboxed_html_document('<img src="https://tracker.test/x"><b>Body</b>')
    assert "tracker.test" not in document
    assert "default-src 'none'" in document
    assert "form-action 'none'" in document
    assert "img-src data:" in document
    assert "img-src cid:" not in document


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
    assert detect_safe_image_type(VALID_PNG) == "image/png"
    assert detect_safe_image_type(b"<svg></svg>") is None


def test_cid_rewriter_accepts_only_validated_raster_data_urls() -> None:
    sanitized = sanitize_html_email('<img src="cid:known"><img src="cid:missing">')
    encoded = "data:image/png;base64," + "A" * 12
    assert encoded in rewrite_cid_images(sanitized, {"known": encoded})
    for unsafe in (
        "data:image/svg+xml;base64,AAAA",
        "data:text/html;base64,AAAA",
        "data:image/png;base64,AAAA<script>",
        "javascript:alert(1)",
    ):
        assert "<img" not in rewrite_cid_images(sanitized, {"known": unsafe})


def test_sanitized_html_bounds_elements_and_depth() -> None:
    with pytest.raises(MailLimitError, match="too many elements"):
        sanitize_html_email("<span></span>" * (MAX_SANITIZED_HTML_ELEMENTS + 1))
    with pytest.raises(MailLimitError, match="nesting"):
        sanitize_html_email(
            "<div>" * (MAX_SANITIZED_HTML_DEPTH + 1)
            + "body"
            + "</div>" * (MAX_SANITIZED_HTML_DEPTH + 1)
        )


def test_inline_image_detector_rejects_animation_and_decode_bombs() -> None:
    assert safe_inline_image_metadata(VALID_PNG) == ("image/png", 1, 1)
    assert safe_inline_image_metadata(VALID_GIF) == ("image/gif", 1, 1)
    assert safe_inline_image_metadata(VALID_JPEG_HEADER) == ("image/jpeg", 1, 1)
    assert safe_inline_image_metadata(VALID_WEBP) == ("image/webp", 1, 1)

    oversized_png = bytearray(VALID_PNG)
    oversized_png[16:20] = (MAX_INLINE_IMAGE_DIMENSION + 1).to_bytes(4, "big")
    assert safe_inline_image_metadata(bytes(oversized_png)) is None

    pixel_bomb = bytearray(VALID_PNG)
    pixel_bomb[16:20] = (8000).to_bytes(4, "big")
    pixel_bomb[20:24] = (8000).to_bytes(4, "big")
    assert safe_inline_image_metadata(bytes(pixel_bomb)) is None

    comment_with_comma = b"\x21\xfe\x01\x2c\x00"
    static_gif_with_comma = VALID_GIF[:19] + comment_with_comma + VALID_GIF[19:]
    assert safe_inline_image_metadata(static_gif_with_comma) == ("image/gif", 1, 1)

    second_frame = VALID_GIF[19:-1]
    animated_gif = VALID_GIF[:-1] + second_frame + b"\x3b"
    assert safe_inline_image_metadata(animated_gif) is None

    animated_png_control = bytes.fromhex(
        "000000086163544c000000010000000000000000"
    )
    animated_png = VALID_PNG[:-12] + animated_png_control + VALID_PNG[-12:]
    assert safe_inline_image_metadata(animated_png) is None

    animated_webp = bytearray(VALID_WEBP)
    animated_webp[12:16] = b"VP8X"
    animated_webp[20] = 0x02
    assert safe_inline_image_metadata(bytes(animated_webp)) is None


def test_attachment_filename_and_headers_are_download_only() -> None:
    assert safe_filename("../../evil\r\n.html") == "evil.html"
    deceptive = "invoice\u202ecod.exe\u2066\u200b"
    assert safe_filename(deceptive) == "invoicecod.exe"
    headers = attachment_download_headers('../../bad"\r\n.html')
    assert headers["Content-Type"] == "application/octet-stream"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Content-Disposition"].startswith("attachment;")
    assert "\r" not in headers["Content-Disposition"]
    assert "\n" not in headers["Content-Disposition"]
    deceptive_header = attachment_download_headers(deceptive)["Content-Disposition"]
    decoded_filename = unquote(deceptive_header.split("filename*=UTF-8''", 1)[1])
    assert decoded_filename == "invoicecod.exe"
    assert all(control not in decoded_filename for control in ("\u202e", "\u2066", "\u200b"))


def test_rich_mime_contains_alternative_cid_and_no_bcc_header() -> None:
    built = build_message(
        _message(
            sender_name="Example Sender",
            cc=("copy@example.test",),
            bcc=("hidden@example.test",),
            html='<p>Rich text<img src="cid:logo"></p>',
            inline_images=(Attachment("logo.png", b"PNG", "image/png", "logo"),),
            attachments=(Attachment("notes.txt", b"notes", "text/plain"),),
        )
    )
    parsed = BytesParser(policy=policy.default).parsebytes(built.raw)
    assert parsed.get_content_type() == "multipart/mixed"
    from_address = parsed["From"].addresses[0]
    assert from_address.display_name == "Example Sender"
    assert from_address.addr_spec == "sender@example.test"
    assert built.envelope_from == "sender@example.test"
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
    with pytest.raises(MailValidationError) as stale_cid:
        build_message(_message(html='<img src="cid:no-longer-attached">'))
    assert stale_cid.value.public_message == (
        "HTML references an inline image that is no longer attached."
    )
    with pytest.raises(MailValidationError) as unused_inline:
        build_message(
            _message(
                html="<p>Body without the selected image</p>",
                inline_images=(Attachment("unused.png", b"PNG", "image/png", "unused"),),
            )
        )
    assert unused_inline.value.public_message == (
        "An attached inline image is no longer referenced by the HTML body."
    )


def test_sender_name_is_encoded_and_cannot_inject_headers() -> None:
    unicode_name = "Jos" + chr(0xE9) + " Example"
    built = build_message(_message(sender_name=unicode_name))
    parsed = BytesParser(policy=policy.default).parsebytes(built.raw)
    from_address = parsed["From"].addresses[0]
    assert from_address.display_name == unicode_name
    assert from_address.addr_spec == "sender@example.test"
    assert built.envelope_from == "sender@example.test"
    raw_headers = built.raw.partition(b"\r\n\r\n")[0]
    assert b"=?utf-8?" in raw_headers.lower()
    assert unicode_name.encode("utf-8") not in raw_headers

    maximum_name = "x" * 256
    maximum = build_message(_message(sender_name=maximum_name))
    maximum_parsed = BytesParser(policy=policy.default).parsebytes(maximum.raw)
    assert maximum_parsed["From"].addresses[0].display_name == maximum_name

    with pytest.raises(MailValidationError) as injected:
        build_message(_message(sender_name="Trusted\r\nBcc: attacker@example.test"))
    assert injected.value.public_message == (
        "Sender name must be 256 characters or fewer and cannot contain control characters."
    )

    with pytest.raises(MailValidationError):
        build_message(_message(sender_name="x" * 257))


def test_html_body_that_is_empty_after_sanitization_is_rejected() -> None:
    for html_body in (
        "<script>alert(1)</script>",
        '<img src="https://tracker.invalid/pixel">',
        '<img alt="missing source">',
    ):
        with pytest.raises(MailValidationError) as rejected:
            build_message(_message(html=html_body))
        assert rejected.value.public_message == (
            "The HTML body is empty after unsafe content is removed."
        )


def test_blank_sender_name_keeps_address_only_from_header() -> None:
    built = build_message(_message(sender_name="   "))
    parsed = BytesParser(policy=policy.default).parsebytes(built.raw)
    from_address = parsed["From"].addresses[0]
    assert from_address.display_name == ""
    assert from_address.addr_spec == "sender@example.test"


def test_sender_name_punctuation_is_quoted_by_the_email_library() -> None:
    sender_name = 'Example, "Sender"'
    built = build_message(_message(sender_name=sender_name))
    parsed = BytesParser(policy=policy.default).parsebytes(built.raw)
    assert parsed["From"].addresses[0].display_name == sender_name
    assert built.envelope_from == "sender@example.test"


@pytest.mark.parametrize(
    ("field", "label"),
    (("to", "To"), ("cc", "CC"), ("bcc", "BCC")),
)
def test_invalid_recipient_field_has_fixed_public_message(field: str, label: str) -> None:
    with pytest.raises(MailValidationError) as error:
        build_message(_message(**{field: ("not-an-address",)}))

    assert str(error.value) == f"invalid {label} recipient address"
    assert error.value.public_message == (
        f"The {label} field contains an invalid email address. Use complete addresses and "
        "separate multiple addresses with commas."
    )
    assert "not-an-address" not in error.value.public_message


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


def _nested_multipart(depth: int) -> bytes:
    chunks: list[str] = []
    for index in range(depth):
        boundary = f"b{index}"
        chunks.append(
            f"Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n"
            f"--{boundary}\r\n"
        )
    chunks.append("Content-Type: text/plain\r\n\r\nbody\r\n")
    for index in reversed(range(depth)):
        chunks.append(f"--b{index}--\r\n")
    return "".join(chunks).encode("ascii")


def test_parse_message_bounds_mime_depth_and_part_construction() -> None:
    assert parse_message(_nested_multipart(MAX_MIME_DEPTH)).text == "body"
    with pytest.raises(MailLimitError, match="nesting"):
        parse_message(_nested_multipart(MAX_MIME_DEPTH + 1))
    with pytest.raises(MailLimitError):
        parse_message(_nested_multipart(1100))

    boundary = "siblings"
    parts = "".join(
        f"--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n\r\n"
        for _ in range(MAX_MIME_PARTS)
    )
    siblings = (
        f"From: sender@example.test\r\n"
        f"Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n"
        f"{parts}--{boundary}--\r\n"
    ).encode("ascii")
    with pytest.raises(MailLimitError, match="too many MIME parts"):
        parse_message(siblings)


def test_attached_message_body_and_cid_are_never_rendered_as_outer_content() -> None:
    attached = EmailMessage()
    attached["From"] = "nested@example.test"
    attached["To"] = "recipient@example.test"
    attached["Subject"] = "Nested"
    attached.set_content("nested plain text")
    attached.add_alternative(
        '<b>nested HTML</b><img src="cid:nested-logo">',
        subtype="html",
    )
    nested_html = attached.get_payload()[-1]
    assert isinstance(nested_html, EmailMessage)
    nested_html.add_related(
        VALID_PNG,
        maintype="image",
        subtype="png",
        cid="<nested-logo>",
        filename="nested.png",
        disposition="inline",
    )

    outer = EmailMessage()
    outer["From"] = "sender@example.test"
    outer["To"] = "recipient@example.test"
    outer["Subject"] = "Outer"
    outer.set_content("outer plain text")
    outer.add_attachment(attached, filename="attached-message.eml")

    parsed = parse_message(outer.as_bytes(policy=policy.SMTP))

    assert parsed.text.strip() == "outer plain text"
    assert parsed.html is None
    assert parsed.attachments
    assert all(not attachment.inline for attachment in parsed.attachments)


def test_parse_message_rejects_header_count_and_address_bombs() -> None:
    too_many_headers = "".join(
        f"X-Test-{index}: value\r\n" for index in range(MAX_HEADERS_PER_PART + 1)
    )
    with pytest.raises(MailLimitError, match="headers"):
        parse_message((too_many_headers + "\r\nbody").encode("ascii"))

    repeated_recipients = "".join(
        f"To: User{index} <user{index}@example.test>\r\n" for index in range(20_000)
    )
    with pytest.raises(MailLimitError, match="headers"):
        parse_message(
            (
                "From: sender@example.test\r\n"
                "Subject: recipient bomb\r\n"
                f"{repeated_recipients}\r\nbody"
            ).encode("ascii")
        )

    recipients = ", ".join(
        f"user{index}@example.test"
        for index in range(MAX_ADDRESS_HEADER_CHARACTERS // 20 + 200)
    )
    with pytest.raises(MailLimitError, match="address headers"):
        parse_message(
            (
                "From: sender@example.test\r\n"
                f"To: {recipients}\r\n"
                "Subject: one large address header\r\n\r\nbody"
            ).encode("ascii")
        )


def test_display_headers_remove_directional_and_invisible_controls() -> None:
    unsafe = "Invoice\u202ecod.exe\u2066\u200b"
    assert safe_display_header(unsafe) == "Invoicecod.exe"

    source = EmailMessage()
    source["From"] = f"{unsafe} <sender@example.test>"
    source["To"] = "recipient@example.test"
    source["Subject"] = unsafe
    source.set_content("body")
    parsed = parse_message(source.as_bytes(policy=policy.SMTP))
    assert parsed.subject == "Invoicecod.exe"
    assert parsed.sender == '"Invoicecod.exe" <sender@example.test>'
    assert all(
        character not in parsed.subject + parsed.sender
        for character in "\u202e\u2066\u200b"
    )


def test_parse_html_only_message_provides_sanitized_plain_text_fallback() -> None:
    source = EmailMessage()
    source["From"] = "sender@example.test"
    source["To"] = "recipient@example.test"
    source["Subject"] = "HTML only"
    source.set_content(
        '<script>hidden()</script><img src="https://tracker.test/pixel">'
        "<p>Visible <strong>message</strong></p>",
        subtype="html",
    )

    parsed = parse_message(source.as_bytes(policy=policy.SMTP))

    assert parsed.html is not None
    assert "script" not in parsed.html
    assert "tracker.test" not in parsed.html
    assert parsed.text.strip()
    assert "Visible message" in parsed.text


def test_threading_headers_are_parsed_and_emitted_without_bcc() -> None:
    source = EmailMessage()
    source["From"] = "Author <author@example.test>"
    source["Reply-To"] = "Help Desk <reply@example.test>"
    source["To"] = "Self <self@example.test>"
    source["Cc"] = "Other <other@example.test>"
    source["Bcc"] = "Hidden <hidden@example.test>"
    source["Subject"] = "Question"
    source["Message-ID"] = "<current@example.test>"
    source["In-Reply-To"] = "<parent@example.test>"
    source["References"] = "<root@example.test> <parent@example.test>"
    source.set_content("body")

    parsed = parse_message(source.as_bytes(policy=policy.SMTP))

    assert parsed.reply_to == ("Help Desk <reply@example.test>",)
    assert parsed.message_id == "<current@example.test>"
    assert parsed.in_reply_to == "<parent@example.test>"
    assert parsed.references == ("<root@example.test>", "<parent@example.test>")

    built = build_message(
        _message(
            reply_to=("Help Desk <reply@example.test>",),
            in_reply_to=parsed.message_id,
            references=reply_thread_headers(parsed)[1],
        )
    )
    emitted = BytesParser(policy=policy.default).parsebytes(built.raw)
    assert str(emitted["Reply-To"]) == "Help Desk <reply@example.test>"
    assert str(emitted["Message-ID"]) == built.message_id
    assert str(emitted["In-Reply-To"]) == "<current@example.test>"
    assert str(emitted["References"]) == (
        "<root@example.test> <parent@example.test> <current@example.test>"
    )
    assert emitted["Bcc"] is None


def test_reply_recipient_derivation_excludes_self_bcc_and_duplicates() -> None:
    source = EmailMessage()
    source["From"] = "Author <author@example.test>"
    source["Reply-To"] = "Help Desk <reply@example.test>"
    source["To"] = "Self <self@example.test>, Other <other@example.test>"
    source["Cc"] = (
        "Duplicate <OTHER@example.test>, Self Alias <alias@example.test>, Team <team@example.test>"
    )
    source["Bcc"] = "Hidden <hidden@example.test>"
    source["Subject"] = "Question"
    source.set_content("body")
    parsed = parse_message(source.as_bytes(policy=policy.SMTP))

    reply = derive_reply_recipients(
        parsed,
        ("self@example.test", "alias@example.test"),
    )
    reply_all = derive_reply_recipients(
        parsed,
        ("self@example.test", "alias@example.test"),
        reply_all=True,
    )

    assert reply.to == ("Help Desk <reply@example.test>",)
    assert reply.cc == ()
    assert reply_all.to == ("Help Desk <reply@example.test>",)
    assert reply_all.cc == ("Other <other@example.test>", "Team <team@example.test>")
    assert "hidden@example.test" not in " ".join((*reply_all.to, *reply_all.cc))


def test_reply_to_own_message_falls_back_to_first_non_self_recipient() -> None:
    source = EmailMessage()
    source["From"] = "Self <self@example.test>"
    source["To"] = "Self <self@example.test>, First <first@example.test>"
    source["Cc"] = "Second <second@example.test>"
    source["Subject"] = "Sent message"
    source.set_content("body")
    parsed = parse_message(source.as_bytes(policy=policy.SMTP))

    reply = derive_reply_recipients(parsed, "self@example.test")
    reply_all = derive_reply_recipients(parsed, "self@example.test", reply_all=True)

    assert reply.to == ("First <first@example.test>",)
    assert reply_all.to == ("First <first@example.test>",)
    assert reply_all.cc == ("Second <second@example.test>",)


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        ("Question", "Re: Question"),
        ("re: Question", "Re: Question"),
        ("RE[2]: Question", "Re: Question"),
        ("", "Re: (No subject)"),
    ),
)
def test_reply_subject_adds_one_bounded_safe_prefix(source: str, expected: str) -> None:
    assert reply_subject(source) == expected


def test_reply_headers_reject_injection_invalid_ids_and_unbounded_references() -> None:
    with pytest.raises(MailError, match="reply subject"):
        reply_subject("Question\r\nBcc: hidden@example.test")
    with pytest.raises(MailError, match="In-Reply-To"):
        build_message(_message(in_reply_to="not-a-message-id"))
    with pytest.raises(MailError, match="References"):
        build_message(_message(references=("<ok@example.test>", "invalid")))
    with pytest.raises(MailLimitError, match="too many References"):
        build_message(
            _message(references=tuple(f"<reference-{index}@example.test>" for index in range(33)))
        )


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
async def test_delivery_rejection_uses_only_explicit_public_message(caplog) -> None:
    public_message = "SMTP authentication failed. Verify the account password."
    gateway = _MailGateway(DeliveryRejected("private diagnostic", public_message=public_message))
    result = await deliver_and_save(
        gateway,
        _message(),
        submission_password=FIXTURE_CREDENTIAL,
    )
    assert result.error == public_message
    assert "private diagnostic" not in result.error
    assert "message delivery was definitively not accepted" in caplog.text
    assert "private diagnostic" not in caplog.text


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
