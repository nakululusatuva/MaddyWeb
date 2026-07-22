"""Safe parsing, rendering and construction of Internet mail messages."""

from __future__ import annotations

import asyncio
import base64
import html
import importlib
import io
import logging
import os
import re
import tempfile
import uuid
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from email import policy
from email.headerregistry import Address
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import format_datetime, getaddresses, make_msgid
from functools import cache
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, BinaryIO, ClassVar, Protocol, runtime_checkable
from urllib.parse import quote

LOGGER = logging.getLogger(__name__)

MAX_RAW_MESSAGE_BYTES = 25 * 1024 * 1024
MAX_BODY_CHARACTERS = 2 * 1024 * 1024
MAX_ATTACHMENT_BYTES = 20 * 1024 * 1024
MAX_TOTAL_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_ATTACHMENTS = 64
MAX_MIME_PARTS = 128

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+$")
_CID_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~@-]{1,200}$")


@cache
def _load_nh3() -> Any | None:
    """Load the sanitizer only when an HTML message is actually rendered."""

    try:
        return importlib.import_module("nh3")
    except ImportError:  # pragma: no cover - fail-closed source-tree fallback
        return None


_HTML_TAGS = {
    "a",
    "abbr",
    "b",
    "blockquote",
    "br",
    "caption",
    "code",
    "col",
    "colgroup",
    "dd",
    "del",
    "div",
    "dl",
    "dt",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "i",
    "img",
    "ins",
    "kbd",
    "li",
    "ol",
    "p",
    "pre",
    "q",
    "s",
    "samp",
    "small",
    "span",
    "strong",
    "sub",
    "sup",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "u",
    "ul",
    "var",
}
_HTML_ATTRIBUTES = {
    "a": {"href", "title"},
    "blockquote": {"cite"},
    "col": {"span", "width"},
    "colgroup": {"span", "width"},
    "img": {"alt", "height", "src", "title", "width"},
    "ol": {"start", "type"},
    "q": {"cite"},
    "table": {"summary"},
    "td": {"colspan", "headers", "rowspan"},
    "th": {"colspan", "headers", "rowspan", "scope"},
}
_REMOVE_CONTENT_TAGS = {
    "applet",
    "embed",
    "form",
    "iframe",
    "math",
    "object",
    "script",
    "style",
    "svg",
    "template",
}


class MailError(ValueError):
    """Base exception for invalid or unreasonably large message input."""


class MailLimitError(MailError):
    """A configured mail resource bound was exceeded."""


class DeliveryRejected(RuntimeError):
    """The backend explicitly rejected delivery; resubmission cannot duplicate it."""


class DeliveryUncertain(RuntimeError):
    """The connection failed after submission may have begun; do not auto-retry."""


class _TextExtractor(HTMLParser):
    _BLOCK_TAGS: ClassVar[frozenset[str]] = frozenset(
        {
            "blockquote",
            "br",
            "div",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "hr",
            "li",
            "p",
            "pre",
            "table",
            "tr",
        }
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


class _CidImageRewriter(HTMLParser):
    """Re-serialize sanitized HTML while mapping only exact, known CID images."""

    _VOID_TAGS: ClassVar[frozenset[str]] = frozenset({"br", "col", "hr", "img"})

    def __init__(self, cid_urls: Mapping[str, str]) -> None:
        super().__init__(convert_charrefs=False)
        self.cid_urls = cid_urls
        self.parts: list[str] = []

    def _start_tag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag not in _HTML_TAGS:
            return
        allowed = _HTML_ATTRIBUTES.get(tag, set())
        rendered: list[str] = []
        seen: set[str] = set()
        if tag == "img":
            source = next((value for name, value in attrs if name.lower() == "src"), None)
            if source is None or not source.lower().startswith("cid:"):
                return
            mapped = self.cid_urls.get(source[4:].strip("<>"))
            if mapped is None or not mapped.startswith("/"):
                return
            rendered.append(f' src="{html.escape(mapped, quote=True)}"')
            seen.add("src")
        for raw_name, raw_value in attrs:
            name = raw_name.lower()
            if name in seen or name not in allowed or name == "src":
                continue
            seen.add(name)
            value = "" if raw_value is None else raw_value
            rendered.append(f' {html.escape(name, quote=True)}="{html.escape(value, quote=True)}"')
        self.parts.append(f"<{tag}{''.join(rendered)}>")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start_tag(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start_tag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in _HTML_TAGS and tag not in self._VOID_TAGS:
            self.parts.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        self.parts.append(html.escape(data, quote=False))

    def handle_entityref(self, name: str) -> None:
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9]+", name):
            self.parts.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        if re.fullmatch(r"(?:[0-9]+|[xX][0-9A-Fa-f]+)", name):
            self.parts.append(f"&#{name};")


def html_to_text(value: str) -> str:
    """Create a conservative plain-text alternative without extra packages."""

    parser = _TextExtractor()
    parser.feed(value[:MAX_BODY_CHARACTERS])
    parser.close()
    lines = (" ".join(line.split()) for line in "".join(parser.parts).splitlines())
    return "\n".join(line for line in lines if line).strip()


def rewrite_cid_images(value: str, cid_urls: Mapping[str, str]) -> str:
    """Map known CID sources to local URLs and remove every unknown image."""

    parser = _CidImageRewriter(cid_urls)
    parser.feed(value)
    parser.close()
    return "".join(parser.parts)


def detect_safe_image_type(data: bytes) -> str | None:
    """Recognize the four passive raster formats allowed in the mail iframe."""

    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def sanitize_html_email(value: str) -> str:
    """Sanitize HTML mail and remove every network-capable image source.

    Only ``cid:`` image URLs survive.  In particular, HTTP(S), protocol-relative,
    ``file:``, SVG/data URLs, forms, scripts, CSS and active embedded content are
    removed.  If nh3 is unavailable, the function fails closed and renders the
    whole input as escaped text.
    """

    if len(value) > MAX_BODY_CHARACTERS:
        raise MailLimitError("HTML body is too large")
    sanitizer = _load_nh3()
    if sanitizer is None:
        return f"<pre>{html.escape(value)}</pre>"
    return sanitizer.clean(
        value,
        tags=_HTML_TAGS,
        attributes=_HTML_ATTRIBUTES,
        clean_content_tags=_REMOVE_CONTENT_TAGS,
        link_rel="noopener noreferrer nofollow",
        strip_comments=True,
        url_schemes={"cid", "http", "https", "mailto"},
        attribute_filter=_mail_attribute_filter,
    )


def _mail_attribute_filter(tag: str, attribute: str, value: str) -> str | None:
    """nh3 callback that permits links but restricts images to ``cid:``."""

    if tag == "img" and attribute == "src":
        if not value.lower().startswith("cid:"):
            return None
        cid = value[4:].strip("<>")
        if not _CID_RE.fullmatch(cid):
            return None
        return f"cid:{cid}"
    if attribute in {"href", "cite"}:
        lowered = value.strip().lower()
        if lowered.startswith(("http://", "https://", "mailto:")):
            return value
        return None
    return value


def sandboxed_html_document(value: str, *, already_sanitized: bool = False) -> str:
    """Wrap sanitized mail in a standalone document for a sandboxed iframe."""

    safe = value if already_sanitized else sanitize_html_email(value)
    return (
        '<!doctype html><html lang="und"><head><meta charset="utf-8">'
        '<meta name="referrer" content="no-referrer">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "base-uri 'none'; form-action 'none'; img-src 'self'; object-src 'none'; "
        "style-src 'unsafe-inline'\">"
        "<style>body{box-sizing:border-box;margin:0;padding:1rem;color:#172033;"
        "font:15px/1.55 system-ui,sans-serif;overflow-wrap:anywhere}"
        "img{max-width:100%;height:auto}table{max-width:100%;border-collapse:collapse}"
        "blockquote{margin-left:.25rem;padding-left:.8rem;border-left:3px solid #ccd3df}"
        "</style></head><body>"
        f"{safe}</body></html>"
    )


def safe_filename(value: str | None, *, default: str = "attachment.bin") -> str:
    """Make an untrusted MIME filename safe for a download header."""

    if not value:
        return default
    name = value.replace("\\", "/").rsplit("/", 1)[-1]
    name = _CONTROL_RE.sub("", name).strip().strip(".")
    if not name or name in {".", ".."}:
        return default
    return name[:180]


def attachment_download_headers(filename: str | None) -> dict[str, str]:
    """Force an attachment download without MIME sniffing or header injection."""

    filename = safe_filename(filename)
    ascii_name = filename.encode("ascii", "ignore").decode("ascii") or "attachment.bin"
    ascii_name = ascii_name.replace('"', "").replace("\\", "_")
    encoded = quote(filename, safe="")
    return {
        "Content-Disposition": (
            f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{encoded}"
        ),
        "Content-Type": "application/octet-stream",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "Cache-Control": "private, no-store",
    }


def _split_content_type(value: str, *, inline: bool = False) -> tuple[str, str]:
    try:
        main, sub = value.lower().split("/", 1)
    except ValueError:
        return ("application", "octet-stream")
    if not _TOKEN_RE.fullmatch(main) or not _TOKEN_RE.fullmatch(sub):
        return ("application", "octet-stream")
    if inline and main != "image":
        raise MailError("inline MIME parts must be images")
    return main, sub


def _validate_header_value(value: str, label: str, *, maximum: int = 998) -> str:
    value = value.strip()
    if _CONTROL_RE.search(value) or len(value) > maximum:
        raise MailError(f"invalid {label}")
    return value


def parse_address_list(values: str | Iterable[str], *, maximum: int = 100) -> tuple[str, ...]:
    """Parse and validate a display-name/address list for message headers."""

    source = [values] if isinstance(values, str) else list(values)
    if any(_CONTROL_RE.search(item) for item in source):
        raise MailError("address header contains control characters")
    parsed = getaddresses(source)
    if len(parsed) > maximum:
        raise MailLimitError("too many recipients")
    result: list[str] = []
    for display_name, addr_spec in parsed:
        if not addr_spec or "@" not in addr_spec:
            raise MailError("invalid email address")
        try:
            address = Address(display_name=display_name, addr_spec=addr_spec)
        except (TypeError, ValueError) as exc:
            raise MailError("invalid email address") from exc
        if not address.username or not address.domain:
            raise MailError("invalid email address")
        result.append(str(address))
    if not result:
        raise MailError("at least one email address is required")
    return tuple(result)


def _envelope_address(value: str) -> str:
    parsed = getaddresses([value])
    if len(parsed) != 1 or not parsed[0][1]:
        raise MailError("invalid envelope address")
    return parsed[0][1]


@dataclass(frozen=True, slots=True)
class Attachment:
    filename: str
    data: bytes | Path | BinaryIO
    content_type: str = "application/octet-stream"
    content_id: str | None = None
    declared_size: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.data, (bytes, Path)) and not hasattr(self.data, "read"):
            raise TypeError("attachment data must be bytes, a Path, or a binary stream")
        if self.declared_size is not None and self.declared_size < 0:
            raise ValueError("declared_size must not be negative")
        if self.size > MAX_ATTACHMENT_BYTES:
            raise MailLimitError("attachment is too large")
        if self.content_id is not None and not _CID_RE.fullmatch(self.content_id.strip("<>")):
            raise MailError("invalid content ID")

    @property
    def size(self) -> int:
        if isinstance(self.data, bytes):
            return len(self.data)
        if isinstance(self.data, Path):
            try:
                return self.data.stat().st_size
            except OSError as exc:
                raise MailError("attachment path is unavailable") from exc
        if self.declared_size is not None:
            return self.declared_size
        stream = self.data
        if not hasattr(stream, "seek") or not hasattr(stream, "tell"):
            raise MailError("a non-seekable stream requires declared_size")
        try:
            position = stream.tell()
            stream.seek(0, os.SEEK_END)
            length = stream.tell()
            stream.seek(position)
        except (OSError, ValueError) as exc:
            raise MailError("unable to determine attachment stream size") from exc
        return length

    @contextmanager
    def open(self) -> Iterator[BinaryIO]:
        """Open the source from its beginning without taking ownership of streams."""

        if isinstance(self.data, bytes):
            with io.BytesIO(self.data) as stream:
                yield stream
            return
        if isinstance(self.data, Path):
            with self.data.open("rb") as stream:
                yield stream
            return
        stream = self.data
        previous: int | None = None
        try:
            if hasattr(stream, "tell"):
                previous = stream.tell()
            if hasattr(stream, "seek"):
                stream.seek(0)
            yield stream
        finally:
            if previous is not None and hasattr(stream, "seek"):
                with suppress(OSError, ValueError):
                    stream.seek(previous)


@dataclass(frozen=True, slots=True)
class OutgoingMessage:
    sender: str
    to: tuple[str, ...]
    subject: str
    text: str
    cc: tuple[str, ...] = ()
    bcc: tuple[str, ...] = ()
    html: str | None = None
    inline_images: tuple[Attachment, ...] = ()
    attachments: tuple[Attachment, ...] = ()


@dataclass(frozen=True, slots=True)
class BuiltMessage:
    raw: bytes
    envelope_from: str
    recipients: tuple[str, ...]
    message_id: str


@dataclass(slots=True)
class PreparedMessage:
    """A securely spooled RFC 5322 message suitable for chunked IPC transfer."""

    path: Path
    envelope_from: str
    recipients: tuple[str, ...]
    message_id: str
    size: int

    def open(self) -> BinaryIO:
        return self.path.open("rb")

    def iter_chunks(self, chunk_size: int = 64 * 1024) -> Iterator[bytes]:
        if chunk_size <= 0 or chunk_size > 1024 * 1024:
            raise ValueError("invalid chunk size")
        with self.open() as stream:
            while chunk := stream.read(chunk_size):
                yield chunk

    def cleanup(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            LOGGER.exception("failed to remove prepared mail spool %s", self.path)


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    delivered: bool
    saved_to_sent: bool
    delivery_id: str | None = None
    error: str | None = None
    retry_delivery: bool = False


@dataclass(frozen=True, slots=True)
class ParsedAttachment:
    attachment_id: str
    filename: str
    content_type: str
    data: bytes
    content_id: str | None = None
    inline: bool = False

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass(frozen=True, slots=True)
class ParsedMessage:
    subject: str
    sender: str
    to: tuple[str, ...]
    cc: tuple[str, ...]
    date: str
    message_id: str
    text: str
    html: str | None
    attachments: tuple[ParsedAttachment, ...]


@runtime_checkable
class MailGateway(Protocol):
    async def deliver_message(
        self,
        message: PreparedMessage,
        envelope_from: str,
        recipients: Sequence[str],
        submission_password: str,
    ) -> str | None:
        """Submit one already-built RFC 5322 message exactly once."""

    async def save_sent(self, message: PreparedMessage) -> None:
        """Store an already-delivered message in the Sent mailbox."""


def _validated_outgoing(
    value: OutgoingMessage,
) -> tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], str, str | None]:
    sender = parse_address_list(value.sender, maximum=1)[0]
    to = tuple(address for item in value.to for address in parse_address_list(item))
    cc = tuple(address for item in value.cc for address in parse_address_list(item))
    bcc = tuple(address for item in value.bcc for address in parse_address_list(item))
    if not to and not cc and not bcc:
        raise MailError("at least one recipient is required")
    if len(to) + len(cc) + len(bcc) > 100:
        raise MailLimitError("too many recipients")
    subject = _validate_header_value(value.subject, "subject")
    if len(value.text) > MAX_BODY_CHARACTERS:
        raise MailLimitError("text body is too large")

    all_parts = value.inline_images + value.attachments
    if len(all_parts) > MAX_ATTACHMENTS:
        raise MailLimitError("too many attachments")
    if sum(part.size for part in all_parts) > MAX_TOTAL_ATTACHMENT_BYTES:
        raise MailLimitError("attachments are too large")
    safe_html = sanitize_html_email(value.html) if value.html is not None else None
    if value.inline_images and safe_html is None:
        raise MailError("inline images require an HTML body")
    seen_cids: set[str] = set()
    for image in value.inline_images:
        cid = (image.content_id or "").strip("<>")
        if not cid or cid in seen_cids:
            raise MailError("inline images require unique content IDs")
        seen_cids.add(cid)
        _split_content_type(image.content_type, inline=True)
    return sender, to, cc, bcc, subject, safe_html


def _header_block(message: EmailMessage) -> bytes:
    raw = message.as_bytes(policy=policy.SMTP)
    header, separator, _body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise MailError("failed to serialize MIME headers")
    return header + separator


def _container_headers(subtype: str, boundary: str) -> bytes:
    message = EmailMessage(policy=policy.SMTP)
    message.set_type(f"multipart/{subtype}")
    message.set_boundary(boundary)
    return _header_block(message)


def _text_part(value: str, subtype: str) -> bytes:
    message = EmailMessage(policy=policy.SMTP)
    message.set_content(value, subtype=subtype, charset="utf-8")
    return message.as_bytes(policy=policy.SMTP)


def _write_boundary(stream: BinaryIO, boundary: str, *, closing: bool = False) -> None:
    suffix = b"--\r\n" if closing else b"\r\n"
    stream.write(b"--" + boundary.encode("ascii") + suffix)


def _write_serialized_part(stream: BinaryIO, boundary: str, raw: bytes) -> None:
    _write_boundary(stream, boundary)
    stream.write(raw)
    if not raw.endswith(b"\r\n"):
        stream.write(b"\r\n")


def _attachment_headers(attachment: Attachment, *, inline: bool) -> bytes:
    main, sub = _split_content_type(attachment.content_type, inline=inline)
    message = EmailMessage(policy=policy.SMTP)
    message["Content-Type"] = f"{main}/{sub}"
    message["Content-Transfer-Encoding"] = "base64"
    message.add_header(
        "Content-Disposition",
        "inline" if inline else "attachment",
        filename=safe_filename(attachment.filename),
    )
    if inline:
        message["Content-ID"] = f"<{(attachment.content_id or '').strip('<>')}>"
    return _header_block(message)


def _write_base64_source(destination: BinaryIO, attachment: Attachment) -> None:
    expected = attachment.size
    total = 0
    carry = b""
    with attachment.open() as source:
        while chunk := source.read(64 * 1024):
            if not isinstance(chunk, bytes):
                raise MailError("attachment stream must return bytes")
            total += len(chunk)
            if total > MAX_ATTACHMENT_BYTES:
                raise MailLimitError("attachment grew beyond its limit")
            buffered = carry + chunk
            complete = len(buffered) - (len(buffered) % 57)
            if complete:
                lines = [
                    base64.b64encode(buffered[index : index + 57])
                    for index in range(0, complete, 57)
                ]
                destination.write(b"\r\n".join(lines) + b"\r\n")
            carry = buffered[complete:]
    if carry:
        destination.write(base64.b64encode(carry) + b"\r\n")
    if total != expected:
        raise MailError("attachment size changed while building message")


def _write_attachment(
    stream: BinaryIO,
    boundary: str,
    attachment: Attachment,
    *,
    inline: bool,
) -> None:
    _write_boundary(stream, boundary)
    stream.write(_attachment_headers(attachment, inline=inline))
    _write_base64_source(stream, attachment)


def prepare_message(
    value: OutgoingMessage,
    *,
    spool_directory: Path | None = None,
) -> PreparedMessage:
    """Stream a complete MIME message to a mode-0600 temporary file."""

    sender, to, cc, bcc, subject, safe_html = _validated_outgoing(value)
    envelope_from = _envelope_address(sender)
    envelope_recipients = tuple(_envelope_address(item) for item in (*to, *cc, *bcc))
    sender_domain = envelope_from.rsplit("@", 1)[-1]
    message_id = make_msgid(domain=sender_domain)
    mixed_boundary = f"maddyweb-mixed-{uuid.uuid4().hex}"
    alt_boundary = f"maddyweb-alt-{uuid.uuid4().hex}"
    related_boundary = f"maddyweb-related-{uuid.uuid4().hex}"

    top = EmailMessage(policy=policy.SMTP)
    top["From"] = sender
    if to:
        top["To"] = ", ".join(to)
    if cc:
        top["Cc"] = ", ".join(cc)
    top["Subject"] = subject
    top["Date"] = format_datetime(datetime.now(UTC))
    top["Message-ID"] = message_id
    top.set_type("multipart/mixed")
    top.set_boundary(mixed_boundary)

    directory = str(spool_directory) if spool_directory is not None else None
    descriptor, filename = tempfile.mkstemp(
        prefix="maddyweb-mail-",
        suffix=".eml",
        dir=directory,
    )
    path = Path(filename)
    try:
        try:
            os.chmod(path, 0o600)
        except OSError:
            LOGGER.debug("unable to chmod mail spool on this platform", exc_info=True)
        with os.fdopen(descriptor, "w+b") as stream:
            stream.write(_header_block(top))
            stream.write(b"This is a MIME multipart message.\r\n")
            plain_text = value.text or (html_to_text(safe_html) if safe_html else "")
            if safe_html is None:
                _write_serialized_part(stream, mixed_boundary, _text_part(plain_text, "plain"))
            else:
                _write_boundary(stream, mixed_boundary)
                stream.write(_container_headers("alternative", alt_boundary))
                _write_serialized_part(stream, alt_boundary, _text_part(plain_text, "plain"))
                if value.inline_images:
                    _write_boundary(stream, alt_boundary)
                    stream.write(_container_headers("related", related_boundary))
                    _write_serialized_part(stream, related_boundary, _text_part(safe_html, "html"))
                    for image in value.inline_images:
                        _write_attachment(
                            stream,
                            related_boundary,
                            image,
                            inline=True,
                        )
                    _write_boundary(stream, related_boundary, closing=True)
                else:
                    _write_serialized_part(stream, alt_boundary, _text_part(safe_html, "html"))
                _write_boundary(stream, alt_boundary, closing=True)
            for attachment in value.attachments:
                _write_attachment(stream, mixed_boundary, attachment, inline=False)
            _write_boundary(stream, mixed_boundary, closing=True)
            stream.flush()
            size = stream.tell()
        return PreparedMessage(
            path=path,
            envelope_from=envelope_from,
            recipients=envelope_recipients,
            message_id=message_id,
            size=size,
        )
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        path.unlink(missing_ok=True)
        raise


def build_message(value: OutgoingMessage) -> BuiltMessage:
    """Compatibility helper returning bytes; production sends use prepare_message."""

    prepared = prepare_message(value)
    try:
        raw = prepared.path.read_bytes()
        return BuiltMessage(
            raw=raw,
            envelope_from=prepared.envelope_from,
            recipients=prepared.recipients,
            message_id=prepared.message_id,
        )
    finally:
        prepared.cleanup()


async def deliver_and_save(
    gateway: MailGateway,
    value: OutgoingMessage,
    *,
    submission_password: str,
    spool_directory: Path | None = None,
) -> DeliveryResult:
    """Deliver first, then save Sent, preserving unambiguous partial success.

    A Sent-storage failure is *not* reported as a delivery failure and callers
    must not retry SMTP delivery: doing so could send a duplicate message.
    """

    prepared = await asyncio.to_thread(
        prepare_message,
        value,
        spool_directory=spool_directory,
    )
    try:
        try:
            delivery_id = await gateway.deliver_message(
                prepared,
                prepared.envelope_from,
                prepared.recipients,
                submission_password,
            )
        except DeliveryRejected:
            LOGGER.exception("message delivery was explicitly rejected")
            return DeliveryResult(
                delivered=False,
                saved_to_sent=False,
                error="The server explicitly rejected the message; it was not delivered.",
                retry_delivery=True,
            )
        except DeliveryUncertain:
            LOGGER.exception("message delivery result is uncertain")
            return DeliveryResult(
                delivered=False,
                saved_to_sent=False,
                error="Delivery is uncertain; check Sent or server logs before trying again.",
                retry_delivery=False,
            )
        except Exception:
            LOGGER.exception("unexpected message delivery failure; treating as uncertain")
            return DeliveryResult(
                delivered=False,
                saved_to_sent=False,
                error="The connection failed and delivery is uncertain; do not resend immediately.",
                retry_delivery=False,
            )
        try:
            await gateway.save_sent(prepared)
        except Exception:
            LOGGER.exception("message was delivered but saving Sent copy failed")
            return DeliveryResult(
                delivered=True,
                saved_to_sent=False,
                delivery_id=delivery_id,
                error="Delivered but not saved to Sent; do not resend.",
                retry_delivery=False,
            )
        return DeliveryResult(
            delivered=True,
            saved_to_sent=True,
            delivery_id=delivery_id,
            retry_delivery=False,
        )
    finally:
        await asyncio.to_thread(prepared.cleanup)


def _decode_text_part(part: Message) -> str:
    try:
        value = part.get_content()
    except LookupError, UnicodeError, ValueError:
        raw = part.get_payload(decode=True) or b""
        value = raw.decode("utf-8", "replace")
    if not isinstance(value, str):
        value = str(value)
    if len(value) > MAX_BODY_CHARACTERS:
        raise MailLimitError("message body is too large")
    return value


def _header_text(message: Message, name: str) -> str:
    value = message.get(name, "")
    rendered = str(value)
    return _CONTROL_RE.sub("", rendered)[:998]


def parse_message(raw: bytes) -> ParsedMessage:
    """Parse a bounded raw message and sanitize its HTML representation."""

    if len(raw) > MAX_RAW_MESSAGE_BYTES:
        raise MailLimitError("raw message is too large")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except (TypeError, ValueError) as exc:
        raise MailError("invalid message") from exc

    text_body = ""
    html_body: str | None = None
    attachments: list[ParsedAttachment] = []
    total_attachment_bytes = 0
    part_count = 0
    for part in message.walk():
        part_count += 1
        if part_count > MAX_MIME_PARTS:
            raise MailLimitError("too many MIME parts")
        if part.is_multipart():
            continue
        content_type = part.get_content_type().lower()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        content_id = _header_text(part, "Content-ID").strip("<>") or None
        is_body = (
            disposition != "attachment"
            and filename is None
            and content_type
            in {
                "text/plain",
                "text/html",
            }
        )
        if is_body:
            decoded = _decode_text_part(part)
            if content_type == "text/plain" and not text_body:
                text_body = decoded
            elif content_type == "text/html" and html_body is None:
                html_body = sanitize_html_email(decoded)
            continue

        payload = part.get_payload(decode=True) or b""
        if len(payload) > MAX_ATTACHMENT_BYTES:
            raise MailLimitError("attachment is too large")
        total_attachment_bytes += len(payload)
        if total_attachment_bytes > MAX_TOTAL_ATTACHMENT_BYTES:
            raise MailLimitError("attachments are too large")
        if len(attachments) >= MAX_ATTACHMENTS:
            raise MailLimitError("too many attachments")
        attachments.append(
            ParsedAttachment(
                attachment_id=str(len(attachments)),
                filename=safe_filename(filename),
                content_type=content_type,
                data=payload,
                content_id=content_id,
                inline=disposition == "inline" or content_id is not None,
            )
        )

    if not text_body and html_body:
        text_body = html_to_text(html_body)
    return ParsedMessage(
        subject=_header_text(message, "Subject") or "(No subject)",
        sender=_header_text(message, "From"),
        to=tuple(str(value) for value in message.get_all("To", [])),
        cc=tuple(str(value) for value in message.get_all("Cc", [])),
        date=_header_text(message, "Date"),
        message_id=_header_text(message, "Message-ID"),
        text=text_body,
        html=html_body,
        attachments=tuple(attachments),
    )


__all__ = [
    "Attachment",
    "BuiltMessage",
    "DeliveryRejected",
    "DeliveryResult",
    "DeliveryUncertain",
    "MailError",
    "MailGateway",
    "MailLimitError",
    "OutgoingMessage",
    "ParsedAttachment",
    "ParsedMessage",
    "PreparedMessage",
    "attachment_download_headers",
    "build_message",
    "deliver_and_save",
    "detect_safe_image_type",
    "html_to_text",
    "parse_address_list",
    "parse_message",
    "prepare_message",
    "rewrite_cid_images",
    "safe_filename",
    "sandboxed_html_document",
    "sanitize_html_email",
]
