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
import unicodedata
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
MAX_MIME_DEPTH = 32
MAX_RENDERED_CID_IMAGES = 8
MAX_RENDERED_CID_BYTES = 4 * 1024 * 1024
MAX_RENDERED_CID_PIXELS = 8_000_000
MAX_INLINE_IMAGE_DIMENSION = 4096
MAX_INLINE_IMAGE_PIXELS = 4_000_000
MAX_SANITIZED_HTML_CHARACTERS = 3 * 1024 * 1024
MAX_SANITIZED_HTML_ELEMENTS = 4096
MAX_SANITIZED_HTML_DEPTH = 64
MAX_TOP_LEVEL_HEADER_BYTES = 64 * 1024
MAX_HEADERS_PER_PART = 256
MAX_HEADER_CHARACTERS_PER_PART = 64 * 1024
MAX_MESSAGE_HEADERS = 512
MAX_MESSAGE_HEADER_CHARACTERS = 128 * 1024
MAX_ADDRESS_HEADER_VALUES = 32
MAX_ADDRESS_HEADER_CHARACTERS = 16 * 1024
MAX_SENDER_NAME_CHARACTERS = 256
MAX_THREAD_MESSAGE_IDS = 32

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+$")
_CID_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~@-]{1,200}$")
_MESSAGE_ID_RE = re.compile(r"<[^<>\s@]+@[^<>\s@]+>", re.ASCII)
_REPLY_PREFIX_RE = re.compile(r"\A\s*re(?:\[\d{1,4}\])?\s*:\s*", re.IGNORECASE)
_CID_DATA_URL_RE = re.compile(
    r"\Adata:image/(?:png|jpeg|gif|webp);base64,[A-Za-z0-9+/]*={0,2}\Z",
    re.ASCII,
)
_UNSAFE_INLINE_STYLE_RE = re.compile(
    r"(?:url|expression|image|image-set|cross-fade|element|attr|var)\s*\("
    r"|(?:javascript|vbscript|data)\s*:|@|\\|/\*",
    re.IGNORECASE,
)
_UNSAFE_FILENAME_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_UNSAFE_HEADER_CATEGORIES = _UNSAFE_FILENAME_CATEGORIES


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
    "*": {"style"},
    "a": {"href", "title"},
    "blockquote": {"cite"},
    "col": {"span", "width"},
    "colgroup": {"span", "width"},
    "div": {"align"},
    "img": {"align", "alt", "height", "src", "title", "width"},
    "ol": {"start", "type"},
    "p": {"align"},
    "q": {"cite"},
    "table": {
        "align",
        "bgcolor",
        "border",
        "cellpadding",
        "cellspacing",
        "height",
        "summary",
        "width",
    },
    "td": {
        "align",
        "bgcolor",
        "colspan",
        "headers",
        "height",
        "rowspan",
        "valign",
        "width",
    },
    "th": {
        "align",
        "bgcolor",
        "colspan",
        "headers",
        "height",
        "rowspan",
        "scope",
        "valign",
        "width",
    },
    "tr": {"align", "bgcolor", "height", "valign"},
}
_HTML_STYLE_PROPERTIES = frozenset(
    {
        "background-color",
        "border",
        "border-bottom",
        "border-bottom-color",
        "border-bottom-style",
        "border-bottom-width",
        "border-collapse",
        "border-color",
        "border-left",
        "border-left-color",
        "border-left-style",
        "border-left-width",
        "border-right",
        "border-right-color",
        "border-right-style",
        "border-right-width",
        "border-spacing",
        "border-style",
        "border-top",
        "border-top-color",
        "border-top-style",
        "border-top-width",
        "border-width",
        "box-sizing",
        "color",
        "font-family",
        "font-size",
        "font-style",
        "font-variant",
        "font-weight",
        "height",
        "letter-spacing",
        "line-height",
        "margin",
        "margin-bottom",
        "margin-left",
        "margin-right",
        "margin-top",
        "max-height",
        "max-width",
        "min-height",
        "min-width",
        "overflow-wrap",
        "padding",
        "padding-bottom",
        "padding-left",
        "padding-right",
        "padding-top",
        "text-align",
        "text-decoration",
        "text-indent",
        "text-transform",
        "vertical-align",
        "white-space",
        "width",
        "word-break",
        "word-spacing",
    }
)
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


class MailValidationError(MailError):
    """Invalid message input with a fixed, safe explanation for the operator."""

    def __init__(self, message: str, *, public_message: str) -> None:
        super().__init__(message)
        self.public_message = public_message


class DeliveryRejected(RuntimeError):
    """The backend explicitly rejected delivery; resubmission cannot duplicate it."""

    def __init__(self, message: str, *, public_message: str | None = None) -> None:
        super().__init__(message)
        self.public_message = public_message


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


class _CidReferenceCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "img":
            return
        source = next((value for name, value in attrs if name.lower() == "src"), None)
        if source is not None and source.lower().startswith("cid:"):
            self.references.add(source[4:].strip("<>"))


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
        allowed = _HTML_ATTRIBUTES.get("*", set()) | _HTML_ATTRIBUTES.get(tag, set())
        rendered: list[str] = []
        seen: set[str] = set()
        if tag == "a" and any(
            name.lower() == "href" and value
            for name, value in attrs
        ):
            # Mail links are user-initiated escapes from the otherwise inert
            # preview.  Force a separate browsing context with no opener and
            # never preserve an attacker-controlled target or rel value.
            rendered.extend(
                (
                    ' target="_blank"',
                    ' rel="noopener noreferrer nofollow"',
                )
            )
        if tag == "img":
            source = next((value for name, value in attrs if name.lower() == "src"), None)
            if source is None or not source.lower().startswith("cid:"):
                return
            mapped = self.cid_urls.get(source[4:].strip("<>"))
            if mapped is None or (
                not mapped.startswith("/") and _CID_DATA_URL_RE.fullmatch(mapped) is None
            ):
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


class _SanitizedHtmlBudget(HTMLParser):
    _VOID_TAGS: ClassVar[frozenset[str]] = frozenset({"br", "col", "hr", "img"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements = 0
        self.depth = 0

    def _element(self, tag: str, *, nested: bool) -> None:
        self.elements += 1
        if self.elements > MAX_SANITIZED_HTML_ELEMENTS:
            raise MailLimitError("HTML body has too many elements")
        if nested and tag.lower() not in self._VOID_TAGS:
            self.depth += 1
            if self.depth > MAX_SANITIZED_HTML_DEPTH:
                raise MailLimitError("HTML body nesting is too deep")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._element(tag, nested=True)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._element(tag, nested=False)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() not in self._VOID_TAGS and self.depth:
            self.depth -= 1


def _validate_sanitized_html(value: str) -> str:
    if len(value) > MAX_SANITIZED_HTML_CHARACTERS:
        raise MailLimitError("sanitized HTML body is too large")
    parser = _SanitizedHtmlBudget()
    parser.feed(value)
    parser.close()
    return value


def html_to_text(value: str) -> str:
    """Create a conservative plain-text alternative without extra packages."""

    parser = _TextExtractor()
    parser.feed(value[:MAX_BODY_CHARACTERS])
    parser.close()
    lines = (" ".join(line.split()) for line in "".join(parser.parts).splitlines())
    return "\n".join(line for line in lines if line).strip()


def _html_cid_references(value: str) -> set[str]:
    parser = _CidReferenceCollector()
    parser.feed(value)
    parser.close()
    return parser.references


def rewrite_cid_images(value: str, cid_urls: Mapping[str, str]) -> str:
    """Map known CID sources to local URLs and remove every unknown image."""

    parser = _CidImageRewriter(cid_urls)
    parser.feed(value)
    parser.close()
    return "".join(parser.parts)


def _safe_image_dimensions(width: int, height: int) -> bool:
    return (
        0 < width <= MAX_INLINE_IMAGE_DIMENSION
        and 0 < height <= MAX_INLINE_IMAGE_DIMENSION
        and width * height <= MAX_INLINE_IMAGE_PIXELS
    )


def _png_dimensions(data: bytes) -> tuple[int, int] | None:
    if (
        len(data) < 45
        or not data.startswith(b"\x89PNG\r\n\x1a\n")
        or data[8:12] != b"\x00\x00\x00\r"
        or data[12:16] != b"IHDR"
    ):
        return None
    dimensions = (
        int.from_bytes(data[16:20], "big"),
        int.from_bytes(data[20:24], "big"),
    )
    offset = 8
    while offset + 12 <= len(data):
        chunk_length = int.from_bytes(data[offset : offset + 4], "big")
        chunk_end = offset + 12 + chunk_length
        if chunk_end > len(data):
            return None
        chunk_type = data[offset + 4 : offset + 8]
        if chunk_type == b"acTL":
            return None
        if chunk_type == b"IEND":
            return dimensions if chunk_length == 0 else None
        offset = chunk_end
    return None


def _gif_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) < 14 or not data.startswith((b"GIF87a", b"GIF89a")):
        return None
    dimensions = (
        int.from_bytes(data[6:8], "little"),
        int.from_bytes(data[8:10], "little"),
    )
    packed = data[10]
    offset = 13
    if packed & 0x80:
        offset += 3 * (1 << ((packed & 0x07) + 1))
    image_count = 0
    while offset < len(data):
        marker = data[offset]
        if marker == 0x3B:
            return dimensions if image_count == 1 else None
        if marker == 0x21:
            if offset + 2 > len(data):
                return None
            offset += 2
        elif marker == 0x2C:
            if offset + 10 > len(data):
                return None
            image_count += 1
            if image_count > 1:
                return None
            left = int.from_bytes(data[offset + 1 : offset + 3], "little")
            top = int.from_bytes(data[offset + 3 : offset + 5], "little")
            frame_width = int.from_bytes(data[offset + 5 : offset + 7], "little")
            frame_height = int.from_bytes(data[offset + 7 : offset + 9], "little")
            dimensions = (
                max(dimensions[0], left + frame_width),
                max(dimensions[1], top + frame_height),
            )
            if not _safe_image_dimensions(*dimensions):
                return None
            descriptor_packed = data[offset + 9]
            offset += 10
            if descriptor_packed & 0x80:
                offset += 3 * (1 << ((descriptor_packed & 0x07) + 1))
            if offset >= len(data):
                return None
            offset += 1
        else:
            return None
        while offset < len(data):
            block_size = data[offset]
            offset += 1
            if block_size == 0:
                break
            offset += block_size
            if offset > len(data):
                return None
        else:
            return None
    return None


def _jpeg_dimensions(data: bytes) -> tuple[int, int] | None:
    if not data.startswith(b"\xff\xd8"):
        return None
    offset = 2
    start_of_frame = {
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    }
    standalone = {0x01, 0xD8, 0xD9, *range(0xD0, 0xD8)}
    while offset < len(data):
        if data[offset] != 0xFF:
            return None
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            return None
        marker = data[offset]
        offset += 1
        if marker in standalone:
            if marker == 0xD9:
                return None
            continue
        if marker == 0xDA or offset + 2 > len(data):
            return None
        segment_length = int.from_bytes(data[offset : offset + 2], "big")
        if segment_length < 2 or offset + segment_length > len(data):
            return None
        if marker in start_of_frame:
            if segment_length < 7:
                return None
            height = int.from_bytes(data[offset + 3 : offset + 5], "big")
            width = int.from_bytes(data[offset + 5 : offset + 7], "big")
            return width, height
        offset += segment_length
    return None


def _webp_dimensions(data: bytes) -> tuple[int, int] | None:
    if (
        len(data) < 30
        or not data.startswith(b"RIFF")
        or data[8:12] != b"WEBP"
        or int.from_bytes(data[4:8], "little") + 8 > len(data)
    ):
        return None
    chunk = data[12:16]
    if chunk == b"VP8X":
        if data[20] & 0x02:
            return None
        width = int.from_bytes(data[24:27], "little") + 1
        height = int.from_bytes(data[27:30], "little") + 1
        return width, height
    if chunk == b"VP8 " and data[23:26] == b"\x9d\x01\x2a":
        width = int.from_bytes(data[26:28], "little") & 0x3FFF
        height = int.from_bytes(data[28:30], "little") & 0x3FFF
        return width, height
    if chunk == b"VP8L" and data[20] == 0x2F:
        dimensions = int.from_bytes(data[21:25], "little")
        width = (dimensions & 0x3FFF) + 1
        height = ((dimensions >> 14) & 0x3FFF) + 1
        return width, height
    return None


def safe_inline_image_metadata(data: bytes) -> tuple[str, int, int] | None:
    """Recognize one bounded, non-animated raster image for mail rendering."""

    dimensions: tuple[int, int] | None = None
    content_type: str | None = None
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        dimensions = _png_dimensions(data)
        content_type = "image/png"
    elif data.startswith((b"GIF87a", b"GIF89a")):
        dimensions = _gif_dimensions(data)
        content_type = "image/gif"
    elif data.startswith(b"\xff\xd8"):
        dimensions = _jpeg_dimensions(data)
        content_type = "image/jpeg"
    elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        dimensions = _webp_dimensions(data)
        content_type = "image/webp"
    if dimensions is None or not _safe_image_dimensions(*dimensions):
        return None
    if content_type is None:  # pragma: no cover - every recognized branch sets it
        return None
    return content_type, dimensions[0], dimensions[1]


def detect_safe_image_type(data: bytes) -> str | None:
    """Return the content type of a bounded passive raster image."""

    metadata = safe_inline_image_metadata(data)
    return metadata[0] if metadata is not None else None


def sanitize_html_email(value: str) -> str:
    """Sanitize HTML mail and remove every network-capable image source.

    Only ``cid:`` image URLs survive.  In particular, HTTP(S), protocol-relative,
    ``file:``, SVG/data URLs, forms, scripts, network-capable CSS and active
    embedded content are removed.  A bounded allow-list of passive inline CSS
    remains so ordinary email layouts retain their typography, spacing, colors,
    borders and table dimensions.  If nh3 is unavailable, the function fails
    closed and renders the whole input as escaped text.
    """

    if len(value) > MAX_BODY_CHARACTERS:
        raise MailLimitError("HTML body is too large")
    sanitizer = _load_nh3()
    if sanitizer is None:
        return _validate_sanitized_html(f"<pre>{html.escape(value)}</pre>")
    return _validate_sanitized_html(
        sanitizer.clean(
            value,
            tags=_HTML_TAGS,
            attributes=_HTML_ATTRIBUTES,
            clean_content_tags=_REMOVE_CONTENT_TAGS,
            link_rel="noopener noreferrer nofollow",
            strip_comments=True,
            url_schemes={"cid", "http", "https", "mailto"},
            attribute_filter=_mail_attribute_filter,
            filter_style_properties=_HTML_STYLE_PROPERTIES,
        )
    )


def _mail_attribute_filter(tag: str, attribute: str, value: str) -> str | None:
    """nh3 callback that permits links but restricts images to ``cid:``."""

    if attribute == "style":
        if _UNSAFE_INLINE_STYLE_RE.search(value):
            return None
        return value
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
        "base-uri 'none'; form-action 'none'; img-src data:; object-src 'none'; "
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
    name = unicodedata.normalize("NFC", value).replace("\\", "/").rsplit("/", 1)[-1]
    name = _CONTROL_RE.sub("", name).strip().strip(".")
    name = "".join(
        character
        for character in name
        if unicodedata.category(character) not in _UNSAFE_FILENAME_CATEGORIES
    )
    name = name.strip().strip(".")
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
    sender_name: str = ""
    cc: tuple[str, ...] = ()
    bcc: tuple[str, ...] = ()
    html: str | None = None
    inline_images: tuple[Attachment, ...] = ()
    attachments: tuple[Attachment, ...] = ()
    reply_to: tuple[str, ...] = ()
    in_reply_to: str = ""
    references: tuple[str, ...] = ()


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
    reply_to: tuple[str, ...] = ()
    in_reply_to: str = ""
    references: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReplyRecipients:
    to: tuple[str, ...]
    cc: tuple[str, ...] = ()


def _validate_message_id(value: str, label: str) -> str:
    candidate = _validate_header_value(value, label, maximum=998)
    if not candidate.isascii() or _MESSAGE_ID_RE.fullmatch(candidate) is None:
        raise MailError(f"invalid {label}")
    return candidate


def _extract_message_ids(
    values: str | Iterable[str],
    *,
    maximum: int = MAX_THREAD_MESSAGE_IDS,
) -> tuple[str, ...]:
    source = [values] if isinstance(values, str) else list(values)
    found: list[str] = []
    seen: set[str] = set()
    for value in source:
        rendered = _CONTROL_RE.sub("", str(value))[:998]
        for match in _MESSAGE_ID_RE.finditer(rendered):
            message_id = match.group(0)
            if not message_id.isascii():
                continue
            key = message_id.casefold()
            if key in seen:
                continue
            seen.add(key)
            found.append(message_id)
    return tuple(found[-maximum:])


def _validate_references(values: Sequence[str]) -> tuple[str, ...]:
    if len(values) > MAX_THREAD_MESSAGE_IDS:
        raise MailLimitError("too many References message IDs")
    references: list[str] = []
    seen: set[str] = set()
    for value in values:
        message_id = _validate_message_id(value, "References message ID")
        key = message_id.casefold()
        if key in seen:
            continue
        seen.add(key)
        references.append(message_id)
    if len(" ".join(references)) > 998:
        raise MailLimitError("References header is too large")
    return tuple(references)


def _received_addresses(values: Iterable[str]) -> tuple[tuple[str, str], ...]:
    source = [_CONTROL_RE.sub("", str(value))[:998] for value in values]
    result: list[tuple[str, str]] = []
    for display_name, addr_spec in getaddresses(source):
        if not addr_spec or "@" not in addr_spec:
            continue
        try:
            address = Address(display_name=display_name, addr_spec=addr_spec)
        except TypeError, ValueError:
            continue
        if not address.username or not address.domain:
            continue
        result.append((str(address), address.addr_spec.casefold()))
    return tuple(result)


def derive_reply_recipients(
    message: ParsedMessage,
    self_addresses: str | Iterable[str],
    *,
    reply_all: bool = False,
) -> ReplyRecipients:
    """Derive safe Reply or Reply All recipients without using Bcc data."""

    self_source = [self_addresses] if isinstance(self_addresses, str) else list(self_addresses)
    if not self_source:
        raise MailError("at least one self address is required")
    self_keys = {
        _envelope_address(address).casefold()
        for value in self_source
        for address in parse_address_list(value)
    }

    primary_source = message.reply_to or ((message.sender,) if message.sender else ())
    primary = _received_addresses(primary_source)
    original = _received_addresses((*message.to, *message.cc))
    to: list[str] = []
    cc: list[str] = []
    seen = set(self_keys)

    def append_unique(destination: list[str], item: tuple[str, str]) -> bool:
        rendered, key = item
        if key in seen:
            return False
        seen.add(key)
        destination.append(rendered)
        return True

    for item in primary:
        append_unique(to, item)
    if not to:
        for item in original:
            if append_unique(to, item):
                break
    if reply_all:
        for item in original:
            append_unique(cc, item)
    return ReplyRecipients(to=tuple(to), cc=tuple(cc))


def reply_subject(subject: str) -> str:
    """Return a bounded English reply subject with exactly one leading marker."""

    source = _validate_header_value(subject or "(No subject)", "reply subject")
    prefix = _REPLY_PREFIX_RE.match(source)
    remainder = source[prefix.end() :] if prefix is not None else source
    candidate = f"Re: {remainder.strip()}" if remainder.strip() else "Re:"
    return candidate[:998].rstrip()


def reply_thread_headers(message: ParsedMessage) -> tuple[str, tuple[str, ...]]:
    """Return a parent Message-ID and bounded References chain for a reply."""

    parent_ids = _extract_message_ids(message.message_id, maximum=1)
    parent = parent_ids[0] if parent_ids else ""
    base = message.references or ((message.in_reply_to,) if message.in_reply_to else ())
    references = list(_extract_message_ids(base))
    if parent and parent.casefold() not in {value.casefold() for value in references}:
        references.append(parent)
    references = references[-MAX_THREAD_MESSAGE_IDS:]
    while references and len(" ".join(references)) > 998:
        references.pop(0)
    return parent, tuple(references)


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
) -> tuple[
    str,
    str,
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    str,
    str | None,
    str,
    tuple[str, ...],
]:
    try:
        sender = parse_address_list(value.sender, maximum=1)[0]
    except MailError as exc:
        raise MailValidationError(
            "invalid sender address",
            public_message="The selected sender account has an invalid email address.",
        ) from exc
    try:
        sender_name = _validate_header_value(
            value.sender_name,
            "sender name",
            maximum=MAX_SENDER_NAME_CHARACTERS,
        )
    except MailError as exc:
        raise MailValidationError(
            "invalid sender name",
            public_message=(
                "Sender name must be 256 characters or fewer and cannot contain control characters."
            ),
        ) from exc

    def recipient_field(items: Sequence[str], label: str) -> tuple[str, ...]:
        try:
            return tuple(address for item in items for address in parse_address_list(item))
        except MailLimitError:
            raise
        except MailError as exc:
            raise MailValidationError(
                f"invalid {label} recipient address",
                public_message=(
                    f"The {label} field contains an invalid email address. Use complete addresses "
                    "and separate multiple addresses with commas."
                ),
            ) from exc

    to = recipient_field(value.to, "To")
    cc = recipient_field(value.cc, "CC")
    bcc = recipient_field(value.bcc, "BCC")
    reply_to = recipient_field(value.reply_to, "Reply-To") if value.reply_to else ()
    if not to and not cc and not bcc:
        raise MailError("at least one recipient is required")
    if len(to) + len(cc) + len(bcc) > 100:
        raise MailLimitError("too many recipients")
    if len(reply_to) > 100:
        raise MailLimitError("too many Reply-To addresses")
    subject = _validate_header_value(value.subject, "subject")
    in_reply_to = (
        _validate_message_id(value.in_reply_to, "In-Reply-To message ID")
        if value.in_reply_to
        else ""
    )
    references = _validate_references(value.references)
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
    if safe_html is not None:
        cid_references = _html_cid_references(safe_html)
        if cid_references - seen_cids:
            raise MailValidationError(
                "HTML body references an unattached inline image",
                public_message="HTML references an inline image that is no longer attached.",
            )
        if seen_cids - cid_references:
            raise MailValidationError(
                "inline image is not referenced by the HTML body",
                public_message="An attached inline image is no longer referenced by the HTML body.",
            )
        if not html_to_text(safe_html) and not cid_references:
            raise MailValidationError(
                "HTML body is empty after sanitization",
                public_message="The HTML body is empty after unsafe content is removed.",
            )
    return (
        sender,
        sender_name,
        to,
        cc,
        bcc,
        reply_to,
        subject,
        safe_html,
        in_reply_to,
        references,
    )


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

    (
        sender,
        sender_name,
        to,
        cc,
        bcc,
        reply_to,
        subject,
        safe_html,
        in_reply_to,
        references,
    ) = _validated_outgoing(value)
    envelope_from = _envelope_address(sender)
    envelope_recipients = tuple(_envelope_address(item) for item in (*to, *cc, *bcc))
    sender_domain = envelope_from.rsplit("@", 1)[-1]
    message_id = make_msgid(domain=sender_domain)
    mixed_boundary = f"maddyweb-mixed-{uuid.uuid4().hex}"
    alt_boundary = f"maddyweb-alt-{uuid.uuid4().hex}"
    related_boundary = f"maddyweb-related-{uuid.uuid4().hex}"

    top = EmailMessage(policy=policy.SMTP)
    top["From"] = (
        Address(display_name=sender_name, addr_spec=envelope_from) if sender_name else sender
    )
    if to:
        top["To"] = ", ".join(to)
    if cc:
        top["Cc"] = ", ".join(cc)
    if reply_to:
        top["Reply-To"] = ", ".join(reply_to)
    top["Subject"] = subject
    top["Date"] = format_datetime(datetime.now(UTC))
    top["Message-ID"] = message_id
    if in_reply_to:
        top["In-Reply-To"] = in_reply_to
    if references:
        top["References"] = " ".join(references)
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
        except DeliveryRejected as exc:
            LOGGER.warning("message delivery was definitively not accepted")
            return DeliveryResult(
                delivered=False,
                saved_to_sent=False,
                error=exc.public_message
                or "Maddy did not accept the message; it was not submitted.",
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


def safe_display_header(value: object, *, maximum: int = 998) -> str:
    """Remove control and directional formatting characters from a display header."""

    if maximum <= 0:
        raise ValueError("display header maximum must be positive")
    rendered = str(value)
    return "".join(
        character
        for character in rendered
        if unicodedata.category(character) not in _UNSAFE_HEADER_CATEGORIES
    )[:maximum]


def _header_text(message: Message, name: str) -> str:
    return safe_display_header(message.get(name, ""))


def _header_values(message: Message, name: str) -> tuple[str, ...]:
    return tuple(safe_display_header(value) for value in message.get_all(name, []))


def _validate_top_level_headers(raw: bytes) -> None:
    stream = io.BytesIO(raw)
    header_bytes = 0
    header_count = 0
    while True:
        line = stream.readline(MAX_TOP_LEVEL_HEADER_BYTES + 2)
        if not line:
            return
        header_bytes += len(line)
        if header_bytes > MAX_TOP_LEVEL_HEADER_BYTES:
            raise MailLimitError("top-level message headers are too large")
        content = line.rstrip(b"\r\n")
        if not content:
            return
        if content[:1] in {b" ", b"\t"}:
            continue
        if b":" not in content:
            return
        header_count += 1
        if header_count > MAX_HEADERS_PER_PART:
            raise MailLimitError("too many top-level message headers")


def _validate_part_headers(part: Message) -> tuple[int, int]:
    header_count = 0
    header_characters = 0
    address_values = 0
    address_characters = 0
    for name, value in part.raw_items():
        header_count += 1
        header_characters += len(name) + len(value)
        if (
            header_count > MAX_HEADERS_PER_PART
            or header_characters > MAX_HEADER_CHARACTERS_PER_PART
        ):
            raise MailLimitError("message headers are too large")
        if name.casefold() in {"to", "cc", "reply-to"}:
            address_values += 1
            address_characters += len(value)
            if (
                address_values > MAX_ADDRESS_HEADER_VALUES
                or address_characters > MAX_ADDRESS_HEADER_CHARACTERS
            ):
                raise MailLimitError("message address headers are too large")
    return header_count, header_characters


def _bounded_message_parts(message: Message) -> Iterator[tuple[Message, bool]]:
    stack: list[tuple[Message, int, bool]] = [(message, 0, False)]
    part_count = 0
    while stack:
        part, depth, under_attachment = stack.pop()
        if depth > MAX_MIME_DEPTH:
            raise MailLimitError("MIME nesting is too deep")
        part_count += 1
        if part_count > MAX_MIME_PARTS:
            raise MailLimitError("too many MIME parts")
        yield part, under_attachment
        if not part.is_multipart():
            continue
        payload = part.get_payload()
        if not isinstance(payload, list) or any(
            not isinstance(child, Message) for child in payload
        ):
            raise MailError("invalid multipart message")
        child_under_attachment = (
            under_attachment
            or part.get_content_disposition() == "attachment"
            or part.get_filename() is not None
            or part.get_content_type().lower() == "message/rfc822"
        )
        stack.extend(
            (child, depth + 1, child_under_attachment) for child in reversed(payload)
        )


def parse_message(raw: bytes) -> ParsedMessage:
    """Parse a bounded raw message and sanitize its HTML representation."""

    if len(raw) > MAX_RAW_MESSAGE_BYTES:
        raise MailLimitError("raw message is too large")
    _validate_top_level_headers(raw)
    parsed_part_count = 0

    def bounded_message_factory(*args: Any, **kwargs: Any) -> EmailMessage:
        nonlocal parsed_part_count
        parsed_part_count += 1
        if parsed_part_count > MAX_MIME_PARTS:
            raise MailLimitError("too many MIME parts")
        return EmailMessage(*args, **kwargs)

    try:
        message = BytesParser(
            _class=bounded_message_factory,
            policy=policy.default,
        ).parsebytes(raw)
    except MailLimitError:
        raise
    except RecursionError as exc:
        raise MailLimitError("MIME nesting is too deep") from exc
    except (TypeError, ValueError) as exc:
        raise MailError("invalid message") from exc

    text_body = ""
    html_body: str | None = None
    attachments: list[ParsedAttachment] = []
    total_attachment_bytes = 0
    total_headers = 0
    total_header_characters = 0
    for part, under_attachment in _bounded_message_parts(message):
        part_headers, part_header_characters = _validate_part_headers(part)
        total_headers += part_headers
        total_header_characters += part_header_characters
        if (
            total_headers > MAX_MESSAGE_HEADERS
            or total_header_characters > MAX_MESSAGE_HEADER_CHARACTERS
        ):
            raise MailLimitError("message headers are too large")
        if part.is_multipart():
            continue
        content_type = part.get_content_type().lower()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        content_id = _header_text(part, "Content-ID").strip("<>") or None
        is_body = (
            not under_attachment
            and
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
                inline=not under_attachment
                and (disposition == "inline" or content_id is not None),
            )
        )

    if not text_body and html_body:
        text_body = html_to_text(html_body)
    in_reply_to = _extract_message_ids(message.get_all("In-Reply-To", []), maximum=1)
    references = _extract_message_ids(message.get_all("References", []))
    return ParsedMessage(
        subject=_header_text(message, "Subject") or "(No subject)",
        sender=_header_text(message, "From"),
        to=_header_values(message, "To"),
        cc=_header_values(message, "Cc"),
        date=_header_text(message, "Date"),
        message_id=_header_text(message, "Message-ID"),
        text=text_body,
        html=html_body,
        attachments=tuple(attachments),
        reply_to=_header_values(message, "Reply-To"),
        in_reply_to=in_reply_to[0] if in_reply_to else "",
        references=references,
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
    "MailValidationError",
    "OutgoingMessage",
    "ParsedAttachment",
    "ParsedMessage",
    "PreparedMessage",
    "ReplyRecipients",
    "attachment_download_headers",
    "build_message",
    "deliver_and_save",
    "derive_reply_recipients",
    "detect_safe_image_type",
    "html_to_text",
    "parse_address_list",
    "parse_message",
    "prepare_message",
    "reply_subject",
    "reply_thread_headers",
    "rewrite_cid_images",
    "safe_display_header",
    "safe_filename",
    "safe_inline_image_metadata",
    "sandboxed_html_document",
    "sanitize_html_email",
]
