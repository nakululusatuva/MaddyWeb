"""aiohttp JSON API and static unprivileged administration application."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import stat
import tempfile
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from aiohttp import BodyPartReader, web

from .gateway import HelperCallError, bind_helper_identity
from .mail import (
    MAX_ATTACHMENT_BYTES,
    MAX_RAW_MESSAGE_BYTES,
    Attachment,
    DeliveryResult,
    MailError,
    MailGateway,
    MailValidationError,
    OutgoingMessage,
    ParsedMessage,
    PreparedMessage,
    attachment_download_headers,
    deliver_and_save,
    derive_reply_recipients,
    detect_safe_image_type,
    parse_message,
    reply_subject,
    reply_thread_headers,
    rewrite_cid_images,
    safe_filename,
    sandboxed_html_document,
)
from .protocol import DEFAULT_MAX_STREAM_BYTES
from .release_attestation import (
    SUPPORTED_AUTHENTICATION_CAPABILITIES,
    SUPPORTED_AUTHENTICATION_PROFILE,
)
from .security import (
    CsrfScope,
    SecurityConfig,
    bounded_concurrency_middleware,
    csrf_token_for_request,
    email_document_headers,
    security_headers_middleware,
    security_middleware,
)

LOGGER = logging.getLogger(__name__)
API_VERSION = "v1"
AUTHENTICATION_PROFILE = SUPPORTED_AUTHENTICATION_PROFILE
AUTHENTICATION_CAPABILITIES = SUPPORTED_AUTHENTICATION_CAPABILITIES
MAX_API_JSON_BYTES = 64 * 1024
MAX_RAW_DOWNLOAD_BYTES = DEFAULT_MAX_STREAM_BYTES
MAX_MAILBOX_PAGE = 10_000
MAX_MESSAGE_CURSOR = (1 << 32) - 1
MAILBOX_CURSOR_CAPACITY = 4096
MESSAGE_FRESHNESS_CAPACITY = 4096
MESSAGE_FRESHNESS_PER_SESSION = 64
MAX_TOTP_QR_SVG_CHARS = 256 * 1024
_SPA_PATHS = frozenset({"/", "/accounts", "/certificates", "/compose", "/mail", "/security"})
_SPA_MAIL_PATH_RE = re.compile(r"\A/mail/([1-9][0-9]{0,9})\Z")

_GATEWAY_KEY = web.AppKey("gateway", object)
_SETTINGS_KEY = web.AppKey("web_settings", object)
_MAIL_WORK_KEY = web.AppKey("mail_work_semaphore", object)
_MAIL_CURSOR_KEY = web.AppKey("mail_cursor_store", object)
_FRESHNESS_KEY = web.AppKey("message_freshness_store", object)
_AUTH_PRINCIPAL_KEY = web.RequestKey("authenticated_principal", object)
_AUTH_TOKEN_KEY = web.RequestKey("authenticated_session_token", str)
_CLIENT_IP_KEY = web.RequestKey("authenticated_client_ip", str)
_SESSION_COOKIE_KEY = web.AppKey("session_cookie_name", str)
_PUBLIC_ORIGIN_KEY = web.AppKey("public_origin", str)
_SECURE_COOKIE_KEY = web.AppKey("secure_session_cookie", bool)
_TOTP_ISSUER_KEY = web.AppKey("totp_issuer", str)
_ACCOUNT_RE = re.compile(r"\A[^\s@/\\\x00-\x1f\x7f]+@[^\s@/\\\x00-\x1f\x7f]+\Z")
_ACCOUNT_ID_RE = re.compile(r"\A[0-9a-f]{32}\Z")
_IMAGE_TYPES = {
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/webp",
}
_MISSING = object()


@runtime_checkable
class Gateway(MailGateway, Protocol):
    """Unprivileged application boundary implemented by the local adapter."""

    async def list_accounts(self) -> Sequence[object]: ...

    async def begin_password_login(
        self,
        email: str,
        password: str,
        *,
        client_ip: str,
    ) -> Mapping[str, object]: ...

    async def begin_totp_enrollment(self, challenge: str) -> Mapping[str, object]: ...

    async def complete_totp_enrollment(
        self,
        challenge: str,
        code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, object]: ...

    async def complete_totp_login(
        self,
        challenge: str,
        code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, object]: ...

    async def complete_recovery_login(
        self,
        challenge: str,
        recovery_code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, object]: ...

    async def session(self, token: str) -> Mapping[str, object]: ...

    async def logout(self, token: str) -> None: ...

    async def change_own_password(
        self,
        current_password: str,
        new_password: str,
        *,
        client_ip: str,
    ) -> Mapping[str, object]: ...

    async def regenerate_recovery_codes(
        self,
        password: str,
        code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, object]: ...

    async def step_up(
        self,
        password: str,
        code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, object]: ...

    async def rotate_account_totp(self, account_id: str) -> Mapping[str, object]: ...

    async def health(self) -> Mapping[str, object]: ...

    async def create_account(self, username: str, password: str) -> object: ...

    async def change_password(self, account_id: str, password: str) -> None: ...

    async def set_append_limit(self, account_id: str, limit: int) -> None: ...

    async def disable_credentials(self, account_id: str) -> None: ...

    async def delete_mailbox(self, account_id: str) -> None: ...

    async def list_mailboxes(self, account_id: str) -> Sequence[object]: ...

    async def create_mailbox(self, account_id: str, mailbox: str) -> None: ...

    async def rename_mailbox(
        self,
        account_id: str,
        old_name: str,
        new_name: str,
    ) -> None: ...

    async def delete_named_mailbox(self, account_id: str, mailbox: str) -> None: ...

    async def list_messages(
        self,
        account_id: str,
        mailbox: str,
        *,
        limit: int,
        offset: int,
    ) -> MessagePage | Mapping[str, object]: ...

    async def spool_message(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
        destination_path: Path,
        *,
        max_bytes: int,
    ) -> int: ...

    async def move_message_to_trash(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
    ) -> str: ...

    async def move_message_to_archive(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
    ) -> str: ...

    async def move_message(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
        target: str,
    ) -> str: ...

    async def set_message_seen(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
        *,
        seen: bool,
    ) -> None: ...

    async def delete_message_permanently(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
    ) -> None: ...

    async def certificate_status(self) -> object: ...

    async def set_certificate_timer(self, enabled: bool) -> None: ...

    async def certificate_dry_run(self, certificate_name: str) -> object: ...

    async def renew_certificate_if_due(self, certificate_name: str) -> object: ...

    async def deliver_message(
        self,
        message: PreparedMessage,
        envelope_from: str,
        recipients: Sequence[str],
        submission_password: str,
    ) -> str | None: ...

    async def save_sent(self, message: PreparedMessage) -> None: ...


@dataclass(frozen=True, slots=True)
class WebSettings:
    page_size: int
    max_upload_bytes: int
    request_body_timeout_seconds: float
    temp_dir: Path


@dataclass(frozen=True, slots=True)
class MessagePage:
    """One bounded mailbox page plus the helper's authoritative continuation."""

    items: Sequence[object]
    has_next: bool
    next_offset: int | None = None
    offset: int = 0


@dataclass(frozen=True, slots=True)
class _MailboxCursorState:
    account: str
    mailbox: str
    offset: int
    page: int
    previous: str | None
    expires_at: float


class _MailboxCursorError(ValueError):
    pass


class _MailboxCursorStore:
    """Bounded, process-local opaque mailbox continuation store."""

    def __init__(self, *, ttl_seconds: int, capacity: int = MAILBOX_CURSOR_CAPACITY) -> None:
        if ttl_seconds <= 0 or capacity <= 0:
            raise ValueError("mailbox cursor limits must be positive")
        self._ttl_seconds = ttl_seconds
        self._capacity = capacity
        self._states: OrderedDict[str, _MailboxCursorState] = OrderedDict()

    def _prune(self, now: float) -> None:
        while self._states:
            token, state = next(iter(self._states.items()))
            if state.expires_at > now:
                break
            del self._states[token]

    def resolve(self, token: str, *, account: str, mailbox: str) -> _MailboxCursorState:
        if re.fullmatch(r"[A-Za-z0-9_-]{32}", token) is None:
            raise _MailboxCursorError("invalid mailbox cursor")
        now = time.monotonic()
        self._prune(now)
        state = self._states.get(token)
        if (
            state is None
            or state.expires_at <= now
            or state.account != account
            or state.mailbox != mailbox
        ):
            raise _MailboxCursorError("expired or mismatched mailbox cursor")
        return state

    def create(
        self,
        *,
        account: str,
        mailbox: str,
        offset: int,
        page: int,
        previous: str | None,
    ) -> str:
        if not 0 <= offset <= MAX_MESSAGE_CURSOR or not 1 <= page <= MAX_MAILBOX_PAGE:
            raise ValueError("mailbox cursor state is out of bounds")
        now = time.monotonic()
        self._prune(now)
        token = secrets.token_urlsafe(24)
        while token in self._states:
            token = secrets.token_urlsafe(24)
        self._states[token] = _MailboxCursorState(
            account=account,
            mailbox=mailbox,
            offset=offset,
            page=page,
            previous=previous,
            expires_at=now + self._ttl_seconds,
        )
        while len(self._states) > self._capacity:
            self._states.popitem(last=False)
        return token


@dataclass(frozen=True, slots=True)
class _FreshnessEntry:
    owner: str
    account: str
    mailbox: str
    uid: str
    digest: str
    expires_at: float


class _FreshnessStore:
    """Bounded, one-use message snapshots that make stale UIDs fail closed."""

    def __init__(
        self,
        *,
        ttl_seconds: int,
        capacity: int = MESSAGE_FRESHNESS_CAPACITY,
        per_owner_capacity: int = MESSAGE_FRESHNESS_PER_SESSION,
    ) -> None:
        if (
            ttl_seconds <= 0
            or capacity <= 0
            or per_owner_capacity <= 0
            or per_owner_capacity > capacity
        ):
            raise ValueError("message freshness limits must be positive")
        self._ttl_seconds = ttl_seconds
        self._capacity = capacity
        self._per_owner_capacity = per_owner_capacity
        self._entries: OrderedDict[str, _FreshnessEntry] = OrderedDict()
        self._owners: dict[str, OrderedDict[str, None]] = {}

    def _remove(self, token: str) -> _FreshnessEntry | None:
        entry = self._entries.pop(token, None)
        if entry is None:
            return None
        owner_entries = self._owners.get(entry.owner)
        if owner_entries is not None:
            owner_entries.pop(token, None)
            if not owner_entries:
                del self._owners[entry.owner]
        return entry

    def _prune(self, now: float) -> None:
        while self._entries:
            token, entry = next(iter(self._entries.items()))
            if entry.expires_at > now:
                break
            self._remove(token)

    def issue(
        self,
        owner: str,
        account: str,
        mailbox: str,
        uid: str,
        digest: str,
    ) -> str:
        now = time.monotonic()
        self._prune(now)
        if re.fullmatch(r"[0-9a-f]{64}", owner) is None:
            raise ValueError("message freshness owner is invalid")
        owner_entries = self._owners.setdefault(owner, OrderedDict())
        while len(owner_entries) >= self._per_owner_capacity:
            self._remove(next(iter(owner_entries)))
        token = secrets.token_urlsafe(32)
        while token in self._entries:
            token = secrets.token_urlsafe(32)
        self._entries[token] = _FreshnessEntry(
            owner=owner,
            account=account,
            mailbox=mailbox,
            uid=uid,
            digest=digest,
            expires_at=now + self._ttl_seconds,
        )
        self._owners.setdefault(owner, OrderedDict())[token] = None
        while len(self._entries) > self._capacity:
            self._remove(next(iter(self._entries)))
        return token

    def consume(self, token: str, owner: str) -> _FreshnessEntry | None:
        now = time.monotonic()
        self._prune(now)
        if re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
            return None
        entry = self._entries.get(token)
        if entry is None or not secrets.compare_digest(entry.owner, owner):
            return None
        return self._remove(token)


def _message_page(value: MessagePage | Mapping[str, object]) -> MessagePage:
    """Normalize a gateway page without inferring continuation from item count."""

    if isinstance(value, MessagePage):
        items = value.items
        next_offset_value = value.next_offset
        offset_value = value.offset
        has_next_value: object = value.has_next
    elif isinstance(value, Mapping):
        items = value.get("items")
        next_offset_value = value.get("next_offset")
        offset_value = value.get("offset", 0)
        has_next_value = value.get("has_next", _MISSING)
    else:
        raise TypeError("messages.list returned an invalid page")
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
        raise TypeError("messages.list items must be a sequence")

    if next_offset_value is not None and (
        isinstance(next_offset_value, bool)
        or not isinstance(next_offset_value, int)
        or not 1 <= next_offset_value <= MAX_MESSAGE_CURSOR
    ):
        raise TypeError("messages.list next_offset must be a positive integer or null")
    if (
        isinstance(offset_value, bool)
        or not isinstance(offset_value, int)
        or not 0 <= offset_value <= MAX_MESSAGE_CURSOR
    ):
        raise TypeError("messages.list offset must be a non-negative integer")
    if next_offset_value is not None and (offset_value == 0 or next_offset_value >= offset_value):
        raise TypeError("messages.list continuation must precede the current UID anchor")
    if has_next_value is _MISSING:
        has_next = next_offset_value is not None
    elif not isinstance(has_next_value, bool):
        raise TypeError("messages.list has_next must be a boolean")
    else:
        has_next = has_next_value
    if has_next != (next_offset_value is not None):
        raise TypeError("messages.list continuation metadata is inconsistent")
    return MessagePage(
        items=items,
        has_next=has_next,
        next_offset=next_offset_value,
        offset=offset_value,
    )


@dataclass(frozen=True, slots=True)
class UploadedFile:
    field_name: str
    filename: str
    path: Path
    content_type: str
    size: int

    def cleanup(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            LOGGER.exception("failed to remove upload spool %s", self.path)


@dataclass(frozen=True, slots=True)
class RawMessageSpool:
    path: Path
    size: int

    def cleanup(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            LOGGER.exception("failed to remove raw message spool %s", self.path)


class PreviewTooLarge(MailError):
    def __init__(self, size: int, digest: str) -> None:
        self.size = size
        self.digest = digest
        super().__init__("message exceeds preview limit")


class CleanupFileResponse(web.FileResponse):
    """FileResponse that removes its private spool after transfer completes."""

    def __init__(self, path: Path, **kwargs: object) -> None:
        super().__init__(path, **kwargs)
        self._cleanup_path = path

    async def prepare(self, request: web.BaseRequest) -> object:
        try:
            return await super().prepare(request)
        except BaseException:
            await asyncio.to_thread(self._cleanup_path.unlink, missing_ok=True)
            raise

    async def write_eof(self, data: bytes = b"") -> None:
        try:
            await super().write_eof(data)
        finally:
            await asyncio.to_thread(self._cleanup_path.unlink, missing_ok=True)


def _config_value(config: object, path: str, default: object = _MISSING) -> object:
    current: object = config
    for component in path.split("."):
        if isinstance(current, Mapping):
            if component not in current:
                if default is not _MISSING:
                    return default
                raise ValueError(f"missing configuration value: {path}")
            current = current[component]
        elif hasattr(current, component):
            current = getattr(current, component)
        elif default is not _MISSING:
            return default
        else:
            raise ValueError(f"missing configuration value: {path}")
    return current


def _session_key(config: object) -> bytes:
    for path in ("session_signing_key", "security.session_signing_key", "security.session_key"):
        value = _config_value(config, path, None)
        if isinstance(value, bytes):
            if not 32 <= len(value) <= 128:
                raise ValueError("session signing key must contain 32 to 128 bytes")
            return value
    key_file = _config_value(config, "security.session_key_file", None)
    if key_file is None:
        raise ValueError("configuration must provide a session signing key")
    path = Path(key_file)
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError("unable to inspect the session signing key") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("session signing key must be a regular non-symlink file")
    if not 32 <= before.st_size <= 128:
        raise ValueError("session signing key file must contain 32 to 128 bytes")
    if os.name == "posix" and before.st_mode & 0o077:
        raise ValueError("session signing key file must not grant group/world permissions")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        opened_identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if identity != opened_identity or not stat.S_ISREG(opened.st_mode):
            raise ValueError("session signing key changed while opening")
        value = os.read(descriptor, 129)
        after = os.fstat(descriptor)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if after_identity != opened_identity:
            raise ValueError("session signing key changed while reading")
    except OSError as exc:
        raise ValueError("unable to read the session signing key") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not 32 <= len(value) <= 128:
        raise ValueError("session signing key file must contain 32 to 128 bytes")
    return value


def _gateway(request: web.Request) -> Gateway:
    return request.app[_GATEWAY_KEY]  # type: ignore[return-value]


def _settings(request: web.Request) -> WebSettings:
    return request.app[_SETTINGS_KEY]  # type: ignore[return-value]


def _mail_cursor_store(request: web.Request) -> _MailboxCursorStore:
    store = request.app[_MAIL_CURSOR_KEY]
    if not isinstance(store, _MailboxCursorStore):
        raise RuntimeError("mailbox cursor store is not configured")
    return store


def _freshness_store(request: web.Request) -> _FreshnessStore:
    store = request.app[_FRESHNESS_KEY]
    if not isinstance(store, _FreshnessStore):
        raise RuntimeError("message freshness store is not configured")
    return store


def _freshness_owner(request: web.Request) -> str:
    token = request.get(_AUTH_TOKEN_KEY)
    if not isinstance(token, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
        raise web.HTTPUnauthorized(text="Authentication is required.")
    account_id = _principal_account_id(request)
    return hashlib.sha256(f"{account_id}\0{token}".encode("ascii")).hexdigest()


@contextlib.asynccontextmanager
async def _mail_work_slot(request: web.Request) -> AsyncIterator[None]:
    semaphore = request.app[_MAIL_WORK_KEY]
    if not isinstance(semaphore, asyncio.Semaphore):
        raise RuntimeError("mail work semaphore is not configured")
    try:
        async with asyncio.timeout(0.2):
            await semaphore.acquire()
    except TimeoutError as exc:
        raise web.HTTPTooManyRequests(
            text="Message processing is busy; try again later.",
            headers={"Retry-After": "1"},
        ) from exc
    try:
        yield
    finally:
        semaphore.release()


def _api_response(
    *,
    data: object | None = None,
    message: str | None = None,
    status: int = 200,
) -> web.Response:
    payload: dict[str, object] = {"api_version": API_VERSION, "ok": True}
    if data is not None:
        payload["data"] = data
    if message is not None:
        payload["message"] = message
    return web.json_response(payload, status=status, dumps=_json_dumps)


def _api_error(code: str, message: str, *, status: int) -> web.Response:
    return web.json_response(
        {
            "api_version": API_VERSION,
            "ok": False,
            "error": {"code": code, "message": message},
        },
        status=status,
        dumps=_json_dumps,
    )


def _json_dumps(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
    )


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"invalid JSON constant: {value}")


async def _read_json_object(
    request: web.Request,
    *,
    allowed_fields: frozenset[str],
) -> dict[str, object]:
    if request.query:
        raise web.HTTPBadRequest(text="This operation does not accept query parameters.")
    if request.content_length is not None and request.content_length > MAX_API_JSON_BYTES:
        raise web.HTTPRequestEntityTooLarge(
            max_size=MAX_API_JSON_BYTES,
            actual_size=request.content_length,
        )
    content = bytearray()
    decoded = ""
    try:
        async with asyncio.timeout(_settings(request).request_body_timeout_seconds):
            async for chunk in request.content.iter_chunked(8192):
                content.extend(chunk)
                if len(content) > MAX_API_JSON_BYTES:
                    raise web.HTTPRequestEntityTooLarge(
                        max_size=MAX_API_JSON_BYTES,
                        actual_size=len(content),
                    )
        decoded = content.decode("utf-8", "strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except web.HTTPException:
        raise
    except TimeoutError as exc:
        raise web.HTTPRequestTimeout(text="Timed out while reading the request body.") from exc
    except (RecursionError, UnicodeError, ValueError) as exc:
        raise web.HTTPBadRequest(
            text="Request body must be valid JSON without duplicate fields."
        ) from exc
    finally:
        if content:
            content[:] = b"\0" * len(content)
            content.clear()
        decoded = ""
    if not isinstance(value, dict):
        raise web.HTTPBadRequest(text="Request body must be a JSON object.")
    unknown = set(value) - allowed_fields
    if unknown:
        raise web.HTTPBadRequest(text="Request contains an unknown field.")
    return value


def _read_query(
    request: web.Request,
    *,
    allowed_fields: frozenset[str],
) -> dict[str, str]:
    unknown = set(request.query) - allowed_fields
    if unknown:
        raise web.HTTPBadRequest(text="Request contains an unknown query parameter.")
    result: dict[str, str] = {}
    for name in allowed_fields:
        values = request.query.getall(name, [])
        if len(values) > 1:
            raise web.HTTPBadRequest(text="Query parameters must not be repeated.")
        if values:
            value = values[0]
            try:
                value.encode("utf-8", "strict")
            except UnicodeEncodeError as exc:
                raise web.HTTPBadRequest(text="Query parameters must contain valid text.") from exc
            result[name] = value
    return result


def _json_text(
    values: Mapping[str, object],
    name: str,
    *,
    default: str = "",
) -> str:
    value = values.get(name, default)
    if not isinstance(value, str):
        raise web.HTTPBadRequest(text=f"Field {name} must be text.")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise web.HTTPBadRequest(text=f"Field {name} must contain valid text.") from exc
    return value


def _public_error_message(value: object, fallback: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        return fallback
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return fallback
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return fallback
    return value


_ANONYMOUS_PATHS = frozenset(
    {
        "/login",
        "/static/login.css",
        "/static/login.js",
        "/api/v1/auth/csrf",
        "/api/v1/auth/password",
        "/api/v1/auth/enrollment",
        "/api/v1/auth/enrollment/confirm",
        "/api/v1/auth/totp",
        "/api/v1/auth/recovery",
    }
)
_PASSWORD_CHANGE_PATHS = frozenset(
    {
        "/security",
        "/api/v1/auth/session",
        "/api/v1/auth/logout",
        "/api/v1/auth/password/change",
        "/static/app.css",
        "/static/app.js",
        "/static/preview.css",
    }
)


def _session_cookie_name(request: web.Request) -> str:
    return request.app[_SESSION_COOKIE_KEY]


def _principal(request: web.Request) -> Mapping[str, object]:
    principal = request.get(_AUTH_PRINCIPAL_KEY)
    if not isinstance(principal, Mapping):
        raise web.HTTPUnauthorized(text="Authentication is required.")
    return principal


def _principal_account_id(request: web.Request) -> str:
    account_id = _principal(request).get("account_id")
    if not isinstance(account_id, str) or _ACCOUNT_ID_RE.fullmatch(account_id) is None:
        raise web.HTTPUnauthorized(text="Authenticated account is invalid.")
    return account_id


def _require_admin(request: web.Request) -> Mapping[str, object]:
    principal = _principal(request)
    if principal.get("role") != "admin":
        raise web.HTTPForbidden(text="Administrator role is required.")
    return principal


def _clear_session_cookie(request: web.Request, response: web.StreamResponse) -> None:
    response.del_cookie(
        _session_cookie_name(request),
        path="/",
        secure=request.app[_SECURE_COOKIE_KEY],
        httponly=True,
        samesite="Strict",
    )


def _set_session_cookie(
    request: web.Request,
    response: web.StreamResponse,
    token: str,
) -> None:
    request[_AUTH_TOKEN_KEY] = token
    response.set_cookie(
        _session_cookie_name(request),
        token,
        secure=request.app[_SECURE_COOKIE_KEY],
        httponly=True,
        samesite="Strict",
        path="/",
        max_age=12 * 60 * 60,
    )


def _request_client_ip(request: web.Request) -> str:
    remote = request.remote or ""
    try:
        remote_ip = str(ipaddress.ip_address(remote))
    except ValueError as exc:
        raise web.HTTPBadRequest(text="Invalid proxy peer.") from exc
    public_origin = request.app[_PUBLIC_ORIGIN_KEY]
    public_host = urlsplit(public_origin).hostname if public_origin else None
    request_host = request.host.split(":", 1)[0].rstrip(".").casefold()
    if public_host and request_host == public_host.casefold():
        if remote_ip != "127.0.0.1":
            raise web.HTTPBadRequest(text="Untrusted proxy peer.")
        forwarded_proto = request.headers.getall("X-Forwarded-Proto", [])
        real_ips = request.headers.getall("X-Real-IP", [])
        if forwarded_proto != ["https"] or len(real_ips) != 1:
            raise web.HTTPBadRequest(text="Invalid trusted proxy headers.")
        if any(
            request.headers.getall(name, [])
            for name in ("Forwarded", "X-Forwarded-Host", "X-Forwarded-For")
        ):
            raise web.HTTPBadRequest(text="Unexpected forwarding header.")
        try:
            return str(ipaddress.ip_address(real_ips[0]))
        except ValueError as exc:
            raise web.HTTPBadRequest(text="Invalid client address.") from exc
    if any(
        request.headers.getall(name, [])
        for name in (
            "Forwarded",
            "X-Forwarded-Host",
            "X-Forwarded-For",
            "X-Forwarded-Proto",
            "X-Real-IP",
        )
    ):
        raise web.HTTPBadRequest(text="Forwarding headers are not accepted on this host.")
    return remote_ip


def _authentication_middleware() -> web.middleware:
    @web.middleware
    async def middleware(
        request: web.Request,
        handler: web.RequestHandler,
    ) -> web.StreamResponse:
        try:
            request[_CLIENT_IP_KEY] = _request_client_ip(request)
        except web.HTTPException as exc:
            if request.path.startswith("/api/"):
                return _api_error("invalid_proxy", exc.text, status=exc.status)
            raise

        if request.path == "/healthz":
            if request.remote != "127.0.0.1" or request.host.split(":", 1)[0] != "127.0.0.1":
                raise web.HTTPNotFound()
            return await handler(request)

        token = request.cookies.get(_session_cookie_name(request))
        principal: Mapping[str, object] | None = None
        invalid_session = bool(token)
        if token and re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            try:
                principal = await _gateway(request).session(token)
                invalid_session = False
            except HelperCallError as exc:
                if exc.code not in {"unauthorized", "forbidden"}:
                    LOGGER.warning("authentication session helper unavailable", exc_info=True)
                    if request.path.startswith("/api/") or request.path.startswith("/static/"):
                        return _api_error(
                            "authentication_unavailable",
                            "Authentication service is temporarily unavailable.",
                            status=503,
                        )
                    return web.Response(
                        status=503,
                        text="Authentication service is temporarily unavailable.",
                        headers={"Retry-After": "5"},
                    )
            except Exception:
                LOGGER.warning("authentication session helper unavailable", exc_info=True)
                if request.path.startswith("/api/") or request.path.startswith("/static/"):
                    return _api_error(
                        "authentication_unavailable",
                        "Authentication service is temporarily unavailable.",
                        status=503,
                    )
                return web.Response(
                    status=503,
                    text="Authentication service is temporarily unavailable.",
                    headers={"Retry-After": "5"},
                )

        if request.path in _ANONYMOUS_PATHS:
            if request.path == "/login" and principal is not None:
                destination = (
                    "/security" if principal.get("password_change_required") is True else "/"
                )
                raise web.HTTPFound(destination)
            if principal is not None and token is not None:
                request[_AUTH_PRINCIPAL_KEY] = principal
                request[_AUTH_TOKEN_KEY] = token
                with bind_helper_identity(token):
                    response = await handler(request)
            else:
                response = await handler(request)
            if invalid_session:
                _clear_session_cookie(request, response)
            return response

        if principal is None or token is None:
            if request.path.startswith("/api/") or request.path.startswith("/static/"):
                response = _api_error(
                    "unauthorized",
                    "Authentication is required.",
                    status=401,
                )
            else:
                response = web.Response(
                    status=302,
                    headers={"Location": "/login"},
                )
            if invalid_session:
                _clear_session_cookie(request, response)
            return response

        if (
            principal.get("password_change_required") is True
            and request.path not in _PASSWORD_CHANGE_PATHS
        ):
            if request.path.startswith("/api/"):
                return _api_error(
                    "password_change_required",
                    "Change the mailbox password before continuing.",
                    status=403,
                )
            raise web.HTTPFound("/security")

        request[_AUTH_PRINCIPAL_KEY] = principal
        request[_AUTH_TOKEN_KEY] = token
        with bind_helper_identity(token):
            return await handler(request)

    return middleware


def _csrf_scope(request: web.Request) -> CsrfScope:
    session_token = request.get(_AUTH_TOKEN_KEY)
    if isinstance(session_token, str):
        return CsrfScope(f"session:{session_token}", False)
    client_ip = request.get(_CLIENT_IP_KEY)
    if not isinstance(client_ip, str):
        raise web.HTTPBadRequest(text="Client identity is unavailable.")
    return CsrfScope(f"client:{client_ip}", True)


def _valid_identifier(value: str) -> bool:
    return not (
        not value
        or len(value) > 512
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
        or "/" in value
        or "\\" in value
    )


def _identifier(value: str, label: str) -> str:
    if not _valid_identifier(value):
        raise web.HTTPBadRequest(text=f"Invalid {label}.")
    return value


def _account_id(value: str) -> str:
    if _ACCOUNT_ID_RE.fullmatch(value) is None:
        raise web.HTTPBadRequest(text="Invalid account identifier.")
    return value


def _valid_mailbox_name(value: str) -> bool:
    return not (
        not value
        or len(value) > 255
        or value.startswith("-")
        or "\\" in value
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    )


def _valid_certificate_name(value: str) -> bool:
    return not (
        not value
        or len(value) > 253
        or value.startswith("-")
        or "/" in value
        or "\\" in value
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    )


def _mailbox_name(value: str) -> str:
    if not _valid_mailbox_name(value):
        raise web.HTTPBadRequest(text="Invalid mailbox identifier.")
    return value


def _normalized_message_uid(value: str) -> str:
    if not value.isascii() or not value.isdecimal() or value.startswith("0") or len(value) > 10:
        raise ValueError("invalid message identifier")
    uid = int(value)
    if not 1 <= uid <= MAX_MESSAGE_CURSOR:
        raise ValueError("invalid message identifier")
    return str(uid)


def _message_uid(value: str) -> str:
    try:
        return _normalized_message_uid(value)
    except ValueError as exc:
        raise web.HTTPBadRequest(text="Invalid message identifier.") from exc


def _record_value(record: object, *names: str, default: object = "") -> object:
    for name in names:
        if isinstance(record, Mapping) and name in record:
            return record[name]
        if hasattr(record, name):
            return getattr(record, name)
    return default


def _backend_sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise TypeError(f"{label} must be a sequence")
    return value


def _backend_optional_text(value: object, label: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise TypeError(f"{label} must be text or null")
    return value


def _account_address(record: object) -> str:
    return str(_record_value(record, "address", "username", "id"))


def _account_payload(record: object) -> dict[str, object]:
    identifier = str(_record_value(record, "id", "username", "address"))
    address = _account_address(record)
    append_limit = _record_value(record, "append_limit", default=None)
    has_credentials = _record_value(
        record,
        "has_credentials",
        "enabled",
        default=True,
    )
    has_mailbox = _record_value(record, "has_mailbox", default=True)
    if type(has_credentials) is not bool or type(has_mailbox) is not bool:
        raise TypeError("account status flags must be booleans")
    if _ACCOUNT_ID_RE.fullmatch(identifier) is None:
        raise TypeError("account list contains an invalid identifier")
    if len(address) > 254 or _ACCOUNT_RE.fullmatch(address) is None:
        raise TypeError("account list contains an invalid address")
    if append_limit is not None and (
        type(append_limit) is not int or not 0 <= append_limit <= 4 * 1024**3
    ):
        raise TypeError("account append limit must be a bounded integer or null")
    return {
        "id": identifier,
        "address": address,
        "has_credentials": has_credentials,
        "has_mailbox": has_mailbox,
        "append_limit": append_limit,
    }


def _mailbox_payload(record: object) -> dict[str, object]:
    if isinstance(record, str):
        name = record
        attributes: Sequence[object] = ()
    else:
        value = _record_value(record, "name", "mailbox", "id", default=None)
        if not isinstance(value, str):
            raise TypeError("mailbox list item must contain a text name")
        name = value
        attributes = _backend_sequence(
            _record_value(record, "attributes", default=()),
            "mailbox attributes",
        )
    if not _valid_mailbox_name(name):
        raise TypeError("mailbox list contains an invalid name")
    if len(attributes) > 64:
        raise TypeError("mailbox attribute list exceeds the supported limit")
    normalized_attributes: set[str] = set()
    for attribute in attributes:
        if (
            not isinstance(attribute, str)
            or not attribute
            or len(attribute) > 255
            or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in attribute)
        ):
            raise TypeError("mailbox attribute list contains an invalid flag")
        normalized_attributes.add(attribute.casefold())
    return {
        "name": name,
        "is_trash": r"\trash" in normalized_attributes,
        "is_archive": r"\archive" in normalized_attributes,
    }


def _resolved_special_mailbox(
    mailboxes: Sequence[Mapping[str, object]],
    special: str,
) -> str | None:
    field = f"is_{special}"
    matches = [str(mailbox["name"]) for mailbox in mailboxes if mailbox.get(field) is True]
    if not matches:
        fallback = special.capitalize()
        matches = [str(mailbox["name"]) for mailbox in mailboxes if mailbox["name"] == fallback]
    return matches[0] if len(matches) == 1 else None


def _resolved_mailbox_payloads(
    records: Sequence[object],
) -> tuple[list[dict[str, object]], bool, bool]:
    mailboxes = [_mailbox_payload(record) for record in records]
    trash_target = _resolved_special_mailbox(mailboxes, "trash")
    archive_target = _resolved_special_mailbox(mailboxes, "archive")
    normalized = [
        {
            "name": mailbox["name"],
            "is_trash": trash_target is not None and mailbox["name"] == trash_target,
            "is_archive": archive_target is not None and mailbox["name"] == archive_target,
        }
        for mailbox in mailboxes
    ]
    return normalized, trash_target is not None, archive_target is not None


def _message_summary_payload(record: object) -> dict[str, object]:
    try:
        identifier = _normalized_message_uid(str(_record_value(record, "uid", "id")))
    except ValueError as exc:
        raise TypeError("message summary contains an invalid UID") from exc
    unread_value = _record_value(record, "unread", default=None)
    if unread_value is None:
        raw_flags = _record_value(record, "flags", default=())
        flags = _backend_sequence(raw_flags, "message flags")
        if any(not isinstance(flag, str) for flag in flags):
            raise TypeError("message summary flags must contain text")
        unread = not any(flag.casefold() == r"\seen" for flag in flags)
    else:
        unread = unread_value
    if type(unread) is not bool:
        raise TypeError("message summary unread flag must be a boolean")
    return {
        "uid": identifier,
        "sender": str(_record_value(record, "sender", "from_", "from", default="")),
        "subject": str(_record_value(record, "subject", default="(No subject)")) or "(No subject)",
        "date": str(_record_value(record, "date", "received_at", default="")),
        "unread": unread,
    }


def _account_identifiers(records: Sequence[object]) -> set[str]:
    return {str(_account_payload(record)["id"]) for record in records}


def _mailbox_names(records: Sequence[object]) -> set[str]:
    return {str(_mailbox_payload(record)["name"]) for record in records}


async def _find_account(request: web.Request, account_id: str) -> object:
    try:
        accounts_found = _backend_sequence(
            await _gateway(request).list_accounts(),
            "account list",
        )
        account_payloads = [_account_payload(account) for account in accounts_found]
    except Exception as exc:
        LOGGER.exception("failed to list accounts for confirmation")
        raise web.HTTPBadGateway(text="Could not verify account status.") from exc
    for account, payload in zip(accounts_found, account_payloads, strict=True):
        if payload["id"] == account_id:
            return account
    raise web.HTTPNotFound(text="Account does not exist.")


async def _gateway_error(_request: web.Request, title: str) -> web.Response:
    LOGGER.exception("gateway operation failed: %s", title)
    return _api_error(
        "backend_failure",
        "Backend failed; check services and audit log.",
        status=502,
    )


def _auth_failure(exc: Exception) -> web.Response:
    code = exc.code if isinstance(exc, HelperCallError) else "backend_failure"
    if code == "rate_limited":
        response = _api_error(
            "rate_limited",
            "Too many authentication attempts. Try again later.",
            status=429,
        )
        response.headers["Retry-After"] = "60"
        return response
    if code in {
        "invalid_credentials",
        "invalid_challenge",
        "invalid_second_factor",
        "unauthorized",
    }:
        return _api_error(
            code,
            "Authentication failed.",
            status=401,
        )
    if code in {"smtp_transport", "timeout"}:
        return _api_error(
            "authentication_unavailable",
            "Authentication service is temporarily unavailable.",
            status=503,
        )
    LOGGER.error(
        "authentication helper failed",
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    return _api_error(
        "backend_failure",
        "Authentication service failed safely.",
        status=502,
    )


def _bounded_auth_text(
    values: Mapping[str, object],
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> str:
    value = _json_text(values, name)
    if not minimum <= len(value) <= maximum or any(char in "\r\n\0" for char in value):
        raise web.HTTPBadRequest(text=f"Field {name} has an invalid length or character.")
    return value


def _totp_qr_svg(provisioning_uri: str) -> str:
    import segno

    qr_code = segno.make_qr(
        provisioning_uri,
        error="M",
        boost_error=True,
    )
    rendered = qr_code.svg_inline(
        scale=5,
        border=4,
        dark="#162033",
        light="#ffffff",
    )
    if (
        not isinstance(rendered, str)
        or not rendered.startswith("<svg ")
        or len(rendered) > MAX_TOTP_QR_SVG_CHARS
        or not rendered.isascii()
    ):
        raise RuntimeError("local QR renderer returned an invalid SVG")
    return rendered


def _valid_totp_provisioning_uri(
    provisioning_uri: str,
    *,
    secret: str,
    issuer: str,
) -> bool:
    try:
        parsed = urlsplit(provisioning_uri)
        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        return False
    return (
        parsed.scheme == "otpauth"
        and parsed.netloc == "totp"
        and parsed.path.startswith("/")
        and parsed.fragment == ""
        and set(query) == {"secret", "issuer", "algorithm", "digits", "period"}
        and query["secret"] == [secret]
        and query["issuer"] == [issuer]
        and query["algorithm"] == ["SHA1"]
        and query["digits"] == ["6"]
        and query["period"] == ["30"]
    )


def _login_response(
    request: web.Request,
    result: Mapping[str, object],
) -> web.Response:
    token = result.get("session_token")
    principal = result.get("principal")
    recovery_codes = result.get("recovery_codes", [])
    if (
        not isinstance(token, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None
        or not isinstance(principal, Mapping)
        or not isinstance(recovery_codes, list)
        or any(not isinstance(code, str) for code in recovery_codes)
    ):
        return _api_error(
            "invalid_backend_response",
            "Authentication service returned an invalid response.",
            status=502,
        )
    response = _api_response(
        data={
            "principal": dict(principal),
            "recovery_codes": recovery_codes,
            "csrf_token": csrf_token_for_request(request),
        }
    )
    _set_session_cookie(request, response, token)
    return response


async def api_auth_csrf(request: web.Request) -> web.Response:
    _read_query(request, allowed_fields=frozenset())
    return _api_response(data={"csrf_token": csrf_token_for_request(request)})


async def api_auth_password(request: web.Request) -> web.Response:
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"email", "password"}),
    )
    email = _bounded_auth_text(values, "email", minimum=3, maximum=254).strip().casefold()
    password = _bounded_auth_text(values, "password", minimum=1, maximum=1024)
    values["password"] = ""
    if _ACCOUNT_RE.fullmatch(email) is None:
        return _api_error("invalid_credentials", "Authentication failed.", status=401)
    try:
        result = await _gateway(request).begin_password_login(
            email,
            password,
            client_ip=_request_client_ip(request),
        )
    except Exception as exc:
        return _auth_failure(exc)
    finally:
        password = ""
    challenge = result.get("challenge")
    next_step = result.get("next")
    if (
        not isinstance(challenge, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge) is None
        or next_step not in {"totp", "enrollment"}
    ):
        return _api_error(
            "invalid_backend_response",
            "Authentication service returned an invalid response.",
            status=502,
        )
    return _api_response(data={"challenge": challenge, "next": next_step})


async def api_auth_enrollment(request: web.Request) -> web.Response:
    values = await _read_json_object(request, allowed_fields=frozenset({"challenge"}))
    challenge = _bounded_auth_text(values, "challenge", minimum=43, maximum=43)
    try:
        result = await _gateway(request).begin_totp_enrollment(challenge)
    except Exception as exc:
        return _auth_failure(exc)
    secret = result.get("secret")
    uri = result.get("provisioning_uri")
    issuer = request.app[_TOTP_ISSUER_KEY]
    if (
        not isinstance(secret, str)
        or re.fullmatch(r"[A-Z2-7]{32}", secret) is None
        or not isinstance(uri, str)
        or not uri.startswith("otpauth://totp/")
        or len(uri) > 1024
        or not _valid_totp_provisioning_uri(uri, secret=secret, issuer=issuer)
    ):
        return _api_error(
            "invalid_backend_response",
            "Authentication service returned an invalid enrollment.",
            status=502,
        )
    try:
        qr_svg = await asyncio.to_thread(_totp_qr_svg, uri)
    except Exception:
        LOGGER.error("local TOTP QR generation failed", exc_info=True)
        return _api_error(
            "qr_generation_failed",
            "Authenticator setup could not be rendered safely.",
            status=503,
        )
    return _api_response(
        data={
            "secret": secret,
            "issuer": issuer,
            "provisioning_uri": uri,
            "qr_svg": qr_svg,
        }
    )


async def api_auth_enrollment_confirm(request: web.Request) -> web.Response:
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"challenge", "code"}),
    )
    challenge = _bounded_auth_text(values, "challenge", minimum=43, maximum=43)
    code = _bounded_auth_text(values, "code", minimum=6, maximum=6)
    try:
        result = await _gateway(request).complete_totp_enrollment(
            challenge,
            code,
            client_ip=_request_client_ip(request),
        )
    except Exception as exc:
        return _auth_failure(exc)
    return _login_response(request, result)


async def api_auth_totp(request: web.Request) -> web.Response:
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"challenge", "code"}),
    )
    challenge = _bounded_auth_text(values, "challenge", minimum=43, maximum=43)
    code = _bounded_auth_text(values, "code", minimum=6, maximum=6)
    try:
        result = await _gateway(request).complete_totp_login(
            challenge,
            code,
            client_ip=_request_client_ip(request),
        )
    except Exception as exc:
        return _auth_failure(exc)
    return _login_response(request, result)


async def api_auth_recovery(request: web.Request) -> web.Response:
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"challenge", "recovery_code"}),
    )
    challenge = _bounded_auth_text(values, "challenge", minimum=43, maximum=43)
    recovery_code = _bounded_auth_text(
        values,
        "recovery_code",
        minimum=8,
        maximum=64,
    )
    try:
        result = await _gateway(request).complete_recovery_login(
            challenge,
            recovery_code,
            client_ip=_request_client_ip(request),
        )
    except Exception as exc:
        return _auth_failure(exc)
    return _login_response(request, result)


async def api_auth_session(request: web.Request) -> web.Response:
    _read_query(request, allowed_fields=frozenset())
    principal = request.get(_AUTH_PRINCIPAL_KEY)
    if not isinstance(principal, Mapping):
        return _api_error("unauthorized", "Authentication is required.", status=401)
    return _api_response(
        data={
            "principal": dict(principal),
            "csrf_token": csrf_token_for_request(request),
        }
    )


async def api_auth_logout(request: web.Request) -> web.Response:
    await _read_json_object(request, allowed_fields=frozenset())
    token = request.get(_AUTH_TOKEN_KEY)
    if not isinstance(token, str):
        return _api_error("unauthorized", "Authentication is required.", status=401)
    try:
        await _gateway(request).logout(token)
    except Exception:
        LOGGER.warning("session logout helper failed", exc_info=True)
        return _api_error(
            "logout_failed",
            "Session revocation failed. Retry before leaving this browser.",
            status=503,
        )
    response = _api_response(message="Signed out.")
    _clear_session_cookie(request, response)
    return response


async def api_auth_change_password(request: web.Request) -> web.Response:
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"current_password", "new_password"}),
    )
    current_password = _bounded_auth_text(
        values,
        "current_password",
        minimum=1,
        maximum=1024,
    )
    new_password = _bounded_auth_text(
        values,
        "new_password",
        minimum=12,
        maximum=1024,
    )
    values["current_password"] = ""
    values["new_password"] = ""
    try:
        await _gateway(request).change_own_password(
            current_password,
            new_password,
            client_ip=_request_client_ip(request),
        )
    except Exception as exc:
        return _auth_failure(exc)
    finally:
        current_password = ""
        new_password = ""
    response = _api_response(message="Password changed. Sign in again.")
    _clear_session_cookie(request, response)
    return response


async def api_auth_recovery_regenerate(request: web.Request) -> web.Response:
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"password", "code"}),
    )
    password = _bounded_auth_text(values, "password", minimum=1, maximum=1024)
    code = _bounded_auth_text(values, "code", minimum=6, maximum=6)
    values["password"] = ""
    try:
        result = await _gateway(request).regenerate_recovery_codes(
            password,
            code,
            client_ip=_request_client_ip(request),
        )
    except Exception as exc:
        return _auth_failure(exc)
    finally:
        password = ""
    recovery_codes = result.get("recovery_codes")
    if not isinstance(recovery_codes, list) or any(
        not isinstance(value, str) for value in recovery_codes
    ):
        return _api_error(
            "invalid_backend_response",
            "Authentication service returned invalid recovery codes.",
            status=502,
        )
    response = _api_response(data={"recovery_codes": recovery_codes})
    _clear_session_cookie(request, response)
    return response


async def api_auth_step_up(request: web.Request) -> web.Response:
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"password", "code"}),
    )
    password = _bounded_auth_text(values, "password", minimum=1, maximum=1024)
    code = _bounded_auth_text(values, "code", minimum=6, maximum=6)
    values["password"] = ""
    try:
        result = await _gateway(request).step_up(
            password,
            code,
            client_ip=_request_client_ip(request),
        )
    except Exception as exc:
        return _auth_failure(exc)
    finally:
        password = ""
    return _api_response(data=dict(result))


def _health_version(value: object) -> str:
    rendered = str(value)
    if re.fullmatch(r"[0-9A-Za-z.+-]{1,64}", rendered) is None:
        return "unknown"
    return rendered


async def _health_snapshot(request: web.Request) -> tuple[dict[str, object], bool]:
    try:
        raw = await _gateway(request).health()
    except Exception:
        LOGGER.warning("health probe failed", exc_info=True)
        raw = {}
    if not isinstance(raw, Mapping):
        LOGGER.error("health probe returned an invalid payload")
        raw = {}
    write_enabled = raw.get("maddy_write_enabled") is True
    storage_available = raw.get("storage_available") is True
    certificate_enabled = raw.get("certificate_management_enabled") is True
    healthy = raw.get("status") == "ok" and write_enabled and storage_available
    payload = {
        "status": "ok" if healthy else "degraded",
        "version": _health_version(raw.get("version", "unknown")),
        "maddy_version": _health_version(raw.get("maddy_version", "unknown")),
        "maddy_write_enabled": write_enabled,
        "storage_available": storage_available,
        "certbot_available": raw.get("certbot_available") is True,
        "certificate_management_enabled": certificate_enabled,
    }
    return payload, healthy


async def healthz(request: web.Request) -> web.Response:
    """Return a non-sensitive, fixed-schema readiness result for service probes."""

    payload, healthy = await _health_snapshot(request)
    return web.json_response(payload, status=200 if healthy else 503)


async def api_health(request: web.Request) -> web.Response:
    _read_query(request, allowed_fields=frozenset())
    payload, healthy = await _health_snapshot(request)
    return _api_response(data=payload, status=200 if healthy else 503)


async def api_session(request: web.Request) -> web.Response:
    return await api_auth_session(request)


async def api_accounts(request: web.Request) -> web.Response:
    _require_admin(request)
    _read_query(request, allowed_fields=frozenset())
    try:
        raw_values = await _gateway(request).list_accounts()
    except Exception:
        return await _gateway_error(request, "Could not read accounts")
    try:
        values = _backend_sequence(raw_values, "account list")
        accounts = [_account_payload(value) for value in values]
    except TypeError, ValueError:
        LOGGER.error("account backend returned an invalid payload", exc_info=True)
        return _api_error(
            "invalid_backend_response",
            "Backend returned an invalid account list.",
            status=502,
        )
    return _api_response(data={"accounts": accounts})


async def create_account(request: web.Request) -> web.Response:
    _require_admin(request)
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"username", "password"}),
    )
    username = _json_text(values, "username").strip()
    password = _json_text(values, "password")
    values["password"] = ""
    if len(username) > 254 or _ACCOUNT_RE.fullmatch(username) is None:
        raise web.HTTPBadRequest(text="Invalid email account format.")
    if not 12 <= len(password) <= 256 or any(char in "\r\n\0" for char in password):
        raise web.HTTPBadRequest(text="Password must contain 12 to 256 valid characters.")
    try:
        created = await _gateway(request).create_account(username, password)
    except Exception:
        return await _gateway_error(request, "Account creation failed")
    finally:
        password = ""  # Avoid retaining the immutable reference in this frame.
    if not isinstance(created, Mapping):
        return _api_error(
            "invalid_backend_response",
            "Backend returned an invalid account enrollment.",
            status=502,
        )
    return _api_response(
        data=dict(created),
        message="Account created. Save its TOTP and recovery credentials now.",
        status=201,
    )


async def change_password(request: web.Request) -> web.Response:
    _require_admin(request)
    account_id = _account_id(request.match_info["account_id"])
    values = await _read_json_object(request, allowed_fields=frozenset({"password"}))
    password = _json_text(values, "password")
    values["password"] = ""
    if not 12 <= len(password) <= 256 or any(char in "\r\n\0" for char in password):
        raise web.HTTPBadRequest(text="Password must contain 12 to 256 valid characters.")
    try:
        await _gateway(request).change_password(account_id, password)
    except Exception:
        return await _gateway_error(request, "Password change failed")
    finally:
        password = ""
    return _api_response(message="Password changed.")


async def set_append_limit(request: web.Request) -> web.Response:
    _require_admin(request)
    account_id = _account_id(request.match_info["account_id"])
    values = await _read_json_object(request, allowed_fields=frozenset({"limit"}))
    limit = values.get("limit")
    if type(limit) is not int:
        raise web.HTTPBadRequest(text="APPENDLIMIT must be an integer.")
    if not 0 <= limit <= 4 * 1024**3:
        raise web.HTTPBadRequest(text="APPENDLIMIT must be between 0 and 4 GiB.")
    try:
        await _gateway(request).set_append_limit(account_id, limit)
    except Exception:
        return await _gateway_error(request, "Failed to set APPENDLIMIT")
    return _api_response(message="APPENDLIMIT updated.")


async def disable_credentials(request: web.Request) -> web.Response:
    _require_admin(request)
    account_id = _account_id(request.match_info["account_id"])
    await _read_json_object(request, allowed_fields=frozenset())
    try:
        await _gateway(request).disable_credentials(account_id)
    except Exception:
        return await _gateway_error(request, "Failed to disable credentials")
    return _api_response(message="Credentials disabled; mailbox not deleted.")


async def delete_mailbox(request: web.Request) -> web.Response:
    _require_admin(request)
    account_id = _account_id(request.match_info["account_id"])
    values = await _read_json_object(request, allowed_fields=frozenset({"confirmation"}))
    confirmation = _json_text(values, "confirmation")
    account = await _find_account(request, account_id)
    if confirmation != _account_address(account):
        raise web.HTTPBadRequest(text="Confirmation address mismatch; mailbox not deleted.")
    try:
        await _gateway(request).delete_mailbox(account_id)
    except Exception:
        return await _gateway_error(request, "Permanent mailbox deletion failed")
    return _api_response(message="Mailbox permanently deleted.")


async def reset_account_totp(request: web.Request) -> web.Response:
    _require_admin(request)
    account_id = _account_id(request.match_info["account_id"])
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"confirmation"}),
    )
    if _json_text(values, "confirmation") != "RESET TOTP":
        raise web.HTTPBadRequest(text="TOTP reset confirmation does not match.")
    try:
        result = await _gateway(request).rotate_account_totp(account_id)
    except HelperCallError as exc:
        if exc.code == "step_up_required":
            return _api_error(
                "step_up_required",
                "Fresh administrator authentication is required.",
                status=403,
            )
        return await _gateway_error(request, "Could not reset account TOTP")
    except Exception:
        return await _gateway_error(request, "Could not reset account TOTP")
    return _api_response(
        data=dict(result),
        message="TOTP reset. Save the new credentials now.",
    )


async def api_mailbox(request: web.Request) -> web.Response:
    personal_scope = request.path.startswith("/api/v1/me/")
    if not personal_scope:
        _require_admin(request)
    query = _read_query(
        request,
        allowed_fields=frozenset({"account", "mailbox", "cursor", "page"}),
    )
    if personal_scope and "account" in query:
        raise web.HTTPBadRequest(text="Personal mailbox APIs do not accept an account field.")
    account = _principal_account_id(request) if personal_scope else query.get("account", "")
    mailbox_name = query.get("mailbox", "")
    if account:
        account = _account_id(account)
    if mailbox_name:
        mailbox_name = _mailbox_name(mailbox_name)
    if "page" in query:
        raise web.HTTPBadRequest(text="Page link expired; restart from the mailbox list.")
    cursor_token = query.get("cursor")
    if cursor_token is not None and (not account or not mailbox_name):
        raise web.HTTPBadRequest(text="Pagination cursor lacks account or mailbox context.")
    page_size = _settings(request).page_size
    if personal_scope:
        principal = _principal(request)
        account_values: Sequence[object] = ()
        account_payloads = [
            {
                "id": account,
                "address": str(principal.get("email", "")),
                "has_credentials": True,
                "has_mailbox": True,
                "append_limit": None,
            }
        ]
    else:
        try:
            raw_account_values = await _gateway(request).list_accounts()
        except Exception:
            return await _gateway_error(request, "Could not read accounts")
        try:
            account_values = _backend_sequence(raw_account_values, "account list")
            account_payloads = [_account_payload(value) for value in account_values]
        except TypeError, ValueError:
            LOGGER.error("account backend returned an invalid payload", exc_info=True)
            return _api_error(
                "invalid_backend_response",
                "Backend returned an invalid account list.",
                status=502,
            )
        if account and account not in _account_identifiers(account_values):
            raise web.HTTPBadRequest(text="Account is not in the allowed list.")
    try:
        raw_mailbox_values = await _gateway(request).list_mailboxes(account) if account else ()
    except Exception:
        return await _gateway_error(request, "Could not read mailboxes")
    try:
        mailbox_values = _backend_sequence(raw_mailbox_values, "mailbox list")
        mailbox_payloads, trash_available, archive_available = _resolved_mailbox_payloads(
            mailbox_values
        )
    except TypeError, ValueError:
        LOGGER.error("mailbox backend returned an invalid payload", exc_info=True)
        return _api_error(
            "invalid_backend_response",
            "Backend returned an invalid mailbox list.",
            status=502,
        )
    mailbox_names = _mailbox_names(mailbox_values)
    if mailbox_name and mailbox_name not in mailbox_names:
        raise web.HTTPBadRequest(text="Mailbox is not in the allowed list.")
    if account and not mailbox_name:
        mailbox_name = next(
            (
                mailbox["name"]
                for mailbox in mailbox_payloads
                if mailbox["name"].casefold() == "inbox"
            ),
            "",
        )

    cursor_state: _MailboxCursorState | None = None
    page = 1
    offset = 0
    if cursor_token is not None:
        try:
            cursor_state = _mail_cursor_store(request).resolve(
                cursor_token,
                account=account,
                mailbox=mailbox_name,
            )
        except _MailboxCursorError as exc:
            raise web.HTTPConflict(text="Pagination expired; refresh.") from exc
        page = cursor_state.page
        offset = cursor_state.offset
    try:
        message_page = (
            _message_page(
                await _gateway(request).list_messages(
                    account,
                    mailbox_name,
                    limit=page_size,
                    offset=offset,
                )
            )
            if account and mailbox_name
            else MessagePage((), False)
        )
    except Exception as exc:
        if getattr(exc, "code", None) == "stale_cursor":
            raise web.HTTPConflict(text="Mailbox changed; refresh before continuing.") from exc
        return await _gateway_error(request, "Could not read messages")

    previous_cursor = cursor_state.previous if cursor_state is not None else None
    next_cursor: str | None = None
    if (
        account
        and mailbox_name
        and message_page.next_offset is not None
        and page < MAX_MAILBOX_PAGE
    ):
        current_cursor = cursor_token
        if current_cursor is None:
            current_cursor = _mail_cursor_store(request).create(
                account=account,
                mailbox=mailbox_name,
                offset=message_page.offset,
                page=page,
                previous=None,
            )
        next_cursor = _mail_cursor_store(request).create(
            account=account,
            mailbox=mailbox_name,
            offset=message_page.next_offset,
            page=page + 1,
            previous=current_cursor,
        )
    try:
        payload = {
            "accounts": account_payloads,
            "mailboxes": mailbox_payloads,
            "trash_available": trash_available,
            "archive_available": archive_available,
            "messages": [_message_summary_payload(value) for value in message_page.items],
            "selected_account": account,
            "selected_mailbox": mailbox_name,
            "page": page,
            "previous_cursor": previous_cursor,
            "next_cursor": next_cursor,
        }
    except TypeError, ValueError:
        LOGGER.error("mail backend returned an invalid payload", exc_info=True)
        return _api_error(
            "invalid_backend_response",
            "Backend returned an invalid mailbox response.",
            status=502,
        )
    return _api_response(data=payload)


def _mail_context(request: web.Request, values: Mapping[str, Any]) -> tuple[str, str]:
    account = _account_context(request, values)
    mailbox_name = _mailbox_name(_json_text(values, "mailbox"))
    return account, mailbox_name


def _account_context(request: web.Request, values: Mapping[str, Any]) -> str:
    if request.path.startswith("/api/v1/me/"):
        if "account" in values:
            raise web.HTTPBadRequest(text="Personal mailbox APIs do not accept an account field.")
        return _principal_account_id(request)
    _require_admin(request)
    return _account_id(_json_text(values, "account"))


async def _parsed_message(
    request: web.Request,
    account: str,
    mailbox_name: str,
) -> ParsedMessage:
    message, _digest = await _parsed_message_snapshot(request, account, mailbox_name)
    return message


def _file_sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


async def _parsed_message_snapshot(
    request: web.Request,
    account: str,
    mailbox_name: str,
) -> tuple[ParsedMessage, str]:
    spool = await _spool_raw_message(request, account, mailbox_name)
    try:
        digest = await asyncio.to_thread(_file_sha256, spool.path)
        if spool.size > MAX_RAW_MESSAGE_BYTES:
            raise PreviewTooLarge(spool.size, digest)
        raw = await asyncio.to_thread(spool.path.read_bytes)
        return await asyncio.to_thread(parse_message, raw), digest
    except PreviewTooLarge:
        raise
    except MailError as exc:
        raise web.HTTPUnprocessableEntity(text="Invalid or oversized message.") from exc
    finally:
        await asyncio.to_thread(spool.cleanup)


async def _spool_raw_message(
    request: web.Request,
    account: str,
    mailbox_name: str,
) -> RawMessageSpool:
    message_id = _message_uid(request.match_info["message_id"])
    await _authorize_mail_context(request, account, mailbox_name)
    settings = _settings(request)
    _ensure_temp_directory(settings)
    descriptor, filename = tempfile.mkstemp(
        prefix="raw-message-",
        suffix=".eml",
        dir=settings.temp_dir,
    )
    path = Path(filename)
    os.close(descriptor)
    try:
        reported_size = await _gateway(request).spool_message(
            account,
            mailbox_name,
            message_id,
            path,
            max_bytes=MAX_RAW_DOWNLOAD_BYTES,
        )
    except Exception as exc:
        await asyncio.to_thread(path.unlink, missing_ok=True)
        LOGGER.exception("failed to read message")
        raise web.HTTPBadGateway(text="Could not read the message.") from exc
    try:
        file_stat = await asyncio.to_thread(path.lstat)
    except OSError as exc:
        await asyncio.to_thread(path.unlink, missing_ok=True)
        raise web.HTTPBadGateway(text="Raw-message spool is unavailable.") from exc
    if (
        type(reported_size) is not int
        or reported_size != file_stat.st_size
        or file_stat.st_size <= 0
        or not stat.S_ISREG(file_stat.st_mode)
        or (os.name == "posix" and bool(file_stat.st_mode & 0o077))
        or file_stat.st_size > MAX_RAW_DOWNLOAD_BYTES
    ):
        await asyncio.to_thread(path.unlink, missing_ok=True)
        if file_stat.st_size > MAX_RAW_DOWNLOAD_BYTES:
            raise web.HTTPRequestEntityTooLarge(
                max_size=MAX_RAW_DOWNLOAD_BYTES,
                actual_size=file_stat.st_size,
            )
        raise web.HTTPBadGateway(text="Backend returned an invalid raw message.")
    return RawMessageSpool(path=path, size=file_stat.st_size)


async def _authorize_mail_context(
    request: web.Request,
    account: str,
    mailbox_name: str,
) -> None:
    try:
        if request.path.startswith("/api/v1/me/"):
            if account != _principal_account_id(request):
                raise web.HTTPForbidden(text="Cross-account access is forbidden.")
        else:
            _require_admin(request)
            accounts_found = _backend_sequence(
                await _gateway(request).list_accounts(),
                "account list",
            )
            for account_value in accounts_found:
                _account_payload(account_value)
            if account not in _account_identifiers(accounts_found):
                raise web.HTTPBadRequest(text="Account is not in the allowed list.")
        mailboxes_found = _backend_sequence(
            await _gateway(request).list_mailboxes(account),
            "mailbox list",
        )
        if mailbox_name not in _mailbox_names(mailboxes_found):
            raise web.HTTPBadRequest(text="Mailbox is not in the allowed list.")
    except web.HTTPException:
        raise
    except Exception as exc:
        LOGGER.exception("failed to authorize mailbox context")
        raise web.HTTPBadGateway(text="Could not validate message context.") from exc


async def _verify_message_freshness(
    request: web.Request,
    *,
    account: str,
    mailbox: str,
    uid: str,
    token: str,
) -> None:
    entry = _freshness_store(request).consume(token, _freshness_owner(request))
    if entry is None or entry.account != account or entry.mailbox != mailbox or entry.uid != uid:
        raise web.HTTPConflict(text="Message confirmation expired; refresh and try again.")
    try:
        spool = await _spool_raw_message(request, account, mailbox)
    except web.HTTPException as exc:
        raise web.HTTPConflict(text="Message state changed; refresh and try again.") from exc
    try:
        current_digest = await asyncio.to_thread(_file_sha256, spool.path)
    finally:
        await asyncio.to_thread(spool.cleanup)
    if not secrets.compare_digest(entry.digest, current_digest):
        raise web.HTTPConflict(text="Message state changed; refresh and try again.")


def _message_download_url(
    request: web.Request,
    message_id: str,
    account: str,
    mailbox_name: str,
    suffix: str,
) -> str:
    personal_scope = request.path.startswith("/api/v1/me/")
    query_values = (
        {"mailbox": mailbox_name}
        if personal_scope
        else {"account": account, "mailbox": mailbox_name}
    )
    query = urlencode(query_values)
    prefix = "/api/v1/me/mail" if personal_scope else "/api/v1/admin/mail"
    return f"{prefix}/{quote(message_id, safe='')}/{suffix}?{query}"


async def api_message_action_snapshot(request: web.Request) -> web.Response:
    query = _read_query(
        request,
        allowed_fields=frozenset({"account", "mailbox"}),
    )
    account, mailbox_name = _mail_context(request, query)
    message_id = _message_uid(request.match_info["message_id"])
    async with _mail_work_slot(request):
        spool = await _spool_raw_message(request, account, mailbox_name)
        try:
            digest = await asyncio.to_thread(_file_sha256, spool.path)
            size = spool.size
        finally:
            await asyncio.to_thread(spool.cleanup)
        freshness = _freshness_store(request).issue(
            _freshness_owner(request),
            account,
            mailbox_name,
            message_id,
            digest,
        )
    return _api_response(
        data={
            "uid": message_id,
            "account": account,
            "mailbox": mailbox_name,
            "size": size,
            "freshness_token": freshness,
        }
    )


async def api_message_detail(request: web.Request) -> web.Response:
    query = _read_query(
        request,
        allowed_fields=frozenset({"account", "mailbox"}),
    )
    account, mailbox_name = _mail_context(request, query)
    message_id = _message_uid(request.match_info["message_id"])
    async with _mail_work_slot(request):
        try:
            message, digest = await _parsed_message_snapshot(request, account, mailbox_name)
        except PreviewTooLarge as exc:
            freshness = _freshness_store(request).issue(
                _freshness_owner(request),
                account,
                mailbox_name,
                message_id,
                exc.digest,
            )
            return _api_response(
                data={
                    "uid": message_id,
                    "account": account,
                    "mailbox": mailbox_name,
                    "preview_too_large": True,
                    "size": exc.size,
                    "freshness_token": freshness,
                    "raw_url": _message_download_url(
                        request,
                        message_id,
                        account,
                        mailbox_name,
                        "raw",
                    ),
                }
            )
        freshness = _freshness_store(request).issue(
            _freshness_owner(request),
            account,
            mailbox_name,
            message_id,
            digest,
        )
        attachments = [
            {
                "id": attachment.attachment_id,
                "filename": attachment.filename,
                "content_type": attachment.content_type,
                "size": attachment.size,
                "inline": attachment.inline,
                "url": _message_download_url(
                    request,
                    message_id,
                    account,
                    mailbox_name,
                    f"attachments/{quote(attachment.attachment_id, safe='')}",
                ),
            }
            for attachment in message.attachments
        ]
        return _api_response(
            data={
                "uid": message_id,
                "account": account,
                "mailbox": mailbox_name,
                "preview_too_large": False,
                "subject": message.subject,
                "sender": message.sender,
                "reply_to": list(message.reply_to),
                "to": list(message.to),
                "cc": list(message.cc),
                "date": message.date,
                "message_id": message.message_id,
                "in_reply_to": message.in_reply_to,
                "references": list(message.references),
                "text": message.text,
                "has_html": message.html is not None,
                "html_url": (
                    _message_download_url(
                        request,
                        message_id,
                        account,
                        mailbox_name,
                        "html",
                    )
                    if message.html is not None
                    else None
                ),
                "raw_url": _message_download_url(
                    request,
                    message_id,
                    account,
                    mailbox_name,
                    "raw",
                ),
                "attachments": attachments,
                "freshness_token": freshness,
            }
        )


async def message_html(request: web.Request) -> web.Response:
    query = _read_query(
        request,
        allowed_fields=frozenset({"account", "mailbox"}),
    )
    account, mailbox_name = _mail_context(request, query)
    async with _mail_work_slot(request):
        message = await _parsed_message(request, account, mailbox_name)
        if message.html is None:
            raise web.HTTPNotFound(text="This message has no HTML body.")
        cid_counts: dict[str, int] = {}
        for attachment in message.attachments:
            if attachment.content_id:
                cid_counts[attachment.content_id] = cid_counts.get(attachment.content_id, 0) + 1
        personal_scope = request.path.startswith("/api/v1/me/")
        context_query = urlencode(
            {"mailbox": mailbox_name}
            if personal_scope
            else {"account": account, "mailbox": mailbox_name}
        )
        route_prefix = "/api/v1/me/mail" if personal_scope else "/api/v1/admin/mail"
        cid_urls = {
            attachment.content_id: (
                f"{route_prefix}/{quote(request.match_info['message_id'], safe='')}/inline/"
                f"{quote(attachment.attachment_id, safe='')}?{context_query}"
            )
            for attachment in message.attachments
            if attachment.inline
            and attachment.content_id is not None
            and cid_counts.get(attachment.content_id) == 1
            and detect_safe_image_type(attachment.data) is not None
        }
        document = await asyncio.to_thread(_iframe_document, message.html, cid_urls)
        return web.Response(
            text=document,
            content_type="text/html",
            charset="utf-8",
            headers=email_document_headers(),
        )


def _iframe_document(message_html: str, cid_urls: Mapping[str, str]) -> str:
    rewritten = rewrite_cid_images(message_html, cid_urls)
    return sandboxed_html_document(rewritten, already_sanitized=True)


async def inline_image(request: web.Request) -> web.Response:
    query = _read_query(
        request,
        allowed_fields=frozenset({"account", "mailbox"}),
    )
    account, mailbox_name = _mail_context(request, query)
    async with _mail_work_slot(request):
        message = await _parsed_message(request, account, mailbox_name)
        attachment_id = _identifier(request.match_info["attachment_id"], "inline image identifier")
        attachment = next(
            (item for item in message.attachments if item.attachment_id == attachment_id),
            None,
        )
        if attachment is None or not attachment.inline or attachment.content_id is None:
            raise web.HTTPNotFound(text="Inline image does not exist.")
        if sum(item.content_id == attachment.content_id for item in message.attachments) != 1:
            raise web.HTTPNotFound(text="Inline image identifier is not unique.")
        content_type = detect_safe_image_type(attachment.data)
        if content_type is None:
            raise web.HTTPUnsupportedMediaType(text="Inline image format is not supported.")
        return web.Response(
            body=attachment.data,
            content_type=content_type,
            headers={
                "Cache-Control": "private, no-store",
                "Content-Security-Policy": "default-src 'none'",
                "Cross-Origin-Resource-Policy": "same-origin",
                "X-Content-Type-Options": "nosniff",
            },
        )


async def raw_message(request: web.Request) -> web.StreamResponse:
    query = _read_query(
        request,
        allowed_fields=frozenset({"account", "mailbox"}),
    )
    account, mailbox_name = _mail_context(request, query)
    spool = await _spool_raw_message(request, account, mailbox_name)
    message_id = _message_uid(request.match_info["message_id"])
    headers = attachment_download_headers(f"message-{message_id}.eml")
    headers["Content-Length"] = str(spool.size)
    return CleanupFileResponse(spool.path, headers=headers)


async def download_attachment(request: web.Request) -> web.Response:
    query = _read_query(
        request,
        allowed_fields=frozenset({"account", "mailbox"}),
    )
    account, mailbox_name = _mail_context(request, query)
    async with _mail_work_slot(request):
        message = await _parsed_message(request, account, mailbox_name)
        attachment_id = _identifier(request.match_info["attachment_id"], "attachment identifier")
        attachment = next(
            (item for item in message.attachments if item.attachment_id == attachment_id),
            None,
        )
        if attachment is None:
            raise web.HTTPNotFound(text="Attachment does not exist.")
        headers = attachment_download_headers(attachment.filename)
        headers["Content-Length"] = str(attachment.size)
        return web.Response(body=attachment.data, headers=headers)


async def move_message_to_trash(request: web.Request) -> web.Response:
    message_id = _message_uid(request.match_info["message_id"])
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"account", "mailbox", "freshness"}),
    )
    account, mailbox_name = _mail_context(request, values)
    await _verify_message_freshness(
        request,
        account=account,
        mailbox=mailbox_name,
        uid=message_id,
        token=_json_text(values, "freshness"),
    )
    try:
        target = await _gateway(request).move_message_to_trash(account, mailbox_name, message_id)
    except Exception:
        return await _gateway_error(request, "Failed to move message")
    if not isinstance(target, str) or not _valid_mailbox_name(target):
        LOGGER.error("mail backend returned an invalid Trash mailbox")
        return _api_error(
            "invalid_backend_response",
            "Backend returned an invalid Trash mailbox.",
            status=502,
        )
    return _api_response(
        data={"account": account, "mailbox": target},
        message="Message moved to Trash.",
    )


async def move_message_to_archive(request: web.Request) -> web.Response:
    message_id = _message_uid(request.match_info["message_id"])
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"account", "mailbox", "freshness"}),
    )
    account, mailbox_name = _mail_context(request, values)
    await _verify_message_freshness(
        request,
        account=account,
        mailbox=mailbox_name,
        uid=message_id,
        token=_json_text(values, "freshness"),
    )
    try:
        target = await _gateway(request).move_message_to_archive(
            account,
            mailbox_name,
            message_id,
        )
    except Exception:
        return await _gateway_error(request, "Failed to archive message")
    if not isinstance(target, str) or not _valid_mailbox_name(target):
        LOGGER.error("mail backend returned an invalid Archive mailbox")
        return _api_error(
            "invalid_backend_response",
            "Backend returned an invalid Archive mailbox.",
            status=502,
        )
    return _api_response(
        data={"account": account, "mailbox": target},
        message="Message archived.",
    )


async def delete_message_permanently(request: web.Request) -> web.Response:
    message_id = _message_uid(request.match_info["message_id"])
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"account", "mailbox", "freshness", "confirmation"}),
    )
    account, mailbox_name = _mail_context(request, values)
    if _json_text(values, "confirmation") != "PERMANENTLY DELETE":
        raise web.HTTPBadRequest(text="Confirmation text mismatch; message not deleted.")
    await _verify_message_freshness(
        request,
        account=account,
        mailbox=mailbox_name,
        uid=message_id,
        token=_json_text(values, "freshness"),
    )
    try:
        await _gateway(request).delete_message_permanently(account, mailbox_name, message_id)
    except Exception:
        return await _gateway_error(request, "Permanent message deletion failed")
    return _api_response(message="Message permanently deleted.")


async def api_message_reply(request: web.Request) -> web.Response:
    query = _read_query(
        request,
        allowed_fields=frozenset({"account", "mailbox", "mode"}),
    )
    account, mailbox_name = _mail_context(request, query)
    mode = query.get("mode", "reply")
    if mode not in {"reply", "reply_all"}:
        raise web.HTTPBadRequest(text="Reply mode is invalid.")
    async with _mail_work_slot(request):
        message = await _parsed_message(request, account, mailbox_name)
    principal = _principal(request)
    if account == principal.get("account_id"):
        self_address = str(principal.get("email", ""))
    else:
        try:
            accounts = _backend_sequence(
                await _gateway(request).list_accounts(),
                "account list",
            )
            matches = [
                _account_payload(value)
                for value in accounts
                if _account_payload(value)["id"] == account
            ]
        except Exception:
            return await _gateway_error(request, "Could not resolve reply identity")
        if len(matches) != 1:
            raise web.HTTPBadRequest(text="Reply identity is unavailable.")
        self_address = str(matches[0]["address"])
    try:
        recipients = derive_reply_recipients(
            message,
            self_address,
            reply_all=mode == "reply_all",
        )
        in_reply_to, references = reply_thread_headers(message)
        subject = reply_subject(message.subject)
    except MailError as exc:
        raise web.HTTPUnprocessableEntity(text="Reply metadata is invalid.") from exc
    quote_source = message.text.strip()
    quoted = "\n".join(f"> {line}" if line else ">" for line in quote_source.splitlines())
    if len(quoted) > 128 * 1024:
        quoted = quoted[: 128 * 1024]
    body = (
        f"\n\nOn {message.date or 'an earlier date'}, {message.sender or 'the sender'} wrote:\n"
        f"{quoted}"
    )
    return _api_response(
        data={
            "sender_account_id": account,
            "to": list(recipients.to),
            "cc": list(recipients.cc),
            "subject": subject,
            "text": body,
            "in_reply_to": in_reply_to,
            "references": list(references),
        }
    )


async def set_message_read_state(request: web.Request) -> web.Response:
    message_id = _message_uid(request.match_info["message_id"])
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"account", "mailbox", "freshness", "seen"}),
    )
    account, mailbox_name = _mail_context(request, values)
    seen = values.get("seen")
    if type(seen) is not bool:
        raise web.HTTPBadRequest(text="Seen state must be a boolean.")
    await _verify_message_freshness(
        request,
        account=account,
        mailbox=mailbox_name,
        uid=message_id,
        token=_json_text(values, "freshness"),
    )
    try:
        await _gateway(request).set_message_seen(
            account,
            mailbox_name,
            message_id,
            seen=seen,
        )
    except Exception:
        return await _gateway_error(request, "Could not update message read state")
    return _api_response(message="Message marked read." if seen else "Message marked unread.")


async def move_message_to_folder(request: web.Request) -> web.Response:
    message_id = _message_uid(request.match_info["message_id"])
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"account", "mailbox", "target_mailbox", "freshness"}),
    )
    account, mailbox_name = _mail_context(request, values)
    target = _mailbox_name(_json_text(values, "target_mailbox"))
    await _verify_message_freshness(
        request,
        account=account,
        mailbox=mailbox_name,
        uid=message_id,
        token=_json_text(values, "freshness"),
    )
    try:
        mailboxes = _backend_sequence(
            await _gateway(request).list_mailboxes(account),
            "mailbox list",
        )
        if target not in _mailbox_names(mailboxes):
            raise web.HTTPBadRequest(text="Target mailbox is not in the allowed list.")
        moved_to = await _gateway(request).move_message(
            account,
            mailbox_name,
            message_id,
            target,
        )
    except web.HTTPException:
        raise
    except Exception:
        return await _gateway_error(request, "Could not move message")
    return _api_response(
        data={"account": account, "mailbox": moved_to},
        message="Message moved.",
    )


async def create_mailbox(request: web.Request) -> web.Response:
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"account", "name"}),
    )
    account = _account_context(request, values)
    name = _mailbox_name(_json_text(values, "name"))
    try:
        await _gateway(request).create_mailbox(account, name)
    except Exception:
        return await _gateway_error(request, "Could not create mailbox")
    return _api_response(data={"name": name}, message="Folder created.", status=201)


async def rename_mailbox(request: web.Request) -> web.Response:
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"account", "old_name", "new_name"}),
    )
    account = _account_context(request, values)
    old_name = _mailbox_name(_json_text(values, "old_name"))
    new_name = _mailbox_name(_json_text(values, "new_name"))
    try:
        await _gateway(request).rename_mailbox(account, old_name, new_name)
    except Exception:
        return await _gateway_error(request, "Could not rename mailbox")
    return _api_response(data={"name": new_name}, message="Folder renamed.")


async def delete_named_mailbox(request: web.Request) -> web.Response:
    values = await _read_json_object(
        request,
        allowed_fields=frozenset({"account", "name", "confirmation"}),
    )
    account = _account_context(request, values)
    name = _mailbox_name(_json_text(values, "name"))
    if _json_text(values, "confirmation") != name:
        raise web.HTTPBadRequest(text="Folder confirmation does not match.")
    try:
        await _gateway(request).delete_named_mailbox(account, name)
    except Exception:
        return await _gateway_error(request, "Could not delete empty mailbox")
    return _api_response(message="Empty folder deleted.")


async def api_compose(request: web.Request) -> web.Response:
    _read_query(request, allowed_fields=frozenset())
    principal = _principal(request)
    if principal.get("role") == "admin":
        try:
            raw_account_values = await _gateway(request).list_accounts()
        except Exception:
            return await _gateway_error(request, "Could not read sending accounts")
        try:
            account_values = _backend_sequence(raw_account_values, "account list")
            senders = _sender_payloads(account_values)
        except TypeError, ValueError:
            LOGGER.error("account backend returned an invalid payload", exc_info=True)
            return _api_error(
                "invalid_backend_response",
                "Backend returned an invalid sending account list.",
                status=502,
            )
    else:
        senders = (
            {
                "id": _principal_account_id(request),
                "address": str(principal.get("email", "")),
            },
        )
    return _api_response(
        data={
            "senders": list(senders),
            "max_upload_bytes": _settings(request).max_upload_bytes,
        },
    )


def _enabled_senders(accounts_found: Sequence[object]) -> tuple[str, ...]:
    result: list[str] = []
    for account in _backend_sequence(accounts_found, "account list"):
        payload = _account_payload(account)
        if payload["has_credentials"] is not True:
            continue
        result.append(str(payload["address"]))
    return tuple(dict.fromkeys(result))


def _sender_payloads(accounts_found: Sequence[object]) -> tuple[dict[str, str], ...]:
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for account in _backend_sequence(accounts_found, "account list"):
        payload = _account_payload(account)
        if payload["has_credentials"] is not True:
            continue
        identifier = str(payload["id"])
        if identifier in seen:
            continue
        seen.add(identifier)
        result.append({"id": identifier, "address": str(payload["address"])})
    return tuple(result)


def _ensure_temp_directory(settings: WebSettings) -> None:
    settings.temp_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory_stat = settings.temp_dir.lstat()
    if stat.S_ISLNK(directory_stat.st_mode) or not stat.S_ISDIR(directory_stat.st_mode):
        raise RuntimeError("mail spool must be a regular non-symlink directory")
    if os.name == "posix" and directory_stat.st_uid != os.geteuid():
        raise RuntimeError("mail spool directory must be owned by the service user")
    try:
        os.chmod(settings.temp_dir, 0o700)
    except OSError:
        LOGGER.debug("unable to chmod upload spool directory", exc_info=True)


async def _spool_part(
    part: BodyPartReader,
    settings: WebSettings,
    *,
    total_so_far: int,
) -> UploadedFile:
    _ensure_temp_directory(settings)
    descriptor, raw_path = tempfile.mkstemp(
        prefix="upload-",
        suffix=".part",
        dir=settings.temp_dir,
    )
    path = Path(raw_path)
    size = 0
    try:
        try:
            os.chmod(path, 0o600)
        except OSError:
            LOGGER.debug("unable to chmod upload spool", exc_info=True)
        with os.fdopen(descriptor, "wb") as stream:
            while chunk := await part.read_chunk(size=64 * 1024):
                size += len(chunk)
                if size > MAX_ATTACHMENT_BYTES or total_so_far + size > settings.max_upload_bytes:
                    raise web.HTTPRequestEntityTooLarge(
                        max_size=settings.max_upload_bytes,
                        actual_size=total_so_far + size,
                    )
                stream.write(chunk)
        return UploadedFile(
            field_name=part.name or "",
            filename=safe_filename(part.filename),
            path=path,
            content_type=(part.headers.get("Content-Type") or "application/octet-stream").lower(),
            size=size,
        )
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        await asyncio.to_thread(path.unlink, missing_ok=True)
        raise


async def _read_multipart_impl(
    request: web.Request,
    *,
    scalar_fields: frozenset[str],
    file_fields: frozenset[str],
    scalar_limits: Mapping[str, int],
    repeatable_scalar_fields: frozenset[str] = frozenset(),
) -> tuple[dict[str, list[str]], dict[str, list[UploadedFile]]]:
    if not request.content_type.startswith("multipart/"):
        raise web.HTTPUnsupportedMediaType(text="This operation requires multipart/form-data.")
    reader = await request.multipart()
    scalars: dict[str, list[str]] = {}
    files: dict[str, list[UploadedFile]] = {}
    created: list[UploadedFile] = []
    total = 0
    part_count = 0
    try:
        while part := await reader.next():
            part_count += 1
            if part_count > 80:
                raise web.HTTPBadRequest(text="Too many form fields.")
            name = part.name or ""
            if part.filename is None:
                if name not in scalar_fields:
                    raise web.HTTPBadRequest(text="Form contains an unknown field.")
                if name in scalars and name not in repeatable_scalar_fields:
                    raise web.HTTPBadRequest(text=f"Field {name} must not be repeated.")
                maximum = scalar_limits.get(name)
                if maximum is None or maximum <= 0:
                    raise web.HTTPBadRequest(text="Form field lacks a safe size limit.")
                remaining = _settings(request).max_upload_bytes - total
                if remaining <= 0:
                    raise web.HTTPRequestEntityTooLarge(
                        max_size=_settings(request).max_upload_bytes,
                        actual_size=total + 1,
                    )
                value, size = await _read_scalar_part(part, maximum=min(maximum, remaining))
                total += size
                scalars.setdefault(name, []).append(value)
                continue
            if name not in file_fields:
                raise web.HTTPBadRequest(text="Form contains an unknown upload field.")
            if not part.filename:
                await part.release()
                continue
            uploaded = await _spool_part(part, _settings(request), total_so_far=total)
            total += uploaded.size
            created.append(uploaded)
            files.setdefault(name, []).append(uploaded)
        return scalars, files
    except BaseException:
        for uploaded in created:
            uploaded.cleanup()
        raise


async def _read_multipart(
    request: web.Request,
    *,
    scalar_fields: frozenset[str],
    file_fields: frozenset[str],
    scalar_limits: Mapping[str, int],
    repeatable_scalar_fields: frozenset[str] = frozenset(),
) -> tuple[dict[str, list[str]], dict[str, list[UploadedFile]]]:
    try:
        async with asyncio.timeout(_settings(request).request_body_timeout_seconds):
            return await _read_multipart_impl(
                request,
                scalar_fields=scalar_fields,
                file_fields=file_fields,
                scalar_limits=scalar_limits,
                repeatable_scalar_fields=repeatable_scalar_fields,
            )
    except TimeoutError as exc:
        raise web.HTTPRequestTimeout(text="Timed out while reading the upload.") from exc


async def _read_scalar_part(part: BodyPartReader, *, maximum: int) -> tuple[str, int]:
    content = bytearray()
    while chunk := await part.read_chunk(size=64 * 1024):
        content.extend(chunk)
        if len(content) > maximum:
            raise web.HTTPRequestEntityTooLarge(
                max_size=maximum,
                actual_size=len(content),
            )
    try:
        return bytes(content).decode(part.get_charset(default="utf-8"), "strict"), len(content)
    except (LookupError, UnicodeError) as exc:
        raise web.HTTPBadRequest(text="Form field is not valid text.") from exc


def _one(values: Mapping[str, list[str]], name: str, *, default: str = "") -> str:
    items = values.get(name, [])
    if len(items) > 1:
        raise web.HTTPBadRequest(text=f"Field {name} must not be repeated.")
    return items[0] if items else default


def _split_addresses(value: str) -> tuple[str, ...]:
    value = value.replace("\uff0c", ",").replace("\uff1b", ",").replace(";", ",")
    return (value,) if value.strip() else ()


def _detect_image_type(upload: UploadedFile) -> str:
    with upload.path.open("rb") as stream:
        start = stream.read(16)
    if start.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if start.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if start.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if start.startswith(b"RIFF") and start[8:12] == b"WEBP":
        return "image/webp"
    raise web.HTTPBadRequest(text="Invalid inline image format.")


async def send_message(request: web.Request) -> web.Response:
    if request.query:
        raise web.HTTPBadRequest(text="This operation does not accept query parameters.")
    scalars: dict[str, list[str]] = {}
    files: dict[str, list[UploadedFile]] = {}
    uploads: list[UploadedFile] = []
    submission_password = ""
    try:
        scalars, files = await _read_multipart(
            request,
            scalar_fields=frozenset(
                {
                    "sender",
                    "sender_account_id",
                    "sender_name",
                    "password",
                    "to",
                    "cc",
                    "bcc",
                    "subject",
                    "text",
                    "html",
                    "inline_cids",
                    "in_reply_to",
                    "references",
                }
            ),
            file_fields=frozenset({"attachments", "inline_images"}),
            scalar_limits={
                "sender": 1024,
                "sender_account_id": 128,
                "sender_name": 1024,
                "password": 4096,
                "to": 16 * 1024,
                "cc": 16 * 1024,
                "bcc": 16 * 1024,
                "subject": 4096,
                "text": 2 * 1024 * 1024,
                "html": 2 * 1024 * 1024,
                "inline_cids": 512,
                "in_reply_to": 1024,
                "references": 16 * 1024,
            },
            repeatable_scalar_fields=frozenset({"inline_cids"}),
        )
        uploads = [item for group in files.values() for item in group]
        inline_files = files.get("inline_images", [])
        inline_cids = scalars.get("inline_cids", [])
        if len(inline_files) != len(inline_cids):
            raise web.HTTPBadRequest(text="Inline image does not match its CID.")
        inline_images = tuple(
            Attachment(
                filename=upload.filename,
                data=upload.path,
                content_type=_detect_image_type(upload),
                content_id=cid,
                declared_size=upload.size,
            )
            for upload, cid in zip(inline_files, inline_cids, strict=True)
        )
        attachments = tuple(
            Attachment(
                filename=upload.filename,
                data=upload.path,
                content_type=upload.content_type,
                declared_size=upload.size,
            )
            for upload in files.get("attachments", [])
        )
        principal = _principal(request)
        selected_account_id = _one(scalars, "sender_account_id")
        submitted_sender = _one(scalars, "sender")
        if principal.get("role") == "admin":
            try:
                sender_records = _sender_payloads(await _gateway(request).list_accounts())
            except Exception:
                return await _gateway_error(request, "Could not validate sending account")
            sender_by_id = {value["id"]: value["address"] for value in sender_records}
            if not selected_account_id and submitted_sender:
                matching_ids = [
                    identifier
                    for identifier, address in sender_by_id.items()
                    if address == submitted_sender
                ]
                selected_account_id = matching_ids[0] if len(matching_ids) == 1 else ""
            sender = sender_by_id.get(selected_account_id, "")
            if not sender:
                raise web.HTTPForbidden(text="Sender is not an enabled account.")
        else:
            selected_account_id = _principal_account_id(request)
            sender = str(principal.get("email", ""))
            if _one(scalars, "sender_account_id") not in {"", selected_account_id}:
                raise web.HTTPForbidden(text="Cross-account sending is forbidden.")
            if submitted_sender not in {"", sender}:
                raise web.HTTPForbidden(text="Cross-account sending is forbidden.")
        submission_password = _one(scalars, "password")
        if (
            not submission_password
            or len(submission_password) > 1024
            or any(character in submission_password for character in "\r\n\0")
        ):
            raise web.HTTPBadRequest(text="Invalid sending account password.")
        html_body = _one(scalars, "html").strip()
        outgoing = OutgoingMessage(
            sender=sender,
            sender_name=_one(scalars, "sender_name"),
            to=_split_addresses(_one(scalars, "to")),
            cc=_split_addresses(_one(scalars, "cc")),
            bcc=_split_addresses(_one(scalars, "bcc")),
            subject=_one(scalars, "subject"),
            text=_one(scalars, "text"),
            html=html_body or None,
            inline_images=inline_images,
            attachments=attachments,
            in_reply_to=_one(scalars, "in_reply_to"),
            references=tuple(_one(scalars, "references").split()),
        )
        _ensure_temp_directory(_settings(request))
        try:
            async with _mail_work_slot(request):
                auth_token = request.get(_AUTH_TOKEN_KEY)
                if not isinstance(auth_token, str):
                    raise web.HTTPUnauthorized(text="Authentication is required.")
                with bind_helper_identity(
                    auth_token,
                    target_account_id=selected_account_id,
                ):
                    result: DeliveryResult = await deliver_and_save(
                        _gateway(request),
                        outgoing,
                        submission_password=submission_password,
                        spool_directory=_settings(request).temp_dir,
                    )
            submission_password = ""
        except MailError as exc:
            LOGGER.info("invalid outgoing message: %s", exc)
            public_message = (
                exc.public_message
                if isinstance(exc, MailValidationError)
                else "Recipients, body, or attachments violate a safety limit."
            )
            return _api_error(
                "invalid_message",
                public_message,
                status=400,
            )
        if result.delivered and result.saved_to_sent:
            return _api_response(
                data={"delivered": True, "saved_to_sent": True},
                message=(
                    "Maddy accepted the message for delivery and saved it to Sent. Remote inbox "
                    "placement is not confirmed here."
                ),
            )
        if result.delivered:
            return _api_response(
                data={"delivered": True, "saved_to_sent": False},
                message=(
                    "Maddy accepted the message for delivery, but MaddyWeb could not confirm that "
                    "it was saved to Sent; do not resend."
                ),
                status=202,
            )
        error_code = "message_not_delivered" if result.retry_delivery else "delivery_unconfirmed"
        return _api_error(
            error_code,
            _public_error_message(result.error, "Message delivery failed."),
            status=502,
        )
    finally:
        password_values = scalars.get("password", [])
        for index in range(len(password_values)):
            password_values[index] = ""
        submission_password = ""
        for upload in uploads:
            upload.cleanup()


def _certificate_payload(certificate: object) -> dict[str, object]:
    name = _record_value(certificate, "name", "domain", "id")
    if not isinstance(name, str) or not _valid_certificate_name(name):
        raise TypeError("certificate status contains an invalid name")
    expires = _backend_optional_text(
        _record_value(certificate, "expires", "not_after", default=""),
        "certificate expiration",
    )
    source_fingerprint = _backend_optional_text(
        _record_value(certificate, "source_fingerprint", default=""),
        "source certificate fingerprint",
    )
    deployed_fingerprint = _backend_optional_text(
        _record_value(certificate, "deployed_fingerprint", default=""),
        "deployed certificate fingerprint",
    )
    matches = _record_value(
        certificate,
        "fingerprints_match",
        "matches",
        default=bool(source_fingerprint) and source_fingerprint == deployed_fingerprint,
    )
    automation_safe = _record_value(certificate, "automation_safe", default=False)
    if type(matches) is not bool or type(automation_safe) is not bool:
        raise TypeError("certificate status flags must be booleans")
    return {
        "name": name,
        "expires": expires,
        "source_fingerprint": source_fingerprint,
        "deployed_fingerprint": deployed_fingerprint,
        "fingerprints_match": matches,
        "automation_safe": automation_safe,
    }


async def api_certificates(request: web.Request) -> web.Response:
    _require_admin(request)
    _read_query(request, allowed_fields=frozenset())
    try:
        status = await _gateway(request).certificate_status()
    except Exception:
        return await _gateway_error(request, "Could not read certificates")
    try:
        if isinstance(status, Mapping):
            certificates_found = _backend_sequence(
                status.get("certificates", ()),
                "certificate list",
            )
            timer_enabled = status.get("timer_enabled", False)
            timer_active = status.get("timer_active", timer_enabled)
            timer_enable_safe = status.get("timer_enable_safe", False)
            if (
                type(timer_enabled) is not bool
                or type(timer_active) is not bool
                or type(timer_enable_safe) is not bool
            ):
                raise TypeError("certificate timer flags must be booleans")
            timer_state_value = status.get(
                "timer_state",
                "Enabled" if timer_enabled else "Disabled",
            )
            if not isinstance(timer_state_value, str):
                raise TypeError("certificate timer state must be text")
            timer_state = timer_state_value
        else:
            certificates_found = _backend_sequence(status, "certificate list")
            timer_enabled = False
            timer_active = False
            timer_state = "Unknown"
            timer_enable_safe = False
        certificates = [_certificate_payload(certificate) for certificate in certificates_found]
    except TypeError, ValueError:
        LOGGER.error("certificate backend returned an invalid payload", exc_info=True)
        return _api_error(
            "invalid_backend_response",
            "Backend returned an invalid certificate status.",
            status=502,
        )
    return _api_response(
        data={
            "timer_enabled": timer_enabled,
            "timer_active": timer_active,
            "timer_state": timer_state,
            "timer_enable_safe": timer_enable_safe,
            "certificates": certificates,
        }
    )


async def set_certificate_timer(request: web.Request) -> web.Response:
    _require_admin(request)
    values = await _read_json_object(request, allowed_fields=frozenset({"action"}))
    action = _json_text(values, "action")
    if action not in {"enable", "disable"}:
        raise web.HTTPBadRequest(text="Invalid timer action.")
    try:
        await _gateway(request).set_certificate_timer(action == "enable")
    except Exception:
        return await _gateway_error(request, "Renewal timer operation failed")
    message = (
        "Automatic renewal timer enabled."
        if action == "enable"
        else "Automatic renewal timer disabled."
    )
    return _api_response(message=message)


async def certificate_dry_run(request: web.Request) -> web.Response:
    _require_admin(request)
    certificate_name = await _allowed_certificate_name(request)
    try:
        await _gateway(request).certificate_dry_run(certificate_name)
    except Exception:
        return await _gateway_error(request, "Certificate renewal dry-run failed")
    return _api_response(message="Certificate renewal dry-run succeeded.")


async def renew_certificate_if_due(request: web.Request) -> web.Response:
    _require_admin(request)
    certificate_name = await _allowed_certificate_name(request)
    try:
        await _gateway(request).renew_certificate_if_due(certificate_name)
    except Exception:
        return await _gateway_error(request, "Certificate renewal-if-due failed")
    return _api_response(message="Due check and any required renewal completed.")


async def _allowed_certificate_name(request: web.Request) -> str:
    values = await _read_json_object(request, allowed_fields=frozenset({"name"}))
    name = _json_text(values, "name")
    if not _valid_certificate_name(name):
        raise web.HTTPBadRequest(text="Invalid certificate name.")
    try:
        status = await _gateway(request).certificate_status()
    except Exception as exc:
        LOGGER.exception("failed to load certificate allowlist")
        raise web.HTTPBadGateway(text="Could not read certificate allowlist.") from exc
    if not isinstance(status, Mapping):
        raise web.HTTPBadGateway(text="Invalid certificate status format.")
    certificate_values = status.get("certificates", ())
    if not isinstance(certificate_values, Sequence) or isinstance(
        certificate_values,
        (str, bytes, bytearray),
    ):
        raise web.HTTPBadGateway(text="Invalid certificate allowlist format.")
    try:
        allowed_names = {str(_certificate_payload(item)["name"]) for item in certificate_values}
    except (TypeError, ValueError) as exc:
        raise web.HTTPBadGateway(text="Invalid certificate allowlist format.") from exc
    if name not in allowed_names:
        raise web.HTTPBadRequest(text="Certificate name is not allowed.")
    return name


@cache
def _static_body(name: str) -> bytes:
    path = Path(__file__).with_name("static") / name
    try:
        return path.read_bytes()
    except OSError as exc:
        raise web.HTTPNotFound() from exc


async def app_shell(_request: web.Request) -> web.Response:
    return web.Response(
        body=_static_body("index.html"),
        content_type="text/html",
        charset="utf-8",
        headers={"Cache-Control": "no-store"},
    )


async def login_shell(_request: web.Request) -> web.Response:
    return web.Response(
        body=_static_body("login.html"),
        content_type="text/html",
        charset="utf-8",
        headers={"Cache-Control": "no-store"},
    )


async def static_asset(request: web.Request) -> web.Response:
    name = request.match_info["name"]
    content_types = {
        "app.css": "text/css",
        "app.js": "application/javascript",
        "preview.css": "text/css",
        "login.css": "text/css",
        "login.js": "application/javascript",
    }
    content_type = content_types.get(name)
    if content_type is None:
        raise web.HTTPNotFound()
    cache_control = (
        "public, max-age=3600" if name in {"login.css", "login.js"} else "private, no-store"
    )
    return web.Response(
        body=_static_body(name),
        content_type=content_type,
        charset="utf-8",
        headers={
            "Cache-Control": cache_control,
            "X-Content-Type-Options": "nosniff",
        },
    )


async def not_found(request: web.Request) -> web.Response:
    if request.method in {"GET", "HEAD"} and _is_spa_path(request.path):
        return await app_shell(request)
    if request.path.startswith("/api/"):
        return _api_error("not_found", "The endpoint does not exist.", status=404)
    return web.Response(status=404, text="The page does not exist.")


def _is_spa_path(path: str) -> bool:
    if path in _SPA_PATHS:
        return True
    match = _SPA_MAIL_PATH_RE.fullmatch(path)
    if match is None:
        return False
    try:
        _normalized_message_uid(match.group(1))
    except ValueError:
        return False
    return True


def create_app(config: object, gateway: Gateway) -> web.Application:
    """Create the bounded aiohttp application without importing privileged helpers."""

    allowed_hosts = tuple(
        str(value)
        for value in _config_value(
            config,
            "server.allowed_hosts",
            ("127.0.0.1", "localhost"),
        )
    )
    max_upload = int(_config_value(config, "server.max_upload_bytes", 20 * 1024 * 1024))
    request_body_timeout = float(_config_value(config, "server.request_body_timeout_seconds", 15.0))
    concurrency = int(_config_value(config, "server.concurrency", 8))
    page_size = int(_config_value(config, "server.page_size", 50))
    temp_dir = Path(
        _config_value(
            config,
            "server.temp_dir",
            Path(tempfile.gettempdir()) / "maddyweb",
        )
    )
    csrf_ttl = int(_config_value(config, "security.csrf_ttl_seconds", 900))
    csrf_cookie_name = str(
        _config_value(
            config,
            "security.csrf_cookie_name",
            _config_value(config, "security.cookie_name", "__Host-maddyweb-csrf"),
        )
    )
    session_cookie_name = str(
        _config_value(
            config,
            "security.session_cookie_name",
            "__Host-maddyweb-session",
        )
    )
    secure_cookies = bool(_config_value(config, "security.secure_cookies", True))
    public_origin = str(_config_value(config, "security.public_origin", ""))
    totp_issuer = str(_config_value(config, "security.totp_issuer", "MaddyWeb"))
    configured_origins = tuple(
        str(value) for value in _config_value(config, "security.public_origins", ())
    )
    public_origins = (public_origin,) if public_origin else configured_origins
    signing_key = _session_key(config)

    browser_security = SecurityConfig(
        allowed_hosts=allowed_hosts,
        session_signing_key=signing_key,
        public_origins=public_origins,
        secure_cookies=secure_cookies,
        csrf_cookie_name=csrf_cookie_name,
        csrf_max_age=csrf_ttl,
        request_body_timeout_seconds=request_body_timeout,
    )
    settings = WebSettings(
        page_size=page_size,
        max_upload_bytes=max_upload,
        request_body_timeout_seconds=request_body_timeout,
        temp_dir=temp_dir,
    )
    app = web.Application(
        middlewares=[
            security_headers_middleware(browser_security),
            bounded_concurrency_middleware(concurrency),
            _authentication_middleware(),
            security_middleware(
                browser_security,
                scope_resolver=_csrf_scope,
            ),
        ],
        client_max_size=max_upload,
        handler_args={
            "max_line_size": 8190,
            "max_field_size": 8190,
        },
    )
    app[_GATEWAY_KEY] = gateway
    app[_SETTINGS_KEY] = settings
    app[_MAIL_WORK_KEY] = asyncio.Semaphore(2)
    app[_MAIL_CURSOR_KEY] = _MailboxCursorStore(ttl_seconds=csrf_ttl)
    app[_FRESHNESS_KEY] = _FreshnessStore(ttl_seconds=csrf_ttl)
    app[_SESSION_COOKIE_KEY] = session_cookie_name
    app[_PUBLIC_ORIGIN_KEY] = public_origin
    app[_SECURE_COOKIE_KEY] = secure_cookies
    app[_TOTP_ISSUER_KEY] = totp_issuer
    app.add_routes(
        [
            web.get("/", app_shell),
            web.get("/login", login_shell),
            web.get("/healthz", healthz),
            web.get("/api/v1/health", api_health),
            web.get("/api/v1/session", api_session),
            web.get("/api/v1/auth/csrf", api_auth_csrf),
            web.post("/api/v1/auth/password", api_auth_password),
            web.post("/api/v1/auth/enrollment", api_auth_enrollment),
            web.post(
                "/api/v1/auth/enrollment/confirm",
                api_auth_enrollment_confirm,
            ),
            web.post("/api/v1/auth/totp", api_auth_totp),
            web.post("/api/v1/auth/recovery", api_auth_recovery),
            web.get("/api/v1/auth/session", api_auth_session),
            web.post("/api/v1/auth/logout", api_auth_logout),
            web.post(
                "/api/v1/auth/password/change",
                api_auth_change_password,
            ),
            web.post(
                "/api/v1/auth/recovery-codes/regenerate",
                api_auth_recovery_regenerate,
            ),
            web.post("/api/v1/auth/step-up", api_auth_step_up),
            web.get("/api/v1/accounts", api_accounts),
            web.post("/api/v1/accounts", create_account),
            web.post("/api/v1/accounts/{account_id}/password", change_password),
            web.post("/api/v1/accounts/{account_id}/append-limit", set_append_limit),
            web.post(
                "/api/v1/accounts/{account_id}/credentials/disable",
                disable_credentials,
            ),
            web.post("/api/v1/accounts/{account_id}/delete", delete_mailbox),
            web.get("/api/v1/mail", api_mailbox),
            web.get("/api/v1/mail/{message_id}/html", message_html),
            web.get("/api/v1/mail/{message_id}/inline/{attachment_id}", inline_image),
            web.get(
                "/api/v1/mail/{message_id}/attachments/{attachment_id}",
                download_attachment,
            ),
            web.get("/api/v1/mail/{message_id}/raw", raw_message),
            web.get(
                "/api/v1/mail/{message_id}/action-snapshot",
                api_message_action_snapshot,
            ),
            web.post("/api/v1/mail/{message_id}/trash", move_message_to_trash),
            web.post("/api/v1/mail/{message_id}/archive", move_message_to_archive),
            web.post("/api/v1/mail/{message_id}/delete", delete_message_permanently),
            web.get("/api/v1/mail/{message_id}", api_message_detail),
            web.get("/api/v1/compose", api_compose),
            web.post("/api/v1/send", send_message),
            web.get("/api/v1/certificates", api_certificates),
            web.post("/api/v1/certificates/timer", set_certificate_timer),
            web.post("/api/v1/certificates/dry-run", certificate_dry_run),
            web.post(
                "/api/v1/certificates/renew-if-due",
                renew_certificate_if_due,
            ),
            web.get("/api/v1/me/mail", api_mailbox),
            web.get("/api/v1/me/mail/{message_id}/html", message_html),
            web.get(
                "/api/v1/me/mail/{message_id}/inline/{attachment_id}",
                inline_image,
            ),
            web.get(
                "/api/v1/me/mail/{message_id}/attachments/{attachment_id}",
                download_attachment,
            ),
            web.get("/api/v1/me/mail/{message_id}/raw", raw_message),
            web.get(
                "/api/v1/me/mail/{message_id}/action-snapshot",
                api_message_action_snapshot,
            ),
            web.get("/api/v1/me/mail/{message_id}/reply", api_message_reply),
            web.post(
                "/api/v1/me/mail/{message_id}/read-state",
                set_message_read_state,
            ),
            web.post("/api/v1/me/mail/{message_id}/move", move_message_to_folder),
            web.post("/api/v1/me/mail/{message_id}/trash", move_message_to_trash),
            web.post("/api/v1/me/mail/{message_id}/archive", move_message_to_archive),
            web.post("/api/v1/me/mail/{message_id}/delete", delete_message_permanently),
            web.get("/api/v1/me/mail/{message_id}", api_message_detail),
            web.post("/api/v1/me/mailboxes", create_mailbox),
            web.post("/api/v1/me/mailboxes/rename", rename_mailbox),
            web.post("/api/v1/me/mailboxes/delete", delete_named_mailbox),
            web.get("/api/v1/me/compose", api_compose),
            web.post("/api/v1/me/send", send_message),
            web.get("/api/v1/admin/accounts", api_accounts),
            web.post("/api/v1/admin/accounts", create_account),
            web.post(
                "/api/v1/admin/accounts/{account_id}/password",
                change_password,
            ),
            web.post(
                "/api/v1/admin/accounts/{account_id}/append-limit",
                set_append_limit,
            ),
            web.post(
                "/api/v1/admin/accounts/{account_id}/credentials/disable",
                disable_credentials,
            ),
            web.post(
                "/api/v1/admin/accounts/{account_id}/delete",
                delete_mailbox,
            ),
            web.post(
                "/api/v1/admin/accounts/{account_id}/totp/reset",
                reset_account_totp,
            ),
            web.get("/api/v1/admin/mail", api_mailbox),
            web.get("/api/v1/admin/mail/{message_id}/html", message_html),
            web.get(
                "/api/v1/admin/mail/{message_id}/inline/{attachment_id}",
                inline_image,
            ),
            web.get(
                "/api/v1/admin/mail/{message_id}/attachments/{attachment_id}",
                download_attachment,
            ),
            web.get("/api/v1/admin/mail/{message_id}/raw", raw_message),
            web.get(
                "/api/v1/admin/mail/{message_id}/action-snapshot",
                api_message_action_snapshot,
            ),
            web.get("/api/v1/admin/mail/{message_id}/reply", api_message_reply),
            web.post(
                "/api/v1/admin/mail/{message_id}/read-state",
                set_message_read_state,
            ),
            web.post(
                "/api/v1/admin/mail/{message_id}/move",
                move_message_to_folder,
            ),
            web.post(
                "/api/v1/admin/mail/{message_id}/trash",
                move_message_to_trash,
            ),
            web.post(
                "/api/v1/admin/mail/{message_id}/archive",
                move_message_to_archive,
            ),
            web.post(
                "/api/v1/admin/mail/{message_id}/delete",
                delete_message_permanently,
            ),
            web.get("/api/v1/admin/mail/{message_id}", api_message_detail),
            web.post("/api/v1/admin/mailboxes", create_mailbox),
            web.post("/api/v1/admin/mailboxes/rename", rename_mailbox),
            web.post("/api/v1/admin/mailboxes/delete", delete_named_mailbox),
            web.get("/api/v1/admin/compose", api_compose),
            web.post("/api/v1/admin/send", send_message),
            web.get("/api/v1/admin/certificates", api_certificates),
            web.post(
                "/api/v1/admin/certificates/timer",
                set_certificate_timer,
            ),
            web.post(
                "/api/v1/admin/certificates/dry-run",
                certificate_dry_run,
            ),
            web.post(
                "/api/v1/admin/certificates/renew-if-due",
                renew_certificate_if_due,
            ),
            web.get("/static/{name}", static_asset),
            web.route("*", "/{tail:.*}", not_found),
        ]
    )
    return app


__all__ = ["Gateway", "MessagePage", "WebSettings", "create_app"]
