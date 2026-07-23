"""HTTP security primitives for the local administration interface.

The web application deliberately has no CORS mode.  Browser state-changing
requests must pass three independent checks: an allow-listed ``Host`` header,
an exact same-origin check, and a CSRF token stored in a SameSite cookie.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urlsplit

from aiohttp import web

SAFE_METHODS: Final = frozenset({"GET", "HEAD"})
DEFAULT_CSP: Final = (
    "default-src 'none'; "
    "base-uri 'none'; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "frame-src 'self' blob:; "
    "img-src 'self' blob:; "
    "object-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'"
)

_CSRF_REQUEST_KEY: Final = web.RequestKey("maddyweb.csrf_token", str)
_API_ERROR_CODES: Final = {
    400: "invalid_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    408: "request_timeout",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "unprocessable_entity",
    429: "too_many_requests",
    500: "internal_error",
    502: "backend_failure",
    503: "service_unavailable",
}
_API_ERROR_MESSAGES: Final = {
    400: "The request is invalid.",
    401: "Authentication is required.",
    403: "The request is forbidden.",
    404: "The endpoint does not exist.",
    405: "This request method is not supported.",
    408: "Timed out while reading the request.",
    409: "The request conflicts with current state.",
    413: "The request body is too large.",
    415: "The request content type is not supported.",
    422: "The request could not be processed.",
    429: "The server is busy; try again later.",
    500: "The request failed unexpectedly.",
    502: "A backend service failed.",
    503: "The service is temporarily unavailable.",
}
_FORWARDED_ERROR_HEADERS: Final = frozenset({"allow", "retry-after"})


def _contains_forbidden_header_characters(value: str) -> bool:
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)


def _is_api_path(path: str) -> bool:
    return path.startswith("/api/")


def _safe_error_message(value: object, *, status: int) -> str:
    fallback = _API_ERROR_MESSAGES.get(status, "The request failed.")
    if not isinstance(value, str):
        return fallback
    value = value.strip()
    if not value or len(value) > 512 or _contains_forbidden_header_characters(value):
        return fallback
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return fallback
    return value


def _error_response(
    request: web.Request,
    *,
    status: int,
    code: str,
    message: str,
    headers: Mapping[str, str] | None = None,
) -> web.Response:
    if _is_api_path(request.path):
        body = json.dumps(
            {
                "api_version": "v1",
                "ok": False,
                "error": {
                    "code": code,
                    "message": _safe_error_message(message, status=status),
                },
            },
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        response = web.Response(
            status=status,
            body=body,
            content_type="application/json",
        )
    else:
        response = web.Response(status=status, text=message)
    if headers is not None:
        for name, value in headers.items():
            if name.lower() in _FORWARDED_ERROR_HEADERS:
                response.headers[name] = value
    return response


def normalize_authority(value: str) -> tuple[str, int | None]:
    """Return a normalized ``(hostname, port)`` pair or reject the authority.

    User information, wildcards and control characters are never accepted.
    A configured hostname without a port intentionally matches that hostname on
    any port, which permits a fixed host policy with an ephemeral test/dev port.
    """

    value = value.strip()
    if not value or _contains_forbidden_header_characters(value) or "*" in value:
        raise ValueError("invalid authority")
    try:
        parsed = urlsplit(f"//{value}")
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid authority") from exc
    if (
        not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid authority")
    try:
        hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("invalid hostname") from exc
    return hostname, port


def normalize_origin(value: str) -> str:
    """Normalize an HTTP(S) origin while rejecting credentials and paths."""

    value = value.strip()
    if not value or _contains_forbidden_header_characters(value):
        raise ValueError("invalid origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid origin") from exc
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid origin")
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    default_port = 80 if parsed.scheme.lower() == "http" else 443
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != default_port:
        authority = f"{authority}:{port}"
    return f"{parsed.scheme.lower()}://{authority}"


@dataclass(frozen=True, slots=True)
class SecurityConfig:
    """Immutable browser-facing security policy."""

    allowed_hosts: tuple[str, ...]
    session_signing_key: bytes
    public_origins: tuple[str, ...] = ()
    secure_cookies: bool = True
    csrf_cookie_name: str = "__Host-maddyweb-csrf"
    csrf_max_age: int = 8 * 60 * 60
    request_body_timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        if not self.allowed_hosts:
            raise ValueError("allowed_hosts must not be empty")
        if (
            not isinstance(self.session_signing_key, bytes)
            or not 32 <= len(self.session_signing_key) <= 128
        ):
            raise ValueError("session_signing_key must contain 32 to 128 bytes")
        if not 0 < self.request_body_timeout_seconds <= 120:
            raise ValueError("request_body_timeout_seconds must be between 0 and 120")
        for authority in self.allowed_hosts:
            normalize_authority(authority)
        for origin in self.public_origins:
            normalize_origin(origin)
        if self.csrf_max_age <= 0:
            raise ValueError("csrf_max_age must be positive")
        if not self.csrf_cookie_name or any(char in self.csrf_cookie_name for char in "\r\n;= \t"):
            raise ValueError("invalid CSRF cookie name")
        if self.csrf_cookie_name.startswith("__Host-") and not self.secure_cookies:
            raise ValueError("__Host- cookies require secure_cookies=True")

    @property
    def normalized_hosts(self) -> tuple[tuple[str, int | None], ...]:
        return tuple(normalize_authority(value) for value in self.allowed_hosts)

    @property
    def normalized_origins(self) -> frozenset[str]:
        return frozenset(normalize_origin(value) for value in self.public_origins)


def host_is_allowed(host_header: str, allowed_hosts: Iterable[str]) -> bool:
    """Check an exact hostname/optional-port allow-list."""

    try:
        actual_host, actual_port = normalize_authority(host_header)
    except ValueError:
        return False
    for configured in allowed_hosts:
        try:
            expected_host, expected_port = normalize_authority(configured)
        except ValueError:
            continue
        if actual_host == expected_host and (expected_port is None or expected_port == actual_port):
            return True
    return False


def origin_is_allowed(origin_header: str, request: web.Request, config: SecurityConfig) -> bool:
    """Check ``Origin`` against configured public origins or this request."""

    if origin_header == "null":
        return False
    try:
        actual = normalize_origin(origin_header)
    except ValueError:
        return False
    configured = config.normalized_origins
    if configured:
        return actual in configured
    try:
        expected = normalize_origin(f"{request.scheme}://{request.host}")
    except ValueError:
        return False
    return hmac.compare_digest(actual, expected)


def referer_is_allowed(referer_header: str, request: web.Request, config: SecurityConfig) -> bool:
    """Apply the same exact-origin policy to a full Referer URL."""

    try:
        parsed = urlsplit(referer_header)
        if not parsed.scheme or not parsed.netloc:
            return False
        referer_origin = normalize_origin(f"{parsed.scheme}://{parsed.netloc}")
    except ValueError:
        return False
    configured = config.normalized_origins
    if configured:
        return referer_origin in configured
    try:
        expected = normalize_origin(f"{request.scheme}://{request.host}")
    except ValueError:
        return False
    return hmac.compare_digest(referer_origin, expected)


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _csrf_signature(key: bytes, payload: str) -> str:
    return _b64encode(hmac.new(key, payload.encode("ascii"), hashlib.sha256).digest())


def new_csrf_token(key: bytes, *, now: int | None = None) -> str:
    """Create a signed token containing version, issued-at and random nonce."""

    issued_at = int(time.time()) if now is None else now
    nonce = secrets.token_urlsafe(24)
    payload = f"v1.{issued_at}.{nonce}"
    return f"{payload}.{_csrf_signature(key, payload)}"


def verify_csrf_token(
    token: str,
    key: bytes,
    *,
    max_age: int,
    now: int | None = None,
) -> tuple[str, int] | None:
    """Return ``(nonce, issued_at)`` for an authentic, unexpired token."""

    if len(token) > 256 or _contains_forbidden_header_characters(token):
        return None
    try:
        version, issued_text, nonce, signature = token.split(".", 3)
        issued_at = int(issued_text)
    except TypeError, ValueError:
        return None
    if version != "v1" or not nonce or len(nonce) > 64:
        return None
    current = int(time.time()) if now is None else now
    if issued_at > current + 60 or current - issued_at > max_age:
        return None
    payload = f"{version}.{issued_at}.{nonce}"
    if not hmac.compare_digest(signature, _csrf_signature(key, payload)):
        return None
    return nonce, issued_at


def csrf_token_for_request(request: web.Request) -> str:
    """Return the token prepared by :func:`security_middleware`."""

    token = request.get(_CSRF_REQUEST_KEY)
    if not isinstance(token, str):
        raise RuntimeError("security middleware is not installed")
    return token


async def _submitted_csrf_token(
    request: web.Request,
    *,
    timeout_seconds: float,
) -> str | None:
    header_tokens = request.headers.getall("X-CSRF-Token", [])
    if len(header_tokens) > 1:
        return None
    header_token = header_tokens[0] if header_tokens else None
    if header_token:
        return header_token
    if request.content_type == "application/x-www-form-urlencoded":
        try:
            async with asyncio.timeout(timeout_seconds):
                form = await request.post()
        except TimeoutError as exc:
            raise web.HTTPRequestTimeout(text="Timed out while reading the request body.") from exc
        form_tokens = form.getall("_csrf", [])
        if len(form_tokens) == 1 and isinstance(form_tokens[0], str):
            return form_tokens[0]
    # Multipart bodies can contain tens of MiB.  They are streamed exactly once
    # by the route into the configured private spool, so multipart submissions
    # must present the current session token in this same-origin header.
    return None


def _apply_security_headers(response: web.StreamResponse) -> None:
    response.headers.setdefault("Content-Security-Policy", DEFAULT_CSP)
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    # Chromium serializes a same-origin HTML form POST with an opaque
    # ``Origin: null`` under a global ``no-referrer`` policy.  That makes the
    # fail-closed Origin gate reject every ordinary form.  ``same-origin``
    # preserves the local origin for writes while still withholding referrers
    # from every cross-origin destination.  Mail HTML keeps its stricter,
    # separate ``no-referrer`` policy in ``email_document_headers``.
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Cache-Control", "no-store")
    # CORS is intentionally unsupported, even if a downstream handler tries to
    # add a permissive header.
    for name in tuple(response.headers):
        if name.lower().startswith("access-control-"):
            del response.headers[name]


def _http_exception_response(
    request: web.Request,
    exc: web.HTTPException,
) -> web.Response:
    """Convert an aiohttp control-flow exception without returning the exception."""

    if _is_api_path(request.path):
        return _error_response(
            request,
            status=exc.status,
            code=_API_ERROR_CODES.get(exc.status, "request_failed"),
            message=_safe_error_message(exc.text, status=exc.status),
            headers=exc.headers,
        )
    return web.Response(
        status=exc.status,
        reason=exc.reason,
        body=exc.body,
        headers=exc.headers,
    )


@dataclass(slots=True)
class NonceStore:
    """Bounded in-memory reservation/consumption set for one-time CSRF tokens."""

    capacity: int
    ttl: int
    _entries: dict[str, tuple[float, bool]] = field(init=False, repr=False)
    _lock: asyncio.Lock = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.capacity <= 0 or self.ttl <= 0:
            raise ValueError("nonce store bounds must be positive")
        self._entries = {}
        self._lock = asyncio.Lock()

    def _purge(self, now: float) -> None:
        for nonce, (expires, _committed) in tuple(self._entries.items()):
            if expires <= now:
                del self._entries[nonce]

    async def available(self, nonce: str) -> bool:
        async with self._lock:
            now = time.monotonic()
            self._purge(now)
            return nonce not in self._entries

    async def reserve(self, nonce: str) -> bool:
        async with self._lock:
            now = time.monotonic()
            self._purge(now)
            if nonce in self._entries:
                return False
            # Never evict an unexpired consumed nonce: eviction would make a
            # previously used signed token replayable.  A full store therefore
            # fails closed until its oldest TTL expires.
            if len(self._entries) >= self.capacity:
                return False
            self._entries[nonce] = (now + self.ttl, False)
            return True

    async def commit(self, nonce: str) -> None:
        async with self._lock:
            if nonce in self._entries:
                self._entries[nonce] = (time.monotonic() + self.ttl, True)


def security_middleware(config: SecurityConfig) -> web.middleware:
    """Build middleware enforcing Host, Origin, CSRF and response policies."""

    nonces = NonceStore(capacity=4096, ttl=config.csrf_max_age)
    # Bind signed tokens to this single Web-process lifetime.  Otherwise a
    # restart would forget the consumed-nonce set and make a pre-restart POST
    # token replayable after an ambiguous SMTP outcome.
    boot_nonce = secrets.token_bytes(32)
    csrf_key = hmac.new(
        config.session_signing_key,
        b"maddyweb-csrf-process-v1\0" + boot_nonce,
        hashlib.sha256,
    ).digest()

    def set_csrf_cookie(response: web.StreamResponse, token: str) -> None:
        response.set_cookie(
            config.csrf_cookie_name,
            token,
            max_age=config.csrf_max_age,
            secure=config.secure_cookies,
            httponly=True,
            samesite="Strict",
            path="/",
        )

    def recoverable_csrf_rejection(
        request: web.Request,
        *,
        message: str,
    ) -> web.Response:
        """Reject before the handler while synchronizing the next explicit attempt."""

        response = _error_response(
            request,
            status=403,
            code="csrf_failed",
            message=message,
        )
        replacement = new_csrf_token(csrf_key)
        request[_CSRF_REQUEST_KEY] = replacement
        set_csrf_cookie(response, replacement)
        response.headers["X-CSRF-Token"] = replacement
        _apply_security_headers(response)
        return response

    @web.middleware
    async def middleware(request: web.Request, handler: web.RequestHandler) -> web.StreamResponse:
        hosts = request.headers.getall("Host", [])
        if len(hosts) != 1 or not host_is_allowed(hosts[0], config.allowed_hosts):
            response: web.StreamResponse = _error_response(
                request,
                status=400,
                code="invalid_host",
                message="Invalid Host header.",
            )
            _apply_security_headers(response)
            return response

        cookie_token = request.cookies.get(config.csrf_cookie_name)
        verified_cookie = (
            verify_csrf_token(
                cookie_token,
                csrf_key,
                max_age=config.csrf_max_age,
            )
            if cookie_token
            else None
        )
        if verified_cookie and await nonces.available(verified_cookie[0]):
            request[_CSRF_REQUEST_KEY] = cookie_token
        else:
            cookie_token = None
            verified_cookie = None
            request[_CSRF_REQUEST_KEY] = new_csrf_token(csrf_key)

        if request.method not in SAFE_METHODS and request.method != "POST":
            response = _error_response(
                request,
                status=405,
                code="method_not_allowed",
                message="This request method is not supported.",
                headers={"Allow": "GET, HEAD, POST"},
            )
            _apply_security_headers(response)
            return response

        if request.method not in SAFE_METHODS:
            origins = request.headers.getall("Origin", [])
            referers = request.headers.getall("Referer", [])
            if len(origins) > 1 or len(referers) > 1:
                same_origin = False
            elif origins:
                origin = origins[0]
                same_origin = origin_is_allowed(origin, request, config)
            else:
                same_origin = bool(referers) and referer_is_allowed(
                    referers[0],
                    request,
                    config,
                )
            fetch_sites = request.headers.getall("Sec-Fetch-Site", [])
            if (
                not same_origin
                or len(fetch_sites) > 1
                or (fetch_sites and fetch_sites[0] == "cross-site")
            ):
                response = _error_response(
                    request,
                    status=403,
                    code="cross_site_rejected",
                    message="Cross-site request rejected.",
                )
                _apply_security_headers(response)
                return response
            # A request without an authentic process-bound cookie can never
            # pass CSRF validation.  Reject it before reading a potentially
            # unbounded slow request body.
            if cookie_token is None or verified_cookie is None:
                return recoverable_csrf_rejection(
                    request,
                    message="CSRF check failed; refresh.",
                )
            send_upload = request.path == "/api/v1/send"
            api_json_write = _is_api_path(request.path) and not send_upload
            required_content_type = (
                "multipart/form-data"
                if send_upload
                else ("application/json" if api_json_write else "application/x-www-form-urlencoded")
            )
            content_type_headers = request.headers.getall("Content-Type", [])
            if len(content_type_headers) != 1 or request.content_type != required_content_type:
                response = _error_response(
                    request,
                    status=415,
                    code="unsupported_media_type",
                    message="Unsupported content type for this write.",
                )
                _apply_security_headers(response)
                return response
            try:
                submitted = await _submitted_csrf_token(
                    request,
                    timeout_seconds=config.request_body_timeout_seconds,
                )
            except web.HTTPException as exc:
                response = _http_exception_response(request, exc)
                _apply_security_headers(response)
                return response
            if submitted is None or not hmac.compare_digest(cookie_token, submitted):
                return recoverable_csrf_rejection(
                    request,
                    message="CSRF check failed; refresh.",
                )
            nonce = verified_cookie[0]
            if not await nonces.reserve(nonce):
                response = _error_response(
                    request,
                    status=403,
                    code="csrf_reused",
                    message="CSRF token reused; refresh.",
                )
                _apply_security_headers(response)
                return response
        else:
            nonce = None

        try:
            response = await handler(request)
        except web.HTTPException as exc:
            response = _http_exception_response(request, exc)
        except BaseException:
            if nonce is not None:
                # Once a write request has passed validation and entered its
                # handler, fail closed: its token must never become replayable,
                # even when the handler cannot produce a response.
                await nonces.commit(nonce)
            raise
        _apply_security_headers(response)
        if nonce is not None:
            # Validation grants exactly one attempt, not one successful
            # attempt.  This prevents ambiguous gateway/SMTP failures from
            # being retried with the same token and duplicating side effects.
            await nonces.commit(nonce)
            replacement = new_csrf_token(csrf_key)
            request[_CSRF_REQUEST_KEY] = replacement
            set_csrf_cookie(response, replacement)
            response.headers["X-CSRF-Token"] = replacement
        elif cookie_token is None and request.method in SAFE_METHODS:
            set_csrf_cookie(response, request[_CSRF_REQUEST_KEY])
        return response

    return middleware


@dataclass(slots=True)
class RequestLimiter:
    """A small FIFO-ish concurrency gate with a bounded wait time."""

    capacity: int
    wait_timeout: float
    _semaphore: asyncio.Semaphore = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.capacity <= 0:
            raise ValueError("capacity must be positive")
        if self.wait_timeout <= 0:
            raise ValueError("wait_timeout must be positive")
        self._semaphore = asyncio.Semaphore(self.capacity)

    async def acquire(self) -> None:
        async with asyncio.timeout(self.wait_timeout):
            await self._semaphore.acquire()

    def release(self) -> None:
        self._semaphore.release()


def bounded_concurrency_middleware(
    capacity: int,
    *,
    wait_timeout: float = 1.0,
) -> web.middleware:
    """Bound in-flight requests and reject queues that cannot drain quickly."""

    limiter = RequestLimiter(capacity, wait_timeout)

    @web.middleware
    async def middleware(request: web.Request, handler: web.RequestHandler) -> web.StreamResponse:
        try:
            await limiter.acquire()
        except TimeoutError:
            response = _error_response(
                request,
                status=429,
                code="too_many_requests",
                message="The server is busy; try again later.",
                headers={"Retry-After": "1"},
            )
            _apply_security_headers(response)
            return response
        try:
            return await handler(request)
        finally:
            limiter.release()

    return middleware


def email_document_headers() -> dict[str, str]:
    """Headers for the separately served, sandboxed HTML-mail document."""

    return {
        "Cache-Control": "no-store",
        "Content-Security-Policy": (
            "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'self'; img-src 'self'; object-src 'none'; "
            "style-src 'unsafe-inline'"
        ),
        "Cross-Origin-Resource-Policy": "same-origin",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
    }


__all__ = [
    "DEFAULT_CSP",
    "RequestLimiter",
    "SecurityConfig",
    "bounded_concurrency_middleware",
    "csrf_token_for_request",
    "email_document_headers",
    "host_is_allowed",
    "new_csrf_token",
    "normalize_authority",
    "normalize_origin",
    "origin_is_allowed",
    "referer_is_allowed",
    "security_middleware",
    "verify_csrf_token",
]
