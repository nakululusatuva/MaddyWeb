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
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
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


def new_csrf_token(
    key: bytes,
    *,
    now: int | None = None,
    flow_id: str | None = None,
) -> str:
    """Create a signed token containing version, issued-at and random nonce."""

    issued_at = int(time.time()) if now is None else now
    resolved_flow_id = secrets.token_urlsafe(18) if flow_id is None else flow_id
    if (
        not isinstance(resolved_flow_id, str)
        or not 16 <= len(resolved_flow_id) <= 32
        or not all(character.isalnum() or character in "_-" for character in resolved_flow_id)
    ):
        raise ValueError("CSRF flow identifier is invalid")
    nonce = secrets.token_urlsafe(24)
    payload = f"v2.{issued_at}.{resolved_flow_id}.{nonce}"
    return f"{payload}.{_csrf_signature(key, payload)}"


def verify_csrf_token(
    token: str,
    key: bytes,
    *,
    max_age: int,
    now: int | None = None,
) -> tuple[str, int, str] | None:
    """Return ``(nonce, issued_at, flow_id)`` for an authentic current token."""

    if len(token) > 256 or _contains_forbidden_header_characters(token):
        return None
    try:
        version, issued_text, flow_id, nonce, signature = token.split(".", 4)
        issued_at = int(issued_text)
    except TypeError, ValueError:
        return None
    if (
        version != "v2"
        or not 16 <= len(flow_id) <= 32
        or not all(character.isalnum() or character in "_-" for character in flow_id)
        or not nonce
        or len(nonce) > 64
    ):
        return None
    current = int(time.time()) if now is None else now
    if issued_at > current + 60 or current - issued_at > max_age:
        return None
    payload = f"{version}.{issued_at}.{flow_id}.{nonce}"
    if not hmac.compare_digest(signature, _csrf_signature(key, payload)):
        return None
    return nonce, issued_at, flow_id


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


def security_headers_middleware(config: SecurityConfig) -> web.middleware:
    """Apply the Host boundary and security headers around every response."""

    @web.middleware
    async def middleware(
        request: web.Request,
        handler: web.RequestHandler,
    ) -> web.StreamResponse:
        hosts = request.headers.getall("Host", [])
        if len(hosts) != 1 or not host_is_allowed(hosts[0], config.allowed_hosts):
            response: web.StreamResponse = _error_response(
                request,
                status=400,
                code="invalid_host",
                message="Invalid Host header.",
            )
        else:
            try:
                response = await handler(request)
            except web.HTTPException as exc:
                response = _http_exception_response(request, exc)
        _apply_security_headers(response)
        return response

    return middleware


@dataclass(frozen=True, slots=True)
class CsrfScope:
    """Stable server-derived scope for one browser's rotating CSRF state."""

    identity: str
    partition_by_flow: bool


@dataclass(frozen=True, slots=True)
class _CsrfCurrent:
    base: str
    nonce: str
    expires_at: float


@dataclass(slots=True)
class CurrentCsrfStore:
    """Bounded current-token registry partitioned by session or login flow.

    Each scope retains only the nonce that may be used next. Consuming it
    atomically replaces it, so replay detection does not require an
    ever-growing global set. Capacity pressure evicts the least-recently used
    scope; an evicted token is rejected on POST and can recover only through a
    safe request that receives a newly generated token.
    """

    capacity: int
    flows_per_identity: int
    ttl: int
    _entries: OrderedDict[str, _CsrfCurrent] = field(init=False, repr=False)
    _lock: asyncio.Lock = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.capacity <= 0 or self.flows_per_identity <= 0 or self.ttl <= 0:
            raise ValueError("CSRF state bounds must be positive")
        self._entries = OrderedDict()
        self._lock = asyncio.Lock()

    def _purge(self, now: float) -> None:
        for key, state in tuple(self._entries.items()):
            if state.expires_at <= now:
                del self._entries[key]

    def _bound_capacity(self, base: str, key: str) -> None:
        matching = [
            candidate
            for candidate, state in self._entries.items()
            if state.base == base and candidate != key
        ]
        while len(matching) >= self.flows_per_identity:
            del self._entries[matching.pop(0)]
        while len(self._entries) >= self.capacity and key not in self._entries:
            self._entries.popitem(last=False)

    async def is_current(self, key: str, nonce: str) -> bool:
        async with self._lock:
            now = time.monotonic()
            self._purge(now)
            state = self._entries.get(key)
            if state is None or not hmac.compare_digest(state.nonce, nonce):
                return False
            self._entries.move_to_end(key)
            return True

    async def replace(self, base: str, key: str, nonce: str) -> None:
        async with self._lock:
            now = time.monotonic()
            self._purge(now)
            self._bound_capacity(base, key)
            self._entries[key] = _CsrfCurrent(base, nonce, now + self.ttl)
            self._entries.move_to_end(key)

    async def rotate(
        self,
        base: str,
        key: str,
        expected_nonce: str,
        replacement_nonce: str,
    ) -> bool:
        async with self._lock:
            now = time.monotonic()
            self._purge(now)
            state = self._entries.get(key)
            if state is None or not hmac.compare_digest(state.nonce, expected_nonce):
                return False
            self._entries[key] = _CsrfCurrent(base, replacement_nonce, now + self.ttl)
            self._entries.move_to_end(key)
            return True


def security_middleware(
    config: SecurityConfig,
    *,
    scope_resolver: Callable[[web.Request], CsrfScope] | None = None,
    state_capacity: int = 4096,
    flows_per_identity: int = 8,
    tokenless_safe_paths: Iterable[str] = (),
) -> web.middleware:
    """Build middleware enforcing Host, Origin, CSRF and response policies."""

    tokenless_paths = frozenset(tokenless_safe_paths)
    if any(not isinstance(path, str) or not path.startswith("/") for path in tokenless_paths):
        raise ValueError("tokenless safe paths must be absolute request paths")
    states = CurrentCsrfStore(
        capacity=state_capacity,
        flows_per_identity=flows_per_identity,
        ttl=config.csrf_max_age,
    )
    # Bind signed tokens to this process lifetime. A restart therefore rejects
    # every pre-restart write token and issues a fresh one through a safe
    # request or an explicit CSRF recovery response.
    boot_nonce = secrets.token_bytes(32)
    csrf_key = hmac.new(
        config.session_signing_key,
        b"maddyweb-csrf-process-v2\0" + boot_nonce,
        hashlib.sha256,
    ).digest()

    def request_scope(request: web.Request) -> CsrfScope:
        scope = (
            scope_resolver(request)
            if scope_resolver is not None
            else CsrfScope(f"client:{request.remote or 'unknown'}", True)
        )
        if (
            not isinstance(scope, CsrfScope)
            or not scope.identity
            or len(scope.identity) > 512
            or _contains_forbidden_header_characters(scope.identity)
        ):
            raise web.HTTPBadRequest(text="Invalid CSRF scope.")
        return scope

    def state_identity(scope: CsrfScope, flow_id: str) -> tuple[str, str]:
        base = hmac.new(
            csrf_key,
            b"maddyweb-csrf-scope-v2\0" + scope.identity.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        flow = flow_id if scope.partition_by_flow else "session"
        key = hmac.new(
            csrf_key,
            b"maddyweb-csrf-state-v2\0" + base.encode("ascii") + b"\0" + flow.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return base, key

    def token_parts(token: str) -> tuple[str, str]:
        verified = verify_csrf_token(
            token,
            csrf_key,
            max_age=config.csrf_max_age,
        )
        if verified is None:
            raise RuntimeError("internally generated CSRF token is invalid")
        return verified[0], verified[2]

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

    async def recoverable_csrf_rejection(
        request: web.Request,
        *,
        message: str,
        scope: CsrfScope,
        flow_id: str,
        code: str = "csrf_failed",
    ) -> web.Response:
        """Reject before the handler while synchronizing the next explicit attempt."""

        response = _error_response(
            request,
            status=403,
            code=code,
            message=message,
        )
        replacement = new_csrf_token(csrf_key, flow_id=flow_id)
        replacement_nonce, _replacement_flow = token_parts(replacement)
        base, state_key = state_identity(scope, flow_id)
        await states.replace(base, state_key, replacement_nonce)
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

        if request.method in SAFE_METHODS and request.path in tokenless_paths:
            try:
                response = await handler(request)
            except web.HTTPException as exc:
                response = _http_exception_response(request, exc)
            _apply_security_headers(response)
            return response

        scope = request_scope(request)
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
        if verified_cookie is not None:
            flow_id = verified_cookie[2]
        else:
            flow_id = token_parts(new_csrf_token(csrf_key))[1]
        base, state_key = state_identity(scope, flow_id)

        if request.method in SAFE_METHODS:
            if verified_cookie is not None and await states.is_current(
                state_key,
                verified_cookie[0],
            ):
                request[_CSRF_REQUEST_KEY] = cookie_token
            else:
                replacement = new_csrf_token(csrf_key, flow_id=flow_id)
                replacement_nonce, _replacement_flow = token_parts(replacement)
                await states.replace(base, state_key, replacement_nonce)
                request[_CSRF_REQUEST_KEY] = replacement
                cookie_token = None
                verified_cookie = None
        elif verified_cookie is not None:
            request[_CSRF_REQUEST_KEY] = cookie_token
        else:
            replacement = new_csrf_token(csrf_key, flow_id=flow_id)
            request[_CSRF_REQUEST_KEY] = replacement
            cookie_token = None

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
                return await recoverable_csrf_rejection(
                    request,
                    message="CSRF check failed; refresh.",
                    scope=scope,
                    flow_id=flow_id,
                )
            send_upload = request.path in {
                "/api/v1/send",
                "/api/v1/me/send",
                "/api/v1/admin/send",
            }
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
                return await recoverable_csrf_rejection(
                    request,
                    message="CSRF check failed; refresh.",
                    scope=scope,
                    flow_id=flow_id,
                )
            replacement_token = new_csrf_token(csrf_key, flow_id=flow_id)
            replacement_nonce, _replacement_flow = token_parts(replacement_token)
            if not await states.rotate(
                base,
                state_key,
                verified_cookie[0],
                replacement_nonce,
            ):
                return await recoverable_csrf_rejection(
                    request,
                    scope=scope,
                    flow_id=flow_id,
                    code="csrf_reused",
                    message="CSRF token reused; refresh.",
                )
            request[_CSRF_REQUEST_KEY] = replacement_token
        else:
            replacement_token = None

        try:
            response = await handler(request)
        except web.HTTPException as exc:
            response = _http_exception_response(request, exc)
        _apply_security_headers(response)
        if replacement_token is not None:
            # Validation grants exactly one attempt, not one successful
            # attempt.  This prevents ambiguous gateway/SMTP failures from
            # being retried with the same token and duplicating side effects.
            post_scope = request_scope(request)
            if post_scope != scope:
                post_base, post_key = state_identity(post_scope, flow_id)
                replacement_nonce, _replacement_flow = token_parts(replacement_token)
                await states.replace(post_base, post_key, replacement_nonce)
            set_csrf_cookie(response, replacement_token)
            response.headers["X-CSRF-Token"] = replacement_token
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
    long_lived_paths: frozenset[str] = frozenset(),
    long_lived_capacity: int | None = None,
) -> web.middleware:
    """Bound in-flight requests and reject queues that cannot drain quickly."""

    limiter = RequestLimiter(capacity, wait_timeout)
    stream_limiter = (
        RequestLimiter(long_lived_capacity, wait_timeout)
        if long_lived_paths and long_lived_capacity is not None
        else None
    )
    if long_lived_paths and stream_limiter is None:
        raise ValueError("long-lived request capacity must be configured")

    @web.middleware
    async def middleware(request: web.Request, handler: web.RequestHandler) -> web.StreamResponse:
        selected_limiter = (
            stream_limiter
            if stream_limiter is not None and request.path in long_lived_paths
            else limiter
        )
        try:
            await selected_limiter.acquire()
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
            selected_limiter.release()

    return middleware


def email_document_headers() -> dict[str, str]:
    """Headers for the separately served, sandboxed HTML-mail document."""

    return {
        "Cache-Control": "private, no-store, no-transform",
        "Content-Security-Policy": (
            "sandbox allow-popups allow-popups-to-escape-sandbox; "
            "default-src 'none'; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'self'; img-src data:; object-src 'none'; "
            "style-src 'unsafe-inline'"
        ),
        "Cross-Origin-Resource-Policy": "same-origin",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
    }


__all__ = [
    "DEFAULT_CSP",
    "CsrfScope",
    "CurrentCsrfStore",
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
    "security_headers_middleware",
    "security_middleware",
    "verify_csrf_token",
]
