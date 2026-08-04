"""Unprivileged asynchronous client for the privileged local helper.

The web process never imports Docker, Certbot, systemd, or Maddy execution
details.  It sends only allow-listed operations over one-request UNIX-socket
connections.  Binary RFC 5322 messages use the protocol stream that follows a
small JSON control frame; filesystem paths never cross the privilege boundary.
"""

from __future__ import annotations

import asyncio
import contextvars
import copy
import hashlib
import logging
import os
import stat
import time
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from . import __version__
from .config import AppConfig
from .mail import DeliveryRejected, DeliveryUncertain, PreparedMessage
from .protocol import (
    DEFAULT_MAX_STREAM_BYTES,
    ErrorPayload,
    Request,
    Response,
    UnixSocketClient,
)

LOGGER = logging.getLogger(__name__)

_HEALTH_CACHE_SECONDS = 10.0
_ACCOUNT_CACHE_SECONDS = 2.0
_MAILBOX_CACHE_SECONDS = 15.0
_MAILBOX_CACHE_CAPACITY = 128
_MESSAGE_LIST_CACHE_SECONDS = 5.0
_MESSAGE_LIST_CACHE_CAPACITY = 128
_SESSION_CACHE_SECONDS = 2.0
_SESSION_CACHE_CAPACITY = 256
_SMTP_AUTH_PUBLIC_MESSAGE = (
    "Authentication for the selected sending account was rejected. Check its mailbox "
    "password and confirm that credentials are enabled, then try again. The message was "
    "not submitted."
)
_AUTH_TOKEN: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "maddyweb_helper_auth_token",
    default=None,
)
_TARGET_ACCOUNT_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "maddyweb_helper_target_account_id",
    default=None,
)
_USE_CONTEXT_TOKEN = object()


def _authorization_cache_key(auth_token: str | None) -> bytes:
    if auth_token is None:
        return b""
    return hashlib.sha256(auth_token.encode("ascii", "strict")).digest()


@contextmanager
def bind_helper_identity(
    auth_token: str,
    *,
    target_account_id: str | None = None,
) -> Any:
    """Bind one authenticated browser identity to downstream helper calls."""

    token_marker = _AUTH_TOKEN.set(auth_token)
    target_marker = _TARGET_ACCOUNT_ID.set(target_account_id)
    try:
        yield
    finally:
        _TARGET_ACCOUNT_ID.reset(target_marker)
        _AUTH_TOKEN.reset(token_marker)


class HelperCallError(RuntimeError):
    """The helper rejected or could not complete an allow-listed operation."""

    def __init__(self, code: str, message: str = "helper operation failed") -> None:
        self.code = code
        super().__init__(message)


def _checked_result(response: Response) -> Any:
    if response.ok:
        return response.result
    error = response.error or ErrorPayload("internal_error", "Helper failed safely")
    raise HelperCallError(error.code, error.message)


def _mapping(value: Any, operation: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise HelperCallError("invalid_response", f"{operation} returned an invalid response")
    return value


def _sequence(value: Any, operation: str) -> Sequence[Any]:
    if not isinstance(value, list):
        raise HelperCallError("invalid_response", f"{operation} returned an invalid response")
    return value


def _single_uid(value: str) -> str:
    if not value.isdecimal() or value.startswith("0"):
        raise ValueError("message identifier must be one positive UID")
    uid = int(value)
    if not 1 <= uid <= (1 << 32) - 1:
        raise ValueError("message identifier must be one positive UID")
    return str(uid)


def _uid_set(values: Sequence[str] | None) -> str:
    if values is None:
        return "1:*"
    if not 1 <= len(values) <= 50:
        raise ValueError("message selection must contain between 1 and 50 UIDs")
    checked: list[str] = []
    seen: set[str] = set()
    for value in values:
        uid = _single_uid(value)
        if uid in seen:
            raise ValueError("message selection contains duplicate UIDs")
        seen.add(uid)
        checked.append(uid)
    return ",".join(checked)


@dataclass(slots=True)
class _HealthCache:
    expires_at: float = 0.0
    value: Mapping[str, object] | None = None


@dataclass(slots=True)
class _AccountCache:
    expires_at: float = 0.0
    value: tuple[dict[str, Any], ...] | None = None
    auth_key: bytes = field(default=b"", repr=False)


@dataclass(slots=True)
class _MailboxCacheEntry:
    expires_at: float
    generation: int
    value: tuple[Any, ...]


@dataclass(slots=True)
class _MessageListCacheEntry:
    expires_at: float
    value: dict[str, Any]


@dataclass(slots=True)
class _SessionCacheEntry:
    expires_at: float
    value: dict[str, Any]


@dataclass(slots=True)
class _TaskOutcome:
    value: Any = None
    error: Exception | None = None


@dataclass(slots=True)
class _AccountFlight:
    generation: int
    auth_key: bytes = field(repr=False)
    auth_token: str | None = field(repr=False)
    task: asyncio.Task[_TaskOutcome]


class HelperGateway:
    """Implement the web-facing gateway without granting it local privileges."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._client = UnixSocketClient(
            config.maddy.helper_socket,
            timeout=config.maddy.command_timeout_seconds + 5.0,
        )
        self._certificate_client = UnixSocketClient(
            config.maddy.helper_socket,
            timeout=config.certificates.command_timeout_seconds + 5.0,
        )
        self._health_cache = _HealthCache()
        self._health_lock = asyncio.Lock()
        self._account_cache = _AccountCache()
        self._account_flight: _AccountFlight | None = None
        self._account_read_tasks: set[asyncio.Task[Any]] = set()
        self._account_generation = 0
        self._account_mutations_inflight = 0
        self._account_mutation_tasks: set[asyncio.Task[Any]] = set()
        self._account_cache_quarantined = False

        self._mailbox_cache: dict[tuple[bytes, str], _MailboxCacheEntry] = {}
        self._mailbox_generation: dict[str, int] = {}
        self._message_list_cache: dict[
            tuple[bytes, str, str, int, int],
            _MessageListCacheEntry,
        ] = {}
        self._session_cache: dict[bytes, _SessionCacheEntry] = {}
        self._session_flights: dict[bytes, asyncio.Task[Mapping[str, Any]]] = {}

    async def _call(
        self,
        operation: str,
        params: Mapping[str, Any] | None = None,
        *,
        auth_token: str | None | object = _USE_CONTEXT_TOKEN,
    ) -> Any:
        resolved_token = _AUTH_TOKEN.get() if auth_token is _USE_CONTEXT_TOKEN else auth_token
        request = Request.create(operation, params, auth_token=resolved_token)
        client = self._certificate_client if operation.startswith("certificates.") else self._client
        response = await asyncio.to_thread(client.call, request)
        return _checked_result(response)

    async def _upload(
        self,
        operation: str,
        params: Mapping[str, Any],
        message: PreparedMessage,
    ) -> Any:
        if not 1 <= message.size <= DEFAULT_MAX_STREAM_BYTES:
            raise HelperCallError("limit_exceeded", "message exceeds the helper stream limit")
        request = Request.create(
            operation,
            params,
            auth_token=_AUTH_TOKEN.get(),
            stream_length=message.size,
        )

        def send() -> Response:
            with message.open() as source:
                return self._client.call_with_stream(request, source)

        return _checked_result(await asyncio.to_thread(send))

    async def begin_password_login(
        self,
        email: str,
        password: str,
        *,
        client_ip: str,
    ) -> Mapping[str, Any]:
        return _mapping(
            await self._call(
                "auth.password_begin",
                {"email": email, "password": password, "client_ip": client_ip},
                auth_token=None,
            ),
            "auth.password_begin",
        )

    async def begin_totp_enrollment(self, challenge: str) -> Mapping[str, Any]:
        return _mapping(
            await self._call(
                "auth.enrollment_begin",
                {"challenge": challenge},
                auth_token=None,
            ),
            "auth.enrollment_begin",
        )

    async def complete_totp_enrollment(
        self,
        challenge: str,
        code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, Any]:
        return _mapping(
            await self._call(
                "auth.enrollment_complete",
                {"challenge": challenge, "code": code, "client_ip": client_ip},
                auth_token=None,
            ),
            "auth.enrollment_complete",
        )

    async def complete_totp_login(
        self,
        challenge: str,
        code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, Any]:
        return _mapping(
            await self._call(
                "auth.totp_complete",
                {"challenge": challenge, "code": code, "client_ip": client_ip},
                auth_token=None,
            ),
            "auth.totp_complete",
        )

    async def complete_recovery_login(
        self,
        challenge: str,
        recovery_code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, Any]:
        return _mapping(
            await self._call(
                "auth.recovery_complete",
                {
                    "challenge": challenge,
                    "recovery_code": recovery_code,
                    "client_ip": client_ip,
                },
                auth_token=None,
            ),
            "auth.recovery_complete",
        )

    async def session(self, token: str) -> Mapping[str, Any]:
        cache_key = _authorization_cache_key(token)
        now = time.monotonic()
        cached = self._session_cache.get(cache_key)
        if cached is not None and cached.expires_at > now:
            return copy.deepcopy(cached.value)

        task = self._session_flights.get(cache_key)
        if task is None:

            async def load() -> Mapping[str, Any]:
                return _mapping(
                    await self._call("auth.session", auth_token=token),
                    "auth.session",
                )

            task = asyncio.create_task(load())
            self._session_flights[cache_key] = task
        try:
            value = await asyncio.shield(task)
        finally:
            if task.done() and self._session_flights.get(cache_key) is task:
                del self._session_flights[cache_key]
        snapshot = copy.deepcopy(dict(value))
        now = time.monotonic()
        for key, entry in tuple(self._session_cache.items()):
            if entry.expires_at <= now:
                del self._session_cache[key]
        while len(self._session_cache) >= _SESSION_CACHE_CAPACITY:
            del self._session_cache[next(iter(self._session_cache))]
        self._session_cache[cache_key] = _SessionCacheEntry(
            expires_at=time.monotonic() + _SESSION_CACHE_SECONDS,
            value=snapshot,
        )
        return copy.deepcopy(snapshot)

    async def peek_session(self, token: str) -> Mapping[str, Any]:
        """Validate a session without extending its idle expiration."""

        return _mapping(
            await self._call("auth.session_peek", auth_token=token),
            "auth.session_peek",
        )

    async def logout(self, token: str) -> None:
        cache_key = _authorization_cache_key(token)
        self._session_cache.pop(cache_key, None)
        try:
            await self._call("auth.logout", auth_token=token)
        finally:
            self._session_cache.pop(cache_key, None)

    async def change_own_password(
        self,
        current_password: str,
        new_password: str,
        *,
        client_ip: str,
    ) -> Mapping[str, Any]:
        try:
            return _mapping(
                await self._call(
                    "auth.change_password",
                    {
                        "current_password": current_password,
                        "new_password": new_password,
                        "client_ip": client_ip,
                    },
                ),
                "auth.change_password",
            )
        finally:
            self._session_cache.clear()

    async def regenerate_recovery_codes(
        self,
        password: str,
        code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, Any]:
        try:
            return _mapping(
                await self._call(
                    "auth.recovery_regenerate",
                    {"password": password, "code": code, "client_ip": client_ip},
                ),
                "auth.recovery_regenerate",
            )
        finally:
            self._session_cache.clear()

    async def step_up(
        self,
        password: str,
        code: str,
        *,
        client_ip: str,
    ) -> Mapping[str, Any]:
        return _mapping(
            await self._call(
                "auth.step_up",
                {"password": password, "code": code, "client_ip": client_ip},
            ),
            "auth.step_up",
        )

    async def rotate_account_totp(self, account_id: str) -> Mapping[str, Any]:
        try:
            return _mapping(
                await self._call(
                    "auth.admin_rotate_totp",
                    {"target_account_id": account_id, "confirm": True},
                ),
                "auth.admin_rotate_totp",
            )
        finally:
            self._session_cache.clear()

    async def health(self) -> Mapping[str, object]:
        """Return a cached, fixed-schema, non-sensitive readiness snapshot."""

        now = time.monotonic()
        cached = self._health_cache.value
        if cached is not None and self._health_cache.expires_at > now:
            return cached
        async with self._health_lock:
            now = time.monotonic()
            cached = self._health_cache.value
            if cached is not None and self._health_cache.expires_at > now:
                return cached
            result: dict[str, object] = {
                "status": "degraded",
                "version": __version__,
                "maddy_version": "unknown",
                "maddy_write_enabled": False,
                "storage_available": False,
                "certbot_available": False,
                "certificate_management_enabled": False,
            }
            try:
                version = _mapping(await self._call("maddy.health"), "maddy.health")
                result["maddy_version"] = str(version.get("version", "unknown"))
                result["maddy_write_enabled"] = version.get("writes_enabled") is True
                result["storage_available"] = version.get("storage_available") is True
                if result["storage_available"]:
                    result["status"] = "ok"
            except Exception:
                LOGGER.warning("Maddy helper health probe failed", exc_info=True)
            if self._config.certificates.enabled and self._config.certificates.names:
                try:
                    certificate_result = await self._call("certificates.health")
                except HelperCallError as exc:
                    if exc.code == "operation_denied":
                        try:
                            certificate_result = await self._call("certificates.list")
                        except Exception:
                            certificate_result = None
                    else:
                        certificate_result = None
                except Exception:
                    certificate_result = None
                if isinstance(certificate_result, Mapping):
                    result["certbot_available"] = (
                        certificate_result.get("certbot_available") is True
                    )
                    result["certificate_management_enabled"] = certificate_result.get(
                        "available"
                    ) is True or (
                        certificate_result.get("certbot_available") is True
                        and certificate_result.get("source_readable") is True
                    )
                elif isinstance(certificate_result, list):
                    result["certificate_management_enabled"] = True
            frozen = dict(result)
            self._health_cache = _HealthCache(
                time.monotonic() + _HEALTH_CACHE_SECONDS,
                frozen,
            )
            return frozen

    async def _fetch_accounts(self, auth_token: str | None) -> tuple[dict[str, Any], ...]:
        return tuple(
            dict(_mapping(account, "accounts.list item"))
            for account in _sequence(
                await self._call(
                    "accounts.list",
                    {"include_append_limits": False},
                    auth_token=auth_token,
                ),
                "accounts.list",
            )
        )

    @staticmethod
    def _copy_accounts(
        accounts: tuple[dict[str, Any], ...],
    ) -> tuple[dict[str, Any], ...]:
        # Helper responses are decoded JSON.  Deep copies prevent an in-process
        # caller from modifying nested extension fields held by the cache.
        return copy.deepcopy(accounts)

    @staticmethod
    def _consume_task_exception(task: asyncio.Task[Any]) -> None:
        if not task.cancelled():
            task.exception()

    def _release_account_read_task(self, task: asyncio.Task[Any]) -> None:
        self._account_read_tasks.discard(task)
        self._consume_task_exception(task)

    async def _run_account_read(
        self,
        generation: int,
        auth_key: bytes,
        auth_token: str | None,
    ) -> _TaskOutcome:
        task = asyncio.current_task()
        try:
            try:
                accounts = await self._fetch_accounts(auth_token)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # A successful Task carrying the error prevents Python 3.14's
                # shield future from logging an expected late exception after
                # its HTTP waiter was cancelled.
                return _TaskOutcome(error=exc)
            if generation == self._account_generation and self._account_mutations_inflight == 0:
                # A successful uncached read after an ambiguous mutation is
                # authoritative: the single helper serves connections serially.
                self._account_cache_quarantined = False
                self._account_cache = _AccountCache(
                    time.monotonic() + _ACCOUNT_CACHE_SECONDS,
                    accounts,
                    auth_key,
                )
            return _TaskOutcome(value=accounts)
        finally:
            # This transition happens before the Task becomes done.  Callers
            # can therefore never spin on a completed flight whose scheduled
            # done callback has not run yet.
            flight = self._account_flight
            if flight is not None and flight.task is task:
                self._account_flight = None

    def _start_account_read(
        self,
        auth_key: bytes,
        auth_token: str | None,
    ) -> _AccountFlight:
        generation = self._account_generation
        task = asyncio.create_task(self._run_account_read(generation, auth_key, auth_token))
        flight = _AccountFlight(generation, auth_key, auth_token, task)
        self._account_flight = flight
        self._account_read_tasks.add(task)
        task.add_done_callback(self._release_account_read_task)
        return flight

    async def _wait_for_account_mutations(self) -> None:
        while self._account_mutations_inflight:
            # The set keeps shielded helper tasks strongly referenced.  Drop
            # tasks whose wrapper already completed before a delayed callback
            # could remove them, then wait for every current writer to settle.
            for task in tuple(self._account_mutation_tasks):
                if task.done():
                    self._account_mutation_tasks.discard(task)
            tasks = tuple(self._account_mutation_tasks)
            if not tasks:
                raise RuntimeError("account mutation task tracking was lost")
            await asyncio.gather(
                *(asyncio.shield(task) for task in tasks),
                return_exceptions=True,
            )

    async def list_accounts(self) -> Sequence[object]:
        # APPENDLIMIT has no bulk CLI in supported Maddy releases.  Avoid an
        # N+1 command storm on every account/mail/compose page; setting a limit
        # remains an explicit verified write operation.
        auth_token = _AUTH_TOKEN.get()
        auth_key = _authorization_cache_key(auth_token)
        while True:
            if self._account_mutations_inflight:
                await self._wait_for_account_mutations()
                continue
            now = time.monotonic()
            cached = self._account_cache.value
            if (
                self._account_mutations_inflight == 0
                and not self._account_cache_quarantined
                and cached is not None
                and self._account_cache.auth_key == auth_key
                and self._account_cache.expires_at > now
            ):
                return self._copy_accounts(cached)
            flight = self._account_flight
            if (
                flight is None
                or flight.generation != self._account_generation
                or flight.auth_key != auth_key
            ):
                flight = self._start_account_read(auth_key, auth_token)
            outcome = await asyncio.shield(flight.task)
            if outcome.error is not None:
                raise outcome.error
            accounts = outcome.value
            if not isinstance(accounts, tuple):
                raise RuntimeError("account read completed without a result")
            # A mutation may have begun while the helper read was in flight.
            # In that case wait for a post-mutation snapshot instead of
            # returning or caching the older result.
            if (
                flight.generation != self._account_generation
                or self._account_mutations_inflight != 0
            ):
                continue
            return self._copy_accounts(accounts)

    def _invalidate_accounts(self) -> None:
        self._account_generation += 1
        self._account_cache = _AccountCache()
        # Do not cancel a shared read: its current waiters may still be alive.
        # Detaching it lets post-mutation readers start a new generation while
        # the older read wrapper is prevented from clearing the new flight.
        self._account_flight = None

    def _release_account_mutation_task(self, task: asyncio.Task[Any]) -> None:
        self._account_mutation_tasks.discard(task)
        self._consume_task_exception(task)

    async def _run_account_mutation(
        self,
        operation: str,
        params: Mapping[str, Any],
    ) -> _TaskOutcome:
        try:
            return _TaskOutcome(value=await self._call(operation, params))
        except HelperCallError as exc:
            # A framed helper error means the serialized operation completed.
            return _TaskOutcome(error=exc)
        except asyncio.CancelledError:
            self._account_cache_quarantined = True
            raise
        except Exception as exc:
            # Transport failures cannot prove when a root-side operation
            # settled.  Bypass cache until a later serialized read succeeds.
            self._account_cache_quarantined = True
            return _TaskOutcome(error=exc)
        finally:
            # Update every state predicate before this wrapper Task becomes
            # done.  No correctness decision depends on done-callback timing.
            self._account_mutations_inflight -= 1
            self._invalidate_accounts()

    async def _account_mutation(
        self,
        operation: str,
        params: Mapping[str, Any],
    ) -> Any:
        # Shield the actual helper call from HTTP-task cancellation.  Its
        # wrapper performs the second invalidation only when that call really
        # settles; transport ambiguity additionally quarantines the cache.
        self._invalidate_accounts()
        self._account_mutations_inflight += 1
        task = asyncio.create_task(self._run_account_mutation(operation, params))
        self._account_mutation_tasks.add(task)
        task.add_done_callback(self._release_account_mutation_task)
        outcome = await asyncio.shield(task)
        if outcome.error is not None:
            raise outcome.error
        return outcome.value

    def _invalidate_mailboxes(self, account_id: str) -> None:
        self._mailbox_generation[account_id] = self._mailbox_generation.get(account_id, 0) + 1
        for key in tuple(self._mailbox_cache):
            if key[1] == account_id:
                del self._mailbox_cache[key]

    def _invalidate_message_lists(
        self,
        account_id: str,
        mailbox: str | None = None,
    ) -> None:
        for key in tuple(self._message_list_cache):
            _auth_key, key_account, key_mailbox, _limit, _offset = key
            if key_account == account_id and (mailbox is None or key_mailbox == mailbox):
                del self._message_list_cache[key]

    def _prune_message_list_cache(self, now: float) -> None:
        for key, entry in tuple(self._message_list_cache.items()):
            if entry.expires_at <= now:
                del self._message_list_cache[key]
        while len(self._message_list_cache) >= _MESSAGE_LIST_CACHE_CAPACITY:
            del self._message_list_cache[next(iter(self._message_list_cache))]

    def _prune_mailbox_cache(self, now: float) -> None:
        for key, entry in tuple(self._mailbox_cache.items()):
            if entry.expires_at <= now:
                del self._mailbox_cache[key]
        while len(self._mailbox_cache) >= _MAILBOX_CACHE_CAPACITY:
            del self._mailbox_cache[next(iter(self._mailbox_cache))]

    @staticmethod
    def _copy_mailboxes(values: Sequence[Any]) -> list[Any]:
        return copy.deepcopy(list(values))

    async def _mailbox_mutation(
        self, account_id: str, operation: str, params: Mapping[str, Any]
    ) -> Any:
        self._invalidate_mailboxes(account_id)
        try:
            return await self._call(operation, params)
        finally:
            self._invalidate_mailboxes(account_id)

    async def create_account(self, username: str, password: str) -> object:
        return await self._account_mutation(
            "accounts.create",
            {"username": username, "password": password},
        )

    async def change_password(self, account_id: str, password: str) -> None:
        try:
            await self._account_mutation(
                "accounts.change_password",
                {"target_account_id": account_id, "password": password},
            )
        finally:
            self._session_cache.clear()

    async def set_append_limit(self, account_id: str, limit: int) -> None:
        await self._account_mutation(
            "accounts.set_append_limit",
            {"target_account_id": account_id, "value": limit},
        )

    async def disable_credentials(self, account_id: str) -> None:
        try:
            await self._account_mutation(
                "accounts.disable_credentials",
                {"target_account_id": account_id, "confirm": True},
            )
        finally:
            self._session_cache.clear()

    async def delete_mailbox(self, account_id: str) -> None:
        self._invalidate_mailboxes(account_id)
        self._invalidate_message_lists(account_id)
        try:
            await self._account_mutation(
                "accounts.delete_imap_account",
                {"target_account_id": account_id, "confirm": True},
            )
        finally:
            self._invalidate_mailboxes(account_id)
            self._invalidate_message_lists(account_id)
            self._session_cache.clear()

    async def list_mailboxes(self, account_id: str) -> Sequence[object]:
        auth_key = _authorization_cache_key(_AUTH_TOKEN.get())
        cache_key = (auth_key, account_id)
        now = time.monotonic()
        cached = self._mailbox_cache.get(cache_key)
        generation = self._mailbox_generation.get(account_id, 0)
        if cached is not None and cached.expires_at > now and cached.generation == generation:
            return self._copy_mailboxes(cached.value)
        values = _sequence(
            await self._call("mailboxes.list", {"target_account_id": account_id}),
            "mailboxes.list",
        )
        snapshot = tuple(self._copy_mailboxes(values))
        if generation == self._mailbox_generation.get(account_id, 0):
            self._prune_mailbox_cache(time.monotonic())
            self._mailbox_cache[cache_key] = _MailboxCacheEntry(
                expires_at=time.monotonic() + _MAILBOX_CACHE_SECONDS,
                generation=generation,
                value=snapshot,
            )
        return self._copy_mailboxes(snapshot)

    async def create_mailbox(self, account_id: str, mailbox: str) -> None:
        await self._mailbox_mutation(
            account_id,
            "mailboxes.create",
            {"target_account_id": account_id, "mailbox": mailbox},
        )

    async def rename_mailbox(
        self,
        account_id: str,
        old_name: str,
        new_name: str,
    ) -> None:
        self._invalidate_message_lists(account_id, old_name)
        self._invalidate_message_lists(account_id, new_name)
        await self._mailbox_mutation(
            account_id,
            "mailboxes.rename",
            {
                "target_account_id": account_id,
                "old_name": old_name,
                "new_name": new_name,
            },
        )

    async def delete_named_mailbox(self, account_id: str, mailbox: str) -> None:
        self._invalidate_message_lists(account_id, mailbox)
        await self._mailbox_mutation(
            account_id,
            "mailboxes.delete",
            {
                "target_account_id": account_id,
                "mailbox": mailbox,
                "confirm": True,
            },
        )

    async def list_messages(
        self,
        account_id: str,
        mailbox: str,
        *,
        limit: int,
        offset: int,
    ) -> Mapping[str, object]:
        cache_key = (
            _authorization_cache_key(_AUTH_TOKEN.get()),
            account_id,
            mailbox,
            limit,
            offset,
        )
        now = time.monotonic()
        cached = self._message_list_cache.get(cache_key)
        if cached is not None and cached.expires_at > now:
            return copy.deepcopy(cached.value)
        result = _mapping(
            await self._call(
                "messages.list",
                {
                    "target_account_id": account_id,
                    "mailbox": mailbox,
                    "limit": limit,
                    "offset": offset,
                },
            ),
            "messages.list",
        )
        _sequence(result.get("items"), "messages.list.items")
        snapshot = copy.deepcopy(dict(result))
        self._prune_message_list_cache(time.monotonic())
        self._message_list_cache[cache_key] = _MessageListCacheEntry(
            expires_at=time.monotonic() + _MESSAGE_LIST_CACHE_SECONDS,
            value=snapshot,
        )
        return copy.deepcopy(snapshot)

    async def latest_message_uid(self, account_id: str, mailbox: str) -> int:
        result = _mapping(
            await self._call(
                "messages.latest",
                {
                    "target_account_id": account_id,
                    "mailbox": mailbox,
                },
            ),
            "messages.latest",
        )
        uid = result.get("uid")
        if type(uid) is not int or not 0 <= uid <= (1 << 32) - 1:
            raise HelperCallError(
                "invalid_response",
                "messages.latest returned an invalid message UID",
            )
        self._invalidate_message_lists(account_id, mailbox)
        return uid

    @staticmethod
    def _open_destination(path: Path) -> BinaryIO:
        flags = os.O_WRONLY | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OSError("raw-message destination is not a private regular file")
            if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
                raise OSError("raw-message destination has an unexpected owner")
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise OSError("raw-message destination permissions are too broad")
            return os.fdopen(descriptor, "wb", buffering=0)
        except BaseException:
            os.close(descriptor)
            raise

    async def spool_message(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
        destination_path: Path,
        *,
        max_bytes: int,
    ) -> int:
        if not 1 <= max_bytes <= DEFAULT_MAX_STREAM_BYTES:
            raise ValueError("invalid raw-message download limit")
        request = Request.create(
            "messages.get",
            {"target_account_id": account_id, "mailbox": mailbox, "uid": message_id},
            auth_token=_AUTH_TOKEN.get(),
        )

        def receive() -> tuple[Response, int]:
            with self._open_destination(destination_path) as destination:
                response = self._client.call_to_stream(request, destination)
                size = destination.tell()
            return response, size

        response, size = await asyncio.to_thread(receive)
        _checked_result(response)
        if size > max_bytes:
            raise HelperCallError("limit_exceeded", "raw message exceeds its download limit")
        return size

    async def move_message_to_trash(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
    ) -> str:
        self._invalidate_message_lists(account_id, mailbox)
        try:
            result = _mapping(
                await self._call(
                    "messages.move",
                    {
                        "target_account_id": account_id,
                        "source": mailbox,
                        "uid": _single_uid(message_id),
                        "target_special": "trash",
                    },
                ),
                "messages.move",
            )
        finally:
            self._invalidate_message_lists(account_id, mailbox)
        target = result.get("target")
        if not isinstance(target, str) or not target:
            raise HelperCallError("invalid_response", "messages.move returned no target mailbox")
        self._invalidate_message_lists(account_id, target)
        return target

    async def move_message_to_archive(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
    ) -> str:
        self._invalidate_message_lists(account_id, mailbox)
        try:
            result = _mapping(
                await self._call(
                    "messages.move",
                    {
                        "target_account_id": account_id,
                        "source": mailbox,
                        "uid": _single_uid(message_id),
                        "target_special": "archive",
                    },
                ),
                "messages.move",
            )
        finally:
            self._invalidate_message_lists(account_id, mailbox)
        target = result.get("target")
        if not isinstance(target, str) or not target:
            raise HelperCallError("invalid_response", "messages.move returned no target mailbox")
        self._invalidate_message_lists(account_id, target)
        return target

    async def move_message(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
        target: str,
    ) -> str:
        self._invalidate_message_lists(account_id, mailbox)
        self._invalidate_message_lists(account_id, target)
        try:
            result = _mapping(
                await self._call(
                    "messages.move",
                    {
                        "target_account_id": account_id,
                        "source": mailbox,
                        "uid": _single_uid(message_id),
                        "target": target,
                    },
                ),
                "messages.move",
            )
        finally:
            self._invalidate_message_lists(account_id, mailbox)
            self._invalidate_message_lists(account_id, target)
        moved_to = result.get("target")
        if not isinstance(moved_to, str) or not moved_to:
            raise HelperCallError("invalid_response", "messages.move returned no target mailbox")
        return moved_to

    async def set_message_seen(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
        *,
        seen: bool,
    ) -> None:
        operation = "messages.add_flags" if seen else "messages.remove_flags"
        self._invalidate_message_lists(account_id, mailbox)
        try:
            await self._call(
                operation,
                {
                    "target_account_id": account_id,
                    "mailbox": mailbox,
                    "uid_set": _single_uid(message_id),
                    "flags": ["\\Seen"],
                },
            )
        finally:
            self._invalidate_message_lists(account_id, mailbox)

    async def set_messages_seen(
        self,
        account_id: str,
        mailbox: str,
        message_ids: Sequence[str] | None,
        *,
        seen: bool,
    ) -> None:
        if type(seen) is not bool:
            raise ValueError("seen state must be a boolean")
        operation = "messages.add_flags" if seen else "messages.remove_flags"
        self._invalidate_message_lists(account_id, mailbox)
        try:
            await self._call(
                operation,
                {
                    "target_account_id": account_id,
                    "mailbox": mailbox,
                    "uid_set": _uid_set(message_ids),
                    "flags": ["\\Seen"],
                },
            )
        finally:
            self._invalidate_message_lists(account_id, mailbox)

    async def move_messages_to_trash(
        self,
        account_id: str,
        mailbox: str,
        message_ids: Sequence[str],
    ) -> str:
        return await self._move_messages(account_id, mailbox, message_ids, "trash")

    async def move_messages_to_archive(
        self,
        account_id: str,
        mailbox: str,
        message_ids: Sequence[str],
    ) -> str:
        return await self._move_messages(account_id, mailbox, message_ids, "archive")

    async def _move_messages(
        self,
        account_id: str,
        mailbox: str,
        message_ids: Sequence[str],
        target_special: str,
    ) -> str:
        self._invalidate_message_lists(account_id, mailbox)
        try:
            result = _mapping(
                await self._call(
                    "messages.move",
                    {
                        "target_account_id": account_id,
                        "source": mailbox,
                        "uid_set": _uid_set(message_ids),
                        "target_special": target_special,
                    },
                ),
                "messages.move",
            )
        finally:
            self._invalidate_message_lists(account_id, mailbox)
        target = result.get("target")
        if not isinstance(target, str) or not target:
            raise HelperCallError("invalid_response", "messages.move returned no target mailbox")
        self._invalidate_message_lists(account_id, target)
        return target

    async def delete_message_permanently(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
    ) -> None:
        self._invalidate_message_lists(account_id, mailbox)
        try:
            await self._call(
                "messages.delete",
                {
                    "target_account_id": account_id,
                    "mailbox": mailbox,
                    "uid": _single_uid(message_id),
                    "confirm": True,
                },
            )
        finally:
            self._invalidate_message_lists(account_id, mailbox)

    async def certificate_status(self) -> object:
        if not self._config.certificates.enabled:
            return {
                "certificates": (),
                "timer_enabled": False,
                "timer_active": False,
                "timer_state": "disabled",
            }
        records = _sequence(await self._call("certificates.list"), "certificates.list")
        normalized_records: list[dict[str, object]] = []
        timer: Mapping[str, Any] = {}
        timer_enable_safe = bool(records)
        for value in records:
            record = _mapping(value, "certificates.list item")
            source = record.get("source")
            deployed = record.get("deployed")
            source_record = source if isinstance(source, Mapping) else {}
            deployed_record = deployed if isinstance(deployed, Mapping) else {}
            if not timer:
                candidate = record.get("timer")
                if isinstance(candidate, Mapping):
                    timer = candidate
            normalized_records.append(
                {
                    "name": str(record.get("name", "")),
                    "expires": source_record.get("not_after", ""),
                    "source_fingerprint": source_record.get("sha256_fingerprint", ""),
                    "deployed_fingerprint": deployed_record.get("sha256_fingerprint", ""),
                    "fingerprints_match": record.get("fingerprints_match") is True,
                    "automation_safe": record.get("automation_safe") is True,
                }
            )
            timer_enable_safe = timer_enable_safe and record.get("timer_enable_safe") is True
        return {
            "certificates": normalized_records,
            "timer_enabled": timer.get("enabled") is True,
            "timer_active": timer.get("active") is True,
            "timer_state": str(timer.get("active_state", "unknown")),
            "timer_enable_safe": timer_enable_safe,
        }

    async def set_certificate_timer(self, enabled: bool) -> None:
        operation = "certificates.timer_enable" if enabled else "certificates.timer_disable"
        await self._call(operation, {"confirm": True})

    async def certificate_dry_run(self, certificate_name: str) -> object:
        return await self._call(
            "certificates.renew_dry_run",
            {"name": certificate_name},
        )

    async def renew_certificate_if_due(self, certificate_name: str) -> object:
        return await self._call(
            "certificates.renew",
            {"name": certificate_name, "confirm": True},
        )

    async def deliver_message(
        self,
        message: PreparedMessage,
        envelope_from: str,
        recipients: Sequence[str],
        submission_password: str,
    ) -> str | None:
        try:
            result = _mapping(
                await self._upload(
                    "messages.send",
                    {
                        "password": submission_password,
                        "mail_from": envelope_from,
                        "recipients": list(recipients),
                        **(
                            {"target_account_id": _TARGET_ACCOUNT_ID.get()}
                            if _TARGET_ACCOUNT_ID.get() is not None
                            else {}
                        ),
                    },
                    message,
                ),
                "messages.send",
            )
        except HelperCallError as exc:
            if exc.code == "smtp_outcome_unknown":
                raise DeliveryUncertain("local submission outcome is unknown") from exc
            # Receiving a structured helper error proves the helper completed
            # classification.  messages.send performs every Maddy gate before
            # opening SMTP and has no fallible work after explicit acceptance.
            public_message = (
                _SMTP_AUTH_PUBLIC_MESSAGE if exc.code == "smtp_authentication_rejection" else None
            )
            raise DeliveryRejected(
                "local submission did not accept the message",
                public_message=public_message,
            ) from exc
        if result.get("accepted") is not True:
            raise DeliveryUncertain("helper returned no explicit SMTP acceptance")
        return message.message_id

    async def save_sent(self, message: PreparedMessage) -> None:
        target_account = _TARGET_ACCOUNT_ID.get()
        if target_account is not None:
            self._invalidate_message_lists(target_account)
        try:
            await self._upload(
                "messages.append",
                {
                    "mailbox_special": "sent",
                    "flags": ["\\Seen"],
                    **({"target_account_id": target_account} if target_account is not None else {}),
                },
                message,
            )
        finally:
            if target_account is not None:
                self._invalidate_message_lists(target_account)


__all__ = ["HelperCallError", "HelperGateway", "bind_helper_identity"]
