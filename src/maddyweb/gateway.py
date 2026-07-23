"""Unprivileged asynchronous client for the privileged local helper.

The web process never imports Docker, Certbot, systemd, or Maddy execution
details.  It sends only allow-listed operations over one-request UNIX-socket
connections.  Binary RFC 5322 messages use the protocol stream that follows a
small JSON control frame; filesystem paths never cross the privilege boundary.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import os
import stat
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
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
_SMTP_AUTH_PUBLIC_MESSAGE = (
    "Authentication for the selected sending account was rejected. Check its mailbox "
    "password and confirm that credentials are enabled, then try again. The message was "
    "not submitted."
)


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


@dataclass(slots=True)
class _HealthCache:
    expires_at: float = 0.0
    value: Mapping[str, object] | None = None


@dataclass(slots=True)
class _AccountCache:
    expires_at: float = 0.0
    value: tuple[dict[str, Any], ...] | None = None


@dataclass(slots=True)
class _TaskOutcome:
    value: Any = None
    error: Exception | None = None


@dataclass(slots=True)
class _AccountFlight:
    generation: int
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

    async def _call(self, operation: str, params: Mapping[str, Any] | None = None) -> Any:
        request = Request.create(operation, params, actor="maddyweb")
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
            actor="maddyweb",
            stream_length=message.size,
        )

        def send() -> Response:
            with message.open() as source:
                return self._client.call_with_stream(request, source)

        return _checked_result(await asyncio.to_thread(send))

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
                version = _mapping(await self._call("maddy.version"), "maddy.version")
                result["maddy_version"] = str(version.get("version", "unknown"))
                result["maddy_write_enabled"] = version.get("writes_enabled") is True
                # A read of the account indexes checks that both configured
                # credential and IMAP storage blocks remain available.  Its
                # contents are deliberately discarded.
                await self._fetch_accounts()
                result["storage_available"] = True
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

    async def _fetch_accounts(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            dict(_mapping(account, "accounts.list item"))
            for account in _sequence(
                await self._call(
                    "accounts.list",
                    {"include_append_limits": False},
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
    ) -> _TaskOutcome:
        task = asyncio.current_task()
        try:
            try:
                accounts = await self._fetch_accounts()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # A successful Task carrying the error prevents Python 3.14's
                # shield future from logging an expected late exception after
                # its HTTP waiter was cancelled.
                return _TaskOutcome(error=exc)
            if (
                generation == self._account_generation
                and self._account_mutations_inflight == 0
            ):
                # A successful uncached read after an ambiguous mutation is
                # authoritative: the single helper serves connections serially.
                self._account_cache_quarantined = False
                self._account_cache = _AccountCache(
                    time.monotonic() + _ACCOUNT_CACHE_SECONDS,
                    accounts,
                )
            return _TaskOutcome(value=accounts)
        finally:
            # This transition happens before the Task becomes done.  Callers
            # can therefore never spin on a completed flight whose scheduled
            # done callback has not run yet.
            flight = self._account_flight
            if flight is not None and flight.task is task:
                self._account_flight = None

    def _start_account_read(self) -> _AccountFlight:
        generation = self._account_generation
        task = asyncio.create_task(self._run_account_read(generation))
        flight = _AccountFlight(generation, task)
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
                and self._account_cache.expires_at > now
            ):
                return self._copy_accounts(cached)
            flight = self._account_flight
            if flight is None or flight.generation != self._account_generation:
                flight = self._start_account_read()
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

    async def create_account(self, username: str, password: str) -> object:
        return await self._account_mutation(
            "accounts.create",
            {"username": username, "password": password},
        )

    async def change_password(self, account_id: str, password: str) -> None:
        await self._account_mutation(
            "accounts.change_password",
            {"username": account_id, "password": password},
        )

    async def set_append_limit(self, account_id: str, limit: int) -> None:
        await self._account_mutation(
            "accounts.set_append_limit",
            {"username": account_id, "value": limit},
        )

    async def disable_credentials(self, account_id: str) -> None:
        await self._account_mutation(
            "accounts.disable_credentials",
            {"username": account_id, "confirm": True},
        )

    async def delete_mailbox(self, account_id: str) -> None:
        await self._account_mutation(
            "accounts.delete_imap_account",
            {"username": account_id, "confirm": True},
        )

    async def list_mailboxes(self, account_id: str) -> Sequence[object]:
        return _sequence(
            await self._call("mailboxes.list", {"username": account_id}),
            "mailboxes.list",
        )

    async def list_messages(
        self,
        account_id: str,
        mailbox: str,
        *,
        limit: int,
        offset: int,
    ) -> Mapping[str, object]:
        result = _mapping(
            await self._call(
                "messages.list",
                {
                    "username": account_id,
                    "mailbox": mailbox,
                    "limit": limit,
                    "offset": offset,
                },
            ),
            "messages.list",
        )
        _sequence(result.get("items"), "messages.list.items")
        return result

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
            {"username": account_id, "mailbox": mailbox, "uid": message_id},
            actor="maddyweb",
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
        result = _mapping(
            await self._call(
                "messages.move",
                {
                    "username": account_id,
                    "source": mailbox,
                    "uid": _single_uid(message_id),
                    "target_special": "trash",
                },
            ),
            "messages.move",
        )
        target = result.get("target")
        if not isinstance(target, str) or not target:
            raise HelperCallError("invalid_response", "messages.move returned no target mailbox")
        return target

    async def delete_message_permanently(
        self,
        account_id: str,
        mailbox: str,
        message_id: str,
    ) -> None:
        await self._call(
            "messages.delete",
            {
                "username": account_id,
                "mailbox": mailbox,
                "uid": _single_uid(message_id),
                "confirm": True,
            },
        )

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
                        "username": envelope_from,
                        "password": submission_password,
                        "mail_from": envelope_from,
                        "recipients": list(recipients),
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
                _SMTP_AUTH_PUBLIC_MESSAGE
                if exc.code == "smtp_authentication_rejection"
                else None
            )
            raise DeliveryRejected(
                "local submission did not accept the message",
                public_message=public_message,
            ) from exc
        if result.get("accepted") is not True:
            raise DeliveryUncertain("helper returned no explicit SMTP acceptance")
        return message.message_id

    async def save_sent(self, message: PreparedMessage) -> None:
        await self._upload(
            "messages.append",
            {
                "username": message.envelope_from,
                "mailbox_special": "sent",
                "flags": ["\\Seen"],
            },
            message,
        )


__all__ = ["HelperCallError", "HelperGateway"]
