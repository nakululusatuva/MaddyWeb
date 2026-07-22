"""Unprivileged asynchronous client for the privileged local helper.

The web process never imports Docker, Certbot, systemd, or Maddy execution
details.  It sends only allow-listed operations over one-request UNIX-socket
connections.  Binary RFC 5322 messages use the protocol stream that follows a
small JSON control frame; filesystem paths never cross the privilege boundary.
"""

from __future__ import annotations

import asyncio
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
                _sequence(
                    await self._call(
                        "accounts.list",
                        {"include_append_limits": False},
                    ),
                    "accounts.list",
                )
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
            self._health_cache = _HealthCache(now + 10.0, frozen)
            return frozen

    async def list_accounts(self) -> Sequence[object]:
        # APPENDLIMIT has no bulk CLI in supported Maddy releases.  Avoid an
        # N+1 command storm on every account/mail/compose page; setting a limit
        # remains an explicit verified write operation.
        return _sequence(
            await self._call("accounts.list", {"include_append_limits": False}),
            "accounts.list",
        )

    async def create_account(self, username: str, password: str) -> object:
        return await self._call(
            "accounts.create",
            {"username": username, "password": password},
        )

    async def change_password(self, account_id: str, password: str) -> None:
        await self._call(
            "accounts.change_password",
            {"username": account_id, "password": password},
        )

    async def set_append_limit(self, account_id: str, limit: int) -> None:
        await self._call(
            "accounts.set_append_limit",
            {"username": account_id, "value": limit},
        )

    async def disable_credentials(self, account_id: str) -> None:
        await self._call(
            "accounts.disable_credentials",
            {"username": account_id, "confirm": True},
        )

    async def delete_mailbox(self, account_id: str) -> None:
        await self._call(
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
            return {"certificates": (), "timer_enabled": False, "timer_state": "disabled"}
        records = _sequence(await self._call("certificates.list"), "certificates.list")
        normalized_records: list[dict[str, object]] = []
        timer: Mapping[str, Any] = {}
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
                }
            )
        return {
            "certificates": normalized_records,
            "timer_enabled": timer.get("enabled") is True,
            "timer_state": str(timer.get("active_state", "unknown")),
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
            raise DeliveryRejected("local submission did not accept the message") from exc
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
