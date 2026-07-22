"""Small structured audit logger with mandatory redaction."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

_LOGGER = logging.getLogger("maddyweb.audit")
_SENSITIVE_NAME = re.compile(
    r"(?:^|_)(?:password|secret|token|body|raw|attachment|private_key|session_key)(?:_|$)",
    re.IGNORECASE,
)


def _safe_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= 8:
        return "[TRUNCATED]"
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Mapping):
        return {
            str(name): (
                "[REDACTED]"
                if _SENSITIVE_NAME.search(str(name))
                else _safe_value(item, depth=depth + 1)
            )
            for name, item in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [_safe_value(item, depth=depth + 1) for item in value]
    return f"<{type(value).__name__}>"


def _redact(values: Mapping[str, Any]) -> dict[str, Any]:
    return _safe_value(values)


def record(action: str, *, outcome: str, fields: Mapping[str, Any] | None = None) -> None:
    payload = {
        "time": datetime.now(UTC).isoformat(),
        "action": action,
        "outcome": outcome,
        "fields": _redact(fields or {}),
    }
    _LOGGER.info("%s", json.dumps(payload, ensure_ascii=True, separators=(",", ":")))
