"""Lightweight canonical mailbox identity validation."""

from __future__ import annotations

import re
from typing import Final

EMAIL_LOCAL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+"
)
DOMAIN_LABEL_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9-]+")


def canonicalize_email(value: str) -> str:
    """Return the canonical ASCII mailbox identity used by MaddyWeb."""

    if not isinstance(value, str):
        raise ValueError("email identity must be text")
    normalized = value.strip()
    if not normalized or len(normalized) > 254 or not normalized.isascii():
        raise ValueError("email identity must be a valid ASCII address")
    if normalized.count("@") != 1:
        raise ValueError("email identity must contain one at sign")
    local, domain = normalized.rsplit("@", 1)
    if (
        not local
        or len(local) > 64
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or EMAIL_LOCAL_PATTERN.fullmatch(local) is None
    ):
        raise ValueError("email identity has an invalid local part")
    if not domain or len(domain) > 253 or domain.startswith(".") or domain.endswith("."):
        raise ValueError("email identity has an invalid domain")
    labels = domain.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or DOMAIN_LABEL_PATTERN.fullmatch(label) is None
        for label in labels
    ):
        raise ValueError("email identity has an invalid domain")
    return f"{local.lower()}@{domain.lower()}"


__all__ = ["DOMAIN_LABEL_PATTERN", "canonicalize_email"]
