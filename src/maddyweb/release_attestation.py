"""Fail-closed authentication capability attestation for installed releases."""

from __future__ import annotations

from types import ModuleType
from typing import Protocol

SUPPORTED_AUTHENTICATION_PROFILE = "required-unified-mailbox-v1"
SUPPORTED_AUTHENTICATION_CAPABILITIES = (
    "authenticated-application-assets",
    "mailbox-password-primary-factor",
    "mandatory-authentication-middleware",
    "opaque-server-side-sessions",
    "totp-or-recovery-second-factor",
)
UNAUTHENTICATED_PROFILE = "unauthenticated"


class _AttestedModule(Protocol):
    AUTHENTICATION_PROFILE: object
    AUTHENTICATION_CAPABILITIES: object


def classify_authentication(module: _AttestedModule | ModuleType | object | None) -> str:
    """Return the supported profile only for one exact capability declaration."""

    if module is None:
        return UNAUTHENTICATED_PROFILE
    profile = getattr(module, "AUTHENTICATION_PROFILE", None)
    capabilities = getattr(module, "AUTHENTICATION_CAPABILITIES", None)
    if (
        profile == SUPPORTED_AUTHENTICATION_PROFILE
        and type(capabilities) is tuple
        and capabilities == SUPPORTED_AUTHENTICATION_CAPABILITIES
    ):
        return SUPPORTED_AUTHENTICATION_PROFILE
    return UNAUTHENTICATED_PROFILE


def main() -> None:
    try:
        from . import web
    except Exception:
        print(UNAUTHENTICATED_PROFILE)
        return
    print(classify_authentication(web))


if __name__ == "__main__":
    main()
