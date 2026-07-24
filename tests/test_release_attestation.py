from __future__ import annotations

from types import SimpleNamespace

from maddyweb import web
from maddyweb.release_attestation import (
    SUPPORTED_AUTHENTICATION_CAPABILITIES,
    SUPPORTED_AUTHENTICATION_PROFILE,
    UNAUTHENTICATED_PROFILE,
    classify_authentication,
)


def test_current_release_reports_exact_supported_authentication_profile() -> None:
    assert classify_authentication(web) == SUPPORTED_AUTHENTICATION_PROFILE


def test_legacy_release_without_attestation_is_unauthenticated() -> None:
    assert classify_authentication(None) == UNAUTHENTICATED_PROFILE


def test_auth_module_presence_without_attestation_is_unauthenticated() -> None:
    module_presence_only = SimpleNamespace(auth=object())
    assert classify_authentication(module_presence_only) == UNAUTHENTICATED_PROFILE


def test_partial_or_changed_capabilities_are_unauthenticated() -> None:
    incomplete = SimpleNamespace(
        AUTHENTICATION_PROFILE=SUPPORTED_AUTHENTICATION_PROFILE,
        AUTHENTICATION_CAPABILITIES=SUPPORTED_AUTHENTICATION_CAPABILITIES[:-1],
    )
    mutable_copy = SimpleNamespace(
        AUTHENTICATION_PROFILE=SUPPORTED_AUTHENTICATION_PROFILE,
        AUTHENTICATION_CAPABILITIES=list(SUPPORTED_AUTHENTICATION_CAPABILITIES),
    )
    assert classify_authentication(incomplete) == UNAUTHENTICATED_PROFILE
    assert classify_authentication(mutable_copy) == UNAUTHENTICATED_PROFILE
