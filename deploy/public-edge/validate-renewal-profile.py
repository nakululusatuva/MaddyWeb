#!/usr/bin/env python3
"""Validate the narrow Certbot plugin policy used by the public Web edge."""

from __future__ import annotations

import sys
from pathlib import Path

MAX_RENEWAL_FILE_BYTES = 256 * 1024
HOOK_OPTIONS = frozenset({"pre_hook", "post_hook", "renew_hook", "deploy_hook"})


class RenewalPolicyError(ValueError):
    """A renewal document violates the public-edge plugin policy."""


def _direct_renewal_parameters(document: str) -> dict[str, list[str]]:
    parameters: dict[str, list[str]] = {}
    section = ""
    renewal_section_count = 0
    nested = False

    for line in document.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[[") and stripped.endswith("]]"):
            nested = True
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            nested = False
            if section == "renewalparams":
                renewal_section_count += 1
            continue
        if section != "renewalparams" or nested:
            continue

        key_text, separator, value_text = line.partition("=")
        if not separator:
            raise RenewalPolicyError("renewal parameters contain an invalid statement")
        key = key_text.strip()
        if key in {"authenticator", "installer", *HOOK_OPTIONS}:
            parameters.setdefault(key, []).append(value_text.strip())

    if renewal_section_count != 1:
        raise RenewalPolicyError("renewal parameters section is missing or duplicated")
    return parameters


def validate_renewal_profile(raw: bytes) -> None:
    """Reject any authenticator, installer, or hook outside the fixed policy."""

    if not raw or len(raw) > MAX_RENEWAL_FILE_BYTES or b"\0" in raw:
        raise RenewalPolicyError("renewal file size or content is invalid")
    try:
        document = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise RenewalPolicyError("renewal file is not valid UTF-8") from exc

    parameters = _direct_renewal_parameters(document)
    if parameters.get("authenticator") != ["webroot"]:
        raise RenewalPolicyError("renewal authenticator is not exactly webroot")

    installers = parameters.get("installer", [])
    if installers not in ([], ["None"]):
        raise RenewalPolicyError("renewal installer is not absent or exact None")

    if any(parameters.get(name) for name in HOOK_OPTIONS):
        raise RenewalPolicyError("renewal file contains a hook")


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: validate-renewal-profile.py RENEWAL_FILE", file=sys.stderr)
        return 2
    try:
        raw = Path(arguments[0]).read_bytes()
        validate_renewal_profile(raw)
    except (OSError, RenewalPolicyError) as exc:
        print(f"renewal policy error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
