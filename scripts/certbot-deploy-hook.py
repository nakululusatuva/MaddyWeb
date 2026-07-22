#!/usr/bin/env python3
# Managed by MaddyWeb install.sh; do not edit.
"""Synchronize one completed Certbot lineage through MaddyWeb's deploy path.

This is a post-issuance adapter only.  It never invokes the Certbot executable;
the sole mutation is the existing transactional deploy, fingerprint read-back,
and Maddy reload implementation.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
import tomllib
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

_PRODUCTION_CONFIG = Path("/etc/maddyweb/config.toml")
_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_LINEAGE_CHARACTERS = 4096
_CERTIFICATE_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,252}\Z")
_FINGERPRINT = re.compile(r"\A(?:[0-9A-F]{2}:){31}[0-9A-F]{2}\Z")


class HookError(RuntimeError):
    """The hook input or deployment state is unsafe or ambiguous."""


def _effective_uid() -> int:
    getter = getattr(os, "geteuid", None)
    if not callable(getter):
        raise HookError("the Certbot deploy hook requires a POSIX runtime")
    return int(getter())


def _lineage_from_environment(environment: Mapping[str, str]) -> tuple[Path, str]:
    value = environment.get("RENEWED_LINEAGE")
    if not value or len(value) > _MAX_LINEAGE_CHARACTERS:
        raise HookError("RENEWED_LINEAGE is missing or too long")
    if "%" in value or "\\" in value:
        raise HookError("RENEWED_LINEAGE contains a forbidden character")
    if any(
        character.isspace() or unicodedata.category(character).startswith("C")
        for character in value
    ):
        raise HookError("RENEWED_LINEAGE contains whitespace or a control character")
    if not value.startswith("/"):
        raise HookError("RENEWED_LINEAGE must be absolute")
    components = value.split("/")
    if components[0] or any(component in {"", ".", ".."} for component in components[1:]):
        raise HookError("RENEWED_LINEAGE is not a canonical POSIX path")
    name = components[-1]
    if name.startswith("-") or _CERTIFICATE_NAME.fullmatch(name) is None:
        raise HookError("RENEWED_LINEAGE has an invalid certificate name")
    pure_path = PurePosixPath(value)
    if str(pure_path) != value:
        raise HookError("RENEWED_LINEAGE is not a canonical POSIX path")
    return Path(value), name


def _assert_secure_directory(path: Path, *, owner_uid: int, description: str) -> None:
    if os.name != "posix" or not path.is_absolute():
        raise HookError(f"{description} is not a safe absolute POSIX directory")
    current = Path("/")
    trusted_owners = {0, owner_uid}
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise HookError(f"{description} is unavailable") from exc
        mode = stat.S_IMODE(metadata.st_mode)
        sticky_root = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
        if not stat.S_ISDIR(metadata.st_mode):
            raise HookError(f"{description} is not a trusted real directory")
        if current == path:
            if metadata.st_uid != owner_uid or mode & 0o022:
                raise HookError(f"{description} is not a trusted real directory")
        elif metadata.st_uid not in trusted_owners or (mode & 0o022 and not sticky_root):
            raise HookError(f"{description} has an untrusted ancestor")


def _read_bounded_file(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            raise HookError("configuration changed while being read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise HookError("configuration changed while being read")
    return b"".join(chunks)


def _load_secure_config(path: Path, *, fixture: bool, effective_uid: int) -> Any:
    if not path.is_absolute():
        raise HookError("configuration path must be absolute")
    if not fixture and path != _PRODUCTION_CONFIG:
        raise HookError("production configuration path is not fixed")
    owner_uid = effective_uid if fixture else 0
    _assert_secure_directory(
        path.parent,
        owner_uid=owner_uid,
        description="configuration parent",
    )
    expected_group: int | None = None
    if not fixture:
        try:
            import grp

            expected_group = int(grp.getgrnam("maddyweb").gr_gid)
            parent_metadata = path.parent.lstat()
        except (ImportError, KeyError, OSError) as exc:
            raise HookError("maddyweb configuration group is unavailable") from exc
        if (
            parent_metadata.st_gid != expected_group
            or stat.S_IMODE(parent_metadata.st_mode) != 0o750
        ):
            raise HookError("configuration parent metadata is unsafe")
    required_flags = ("O_CLOEXEC", "O_NOFOLLOW")
    if os.name != "posix" or any(not hasattr(os, name) for name in required_flags):
        raise HookError("secure configuration open is unavailable")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != owner_uid
            or (expected_group is not None and metadata.st_gid != expected_group)
            or mode & 0o022
            or (not fixture and mode != 0o640)
            or not 0 < metadata.st_size <= _MAX_CONFIG_BYTES
        ):
            raise HookError("configuration file metadata is unsafe")
        raw = _read_bounded_file(descriptor, metadata.st_size)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(after, field) != getattr(metadata, field) for field in stable_fields):
            raise HookError("configuration changed while being read")
    except HookError:
        raise
    except OSError as exc:
        raise HookError("configuration file cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise HookError("configuration is not valid UTF-8 TOML") from exc
    try:
        from maddyweb.config import AppConfig

        return AppConfig.from_dict(parsed)
    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        raise HookError("configuration validation failed") from exc


def _validate_lineage_location(
    lineage: Path,
    name: str,
    certificate_config: Any,
    *,
    owner_uid: int,
) -> bool:
    live_dir = Path(certificate_config.live_dir)
    expected = live_dir / name
    if lineage != expected:
        raise HookError("RENEWED_LINEAGE does not exactly match the configured live directory")
    _assert_secure_directory(
        live_dir,
        owner_uid=owner_uid,
        description="certificate live directory",
    )
    _assert_secure_directory(
        lineage,
        owner_uid=owner_uid,
        description="renewed lineage",
    )
    try:
        resolved_live = live_dir.resolve(strict=True)
        resolved_lineage = lineage.resolve(strict=True)
    except OSError as exc:
        raise HookError("renewed lineage cannot be resolved safely") from exc
    if resolved_lineage.parent != resolved_live or resolved_lineage != resolved_live / name:
        raise HookError("renewed lineage escapes the configured live directory")
    return certificate_config.enabled is True and name in tuple(certificate_config.names)


def _build_certificate_manager(config: Any) -> Any:
    try:
        from maddyweb import cli as cli_module
        from maddyweb.maddy import MaddyService, SubprocessRunner
    except (ImportError, AttributeError) as exc:
        raise HookError("MaddyWeb certificate deployment API is unavailable") from exc
    manager_factory = getattr(cli_module, "_certificate_manager", None)
    spool_factory = getattr(cli_module, "_private_helper_spool_directory", None)
    if not callable(manager_factory) or not callable(spool_factory):
        raise HookError("MaddyWeb certificate deployment API is unavailable")
    runner = SubprocessRunner()
    maddy = MaddyService.from_config(config.maddy, runner=runner)
    return manager_factory(config, runner, maddy, spool_factory())


def _verified_source_fingerprint(report: Any) -> str:
    if not isinstance(report, Mapping):
        raise HookError("certificate status returned an invalid report")
    source = report.get("source")
    if not isinstance(source, Mapping) or source.get("error") is not None:
        raise HookError("renewed source certificate is invalid")
    fingerprint = source.get("sha256_fingerprint")
    if not isinstance(fingerprint, str) or _FINGERPRINT.fullmatch(fingerprint) is None:
        raise HookError("renewed source certificate has no valid fingerprint")
    return fingerprint


def _verify_deployed_report(report: Any) -> None:
    source_fingerprint = _verified_source_fingerprint(report)
    if not isinstance(report, Mapping):  # Narrowed above; keeps type checkers explicit.
        raise HookError("certificate status returned an invalid report")
    deployed = report.get("deployed")
    if not isinstance(deployed, Mapping) or deployed.get("error") is not None:
        raise HookError("deployed certificate status is invalid")
    deployed_fingerprint = deployed.get("sha256_fingerprint")
    if deployed_fingerprint != source_fingerprint or report.get("fingerprints_match") is not True:
        raise HookError("deployed certificate fingerprint does not match the renewed source")


def _deploy_and_verify(
    config: Any,
    name: str,
    *,
    manager_factory: Callable[[Any], Any] = _build_certificate_manager,
) -> None:
    manager = manager_factory(config)
    status = getattr(manager, "deployment_status", None)
    deploy = getattr(manager, "_deploy_and_reload", None)
    if not callable(status) or not callable(deploy):
        raise HookError("MaddyWeb certificate deployment API is unavailable")
    _verified_source_fingerprint(status(name))
    deploy(name)
    _verify_deployed_report(status(name))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MaddyWeb Certbot deploy hook")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--fixture", action="store_true", help=argparse.SUPPRESS)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        effective_uid = _effective_uid()
        if arguments.fixture:
            if effective_uid == 0:
                raise HookError("root cannot use fixture overrides")
        elif effective_uid != 0:
            raise HookError("the production Certbot deploy hook must run as root")
        lineage, name = _lineage_from_environment(os.environ)
        config = _load_secure_config(
            arguments.config,
            fixture=bool(arguments.fixture),
            effective_uid=effective_uid,
        )
        owner_uid = effective_uid if arguments.fixture else 0
        managed = _validate_lineage_location(
            lineage,
            name,
            config.certificates,
            owner_uid=owner_uid,
        )
        if not managed:
            print(f"maddyweb_certbot_deploy=ignored name={name}")
            return 0
        _deploy_and_verify(config, name)
    except HookError, OSError, RuntimeError, ValueError:
        print("maddyweb Certbot deploy hook failed closed", file=sys.stderr)
        return 1
    print(f"maddyweb_certbot_deploy=ok name={name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
