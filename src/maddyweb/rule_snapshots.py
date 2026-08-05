"""Atomic, privacy-preserving snapshots for Maddy delivery-time rules."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

DEFAULT_FILTER_STATE_DIR: Final[Path] = Path("/var/lib/maddyweb-filter")
DEFAULT_FILTER_SNAPSHOT_DIR: Final[Path] = DEFAULT_FILTER_STATE_DIR / "snapshots"
DEFAULT_FILTER_TOKEN_FILE: Final[Path] = DEFAULT_FILTER_STATE_DIR / "bridge.token"
MAX_SNAPSHOT_BYTES: Final[int] = 256 * 1024
SNAPSHOT_VERSION: Final[int] = 1
_SNAPSHOT_FILE_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\.json")


class RuleSnapshotError(RuntimeError):
    """A snapshot path or document violated the fixed storage contract."""


def snapshot_name(canonical_email: str) -> str:
    if not isinstance(canonical_email, str) or not canonical_email or not canonical_email.isascii():
        raise ValueError("canonical email must be non-empty ASCII text")
    return hashlib.sha256(canonical_email.encode("ascii")).hexdigest() + ".json"


def build_snapshot(canonical_email: str, rules: Sequence[Mapping[str, object]]) -> bytes:
    if not isinstance(rules, list | tuple) or len(rules) > 100:
        raise ValueError("rule snapshot contains too many rules")
    document: dict[str, object] = {
        "version": SNAPSHOT_VERSION,
        "account": canonical_email,
        "rules": [dict(rule) for rule in rules],
    }
    try:
        encoded = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("rule snapshot is not valid JSON") from exc
    if not 2 <= len(encoded) <= MAX_SNAPSHOT_BYTES:
        raise ValueError("rule snapshot exceeds its size limit")
    return encoded


def publish_snapshot(
    directory: Path,
    canonical_email: str,
    rules: Sequence[Mapping[str, object]],
    *,
    group_id: int | None = None,
) -> Path:
    """Atomically replace one account snapshot without exposing its address in a path."""

    _require_snapshot_directory(directory, writable=True)
    payload = build_snapshot(canonical_email, rules)
    target = directory / snapshot_name(canonical_email)
    if target.exists() or target.is_symlink():
        _require_snapshot_file(target)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".snapshot-", dir=directory)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o640)
        if group_id is not None and os.name == "posix":
            os.fchown(descriptor, 0, group_id)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        _sync_directory(directory)
        _require_snapshot_file(target)
        if target.read_bytes() != payload:
            raise RuleSnapshotError("rule snapshot read-back verification failed")
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return target


def remove_snapshot(directory: Path, canonical_email: str) -> None:
    _require_snapshot_directory(directory, writable=True)
    target = directory / snapshot_name(canonical_email)
    try:
        _require_snapshot_file(target)
    except FileNotFoundError:
        return
    target.unlink()
    _sync_directory(directory)


def replace_snapshot_set(
    directory: Path,
    snapshots: Mapping[str, Sequence[Mapping[str, object]]],
    *,
    group_id: int | None = None,
) -> None:
    """Replace every account snapshot from one authoritative metadata view.

    Existing snapshots are removed before any replacement is published. A
    crash or storage failure can therefore disable some filing rules, but it
    cannot leave an older rule set active after metadata has been restored.
    """

    _require_snapshot_directory(directory, writable=True)
    prepared = {
        account: build_snapshot(account, rules)
        for account, rules in sorted(snapshots.items())
    }
    entries = tuple(directory.iterdir())
    existing_snapshots: list[Path] = []
    unsafe_entry = False
    for entry in entries:
        if (
            _SNAPSHOT_FILE_RE.fullmatch(entry.name) is None
            and not entry.name.startswith(".snapshot-")
        ):
            unsafe_entry = True
            continue
        try:
            _require_snapshot_file(entry)
        except (FileNotFoundError, RuleSnapshotError):
            unsafe_entry = True
            continue
        existing_snapshots.append(entry)
    # Purge every verified old snapshot before reporting an unsafe entry. A
    # leftover temporary file or other unexpected directory entry may prevent
    # startup, but it must never preserve rules older than the authoritative
    # database view.
    for entry in existing_snapshots:
        entry.unlink()
    _sync_directory(directory)
    if unsafe_entry:
        raise RuleSnapshotError("rule snapshot directory contains an unsafe or unexpected entry")
    for account, rules in sorted(snapshots.items()):
        path = publish_snapshot(directory, account, rules, group_id=group_id)
        if path.read_bytes() != prepared[account]:
            raise RuleSnapshotError("rule snapshot set read-back verification failed")


def load_snapshot(directory: Path, canonical_email: str) -> dict[str, object] | None:
    _require_snapshot_directory(directory, writable=False)
    path = directory / snapshot_name(canonical_email)
    try:
        _require_snapshot_file(path)
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    if not 2 <= len(data) <= MAX_SNAPSHOT_BYTES:
        raise RuleSnapshotError("rule snapshot size is invalid")
    try:
        value = json.loads(data, object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise RuleSnapshotError("rule snapshot JSON is invalid") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "account", "rules"}
        or value.get("version") != SNAPSHOT_VERSION
        or value.get("account") != canonical_email
        or not isinstance(value.get("rules"), list)
        or len(value["rules"]) > 100
    ):
        raise RuleSnapshotError("rule snapshot document is invalid")
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _require_snapshot_directory(directory: Path, *, writable: bool) -> None:
    if not isinstance(directory, Path) or not directory.is_absolute() or directory == Path("/"):
        raise RuleSnapshotError("rule snapshot directory must be a specific absolute path")
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or directory.is_symlink():
        raise RuleSnapshotError("rule snapshot directory must not be a symlink")
    if os.name == "posix":
        mode = stat.S_IMODE(metadata.st_mode)
        if mode & 0o007 or (writable and metadata.st_uid != os.geteuid()):
            raise RuleSnapshotError("rule snapshot directory permissions are unsafe")


def _require_snapshot_file(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o007
    ):
        raise RuleSnapshotError("rule snapshot must be a private single-link regular file")


def _sync_directory(directory: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(
        directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "DEFAULT_FILTER_SNAPSHOT_DIR",
    "DEFAULT_FILTER_STATE_DIR",
    "DEFAULT_FILTER_TOKEN_FILE",
    "MAX_SNAPSHOT_BYTES",
    "RuleSnapshotError",
    "build_snapshot",
    "load_snapshot",
    "publish_snapshot",
    "remove_snapshot",
    "replace_snapshot_set",
    "snapshot_name",
]
