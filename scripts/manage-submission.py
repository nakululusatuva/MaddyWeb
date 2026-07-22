#!/usr/bin/env python3
"""Safely add/remove MaddyWeb's marked local Submission listener block."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Never

MAX_CONFIG_BYTES = 4 * 1024 * 1024
BEGIN_MARKER = "# BEGIN MADDYWEB MANAGED SUBMISSION v1"
END_MARKER = "# END MADDYWEB MANAGED SUBMISSION v1"
MANAGED_HEADER = "submission tcp://127.0.0.1:1587 {"
REQUIRED_TOKENS = ("authorize_sender", "local_routing", "dkim", "remote_queue")
REQUIRED_SOURCE_PATTERNS = (
    r"\bsource\s+\$\(local_domains\)\s*\{",
    r"\bauthorize_sender\s*\{",
    r"\bprepare_email\s+&local_rewrites\b",
    r"\buser_to_email\s+identity\b",
    r"\bdestination\s+postmaster\s+\$\(local_domains\)\s*\{",
    r"\bdeliver_to\s+&local_routing\b",
    r"\bdefault_destination\s*\{",
    r"\bdkim\s+\$\(primary_domain\)\s+\$\(local_domains\)\s+default\b",
    r"\bdeliver_to\s+&remote_queue\b",
    r"\bdefault_source\s*\{",
)
SUBMISSION_RE = re.compile(r"^\s*submission\s+(.+?)\s*\{\s*$")
DIRECTIVE_RE = re.compile(r"^(\s*)(tls|auth)\s+[^{}#]+\s*(?:#.*)?$")


class EditError(RuntimeError):
    pass


@dataclass(frozen=True)
class Block:
    start: int
    end: int
    depth_by_line: tuple[int, ...]


@dataclass(frozen=True)
class Snapshot:
    path: Path
    data: bytes
    mode: int
    uid: int
    gid: int
    inode: int
    device: int
    mtime_ns: int

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def fail(message: str) -> Never:
    raise EditError(message)


def strip_comments_and_strings(line: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escaped = False
    for character in line:
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            output.append(" ")
            continue
        if character in {'"', "'"}:
            quote = character
            output.append(" ")
        elif character == "#":
            break
        else:
            output.append(character)
    if quote is not None:
        fail("multiline or unterminated quoted strings are not supported")
    return "".join(output)


def find_submission_blocks(lines: list[str]) -> list[Block]:
    blocks: list[Block] = []
    depth = 0
    active_start: int | None = None
    active_depths: list[int] = []
    for index, line in enumerate(lines):
        code = strip_comments_and_strings(line).strip()
        depth_before = depth
        if depth == 0 and SUBMISSION_RE.fullmatch(code):
            active_start = index
            active_depths = []
        if active_start is not None:
            active_depths.append(depth_before)
        depth += code.count("{") - code.count("}")
        if depth < 0:
            fail("configuration has an unmatched closing brace")
        if active_start is not None and depth == 0:
            blocks.append(Block(active_start, index, tuple(active_depths)))
            active_start = None
            active_depths = []
    if depth != 0 or active_start is not None:
        fail("configuration has an unmatched opening brace")
    return blocks


def code_for(lines: list[str], block: Block) -> str:
    block_lines = lines[block.start : block.end + 1]
    return "\n".join(strip_comments_and_strings(line) for line in block_lines)


def managed_marker_range(lines: list[str]) -> tuple[int, int] | None:
    begins = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == BEGIN_MARKER]
    ends = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == END_MARKER]
    if not begins and not ends:
        return None
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        fail("managed Submission markers are incomplete, duplicated, or out of order")
    return begins[0], ends[0]


def source_submission(lines: list[str]) -> Block:
    candidates: list[Block] = []
    for block in find_submission_blocks(lines):
        text = code_for(lines, block)
        lowered = text.lower()
        if all(re.search(rf"\b{re.escape(token)}\b", lowered) for token in REQUIRED_TOKENS):
            candidates.append(block)
    if len(candidates) != 1:
        fail(
            "expected exactly one default submission block containing "
            "authorize_sender, local_routing, DKIM, and remote_queue rules"
        )
    candidate = candidates[0]
    header = strip_comments_and_strings(lines[candidate.start]).strip()
    if "tls://0.0.0.0:465" not in header or "tcp://0.0.0.0:587" not in header:
        fail("default submission listener does not match the supported 465/587 layout")
    normalized = code_for(lines, candidate).lower()
    for pattern in REQUIRED_SOURCE_PATTERNS:
        if re.search(pattern, normalized) is None:
            fail(f"default submission block is missing required structure: {pattern}")
    return candidate


def build_managed(source: str) -> str:
    lines = source.splitlines(keepends=True)
    if managed_marker_range(lines) is not None:
        fail("managed Submission block already exists")
    for block in find_submission_blocks(lines):
        header = strip_comments_and_strings(lines[block.start])
        if re.search(r"(?<!\d)1587(?!\d)", header):
            fail("a Submission endpoint already references port 1587")
    block = source_submission(lines)
    inner = list(lines[block.start + 1 : block.end])
    tls_indexes: list[int] = []
    auth_indexes: list[int] = []
    for relative, line in enumerate(inner, start=1):
        # depth_by_line is the global depth before the line; direct children of
        # a top-level submission block have depth one.
        if block.depth_by_line[relative] != 1:
            continue
        match = DIRECTIVE_RE.fullmatch(line.rstrip("\r\n"))
        if match is None:
            continue
        if match.group(2) == "tls":
            tls_indexes.append(relative - 1)
        elif match.group(2) == "auth":
            auth_indexes.append(relative - 1)
    if tls_indexes or len(auth_indexes) != 1:
        fail(
            "default submission block must have no top-level tls directive "
            "and exactly one auth directive"
        )
    auth_source = strip_comments_and_strings(inner[auth_indexes[0]]).strip()
    if auth_source != "auth &local_authdb":
        fail("default submission auth reference must be exactly &local_authdb")

    limit_starts = [
        relative
        for relative, line in enumerate(inner, start=1)
        if block.depth_by_line[relative] == 1
        and strip_comments_and_strings(line).strip() == "limits {"
    ]
    if len(limit_starts) != 1 or re.search(r"(?m)^\s*all\s+concurrency\b", code_for(lines, block)):
        fail("default submission limits layout is not supported")
    limit_start = limit_starts[0]
    limit_ends = [
        relative
        for relative, line in enumerate(inner, start=1)
        if relative > limit_start
        and block.depth_by_line[relative] == 2
        and strip_comments_and_strings(line).strip() == "}"
    ]
    if not limit_ends:
        fail("default submission limits block is not balanced")
    limit_end = limit_ends[0]

    newline = "\r\n" if "\r\n" in source else "\n"
    limits_indent = re.match(r"^\s*", inner[limit_start - 1]).group(0)  # type: ignore[union-attr]
    auth_indent = re.match(r"^\s*", inner[auth_indexes[0]]).group(0)  # type: ignore[union-attr]
    inner.insert(limit_end - 1, f"{limits_indent}    all concurrency 2{newline}")
    # Preserve the exact real auth directive. The managed loopback listener is
    # reachable by other local processes and must never become unauthenticated.
    inner.insert(0, f"{auth_indent}tls off{newline}")
    managed = "".join(
        [
            BEGIN_MARKER + newline,
            MANAGED_HEADER + newline,
            *inner,
            "}" + newline,
            END_MARKER + newline,
        ]
    )
    result = source
    if not result.endswith(("\n", "\r")):
        result += newline
    result += newline + managed
    # Parse the complete result and validate that the copied routing/security
    # rules survived exactly as recognizable tokens.
    result_lines = result.splitlines(keepends=True)
    marker = managed_marker_range(result_lines)
    if marker is None:
        fail("generated managed block markers are missing")
    managed_text = "".join(result_lines[marker[0] + 1 : marker[1]])
    if not managed_text.startswith(MANAGED_HEADER + newline):
        fail("generated managed block has an invalid header")
    lowered = "\n".join(
        strip_comments_and_strings(line) for line in managed_text.splitlines()
    ).lower()
    if not all(re.search(rf"\b{re.escape(token)}\b", lowered) for token in REQUIRED_TOKENS):
        fail("generated managed block lost a required routing rule")
    if "auth dummy" in lowered or lowered.count("auth &local_authdb") != 1:
        fail("generated managed block did not preserve exactly one real auth reference")
    return result


def remove_managed(source: str) -> str:
    lines = source.splitlines(keepends=True)
    marker = managed_marker_range(lines)
    if marker is None:
        fail("managed Submission block does not exist")
    begin, end = marker
    managed_lines = lines[begin + 1 : end]
    if not managed_lines or managed_lines[0].rstrip("\r\n") != MANAGED_HEADER:
        fail("managed marker does not contain the expected listener block")
    managed_text = "".join(managed_lines)
    lowered = "\n".join(
        strip_comments_and_strings(line) for line in managed_text.splitlines()
    ).lower()
    if "auth dummy" in lowered:
        fail("managed block contains forbidden dummy authentication")
    for token in (*REQUIRED_TOKENS, "tls off", "auth &local_authdb", "all concurrency 2"):
        if token not in lowered:
            fail("managed block was modified; refusing imprecise removal")
    # Ensure the marker encloses exactly one complete Submission block.
    managed_blocks = find_submission_blocks(managed_lines)
    expected_end = len(managed_lines) - 1
    if (
        len(managed_blocks) != 1
        or managed_blocks[0].start != 0
        or managed_blocks[0].end != expected_end
    ):
        fail("managed marker contains unexpected content")
    result_lines = lines[:begin] + lines[end + 1 :]
    # Addition introduces one separating blank line. Remove only that blank
    # line, never any non-whitespace content outside the markers.
    if begin >= 1 and lines[begin - 1].strip() == "":
        result_lines = lines[: begin - 1] + lines[end + 1 :]
    return "".join(result_lines)


@contextlib.contextmanager
def locked_snapshot(path: Path):
    if not path.is_absolute() or path == Path("/"):
        fail("configuration path must be a specific absolute path")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot safely open configuration: {exc}")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail("configuration must be a single-link regular file")
        if metadata.st_size <= 0 or metadata.st_size > MAX_CONFIG_BYTES:
            fail("configuration size is outside the safe range")
        data = b""
        while len(data) <= MAX_CONFIG_BYTES:
            chunk = os.read(descriptor, min(128 * 1024, MAX_CONFIG_BYTES + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        if len(data) != metadata.st_size:
            fail("configuration changed while being read")
        yield Snapshot(
            path=path,
            data=data,
            mode=stat.S_IMODE(metadata.st_mode),
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            inode=metadata.st_ino,
            device=metadata.st_dev,
            mtime_ns=metadata.st_mtime_ns,
        )
    finally:
        os.close(descriptor)


def decode(data: bytes) -> str:
    if b"\0" in data:
        fail("configuration contains a NUL byte")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"configuration is not UTF-8: {exc}")


def create_backup(snapshot: Snapshot, directory: Path) -> Path:
    if not directory.is_absolute() or directory == Path("/"):
        fail("backup directory must be a specific absolute path")
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("backup destination must be a real directory")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        fail("backup destination must not grant group/other access")
    name = f"maddy.conf.{int(time.time())}.{snapshot.sha256[:12]}.bak"
    target = directory / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(target, flags, 0o600)
    try:
        os.write(descriptor, snapshot.data)
        os.fsync(descriptor)
        owner = 0 if os.geteuid() == 0 else snapshot.uid
        group = 0 if os.geteuid() == 0 else snapshot.gid
        os.fchown(descriptor, owner, group)
    finally:
        os.close(descriptor)
    directory_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return target


def atomic_replace(snapshot: Snapshot, data: bytes) -> None:
    current = snapshot.path.stat(follow_symlinks=False)
    if (
        current.st_ino != snapshot.inode
        or current.st_dev != snapshot.device
        or current.st_size != len(snapshot.data)
        or current.st_mtime_ns != snapshot.mtime_ns
    ):
        fail("configuration changed before replacement")
    verify_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    verify_descriptor = os.open(snapshot.path, verify_flags)
    try:
        verify_metadata = os.fstat(verify_descriptor)
        current_data = b""
        while len(current_data) <= MAX_CONFIG_BYTES:
            chunk = os.read(
                verify_descriptor,
                min(128 * 1024, MAX_CONFIG_BYTES + 1 - len(current_data)),
            )
            if not chunk:
                break
            current_data += chunk
    finally:
        os.close(verify_descriptor)
    if (
        verify_metadata.st_ino != snapshot.inode
        or verify_metadata.st_dev != snapshot.device
        or hashlib.sha256(current_data).digest() != hashlib.sha256(snapshot.data).digest()
    ):
        fail("configuration content changed before replacement")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{snapshot.path.name}.",
        dir=snapshot.path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, snapshot.mode)
        os.fchown(descriptor, snapshot.uid, snapshot.gid)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, snapshot.path)
        directory_fd = os.open(snapshot.path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--action",
        choices=("check-add", "check-remove", "add", "remove", "restore"),
        required=True,
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--expected-current-sha256")
    args = parser.parse_args()

    try:
        with locked_snapshot(args.config) as snapshot:
            source = decode(snapshot.data)
            backup_path: Path | None = None
            if args.action in {"check-add", "add"}:
                result = build_managed(source).encode("utf-8")
            elif args.action in {"check-remove", "remove"}:
                result = remove_managed(source).encode("utf-8")
            else:
                if args.backup is None or args.expected_current_sha256 is None:
                    fail("restore requires --backup and --expected-current-sha256")
                if snapshot.sha256 != args.expected_current_sha256:
                    fail("current configuration hash differs from the failed candidate")
                with locked_snapshot(args.backup) as backup:
                    result = backup.data

            if args.action in {"add", "remove"}:
                if args.backup_dir is None:
                    fail("mutating actions require --backup-dir")
                backup_path = create_backup(snapshot, args.backup_dir)
                atomic_replace(snapshot, result)
            elif args.action == "restore":
                atomic_replace(snapshot, result)

            print(
                json.dumps(
                    {
                        "status": "ok",
                        "action": args.action,
                        "before_sha256": snapshot.sha256,
                        "after_sha256": hashlib.sha256(result).hexdigest(),
                        "backup": str(backup_path) if backup_path else None,
                    },
                    sort_keys=True,
                )
            )
    except (EditError, OSError) as exc:
        print(f"managed Submission edit failed: {exc}", file=os.sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
