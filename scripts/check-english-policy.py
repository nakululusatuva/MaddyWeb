#!/usr/bin/env python3
"""Reject non-English repository history using ASCII as the mechanical gate."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path, PurePosixPath

BINARY_SUFFIXES = frozenset(
    {
        ".7z",
        ".avif",
        ".bz2",
        ".eot",
        ".gif",
        ".gz",
        ".ico",
        ".jpeg",
        ".jpg",
        ".otf",
        ".pdf",
        ".png",
        ".tar",
        ".ttf",
        ".webp",
        ".woff",
        ".woff2",
        ".xz",
        ".zip",
    }
)
MAX_TEXT_BLOB_BYTES = 16 * 1024 * 1024


class PolicyViolation(RuntimeError):
    """An English-only repository policy violation."""


def run_git(repository: Path, *args: str) -> bytes:
    result = subprocess.run(  # noqa: S603 - arguments are passed without a shell
        ["git", *args],  # noqa: S607 - Git is the required command-line dependency
        cwd=repository,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise PolicyViolation(f"Git command failed: {' '.join(args)}: {detail}")
    return result.stdout


def first_non_ascii(value: bytes) -> int | None:
    return next((index for index, byte in enumerate(value) if byte > 0x7F), None)


def resolve_commit(repository: Path, ref: str) -> str:
    raw = run_git(repository, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
    commit = raw.strip().decode("ascii", errors="strict")
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise PolicyViolation(f"Git did not resolve {ref!r} to a SHA-1 commit")
    return commit


def commit_message(repository: Path, commit: str) -> bytes:
    raw = run_git(repository, "cat-file", "commit", commit)
    separator = raw.find(b"\n\n")
    if separator < 0:
        raise PolicyViolation(f"Malformed commit object: {commit}")
    return raw[separator + 2 :]


def check_message(repository: Path, commit: str) -> None:
    message = commit_message(repository, commit)
    offset = first_non_ascii(message)
    if offset is None:
        return
    line = message.count(b"\n", 0, offset) + 1
    raise PolicyViolation(f"Non-ASCII commit message at {commit}, line {line}")


def check_blob(path: str, data: bytes, commit: str) -> None:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in BINARY_SUFFIXES:
        return
    if len(data) > MAX_TEXT_BLOB_BYTES:
        raise PolicyViolation(
            f"Unreviewable text blob larger than {MAX_TEXT_BLOB_BYTES} bytes at {commit}:{path}"
        )
    if b"\0" in data:
        raise PolicyViolation(f"Binary data uses a non-binary file name at {commit}:{path}")
    offset = first_non_ascii(data)
    if offset is None:
        return
    line = data.count(b"\n", 0, offset) + 1
    raise PolicyViolation(f"Non-ASCII text at {commit}:{path}:{line}")


def check_tree(
    repository: Path,
    commit: str,
    checked_blobs: set[tuple[str, bool]],
) -> None:
    entries = run_git(repository, "ls-tree", "-r", "-z", commit).split(b"\0")
    for entry in entries:
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        path_offset = first_non_ascii(raw_path)
        if path_offset is not None:
            raise PolicyViolation(f"Non-ASCII tracked path at {commit}")
        path = raw_path.decode("ascii", errors="strict")
        _mode, object_type, raw_object_id = metadata.split(b" ")
        if object_type != b"blob":
            raise PolicyViolation(f"Unsupported tracked object type at {commit}:{path}")
        object_id = raw_object_id.decode("ascii")
        binary_allowed = PurePosixPath(path).suffix.lower() in BINARY_SUFFIXES
        cache_key = object_id, binary_allowed
        if cache_key in checked_blobs:
            continue
        data = run_git(repository, "cat-file", "blob", object_id)
        check_blob(path, data, commit)
        checked_blobs.add(cache_key)


def check_history(repository: Path, ref: str) -> tuple[int, int]:
    head = resolve_commit(repository, ref)
    commits = run_git(repository, "rev-list", "--reverse", head).decode("ascii").splitlines()
    checked_blobs: set[tuple[str, bool]] = set()
    for commit in commits:
        check_message(repository, commit)
        check_tree(repository, commit, checked_blobs)
    return len(commits), len(checked_blobs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--ref", default="HEAD")
    args = parser.parse_args()

    repository = args.repository.resolve()
    try:
        commits, blobs = check_history(repository, args.ref)
    except (PolicyViolation, UnicodeError, ValueError) as exc:
        print(f"English policy violation: {exc}", file=sys.stderr)
        return 1
    print(f"English policy passed: {commits} commits and {blobs} text/binary blobs checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
