#!/usr/bin/env python3
"""Bind a local wheel checksum to an explicit 40-character Git commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Never

MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


def fail(message: str) -> Never:
    print(f"release artifact verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def open_regular_non_link(
    path: Path,
    maximum: int | None = None,
) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot safely open {path}: {type(exc).__name__}")
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        os.close(descriptor)
        fail(f"must be a single-link regular file: {path}")
    if maximum is not None and not 0 < metadata.st_size <= maximum:
        os.close(descriptor)
        fail(f"file size is outside the allowed range: {path}")
    return descriptor, metadata


def read_regular(path: Path, maximum: int) -> bytes:
    descriptor, metadata = open_regular_non_link(path, maximum)
    data = bytearray()
    try:
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(descriptor)
    if len(data) != metadata.st_size:
        fail(f"file changed while being read: {path}")
    return bytes(data)


def sha256_and_copy(path: Path, destination: Path | None) -> str:
    source, metadata = open_regular_non_link(path, MAX_ARTIFACT_BYTES)
    digest = hashlib.sha256()
    output: int | None = None
    destination_created = False
    copied = 0
    try:
        if destination is not None:
            if not destination.is_absolute() or destination.name != path.name:
                fail("copy destination must be absolute and preserve the artifact filename")
            if not hasattr(os, "geteuid") or os.geteuid() != 0:
                fail("artifact copy requires root")
            parent = destination.parent
            parent_metadata = parent.lstat()
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or stat.S_ISLNK(parent_metadata.st_mode)
                or parent_metadata.st_uid != 0
                or stat.S_IMODE(parent_metadata.st_mode) != 0o700
            ):
                fail("artifact copy parent must be a root-owned 0700 directory")
            output_flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            output = os.open(destination, output_flags, 0o600)
            destination_created = True
        while chunk := os.read(source, 1024 * 1024):
            digest.update(chunk)
            copied += len(chunk)
            if output is not None:
                remaining = memoryview(chunk)
                while remaining:
                    written = os.write(output, remaining)
                    if written <= 0:
                        fail("artifact copy made no progress")
                    remaining = remaining[written:]
        if copied != metadata.st_size:
            fail("artifact changed while being copied")
        if output is not None:
            os.fsync(output)
    except BaseException:
        if output is not None:
            os.close(output)
            output = None
        if destination is not None and destination_created:
            destination.unlink(missing_ok=True)
        raise
    finally:
        os.close(source)
        if output is not None:
            os.close(output)
    if destination is not None:
        parent_descriptor = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--copy-to", type=Path)
    args = parser.parse_args()

    if not args.artifact.is_absolute() or not args.manifest.is_absolute():
        fail("artifact and manifest paths must be absolute")
    if args.artifact.suffix != ".whl":
        fail("artifact must be a wheel")
    if re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256) is None:
        fail("expected checksum must be 64 lowercase hexadecimal characters")
    try:
        manifest = json.loads(read_regular(args.manifest, 16 * 1024).decode("utf-8"))
    except OSError, UnicodeDecodeError, json.JSONDecodeError:
        fail("manifest is not valid UTF-8 JSON")
    required_keys = {"format", "commit", "artifact", "sha256"}
    if not isinstance(manifest, dict) or set(manifest) != required_keys:
        fail("manifest must contain exactly format, commit, artifact, and sha256")
    if manifest["format"] != "maddyweb-release-v1":
        fail("manifest format is not recognized")
    if (
        not isinstance(manifest["commit"], str)
        or re.fullmatch(r"[0-9a-f]{40}", manifest["commit"]) is None
    ):
        fail("manifest commit must be a full lowercase Git object ID")
    if manifest["artifact"] != args.artifact.name:
        fail("manifest artifact filename does not match")
    if manifest["sha256"] != args.expected_sha256:
        fail("manifest checksum differs from the explicit checksum")
    actual = sha256_and_copy(args.artifact, args.copy_to)
    if actual != args.expected_sha256:
        if args.copy_to is not None:
            args.copy_to.unlink(missing_ok=True)
        fail("artifact content checksum mismatch")
    print(
        json.dumps(
            {
                "status": "ok",
                "commit": manifest["commit"],
                "artifact": args.artifact.name,
                "sha256": actual,
                "copy": str(args.copy_to) if args.copy_to is not None else None,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
