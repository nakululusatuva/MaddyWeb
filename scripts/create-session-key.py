#!/usr/bin/env python3
"""Atomically create the production session key without exposing its bytes."""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import secrets
import stat
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Never


def fail(message: str) -> Never:
    print(f"session-key creation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--check-existing", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        fail("must run as root")
    try:
        config_meta = args.config.lstat()
        raw = args.config.read_bytes()
    except OSError as exc:
        fail(f"cannot read configuration: {exc}")
    if not stat.S_ISREG(config_meta.st_mode) or stat.S_ISLNK(config_meta.st_mode):
        fail("configuration must be a regular non-link file")
    try:
        config = tomllib.loads(raw.decode("utf-8"))
        key = Path(config["security"]["session_key_file"])
    except UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError:
        fail("configuration has no valid security.session_key_file")
    if key != Path("/var/lib/maddyweb/session.key"):
        fail("production session key path must be exactly /var/lib/maddyweb/session.key")
    try:
        parent_meta = key.parent.lstat()
    except OSError as exc:
        fail(f"cannot inspect session directory: {exc}")
    if not stat.S_ISDIR(parent_meta.st_mode) or stat.S_ISLNK(parent_meta.st_mode):
        fail("session directory must be a real directory")
    try:
        account = pwd.getpwnam("maddyweb")
        group = grp.getgrnam("maddyweb")
    except KeyError:
        fail("maddyweb user/group does not exist")

    if args.check_existing:
        if not os.path.lexists(key):
            fail("session key does not exist")
        metadata = key.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != account.pw_uid
            or metadata.st_gid != group.gr_gid
            or metadata.st_size < 32
        ):
            fail("existing session key failed ownership, mode, or size verification")
        print(
            json.dumps(
                {"status": "ok", "path": str(key), "bytes": metadata.st_size},
                sort_keys=True,
            )
        )
        return
    if os.path.lexists(key):
        fail("session key already exists; refusing to overwrite it")

    descriptor, temporary_name = tempfile.mkstemp(prefix=".session.key.", dir=key.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, account.pw_uid, group.gr_gid)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(secrets.token_bytes(48))
            handle.flush()
            os.fsync(handle.fileno())
        # link() is atomic and refuses an existing destination. It avoids the
        # overwrite behavior of os.replace for this create-once secret.
        os.link(temporary, key, follow_symlinks=False)
        temporary.unlink()
        directory_fd = os.open(key.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    metadata = key.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != account.pw_uid
        or metadata.st_gid != group.gr_gid
        or metadata.st_size < 32
    ):
        fail("created session key failed ownership, mode, or size verification")
    print(json.dumps({"status": "ok", "path": str(key), "bytes": metadata.st_size}, sort_keys=True))


if __name__ == "__main__":
    main()
