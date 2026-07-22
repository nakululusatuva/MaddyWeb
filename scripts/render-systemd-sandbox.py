#!/usr/bin/env python3
"""Render deterministic systemd path allow-lists from validated MaddyWeb config."""

from __future__ import annotations

import argparse
import os
import re
import stat
from pathlib import Path, PurePosixPath

from maddyweb.config import load_config

_SAFE_COMPONENT = re.compile(r"[A-Za-z0-9_+.][A-Za-z0-9_.+-]*")
_HEADER = "# Managed by MaddyWeb install.sh; do not edit.\n[Service]\n"


def systemd_path(value: object, label: str) -> str:
    """Return one conservative absolute path token safe for systemd directives."""
    text = str(value)
    path = PurePosixPath(text)
    if (
        not path.is_absolute()
        or text == "/"
        or str(path) != text
        or any(
            part in {".", ".."} or _SAFE_COMPONENT.fullmatch(part) is None
            for part in path.parts[1:]
        )
    ):
        raise ValueError(f"{label} is not a safe canonical systemd path")
    return text


def _parents(*values: object) -> tuple[str, ...]:
    result: list[str] = []
    for index, value in enumerate(values):
        path = PurePosixPath(systemd_path(value, f"certificate target {index + 1}"))
        parent = systemd_path(path.parent, f"certificate target parent {index + 1}")
        if parent not in result:
            result.append(parent)
    return tuple(result)


def render(config_path: Path) -> tuple[str, str]:
    config = load_config(config_path)
    web_temp = systemd_path(config.server.temp_dir, "server.temp_dir")
    temp_path = PurePosixPath(web_temp)
    private_roots = (PurePosixPath("/tmp"), PurePosixPath("/var/tmp"))  # noqa: S108
    # PrivateTmp replaces both roots with isolated writable mounts before path
    # allow-lists are applied.  Referring to a not-yet-created child there as a
    # required ReadWritePaths source makes systemd fail with 226/NAMESPACE.
    # Paths elsewhere still retain the strict, required leaf allow-list.
    if any(temp_path.is_relative_to(root) for root in private_roots):
        web = _HEADER
    else:
        web = _HEADER + f"ReadWritePaths={web_temp}\n"

    helper_lines: list[str] = []
    if config.certificates.enabled and config.certificates.webroot_roots:
        config_root = PurePosixPath(config.certificates.renewal_dir).parent
        helper_lines.append(
            "ReadWritePaths=-"
            f"{systemd_path(config_root, 'certificates renewal config root')}"
        )
        helper_lines.extend(
            (
                "ReadWritePaths=-/var/lib/letsencrypt",
                "ReadWritePaths=-/var/log/letsencrypt",
            )
        )
        for index, root in enumerate(config.certificates.webroot_roots, start=1):
            helper_lines.append(
                f"ReadWritePaths=-{systemd_path(root, f'certificates.webroot_roots[{index}]')}"
            )
    if config.maddy.mode == "native":
        helper_lines.append(
            f"ReadOnlyPaths={systemd_path(config.maddy.config_path, 'maddy.config_path')}"
        )
        helper_lines.append(
            f"ReadWritePaths={systemd_path(config.maddy.data_dir, 'maddy.data_dir')}"
        )
        if config.certificates.enabled:
            for parent in _parents(
                config.certificates.deployed_cert_path,
                config.certificates.deployed_key_path,
            ):
                helper_lines.append(f"ReadWritePaths={parent}")
    helper = _HEADER + "\n".join(helper_lines) + ("\n" if helper_lines else "")
    return web, helper


def _write_new(parent: Path, name: str, content: str) -> None:
    parent_stat = parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
        raise ValueError("output directory must be a real directory")
    parent_descriptor = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o644,
            dir_fd=parent_descriptor,
        )
        data = content.encode("utf-8")
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("systemd drop-in write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o644)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.output_dir.is_absolute():
        raise SystemExit("output directory must be absolute")
    web, helper = render(args.config)
    _write_new(args.output_dir, "SYSTEMD-WEB-PATHS.conf", web)
    _write_new(args.output_dir, "SYSTEMD-HELPER-PATHS.conf", helper)


if __name__ == "__main__":
    main()
