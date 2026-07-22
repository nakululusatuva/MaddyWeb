#!/usr/bin/env python3
"""Verify CPython 3.14/free-threaded runtime and installed wheel contracts."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import sys
import sysconfig
from pathlib import PurePosixPath
from typing import Never


def fail(message: str) -> Never:
    print(f"python314-check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def distribution_has_extension(dist: importlib.metadata.Distribution) -> bool:
    for entry in dist.files or ():
        suffix = PurePosixPath(str(entry)).suffix.lower()
        if suffix in {".so", ".pyd", ".dll", ".dylib"}:
            return True
    return False


def verify_cp314t_wheel(dist: importlib.metadata.Distribution) -> list[str]:
    if not distribution_has_extension(dist):
        return []
    wheel = dist.read_text("WHEEL")
    if wheel is None:
        fail(f"extension distribution {dist.metadata['Name']} has no WHEEL metadata")
    tags = [
        line.partition(":")[2].strip() for line in wheel.splitlines() if line.startswith("Tag:")
    ]
    if not tags:
        fail(f"extension distribution {dist.metadata['Name']} has no wheel tags")
    # Wheel tags encode the free-threaded ABI in the second component.  The
    # canonical 3.14t wheels published by aiohttp/nh3 use
    # ``cp314-cp314t-<platform>`` (not ``cp314t-...``).
    if not any(
        len(parts := tag.split("-", 2)) == 3
        and parts[0] in {"cp314", "cp314t"}
        and parts[1] == "cp314t"
        for tag in tags
    ):
        fail(
            f"extension distribution {dist.metadata['Name']} is not tagged cp314t "
            f"(cp314 and abi3 are not accepted): {tags}"
        )
    return tags


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-build", choices=("standard", "free-threaded"), required=True)
    parser.add_argument("--expect-gil", choices=("enabled", "disabled"), required=True)
    parser.add_argument("--require-distribution", action="append", default=["maddyweb"])
    parser.add_argument("--import", dest="imports", action="append", default=[])
    parser.add_argument(
        "--skip-extension-wheel-check",
        action="store_true",
        help="diagnostic only; production/CI must not use this for a free-threaded build",
    )
    args = parser.parse_args()

    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14):
        fail(f"expected CPython 3.14, got {sys.implementation.name} {sys.version.split()[0]}")
    is_gil_enabled = getattr(sys, "_is_gil_enabled", None)
    if is_gil_enabled is None:
        fail("sys._is_gil_enabled() is unavailable")
    gil_disabled_build = bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
    gil_enabled = bool(is_gil_enabled())
    expected_build = args.expect_build == "free-threaded"
    expected_gil = args.expect_gil == "enabled"
    if gil_disabled_build != expected_build:
        fail(
            f"build mismatch: Py_GIL_DISABLED={int(gil_disabled_build)}, "
            f"expected {args.expect_build}"
        )
    if gil_enabled != expected_gil:
        fail(f"runtime GIL state is {gil_enabled}, expected {args.expect_gil}")
    if args.skip_extension_wheel_check and gil_disabled_build:
        fail("extension wheel checks cannot be skipped on a free-threaded build")

    for module_name in args.imports:
        importlib.import_module(module_name)
    # C extensions can request the GIL while they are imported.  The free-
    # threaded no-GIL gate is meaningful only after the complete application
    # import set has loaded, not merely at interpreter startup.
    gil_enabled_after_imports = bool(is_gil_enabled())
    if gil_enabled_after_imports != expected_gil:
        fail(
            "runtime GIL state changed after imports: "
            f"{gil_enabled_after_imports}, expected {args.expect_gil}"
        )

    distributions: list[dict[str, object]] = []
    for name in dict.fromkeys(args.require_distribution):
        try:
            dist = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            fail(f"required distribution is not installed: {name}")
        tags: list[str] = []
        if gil_disabled_build and not args.skip_extension_wheel_check:
            tags = verify_cp314t_wheel(dist)
        distributions.append(
            {"name": dist.metadata["Name"], "version": dist.version, "extension_tags": tags}
        )

    if gil_disabled_build and not args.skip_extension_wheel_check:
        for dist in importlib.metadata.distributions():
            verify_cp314t_wheel(dist)

    thread_context = getattr(sys.flags, "thread_inherit_context", None)
    report = {
        "status": "ok",
        "python": sys.version.split()[0],
        "cache_tag": sys.implementation.cache_tag,
        "py_gil_disabled": int(gil_disabled_build),
        "gil_enabled": gil_enabled_after_imports,
        "thread_inherit_context": thread_context,
        "distributions": distributions,
    }
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
