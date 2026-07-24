#!/usr/bin/env python3
"""Produce a fail-closed snapshot of a running Maddy container."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Never

NETWORK_MODE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


def fail(message: str) -> Never:
    print(f"Maddy container inspection failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def run_json(argv: list[str], maximum: int = 4 * 1024 * 1024) -> Any:
    try:
        # Callers construct argv from an absolute validated Docker executable.
        result = subprocess.run(  # noqa: S603
            argv,
            check=True,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        fail(f"fixed Docker inspection failed: {type(exc).__name__}")
    if not 0 < len(result.stdout) <= maximum:
        fail("Docker inspection output size is invalid")
    try:
        return json.loads(result.stdout)
    except UnicodeDecodeError, json.JSONDecodeError:
        fail("Docker inspection returned invalid JSON")


def one_record(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        fail(f"{label} did not return exactly one record")
    return value[0]


def canonical_hash(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def validated_network_mode(value: Any) -> str:
    if not isinstance(value, str) or not value:
        fail("Docker network mode is missing or invalid")
    if value == "none" or value.startswith("container:"):
        fail(f"Docker network mode {value!r} is unsupported")
    if value not in {"host", "bridge", "default"} and NETWORK_MODE_RE.fullmatch(value) is None:
        fail("Docker network mode is unsafe or unsupported")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--container", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", args.container) is None:
        fail("container name is unsafe")
    if (
        not args.docker.is_absolute()
        or not args.docker.is_file()
        or not os.access(args.docker, os.X_OK)
    ):
        fail("Docker binary must be an absolute executable file")

    container = one_record(
        run_json([str(args.docker), "inspect", args.container]),
        "docker inspect",
    )
    state = container.get("State")
    host_config = container.get("HostConfig")
    network = container.get("NetworkSettings")
    mounts = container.get("Mounts")
    config = container.get("Config")
    if not all(isinstance(item, dict) for item in (state, host_config, network, config)):
        fail("container metadata is incomplete")
    if (
        not isinstance(mounts, list)
        or state.get("Running") is not True
        or state.get("Paused") is True
    ):
        fail("container must be running and unpaused")
    network_mode = validated_network_mode(host_config.get("NetworkMode"))
    data_mounts = [
        item for item in mounts if isinstance(item, dict) and item.get("Destination") == "/data"
    ]
    if len(data_mounts) != 1:
        fail("container must have exactly one /data mount")
    data_mount = data_mounts[0]
    if data_mount.get("Type") not in {"volume", "bind"} or data_mount.get("RW") is not True:
        fail("/data must be one writable volume or bind mount")

    port_bindings = host_config.get("PortBindings") or {}
    runtime_ports = network.get("Ports") or {}
    if not isinstance(port_bindings, dict) or not isinstance(runtime_ports, dict):
        fail("container port metadata is invalid")
    for metadata in (port_bindings, runtime_ports):
        for container_port, bindings in metadata.items():
            if str(container_port).split("/", 1)[0] == "1587":
                fail("managed port 1587 must not be published by Docker")
            if isinstance(bindings, list) and any(
                isinstance(binding, dict) and str(binding.get("HostPort", "")) == "1587"
                for binding in bindings
            ):
                fail("host port 1587 must not be published by Docker")

    image_id = container.get("Image")
    if not isinstance(image_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        fail("container image ID is not digest-shaped")
    image = one_record(
        run_json([str(args.docker), "image", "inspect", image_id]),
        "docker image inspect",
    )
    repo_digests = image.get("RepoDigests")
    if not isinstance(repo_digests, list):
        fail("image has no repository digest metadata")
    pinned = sorted(
        value
        for value in repo_digests
        if isinstance(value, str) and re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", value)
    )
    if not pinned:
        fail("image is not associated with an immutable repository digest")

    container_id = container.get("Id")
    if not isinstance(container_id, str) or re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
        fail("container ID is invalid")
    report = {
        "status": "ok",
        "container": args.container,
        "container_id": container_id,
        "image_id": image_id,
        "image_digest": pinned[0],
        "data_mount": data_mount,
        "mounts_sha256": canonical_hash(mounts),
        "ports_sha256": canonical_hash({"configured": port_bindings, "runtime": runtime_ports}),
        "restart_policy": host_config.get("RestartPolicy"),
        "restart_policy_sha256": canonical_hash(host_config.get("RestartPolicy")),
        "network_mode": network_mode,
        "health": (
            state.get("Health", {}).get("Status") if isinstance(state.get("Health"), dict) else None
        ),
    }
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
