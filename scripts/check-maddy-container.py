#!/usr/bin/env python3
"""Inspect the fixed Maddy container without mutating Docker state."""

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


def fail(message: str) -> Never:
    print(f"Maddy container check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--host-config", type=Path, required=True)
    args = parser.parse_args()

    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", args.container) is None:
        fail("container name is unsafe")

    if (
        not args.docker.is_absolute()
        or not args.docker.is_file()
        or not os.access(args.docker, os.X_OK)
    ):
        fail("Docker binary must be an absolute executable file")
    try:
        # The executable is required to be an absolute, existing executable above.
        completed = subprocess.run(  # noqa: S603
            [str(args.docker), "inspect", args.container],
            check=True,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        fail(f"docker inspect failed: {type(exc).__name__}")
    if len(completed.stdout) > 4 * 1024 * 1024:
        fail("docker inspect output exceeded 4 MiB")
    try:
        records = json.loads(completed.stdout)
    except UnicodeDecodeError, json.JSONDecodeError:
        fail("docker inspect returned invalid JSON")
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        fail("docker inspect did not return exactly one container")
    record = records[0]
    state = record.get("State")
    host_config = record.get("HostConfig")
    mounts = record.get("Mounts")
    network = record.get("NetworkSettings")
    if not all(isinstance(item, dict) for item in (state, host_config, network)) or not isinstance(
        mounts, list
    ):
        fail("container inspection is missing required structures")
    if state.get("Running") is not True:
        fail("Maddy container is not running")

    data_mounts = []
    for mount in mounts:
        if not isinstance(mount, dict):
            fail("container mount record is invalid")
        if mount.get("Destination") == "/data":
            data_mounts.append(mount)
    if len(data_mounts) != 1:
        fail("container must have exactly one /data directory mount")
    data_mount = data_mounts[0]
    if data_mount.get("Type") != "bind":
        fail("/data must be a host bind directory so atomic config replacement remains visible")
    source = data_mount.get("Source")
    if not isinstance(source, str):
        fail("configuration mount source is invalid")
    try:
        mounted_data = Path(source).resolve(strict=True)
        expected_config = args.host_config.resolve(strict=True)
    except OSError:
        fail("configuration mount source cannot be resolved")
    if not mounted_data.is_dir() or mounted_data / "maddy.conf" != expected_config:
        fail("--host-config must be the maddy.conf inside the directory bound to /data")

    port_bindings = host_config.get("PortBindings") or {}
    runtime_ports = network.get("Ports") or {}
    if not isinstance(port_bindings, dict) or not isinstance(runtime_ports, dict):
        fail("container port metadata is invalid")
    for metadata in (port_bindings, runtime_ports):
        for container_port, bindings in metadata.items():
            if str(container_port).split("/", 1)[0] == "1587":
                fail("Docker must not publish MaddyWeb's managed port 1587")
            if isinstance(bindings, list):
                for binding in bindings:
                    if isinstance(binding, dict) and str(binding.get("HostPort", "")) == "1587":
                        fail("Docker must not publish host port 1587")

    health = state.get("Health")
    health_status = health.get("Status") if isinstance(health, dict) else None
    report = {
        "status": "ok",
        "id": record.get("Id"),
        "running": True,
        "health": health_status,
        "mounts_sha256": digest(mounts),
        "ports_sha256": digest({"configured": port_bindings, "runtime": runtime_ports}),
        "restart_policy_sha256": digest(host_config.get("RestartPolicy")),
        "config_source": str(expected_config),
    }
    if not isinstance(report["id"], str) or len(report["id"]) != 64:
        fail("container ID is invalid")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
