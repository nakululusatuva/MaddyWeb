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


def docker_output(argv: list[str], maximum: int = 4 * 1024 * 1024) -> bytes:
    try:
        result = subprocess.run(  # noqa: S603
            argv,
            check=True,
            capture_output=True,
            timeout=15,
        )
    except OSError, subprocess.SubprocessError:
        fail("fixed Docker inspection failed")
    if not 0 < len(result.stdout) <= maximum or len(result.stderr) > maximum:
        fail("Docker inspection output size is invalid")
    return result.stdout


def assert_local_docker(docker: Path) -> None:
    if os.environ.get("DOCKER_HOST") or os.environ.get("DOCKER_CONTEXT"):
        fail("DOCKER_HOST and DOCKER_CONTEXT overrides are forbidden")
    context = docker_output([str(docker), "context", "show"], 1024)
    if context.strip() != b"default":
        fail("Docker must use the default local context")
    try:
        records = json.loads(docker_output([str(docker), "context", "inspect", "default"]))
        endpoint = records[0]["Endpoints"]["docker"]["Host"]
    except UnicodeDecodeError, json.JSONDecodeError, IndexError, KeyError, TypeError:
        fail("default Docker context metadata is invalid")
    if endpoint != "unix:///var/run/docker.sock":
        fail("Docker daemon must be the fixed local system socket")


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
    assert_local_docker(args.docker)
    try:
        records = json.loads(docker_output([str(args.docker), "inspect", args.container]))
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
    running_value = state.get("Running")
    paused_value = state.get("Paused")
    if not isinstance(running_value, bool) or not isinstance(paused_value, bool):
        fail("container running/paused state types are invalid")
    if running_value is not True or paused_value is True:
        fail("Maddy container must be running and unpaused")
    container_id = record.get("Id")
    if not isinstance(container_id, str) or re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
        fail("container ID is invalid")

    data_mounts = []
    for mount in mounts:
        if not isinstance(mount, dict):
            fail("container mount record is invalid")
        if mount.get("Destination") == "/data":
            data_mounts.append(mount)
        elif str(mount.get("Destination", "")).startswith("/data/"):
            fail("nested mounts beneath /data are not supported")
    if len(data_mounts) != 1:
        fail("container must have exactly one /data directory mount")
    data_mount = data_mounts[0]
    if data_mount.get("RW") is not True:
        fail("/data must be writable by the Maddy container")
    mount_type = data_mount.get("Type")
    volume_name: str | None = None
    volume_sha256: str | None = None
    if mount_type == "bind":
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
        config_source = str(expected_config)
        config_kind = "bind"
    elif mount_type == "volume":
        # Named-volume operation never accepts a Docker daemon host path.  The
        # only supported configuration location is the image contract path.
        if str(args.host_config) != "/data/maddy.conf":
            fail("named-volume mode requires --host-config exactly /data/maddy.conf")
        name = data_mount.get("Name")
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name) is None
        ):
            fail("named volume identity is unsafe")
        try:
            volume_records = json.loads(
                docker_output([str(args.docker), "volume", "inspect", name])
            )
        except UnicodeDecodeError, json.JSONDecodeError:
            fail("named volume inspection failed")
        if (
            not isinstance(volume_records, list)
            or len(volume_records) != 1
            or not isinstance(volume_records[0], dict)
        ):
            fail("named volume inspection did not return exactly one record")
        volume = volume_records[0]
        if (
            volume.get("Name") != name
            or volume.get("Driver") != "local"
            or volume.get("Scope") not in {None, "local"}
            or volume.get("Options") not in (None, {})
        ):
            fail("only an unmodified local Docker named volume is supported")
        mountpoint = volume.get("Mountpoint")
        if not isinstance(mountpoint, str) or data_mount.get("Source") != mountpoint:
            fail("container mount source does not match Docker volume metadata")
        try:
            users_output = docker_output(
                [
                    str(args.docker),
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--no-trunc",
                    "--filter",
                    f"volume={name}",
                ]
            ).decode("ascii")
        except UnicodeDecodeError:
            fail("named volume attachment inspection failed")
        users = {line.strip() for line in users_output.splitlines() if line.strip()}
        if users != {container_id}:
            fail("named volume must be referenced only by the selected Maddy container")
        volume_name = name
        volume_sha256 = digest(
            {
                "Name": volume.get("Name"),
                "Driver": volume.get("Driver"),
                "Scope": volume.get("Scope"),
                "Options": volume.get("Options"),
                "Labels": volume.get("Labels"),
            }
        )
        config_source = f"docker-volume:{name}:/data/maddy.conf"
        config_kind = "volume"
    else:
        fail("/data must be exactly one bind or local named volume")

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
        "config_kind": config_kind,
        "config_source": config_source,
        "volume_name": volume_name,
        "volume_sha256": volume_sha256,
    }
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
