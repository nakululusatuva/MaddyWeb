#!/usr/bin/env python3
"""Safely read or atomically replace /data/maddy.conf in a named volume.

The volume name and immutable helper image are derived exclusively from the
selected running Maddy container.  No Docker daemon storage path is inspected
or accepted from the caller.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Never

MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_DOCKER_OUTPUT = 4 * 1024 * 1024
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
SHA256 = re.compile(r"[0-9a-f]{64}")
EXPORT_HEADER = re.compile(
    rb"MADDYWEB_CONFIG_V1 ([0-7]{3,4}) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9a-f]{64})\n"
)


class VolumeConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Identity:
    container_id: str
    image_id: str
    image_digest: str
    volume_name: str
    mounts_sha256: str
    volume_sha256: str

    def report(self) -> dict[str, str]:
        return {
            "container_id": self.container_id,
            "image_id": self.image_id,
            "image_digest": self.image_digest,
            "volume_name": self.volume_name,
            "mounts_sha256": self.mounts_sha256,
            "volume_sha256": self.volume_sha256,
        }


def fail(message: str) -> Never:
    raise VolumeConfigError(message)


def interrupted(signum: int, _frame: object) -> Never:
    fail(f"operation interrupted by signal {signum}")


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def assert_local_docker(docker: Path) -> None:
    if os.environ.get("DOCKER_HOST") or os.environ.get("DOCKER_CONTEXT"):
        fail("DOCKER_HOST and DOCKER_CONTEXT overrides are forbidden")
    context = run([str(docker), "context", "show"], maximum=1024)
    if context.stdout.strip() != b"default":
        fail("Docker must use the default local context")
    try:
        records = json.loads(run([str(docker), "context", "inspect", "default"]).stdout)
        endpoint = records[0]["Endpoints"]["docker"]["Host"]
    except UnicodeDecodeError, json.JSONDecodeError, IndexError, KeyError, TypeError:
        fail("default Docker context metadata is invalid")
    if endpoint != "unix:///var/run/docker.sock":
        fail("Docker daemon must be the fixed local system socket")


def run(
    argv: list[str],
    *,
    timeout: int = 30,
    maximum: int = MAX_DOCKER_OUTPUT,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        # Every executable and argument is individually validated and no shell
        # is involved.  Docker is the sole external dispatcher in this module.
        result = subprocess.run(  # noqa: S603
            argv,
            check=False,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        fail(f"fixed Docker operation failed: {type(exc).__name__}")
    if len(result.stdout) > maximum or len(result.stderr) > MAX_DOCKER_OUTPUT:
        fail("Docker operation output exceeded the safe limit")
    if check and result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()[-1000:]
        fail(f"Docker operation failed: {message or 'no diagnostic'}")
    return result


def json_records(docker: Path, argv: list[str], label: str) -> list[Any]:
    result = run([str(docker), *argv])
    try:
        value = json.loads(result.stdout)
    except UnicodeDecodeError, json.JSONDecodeError:
        fail(f"{label} returned invalid JSON")
    if not isinstance(value, list):
        fail(f"{label} did not return a JSON list")
    return value


def one_record(records: list[Any], label: str) -> dict[str, Any]:
    if len(records) != 1 or not isinstance(records[0], dict):
        fail(f"{label} did not return exactly one record")
    return records[0]


def inspect_identity(
    docker: Path,
    container_name: str,
    expected_container_id: str,
    required_state: str,
) -> Identity:
    container = one_record(
        json_records(docker, ["inspect", container_name], "container inspect"),
        "container inspect",
    )
    container_id = container.get("Id")
    if container_id != expected_container_id or CONTAINER_ID.fullmatch(str(container_id)) is None:
        fail("container name no longer identifies the reviewed container ID")
    state = container.get("State")
    mounts = container.get("Mounts")
    if not isinstance(state, dict) or not isinstance(mounts, list):
        fail("container state or mount metadata is incomplete")
    running_value = state.get("Running")
    paused_value = state.get("Paused")
    if not isinstance(running_value, bool) or not isinstance(paused_value, bool):
        fail("container running/paused state types are invalid")
    running = running_value
    paused = paused_value
    expected = {
        "running": (True, False),
        "paused": (True, True),
        "stopped": (False, False),
    }[required_state]
    if (running, paused) != expected:
        fail(f"selected Maddy container must be {required_state}")
    data_mounts = [
        item for item in mounts if isinstance(item, dict) and item.get("Destination") == "/data"
    ]
    if any(
        isinstance(item, dict) and str(item.get("Destination", "")).startswith("/data/")
        for item in mounts
    ):
        fail("nested mounts beneath /data are not supported")
    if len(data_mounts) != 1:
        fail("container must have exactly one /data mount")
    data_mount = data_mounts[0]
    name = data_mount.get("Name")
    if (
        data_mount.get("Type") != "volume"
        or data_mount.get("RW") is not True
        or not isinstance(name, str)
        or SAFE_NAME.fullmatch(name) is None
    ):
        fail("/data must be one writable, safely named Docker volume")

    volume = one_record(
        json_records(docker, ["volume", "inspect", name], "volume inspect"),
        "volume inspect",
    )
    if (
        volume.get("Name") != name
        or volume.get("Driver") != "local"
        or volume.get("Scope") not in (None, "local")
        or volume.get("Options") not in (None, {})
    ):
        fail("only an unmodified local Docker named volume is supported")
    mountpoint = volume.get("Mountpoint")
    if not isinstance(mountpoint, str) or data_mount.get("Source") != mountpoint:
        fail("container mount source does not match Docker volume metadata")

    attached = run(
        [
            str(docker),
            "container",
            "ls",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"volume={name}",
        ]
    )
    try:
        attached_ids = {
            line.strip() for line in attached.stdout.decode("ascii").splitlines() if line.strip()
        }
    except UnicodeDecodeError:
        fail("volume attachment list is not ASCII")
    if attached_ids != {container_id}:
        fail("named volume must be referenced only by the selected Maddy container")

    image_id = container.get("Image")
    if not isinstance(image_id, str) or IMAGE_ID.fullmatch(image_id) is None:
        fail("container image ID is invalid")
    image = one_record(
        json_records(docker, ["image", "inspect", image_id], "image inspect"),
        "image inspect",
    )
    if image.get("Id") != image_id:
        fail("reviewed container image ID is no longer available")
    repo_digests = image.get("RepoDigests")
    pinned = sorted(
        item
        for item in repo_digests or []
        if isinstance(item, str) and re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", item)
    )
    if not pinned:
        fail("Maddy helper image is not associated with an immutable repository digest")

    volume_identity = {
        "Name": volume.get("Name"),
        "Driver": volume.get("Driver"),
        "Scope": volume.get("Scope"),
        "Options": volume.get("Options"),
        "Labels": volume.get("Labels"),
    }
    return Identity(
        container_id=container_id,
        image_id=image_id,
        image_digest=pinned[0],
        volume_name=name,
        mounts_sha256=canonical_hash(mounts),
        volume_sha256=canonical_hash(volume_identity),
    )


def validate_private_file(path: Path, label: str) -> os.stat_result:
    if not path.is_absolute() or path == Path("/") or "," in str(path):
        fail(f"{label} path must be a specific comma-free absolute path")
    try:
        metadata = path.lstat()
        parent = path.parent.lstat()
    except OSError:
        fail(f"{label} path cannot be inspected")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > MAX_CONFIG_BYTES
    ):
        fail(f"{label} must be a single-link regular file of safe size")
    if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
        fail(f"{label} parent must be a real directory")
    if stat.S_IMODE(parent.st_mode) & 0o077:
        fail(f"{label} parent directory must be private")
    return metadata


def helper_path() -> Path:
    path = Path(__file__).resolve().with_name("docker-volume-config-helper.sh")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or "," in str(path)
    ):
        fail("fixed named-volume helper script is not trusted")
    return path


def docker_run_base(docker: Path, identity: Identity, name: str) -> list[str]:
    return [
        str(docker),
        "run",
        "--rm",
        "--name",
        name,
        "--label",
        "io.maddyweb.purpose=submission-volume-config",
        "--network",
        "none",
        "--read-only",
        "--pids-limit",
        "32",
        "--memory",
        "64m",
        "--cpus",
        "0.5",
        "--security-opt",
        "no-new-privileges:true",
        "--cap-drop",
        "ALL",
        "--user",
        "0:0",
    ]


def cleanup_helper(docker: Path, name: str) -> None:
    if SAFE_NAME.fullmatch(name) is None:
        fail("disposable named-volume helper name is unsafe")
    run([str(docker), "rm", "--force", name], timeout=15, check=False)
    # `docker inspect` uses exit 1 both for an absent object and for several
    # daemon/permission failures. Require a successful daemon query whose
    # exact-name result is empty so cleanup is positively proven.
    listing = run(
        [
            str(docker),
            "container",
            "ls",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"name=^/{name}$",
        ],
        timeout=15,
        maximum=1024,
    )
    if listing.stdout:
        fail("disposable named-volume helper still exists after cleanup")


def parse_exported_config(data: bytes, metadata: bytes, expected_hash: str) -> dict[str, Any]:
    try:
        fields = metadata.decode("ascii").strip().split(":")
    except UnicodeDecodeError:
        fail("configuration metadata is not ASCII")
    if len(fields) != 6 or fields[5] != "regular file":
        fail("configuration must be a regular file with fixed metadata")
    mode, uid, gid, size_text, links, _kind = fields
    if re.fullmatch(r"[0-7]{3,4}", mode) is None or any(
        re.fullmatch(r"[0-9]+", item) is None for item in (uid, gid, size_text, links)
    ):
        fail("configuration metadata is unsafe")
    mode_value = int(mode, 8)
    if mode_value & 0o7000 or mode_value & 0o022:
        fail("configuration mode has special or group/world-writable bits")
    size = int(size_text)
    if int(links) != 1 or not 0 < size <= MAX_CONFIG_BYTES or len(data) != size:
        fail("configuration size or link count is outside the safe range")
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash != expected_hash:
        fail("configuration changed while it was exported")
    return {
        "mode": mode,
        "uid": int(uid),
        "gid": int(gid),
        "size": size,
        "sha256": actual_hash,
    }


def fixed_exec(
    docker: Path,
    container_id: str,
    argv: list[str],
    *,
    maximum: int = MAX_DOCKER_OUTPUT,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    return run(
        [str(docker), "exec", "--user", "0:0", container_id, *argv],
        maximum=maximum,
        check=check,
    )


def run_running_export(docker: Path, identity: Identity) -> tuple[bytes, dict[str, Any]]:
    stat_argv = [
        "/bin/stat",
        "-c",
        "%a:%u:%g:%s:%h:%F",
        "/data/maddy.conf",
    ]
    metadata_before = fixed_exec(docker, identity.container_id, stat_argv).stdout
    link = fixed_exec(
        docker,
        identity.container_id,
        ["/usr/bin/readlink", "/data/maddy.conf"],
        maximum=MAX_CONFIG_BYTES,
        check=False,
    )
    if link.returncode == 0 or link.stdout:
        fail("configuration must not be a symlink")
    if link.returncode != 1:
        fail("configuration symlink check failed")
    hash_before_output = fixed_exec(
        docker,
        identity.container_id,
        ["/usr/bin/sha256sum", "/data/maddy.conf"],
        maximum=1024,
    ).stdout
    try:
        hash_before = hash_before_output.decode("ascii").split()[0]
    except UnicodeDecodeError, IndexError:
        fail("configuration hash output is invalid")
    if SHA256.fullmatch(hash_before) is None:
        fail("configuration hash output is invalid")
    data = fixed_exec(
        docker,
        identity.container_id,
        ["/bin/cat", "/data/maddy.conf"],
        maximum=MAX_CONFIG_BYTES,
    ).stdout
    metadata_after = fixed_exec(docker, identity.container_id, stat_argv).stdout
    hash_after_output = fixed_exec(
        docker,
        identity.container_id,
        ["/usr/bin/sha256sum", "/data/maddy.conf"],
        maximum=1024,
    ).stdout
    try:
        hash_after = hash_after_output.decode("ascii").split()[0]
    except UnicodeDecodeError, IndexError:
        fail("configuration hash output is invalid")
    if metadata_before != metadata_after or hash_before != hash_after:
        fail("configuration changed during the read-only export")
    return data, parse_exported_config(data, metadata_before, hash_before)


def run_helper_export(docker: Path, identity: Identity) -> tuple[bytes, dict[str, Any]]:
    helper = helper_path()
    name = f"maddyweb-submission-export-{os.urandom(8).hex()}"
    argv = [
        *docker_run_base(docker, identity, name),
        "--cap-add",
        "DAC_OVERRIDE",
        "--mount",
        f"type=volume,source={identity.volume_name},target=/data,readonly",
        "--mount",
        f"type=bind,source={helper},target=/maddyweb/helper.sh,readonly",
        "--entrypoint",
        "/bin/sh",
        identity.image_id,
        "/maddyweb/helper.sh",
        "export",
    ]
    try:
        result = run(argv, maximum=MAX_CONFIG_BYTES + 512)
    finally:
        cleanup_helper(docker, name)
    match = EXPORT_HEADER.match(result.stdout)
    if match is None:
        fail("named-volume helper returned an invalid export header")
    mode, uid, gid, size_text, expected_hash = (item.decode("ascii") for item in match.groups())
    data = result.stdout[match.end() :]
    size = int(size_text)
    if len(data) != size:
        fail("named-volume helper returned an invalid configuration size")
    metadata = f"{mode}:{uid}:{gid}:{size}:1:regular file\n".encode()
    return data, parse_exported_config(data, metadata, expected_hash)


def run_export(
    docker: Path,
    identity: Identity,
    required_state: str,
) -> tuple[bytes, dict[str, Any]]:
    if required_state == "running":
        return run_running_export(docker, identity)
    return run_helper_export(docker, identity)


def write_snapshot(path: Path, data: bytes) -> None:
    if not path.is_absolute() or path == Path("/") or "," in str(path):
        fail("output must be a specific comma-free absolute path")
    try:
        parent = path.parent.lstat()
    except OSError:
        fail("output parent cannot be inspected")
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        fail("output parent must be a private real directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        fail(f"cannot create private exported snapshot: {exc}")


def run_replace(
    docker: Path,
    identity: Identity,
    candidate: Path,
    expected_current: str,
    expected_candidate: str,
) -> None:
    validate_private_file(candidate, "candidate")
    data = candidate.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_candidate:
        fail("candidate content does not match its reviewed hash")
    helper = helper_path()
    name = f"maddyweb-submission-replace-{os.urandom(8).hex()}"
    nonce = os.urandom(16).hex()
    argv = [
        *docker_run_base(docker, identity, name),
        "--cap-add",
        "CHOWN",
        "--cap-add",
        "DAC_OVERRIDE",
        "--mount",
        f"type=volume,source={identity.volume_name},target=/data",
        "--mount",
        f"type=bind,source={candidate},target=/input/maddy.conf,readonly",
        "--mount",
        f"type=bind,source={helper},target=/maddyweb/helper.sh,readonly",
        "--entrypoint",
        "/bin/sh",
        identity.image_id,
        "/maddyweb/helper.sh",
        "replace",
        expected_current,
        expected_candidate,
        nonce,
    ]
    try:
        result = run(argv)
    finally:
        cleanup_helper(docker, name)
    expected = f"MADDYWEB_REPLACED_V1 {expected_candidate}\n".encode()
    if result.stdout != expected:
        fail("named-volume helper replacement acknowledgement is invalid")


def main() -> None:
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--expected-container-id", required=True)
    parser.add_argument("--state", choices=("running", "paused", "stopped"), required=True)
    parser.add_argument("--action", choices=("export", "replace"), required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--expected-current-sha256")
    parser.add_argument("--expected-candidate-sha256")
    args = parser.parse_args()

    try:
        if SAFE_NAME.fullmatch(args.container) is None:
            fail("container name is unsafe")
        if CONTAINER_ID.fullmatch(args.expected_container_id) is None:
            fail("expected container ID is invalid")
        if (
            not args.docker.is_absolute()
            or not args.docker.is_file()
            or not os.access(args.docker, os.X_OK)
        ):
            fail("Docker binary must be an absolute executable file")
        assert_local_docker(args.docker)
        identity = inspect_identity(
            args.docker,
            args.container,
            args.expected_container_id,
            args.state,
        )
        if args.action == "export":
            if args.output is None or any(
                value is not None
                for value in (
                    args.candidate,
                    args.expected_current_sha256,
                    args.expected_candidate_sha256,
                )
            ):
                fail("export requires only --output")
            data, config = run_export(args.docker, identity, args.state)
            # Re-inspection after helper removal detects container/name/volume
            # switches during the read operation.
            if (
                inspect_identity(
                    args.docker, args.container, args.expected_container_id, args.state
                )
                != identity
            ):
                fail("container or volume identity changed during export")
            write_snapshot(args.output, data)
            report: dict[str, Any] = {"status": "ok", "action": "export", **config}
        elif args.action == "replace":
            if (
                args.output is not None
                or args.candidate is None
                or SHA256.fullmatch(args.expected_current_sha256 or "") is None
                or SHA256.fullmatch(args.expected_candidate_sha256 or "") is None
            ):
                fail("replace requires candidate and two SHA-256 values")
            run_replace(
                args.docker,
                identity,
                args.candidate,
                args.expected_current_sha256,
                args.expected_candidate_sha256,
            )
            if (
                inspect_identity(
                    args.docker, args.container, args.expected_container_id, args.state
                )
                != identity
            ):
                fail("container or volume identity changed during replacement")
            data, config = run_export(args.docker, identity, args.state)
            if config["sha256"] != args.expected_candidate_sha256:
                fail("candidate read-back differs after replacement")
            report = {"status": "ok", "action": "replace", **config}
        report["identity"] = identity.report()
        print(json.dumps(report, sort_keys=True))
    except (VolumeConfigError, OSError) as exc:
        print(f"named-volume configuration failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
