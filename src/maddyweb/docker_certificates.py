"""Docker-only certificate inspection and transactional deployment.

The privileged helper constructs this adapter exclusively from trusted
configuration.  No browser value can choose a container, executable or path.
Private-key bytes and container paths never appear in public status values or
exception messages.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import ssl
import stat
import tempfile
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, Self

from .certificates import (
    MAX_CERTIFICATE_BYTES,
    MAX_PRIVATE_KEY_BYTES,
    CertificateCommandError,
    CertificateStatus,
    CertificateValidationError,
    UnknownCertificate,
)

_CONTAINER_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_CERTIFICATE_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,252}\Z")
_CERTIFICATE_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+"
    rb"-----END CERTIFICATE-----",
    re.DOTALL,
)
_OWNER_RE = re.compile(rb"\A(0|[1-9]\d{0,9}):(0|[1-9]\d{0,9})\n?\Z")
_DOCKER_EXECUTABLE = "/usr/bin/docker"
_DEFAULT_OWNER = "0:0"
_COMMAND_OUTPUT_LIMIT = 64 * 1024
_STATUS_ERROR = "Docker deployed certificate status is unavailable"


class DockerRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        max_output_bytes: int,
        max_input_bytes: int = ...,
        run_as_user: str | None = None,
    ) -> Any: ...


def _container_path(value: object, description: str) -> str:
    raw = str(value)
    path = PurePosixPath(raw)
    if (
        not path.is_absolute()
        or raw == "/"
        or str(path) != raw
        or path.name in {"", ".", ".."}
        or ".." in path.parts
        or ":" in raw
        or len(raw) > 4096
        or any(not 0x20 <= ord(character) <= 0x7E for character in raw)
    ):
        raise ValueError(f"invalid container-internal {description}")
    if path.parts[1:2] in (("dev",), ("proc",), ("sys",)):
        raise ValueError(f"unsafe container-internal {description}")
    return raw


def _bounded_host_read(path: Path, maximum: int, description: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CertificateValidationError(f"configured {description} is unreadable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise CertificateValidationError(f"configured {description} has an invalid size")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise CertificateValidationError(
                    f"configured {description} changed while being read"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CertificateValidationError(f"configured {description} changed while being read")
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise CertificateValidationError(f"configured {description} changed while being read")
        return b"".join(chunks)
    except OSError as exc:
        raise CertificateValidationError(f"configured {description} is unreadable") from exc
    finally:
        os.close(descriptor)


def _validate_pair(certificate: bytes, private_key: bytes) -> str:
    if not 0 < len(certificate) <= MAX_CERTIFICATE_BYTES:
        raise CertificateValidationError("certificate data has an invalid size")
    if not 0 < len(private_key) <= MAX_PRIVATE_KEY_BYTES:
        raise CertificateValidationError("private-key data has an invalid size")
    match = _CERTIFICATE_RE.search(certificate)
    if match is None:
        raise CertificateValidationError("certificate PEM block is missing")
    with tempfile.TemporaryDirectory(prefix="maddyweb-docker-certcheck-") as directory:
        certificate_path = Path(directory, "certificate")
        private_key_path = Path(directory, "private-key")
        certificate_path.write_bytes(certificate)
        private_key_path.write_bytes(private_key)
        os.chmod(certificate_path, 0o600)
        os.chmod(private_key_path, 0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.load_cert_chain(certificate_path, private_key_path)
        except (OSError, ssl.SSLError) as exc:
            raise CertificateValidationError(
                "certificate and private key are invalid or do not match"
            ) from exc
    try:
        first_certificate = match.group(0).decode("ascii")
        der = ssl.PEM_cert_to_DER_cert(first_certificate)
    except (UnicodeError, ValueError, ssl.SSLError) as exc:
        raise CertificateValidationError("certificate PEM block is invalid") from exc
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


@dataclass(frozen=True, slots=True)
class _ContainerMaterial:
    certificate: bytes | None
    private_key: bytes | None
    certificate_owner: str = _DEFAULT_OWNER
    private_key_owner: str = _DEFAULT_OWNER


@dataclass(slots=True)
class DockerCertificateAdapter:
    """Inspect and replace one fixed certificate pair in one fixed container."""

    container: str
    allowed_names: tuple[str, ...]
    live_dir: Path = field(repr=False)
    data_dir: str = field(repr=False)
    deployed_certificate_path: str = field(repr=False)
    deployed_private_key_path: str = field(repr=False)
    runner: DockerRunner = field(repr=False)
    spool_dir: Path = field(repr=False)
    timeout: float = 30.0
    docker_executable: str = _DOCKER_EXECUTABLE
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        if _CONTAINER_RE.fullmatch(self.container) is None:
            raise ValueError("invalid Docker container name")
        if not self.allowed_names or len(set(self.allowed_names)) != len(self.allowed_names):
            raise ValueError("certificate allow-list is empty or contains duplicates")
        if any(_CERTIFICATE_NAME_RE.fullmatch(name) is None for name in self.allowed_names):
            raise ValueError("certificate allow-list contains an invalid name")
        if not self.live_dir.is_absolute():
            raise ValueError("certificate live directory must be absolute")
        self.data_dir = _container_path(self.data_dir, "data directory")
        self.deployed_certificate_path = _container_path(
            self.deployed_certificate_path, "certificate path"
        )
        self.deployed_private_key_path = _container_path(
            self.deployed_private_key_path, "private-key path"
        )
        if self.deployed_certificate_path == self.deployed_private_key_path:
            raise ValueError("container certificate and private-key paths must differ")
        data_path = PurePosixPath(self.data_dir)
        if any(
            not PurePosixPath(path).is_relative_to(data_path)
            for path in (
                self.deployed_certificate_path,
                self.deployed_private_key_path,
            )
        ):
            raise ValueError("container certificate paths must be inside the Maddy data directory")
        if self.docker_executable != _DOCKER_EXECUTABLE:
            raise ValueError("Docker executable is not the fixed allow-listed path")
        if not 1.0 <= self.timeout <= 900.0:
            raise ValueError("Docker certificate command timeout is out of range")
        if not self.spool_dir.is_absolute():
            raise ValueError("Docker certificate spool directory must be absolute")
        try:
            spool_status = self.spool_dir.lstat()
        except OSError as exc:
            raise ValueError("Docker certificate spool directory is unavailable") from exc
        if not stat.S_ISDIR(spool_status.st_mode) or self.spool_dir.is_symlink():
            raise ValueError("Docker certificate spool directory is unsafe")
        if os.name == "posix" and stat.S_IMODE(spool_status.st_mode) & 0o022:
            raise ValueError("Docker certificate spool directory is writable by other users")

    @classmethod
    def from_config(
        cls,
        maddy_config: Any,
        certificate_config: Any,
        runner: DockerRunner,
        spool_dir: str | os.PathLike[str],
        timeout: float = 30.0,
    ) -> Self:
        if str(maddy_config.mode) != "docker":
            raise ValueError("Docker certificate adapter requires Docker Maddy mode")
        return cls(
            container=str(maddy_config.container),
            allowed_names=tuple(str(name) for name in certificate_config.names),
            live_dir=Path(certificate_config.live_dir),
            data_dir=str(maddy_config.data_dir),
            deployed_certificate_path=str(certificate_config.deployed_cert_path),
            deployed_private_key_path=str(certificate_config.deployed_key_path),
            runner=runner,
            spool_dir=Path(spool_dir),
            timeout=float(timeout),
        )

    def _argv(self, *inner: str) -> tuple[str, ...]:
        return (
            self.docker_executable,
            "exec",
            "--user",
            "0:0",
            self.container,
            *inner,
        )

    def _run(
        self,
        argv: Sequence[str],
        *,
        max_output_bytes: int = _COMMAND_OUTPUT_LIMIT,
        allow_nonzero: bool = False,
    ) -> Any:
        result = self.runner.run(
            tuple(argv),
            timeout=self.timeout,
            max_output_bytes=max_output_bytes,
            max_input_bytes=1,
            run_as_user=None,
        )
        if result.returncode != 0 and not allow_nonzero:
            raise CertificateCommandError("fixed Docker certificate command failed")
        return result

    def _read(self, path: str, maximum: int, *, allow_missing: bool) -> bytes | None:
        result = self._run(
            self._argv("/bin/cat", path),
            max_output_bytes=maximum,
            allow_nonzero=allow_missing,
        )
        if result.returncode != 0:
            return None
        value = bytes(result.stdout)
        if not 0 < len(value) <= maximum:
            raise CertificateValidationError("deployed certificate material has an invalid size")
        return value

    def _owner(self, path: str) -> str:
        result = self._run(
            self._argv("/bin/stat", "-c", "%u:%g", path),
            max_output_bytes=128,
        )
        match = _OWNER_RE.fullmatch(bytes(result.stdout))
        if match is None or int(match.group(1)) > 2**31 - 1 or int(match.group(2)) > 2**31 - 1:
            raise CertificateCommandError("deployed certificate owner is invalid")
        return f"{int(match.group(1))}:{int(match.group(2))}"

    def _read_material(
        self, *, allow_missing: bool, read_owners: bool = True
    ) -> _ContainerMaterial:
        self._run(self._argv("/bin/true"), max_output_bytes=1024)
        certificate = self._read(
            self.deployed_certificate_path,
            MAX_CERTIFICATE_BYTES,
            allow_missing=allow_missing,
        )
        private_key = self._read(
            self.deployed_private_key_path,
            MAX_PRIVATE_KEY_BYTES,
            allow_missing=allow_missing,
        )
        certificate_owner = (
            self._owner(self.deployed_certificate_path)
            if certificate is not None and read_owners
            else _DEFAULT_OWNER
        )
        private_key_owner = (
            self._owner(self.deployed_private_key_path)
            if private_key is not None and read_owners
            else _DEFAULT_OWNER
        )
        return _ContainerMaterial(
            certificate=certificate,
            private_key=private_key,
            certificate_owner=certificate_owner,
            private_key_owner=private_key_owner,
        )

    def status(self) -> CertificateStatus:
        """Return only non-secret deployment metadata for CertificateManager."""

        try:
            with self._lock:
                self._verify_parent_paths()
                material = self._read_material(allow_missing=True, read_owners=False)
            if material.certificate is None or material.private_key is None:
                return CertificateStatus(
                    name="deployed",
                    certificate_path="",
                    private_key_path="",
                    exists=material.certificate is not None,
                    private_key_exists=material.private_key is not None,
                    error=_STATUS_ERROR,
                )
            fingerprint = _validate_pair(material.certificate, material.private_key)
            return CertificateStatus(
                name="deployed",
                certificate_path="",
                private_key_path="",
                exists=True,
                private_key_exists=True,
                sha256_fingerprint=fingerprint,
            )
        except Exception:
            return CertificateStatus(
                name="deployed",
                certificate_path="",
                private_key_path="",
                exists=False,
                private_key_exists=False,
                error=_STATUS_ERROR,
            )

    def _host_temp(self, data: bytes, suffix: str) -> Path:
        descriptor, raw_path = tempfile.mkstemp(
            prefix="maddyweb-docker-certificate-",
            suffix=suffix,
            dir=self.spool_dir,
        )
        path = Path(raw_path)
        try:
            os.chmod(path, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            return path
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            path.unlink(missing_ok=True)
            raise

    @staticmethod
    def _container_temp(final_path: str, token: str, kind: str) -> str:
        final = PurePosixPath(final_path)
        return str(final.parent / f".{final.name}.maddyweb-{token}-{kind}")

    def _staged_paths(self, token: str) -> tuple[str, str]:
        return (
            self._container_temp(self.deployed_certificate_path, token, "certificate"),
            self._container_temp(self.deployed_private_key_path, token, "private-key"),
        )

    def _copy_to_container(self, source: Path, destination: str) -> None:
        self._run(
            (
                self.docker_executable,
                "cp",
                str(source),
                f"{self.container}:{destination}",
            )
        )

    def _verify_parent_paths(self) -> None:
        parents = {
            str(PurePosixPath(self.deployed_certificate_path).parent),
            str(PurePosixPath(self.deployed_private_key_path).parent),
        }
        for parent in sorted(parents):
            result = self._run(
                self._argv("/usr/bin/readlink", "-f", parent),
                max_output_bytes=4096,
            )
            if bytes(result.stdout) != parent.encode("ascii") + b"\n":
                raise CertificateCommandError(
                    "container certificate parent is missing or contains a symbolic link"
                )

    def _remove_container_paths(self, paths: Sequence[str]) -> None:
        if paths:
            self._run(self._argv("/bin/rm", "-f", *paths))

    def _install_material(
        self,
        material: _ContainerMaterial,
        *,
        token: str,
    ) -> None:
        staged: list[str] = []
        host_temps: list[Path] = []
        try:
            operations = (
                (
                    material.certificate,
                    self.deployed_certificate_path,
                    material.certificate_owner,
                    "0644",
                    "certificate",
                ),
                (
                    material.private_key,
                    self.deployed_private_key_path,
                    material.private_key_owner,
                    "0600",
                    "private-key",
                ),
            )
            for data, final_path, owner, mode, kind in operations:
                if data is None:
                    continue
                host_temp = self._host_temp(data, f"-{kind}")
                host_temps.append(host_temp)
                container_temp = self._container_temp(final_path, token, kind)
                staged.append(container_temp)
                self._copy_to_container(host_temp, container_temp)
                self._run(self._argv("/bin/chmod", mode, container_temp))
                self._run(self._argv("/bin/chown", owner, container_temp))
            for data, final_path, _owner, _mode, kind in operations:
                if data is None:
                    self._remove_container_paths((final_path,))
                    continue
                container_temp = self._container_temp(final_path, token, kind)
                self._run(self._argv("/bin/mv", "-f", container_temp, final_path))
                staged.remove(container_temp)
        except BaseException:
            try:
                self._remove_container_paths(staged)
            except BaseException as cleanup_exc:
                raise CertificateCommandError(
                    "Docker certificate staging cleanup failed"
                ) from cleanup_exc
            raise
        finally:
            for host_temp in host_temps:
                host_temp.unlink(missing_ok=True)

    def _restore(self, old: _ContainerMaterial) -> None:
        rollback_token = secrets.token_hex(12)
        self._verify_parent_paths()
        self._install_material(old, token=rollback_token)
        restored = self._read_material(allow_missing=True)
        if (
            restored.certificate != old.certificate
            or restored.private_key != old.private_key
            or restored.certificate_owner != old.certificate_owner
            or restored.private_key_owner != old.private_key_owner
        ):
            raise CertificateCommandError("Docker certificate rollback verification failed")

    def deploy(self, name: str) -> Callable[[], None]:
        """Transactionally deploy one allow-listed Certbot certificate pair."""

        if name not in self.allowed_names:
            raise UnknownCertificate("certificate name is not allow-listed")
        source_directory = self.live_dir / name
        certificate = _bounded_host_read(
            source_directory / "fullchain.pem",
            MAX_CERTIFICATE_BYTES,
            "source certificate",
        )
        private_key = _bounded_host_read(
            source_directory / "privkey.pem",
            MAX_PRIVATE_KEY_BYTES,
            "source private key",
        )
        source_fingerprint = _validate_pair(certificate, private_key)

        with self._lock:
            self._verify_parent_paths()
            old = self._read_material(allow_missing=True)
            token = secrets.token_hex(12)
            try:
                self._install_material(
                    _ContainerMaterial(
                        certificate=certificate,
                        private_key=private_key,
                        certificate_owner=old.certificate_owner,
                        private_key_owner=old.private_key_owner,
                    ),
                    token=token,
                )
                deployed = self._read_material(allow_missing=False)
                if deployed.certificate is None or deployed.private_key is None:
                    raise CertificateValidationError("deployed certificate material is incomplete")
                deployed_fingerprint = _validate_pair(deployed.certificate, deployed.private_key)
                if deployed_fingerprint != source_fingerprint:
                    raise CertificateValidationError(
                        "deployed certificate fingerprint does not match source"
                    )
            except BaseException as exc:
                rollback_succeeded = False
                try:
                    self._restore(old)
                    self._remove_container_paths(self._staged_paths(token))
                    rollback_succeeded = True
                except BaseException:
                    rollback_succeeded = False
                if rollback_succeeded:
                    raise CertificateCommandError(
                        "Docker certificate deployment failed and prior material was restored"
                    ) from exc
                raise CertificateCommandError(
                    "Docker certificate deployment failed and rollback failed"
                ) from exc

        rollback_used = False

        def rollback() -> None:
            nonlocal rollback_used
            with self._lock:
                if rollback_used:
                    raise CertificateCommandError(
                        "Docker certificate rollback token has already been used"
                    )
                self._restore(old)
                rollback_used = True

        return rollback


__all__ = ["DockerCertificateAdapter"]
