"""Narrow, allow-listed certificate operations for the privileged helper.

The public surface deliberately has no PEM upload, private-key export, issuance,
revoke, delete, or force-renew operation.  Certbot names and all executable/file
paths come only from trusted configuration.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import ssl
import stat
import tempfile
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, Self

MAX_CERTIFICATE_BYTES = 2 * 1024 * 1024
MAX_PRIVATE_KEY_BYTES = 1024 * 1024
MAX_RENEWAL_CONFIG_BYTES = 256 * 1024
_EMPTY_CERTBOT_CONFIG = "/dev/null"
_LINEAGE_OPTIONS = frozenset(
    {"version", "archive_dir", "cert", "chain", "fullchain", "privkey"}
)
_RENEWAL_PARAMETER_OPTIONS = frozenset(
    {
        "account",
        "allow_subset_of_names",
        "authenticator",
        "autorenew",
        "configurator",
        "elliptic_curve",
        "installer",
        "key_type",
        "manual_public_ip_logging_ok",
        "must_staple",
        "preferred_chain",
        "preferred_profile",
        "pref_challs",
        "required_profile",
        "reuse_key",
        "rsa_key_size",
        "server",
        "webroot_path",
    }
)
_LETS_ENCRYPT_PRODUCTION_SERVER = "https://acme-v02.api.letsencrypt.org/directory"
_RENEWAL_KEY_RE = re.compile(r"[A-Za-z0-9_.-]+")
_ACCOUNT_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,256}")
_CERTBOT_VERSION_RE = re.compile(r"([0-9]+)\.([0-9]+)(?:\.([0-9]+))?")
_HTTP01_IDENTIFIER_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
)
_PROFILE_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_MIN_CERTBOT_VERSION = (1, 0, 0)
_MAX_CERTBOT_VERSION = (5, 7, 0)
_CERTIFICATE_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+"
    rb"-----END CERTIFICATE-----",
    re.DOTALL,
)
_PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----\s+"
    rb"[A-Za-z0-9+/=\r\n]+-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)


class CertificateError(RuntimeError):
    """Base class for certificate administration failures."""


class UnknownCertificate(CertificateError):
    """A request named a certificate outside the configured allow-list."""


class CertificateValidationError(CertificateError):
    """Configured certificate material is invalid or mismatched."""


class CertificateCommandError(CertificateError):
    """An allow-listed nginx, certbot, systemctl, deployment or reload step failed."""


@dataclass(frozen=True, slots=True)
class CertificateStatus:
    name: str
    certificate_path: str
    private_key_path: str
    exists: bool
    private_key_exists: bool
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    sha256_fingerprint: str | None = None
    dns_names: tuple[str, ...] = ()
    private_key_mode: str | None = None
    private_key_permissions_safe: bool | None = None
    certificate_is_symlink: bool = False
    private_key_is_symlink: bool = False
    error: str | None = None
    ip_addresses: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["dns_names"] = list(self.dns_names)
        value["ip_addresses"] = list(self.ip_addresses)
        return value


class CertificateReport(dict[str, Any]):
    """JSON mapping with a compatibility ``to_dict`` convenience."""

    def to_dict(self) -> dict[str, Any]:
        return dict(self)


class ExternalRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        input_data: bytes | None = None,
        timeout: float,
        max_output_bytes: int,
        max_input_bytes: int = ...,
        run_as_user: str | None = None,
    ) -> Any: ...


def _default_audit(action: str, *, outcome: str, fields: Mapping[str, Any]) -> None:
    try:
        from .audit import record

        record(action, outcome=outcome, fields=fields)
    except ImportError, RuntimeError:
        return


def _bounded_read(path: Path, maximum: int, description: str) -> bytes:
    try:
        size = path.stat().st_size
        if size <= 0 or size > maximum:
            raise CertificateValidationError(f"configured {description} has an invalid size")
        data = path.read_bytes()
    except CertificateValidationError:
        raise
    except OSError as exc:
        raise CertificateError(f"cannot read configured {description}") from exc
    if len(data) != size:
        raise CertificateError(f"configured {description} changed while being read")
    return data


def _open_trusted_parent(path: Path) -> int:
    """Open an absolute parent without following replaceable directory links.

    The helper runs as root in production, so every non-sticky ancestor must be
    root-owned there.  Allowing the effective uid as well keeps the primitive
    testable by an unprivileged CI user without weakening the root deployment.
    """

    if os.name != "posix" or not path.is_absolute() or path.name in {"", ".", ".."}:
        raise CertificateError("configured deployment path is not a safe POSIX path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    trusted_owners = {0, os.geteuid()}
    try:
        for component in path.parent.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            status = os.fstat(descriptor)
            mode = stat.S_IMODE(status.st_mode)
            sticky_root_directory = bool(mode & stat.S_ISVTX) and status.st_uid == 0
            if (
                not stat.S_ISDIR(status.st_mode)
                or status.st_uid not in trusted_owners
                or (mode & 0o022 and not sticky_root_directory)
            ):
                raise CertificateError("configured deployment ancestor is not trusted")
        parent_status = os.fstat(descriptor)
        if stat.S_IMODE(parent_status.st_mode) & 0o022:
            raise CertificateError("configured deployment parent is writable by other users")
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise CertificateError("configured deployment ancestor cannot be opened safely") from exc
    except BaseException:
        os.close(descriptor)
        raise


def _trusted_target_status(parent_descriptor: int, name: str) -> os.stat_result | None:
    try:
        status = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(status.st_mode):
        raise CertificateError("configured deployment target is not a regular file")
    return status


def _trusted_target_exists(path: Path) -> bool:
    parent_descriptor = _open_trusted_parent(path)
    try:
        return _trusted_target_status(parent_descriptor, path.name) is not None
    finally:
        os.close(parent_descriptor)


def _bounded_trusted_read(path: Path, maximum: int, description: str) -> bytes:
    parent_descriptor = _open_trusted_parent(path)
    descriptor = -1
    try:
        status = _trusted_target_status(parent_descriptor, path.name)
        if status is None or not 0 < status.st_size <= maximum:
            raise CertificateValidationError(f"configured {description} has an invalid size")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        opened_status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_status.st_mode)
            or opened_status.st_dev != status.st_dev
            or opened_status.st_ino != status.st_ino
            or opened_status.st_size != status.st_size
        ):
            raise CertificateError(f"configured {description} changed while being opened")
        chunks: list[bytes] = []
        remaining = opened_status.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise CertificateError(f"configured {description} changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CertificateError(f"configured {description} changed while being read")
        return b"".join(chunks)
    except CertificateError:
        raise
    except OSError as exc:
        raise CertificateError(f"cannot read configured {description}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def _trusted_file_metadata(path: Path, description: str) -> os.stat_result:
    try:
        status = path.lstat()
    except OSError as exc:
        raise CertificateCommandError(f"configured {description} is unavailable") from exc
    trusted_owners = {0, os.geteuid()}
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid not in trusted_owners
        or stat.S_IMODE(status.st_mode) & 0o022
        or status.st_nlink != 1
    ):
        raise CertificateCommandError(f"configured {description} metadata is unsafe")
    return status


def _trusted_directory_metadata(path: Path, description: str) -> os.stat_result:
    try:
        status = path.lstat()
    except OSError as exc:
        raise CertificateCommandError(f"configured {description} is unavailable") from exc
    trusted_owners = {0, os.geteuid()}
    if (
        not stat.S_ISDIR(status.st_mode)
        or status.st_uid not in trusted_owners
        or stat.S_IMODE(status.st_mode) & 0o022
    ):
        raise CertificateCommandError(f"configured {description} metadata is unsafe")
    descriptor = _open_trusted_parent(path / ".maddyweb-directory-probe")
    os.close(descriptor)
    return status


def _normalized_option(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def _configobj_list(value: str) -> tuple[str, ...]:
    cleaned = value.strip()
    if cleaned.lower() in {"none", "null"}:
        return ()
    if any(character in cleaned for character in "'\"\\"):
        raise CertificateCommandError("Certbot renewal list syntax is unsupported")
    parts = [part.strip() for part in cleaned.split(",")]
    if parts and not parts[-1]:
        parts.pop()
    if not parts or any(not part for part in parts):
        raise CertificateCommandError("Certbot renewal list syntax is unsupported")
    return tuple(parts)


def _optional_configobj_value(value: str) -> str:
    cleaned = value.strip().lower()
    return "" if cleaned in {"", "none", "null"} else cleaned


def _strict_configobj_bool(value: str, description: str) -> bool:
    normalized = value.strip().lower()
    if normalized not in {"true", "false"}:
        raise CertificateCommandError(f"Certbot {description} boolean is invalid")
    return normalized == "true"


def _supported_certbot_version(value: str, description: str) -> tuple[int, int, int]:
    match = _CERTBOT_VERSION_RE.fullmatch(value.strip())
    if match is None:
        raise CertificateCommandError(f"Certbot {description} version is unsupported")
    version = tuple(int(part or "0") for part in match.groups())
    if not _MIN_CERTBOT_VERSION <= version <= _MAX_CERTBOT_VERSION:
        raise CertificateCommandError(f"Certbot {description} version is unsupported")
    return version  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class _RenewalProfile:
    policy_sha256: str


def _parse_renewal_document(
    raw: bytes,
) -> tuple[dict[str, str], dict[str, str], dict[str, str], tuple[str, ...]]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise CertificateCommandError("Certbot renewal file is not safely parseable") from exc
    if "\0" in text:
        raise CertificateCommandError("Certbot renewal file is not safely parseable")
    section = "lineage"
    values: dict[str, dict[str, str]] = {section: {}}
    webroots: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if line[0].isspace():
            raise CertificateCommandError("Certbot renewal continuations are forbidden")
        if stripped.startswith("[[") and stripped.endswith("]]"):
            nested = stripped[2:-2].strip().lower()
            if nested != "webroot_map" or section != "renewalparams":
                raise CertificateCommandError("Certbot renewal section is unsupported")
            section = "webroot_map"
            values.setdefault(section, {})
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            named = stripped[1:-1].strip().lower()
            if named not in {"renewalparams", "acme_renewal_info"}:
                raise CertificateCommandError("Certbot renewal section is unsupported")
            section = named
            if section in values:
                raise CertificateCommandError("Certbot renewal section is duplicated")
            values[section] = {}
            continue
        key_text, separator, value = line.partition("=")
        key = key_text.strip()
        if (
            not separator
            or not key
            or (section != "webroot_map" and not _RENEWAL_KEY_RE.fullmatch(key))
        ):
            raise CertificateCommandError("Certbot renewal file is not safely parseable")
        normalized = key.casefold() if section == "webroot_map" else _normalized_option(key)
        if section != "webroot_map" and key != normalized:
            raise CertificateCommandError("Certbot renewal option spelling is unsupported")
        if section == "webroot_map" and _HTTP01_IDENTIFIER_RE.fullmatch(key) is None:
            raise CertificateCommandError("Certbot webroot map identifier is unsupported")
        if normalized in values[section]:
            raise CertificateCommandError("Certbot renewal option is duplicated")
        cleaned = value.strip()
        if not cleaned or any(ord(char) < 0x20 or ord(char) == 0x7F for char in cleaned):
            raise CertificateCommandError("Certbot renewal value is unsafe")
        values[section][normalized] = cleaned
        if section == "webroot_map":
            mapped = _configobj_list(cleaned)
            if len(mapped) != 1:
                raise CertificateCommandError("Certbot webroot map value is ambiguous")
            webroots.extend(mapped)
    if "renewalparams" not in values:
        raise CertificateCommandError("Certbot renewal parameters are missing")
    lineage = values["lineage"]
    if set(lineage) != _LINEAGE_OPTIONS:
        raise CertificateCommandError("Certbot renewal lineage options are unsupported")
    _supported_certbot_version(lineage["version"], "lineage")
    parameters = values["renewalparams"]
    if set(parameters) - _RENEWAL_PARAMETER_OPTIONS:
        raise CertificateCommandError("Certbot renewal parameters are unsupported")
    acme_renewal_info = values.get("acme_renewal_info", {})
    if set(acme_renewal_info) - {"ari_retry_after"}:
        raise CertificateCommandError("Certbot ARI renewal section is unsupported")
    if retry_after := acme_renewal_info.get("ari_retry_after"):
        if re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:Z|[+-][0-9]{2}:[0-9]{2})?",
            retry_after,
        ) is None:
            raise CertificateCommandError("Certbot ARI retry time is invalid")
        try:
            parsed_retry = datetime.fromisoformat(retry_after.replace("Z", "+00:00"))
        except ValueError as exc:
            raise CertificateCommandError("Certbot ARI retry time is invalid") from exc
        if len(retry_after) > 64 or not 2000 <= parsed_retry.year <= 2200:
            raise CertificateCommandError("Certbot ARI retry time is invalid")
    account = parameters.get("account")
    if account is not None and _ACCOUNT_ID_RE.fullmatch(account) is None:
        raise CertificateCommandError("Certbot renewal account is unsupported")
    key_type = parameters.get("key_type")
    if key_type is not None and key_type not in {"rsa", "ecdsa"}:
        raise CertificateCommandError("Certbot renewal key type is unsupported")
    rsa_key_size = parameters.get("rsa_key_size")
    if rsa_key_size is not None and rsa_key_size not in {"2048", "3072", "4096"}:
        raise CertificateCommandError("Certbot renewal RSA key size is unsupported")
    elliptic_curve = parameters.get("elliptic_curve")
    if elliptic_curve is not None and elliptic_curve not in {
        "secp256r1",
        "secp384r1",
        "secp521r1",
    }:
        raise CertificateCommandError("Certbot renewal elliptic curve is unsupported")
    if (pref_challs := parameters.get("pref_challs")) and tuple(
        item.lower() for item in _configobj_list(pref_challs)
    ) != ("http-01",):
        raise CertificateCommandError("Certbot renewal challenge type is unsupported")
    for option in ("must_staple", "reuse_key", "autorenew"):
        if option in parameters:
            _strict_configobj_bool(parameters[option], option)
    if "allow_subset_of_names" in parameters and _strict_configobj_bool(
        parameters["allow_subset_of_names"], "allow_subset_of_names"
    ):
        raise CertificateCommandError("Certbot partial-name renewal is forbidden")
    manual_logging = _optional_configobj_value(
        parameters.get("manual_public_ip_logging_ok", "")
    )
    if manual_logging and _strict_configobj_bool(
        parameters["manual_public_ip_logging_ok"], "manual_public_ip_logging_ok"
    ):
        raise CertificateCommandError("Certbot manual authenticator state is forbidden")
    preferred_chain = parameters.get("preferred_chain")
    if preferred_chain is not None and (
        len(preferred_chain) > 256 or any(character in preferred_chain for character in "'\"\\")
    ):
        raise CertificateCommandError("Certbot preferred chain is unsupported")
    for option in ("preferred_profile", "required_profile"):
        value = parameters.get(option)
        if value is not None and _PROFILE_NAME_RE.fullmatch(value) is None:
            raise CertificateCommandError("Certbot certificate profile is unsupported")
    if "webroot_path" in parameters:
        webroots.extend(_configobj_list(parameters["webroot_path"]))
    return lineage, parameters, values.get("webroot_map", {}), tuple(webroots)


def _safe_renewal_profile(
    path: Path,
    *,
    renewal_dir: Path,
    live_dir: Path,
    name: str,
    allowed_webroot_roots: tuple[Path, ...],
) -> _RenewalProfile:
    before = _trusted_file_metadata(path, "Certbot renewal file")
    raw = _bounded_trusted_read(
        path,
        MAX_RENEWAL_CONFIG_BYTES,
        "Certbot renewal file",
    )
    after = _trusted_file_metadata(path, "Certbot renewal file")
    compared = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(getattr(before, field) != getattr(after, field) for field in compared):
        raise CertificateCommandError("Certbot renewal file changed while being read")
    lineage, parameters, webroot_map, webroot_values = _parse_renewal_document(raw)
    expected_lineage = {
        "archive_dir": str(renewal_dir.parent / "archive" / name),
        "cert": str(live_dir / name / "cert.pem"),
        "chain": str(live_dir / name / "chain.pem"),
        "fullchain": str(live_dir / name / "fullchain.pem"),
        "privkey": str(live_dir / name / "privkey.pem"),
    }
    if any(lineage.get(key) != value for key, value in expected_lineage.items()):
        raise CertificateCommandError("Certbot renewal lineage paths are unsafe")
    authenticator = _optional_configobj_value(parameters.get("authenticator", ""))
    configurator = _optional_configobj_value(parameters.get("configurator", ""))
    if authenticator != "webroot":
        raise CertificateCommandError("Certbot renewal authenticator is not Web-safe")
    if configurator not in {"", "webroot"}:
        raise CertificateCommandError("Certbot renewal authenticator is ambiguous")
    installer = _optional_configobj_value(parameters.get("installer", ""))
    if installer:
        raise CertificateCommandError("Certbot renewal installer is not Web-safe")
    if parameters.get("server") != _LETS_ENCRYPT_PRODUCTION_SERVER:
        raise CertificateCommandError("Certbot renewal server is not allow-listed")
    if not webroot_values:
        raise CertificateCommandError("Certbot renewal webroot is missing")
    for value in webroot_values:
        webroot = Path(value)
        if not webroot.is_absolute() or webroot.resolve(strict=True) != webroot:
            raise CertificateCommandError("Certbot renewal webroot is unsafe")
        _trusted_directory_metadata(webroot, "Certbot renewal webroot")
        if not any(
            webroot == root or root in webroot.parents for root in allowed_webroot_roots
        ):
            raise CertificateCommandError("Certbot renewal webroot is unsafe")
    policy = repr(
        (
            tuple(sorted(lineage.items())),
            tuple(sorted(parameters.items())),
            tuple(sorted(webroot_map.items())),
            tuple(webroot_values),
        )
    ).encode("utf-8")
    return _RenewalProfile(policy_sha256=hashlib.sha256(policy).hexdigest())


def _first_certificate(certificate_pem: bytes) -> bytes:
    match = _CERTIFICATE_RE.search(certificate_pem)
    if match is None:
        raise CertificateValidationError("certificate PEM block is missing")
    return match.group(0).rstrip() + b"\n"


def _validate_pair(certificate_pem: bytes, private_key_pem: bytes) -> None:
    if len(certificate_pem) > MAX_CERTIFICATE_BYTES or len(private_key_pem) > MAX_PRIVATE_KEY_BYTES:
        raise CertificateValidationError("configured certificate material is too large")
    if _CERTIFICATE_RE.search(certificate_pem) is None:
        raise CertificateValidationError("certificate PEM block is missing")
    if _PRIVATE_KEY_RE.fullmatch(private_key_pem.strip()) is None:
        raise CertificateValidationError("private key PEM block is malformed")
    with tempfile.TemporaryDirectory(prefix="maddyweb-certcheck-") as directory:
        certificate_path = Path(directory, "fullchain.pem")
        private_key_path = Path(directory, "privkey.pem")
        certificate_path.write_bytes(certificate_pem)
        private_key_path.write_bytes(private_key_pem)
        os.chmod(certificate_path, 0o600)
        os.chmod(private_key_path, 0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.load_cert_chain(certificate_path, private_key_path)
        except (ssl.SSLError, OSError) as exc:
            raise CertificateValidationError(
                "configured certificate and private key are invalid or do not match"
            ) from exc


def _x509_name(value: Any) -> str | None:
    parts: list[str] = []
    if isinstance(value, tuple):
        for relative_name in value:
            if not isinstance(relative_name, tuple):
                continue
            for attribute in relative_name:
                if isinstance(attribute, tuple) and len(attribute) == 2:
                    parts.append(f"{attribute[0]}={attribute[1]}")
    return ", ".join(parts) or None


def _inspect(name: str, certificate_path: Path, private_key_path: Path) -> CertificateStatus:
    certificate_exists = certificate_path.is_file()
    private_key_exists = private_key_path.is_file()
    key_mode: str | None = None
    key_permissions_safe: bool | None = None
    if private_key_exists:
        try:
            numeric_mode = stat.S_IMODE(private_key_path.stat().st_mode)
            key_mode = f"{numeric_mode:04o}"
            key_permissions_safe = numeric_mode & 0o077 == 0
        except OSError:
            pass
    base = {
        "name": name,
        "certificate_path": str(certificate_path),
        "private_key_path": str(private_key_path),
        "exists": certificate_exists,
        "private_key_exists": private_key_exists,
        "private_key_mode": key_mode,
        "private_key_permissions_safe": key_permissions_safe,
        "certificate_is_symlink": certificate_path.is_symlink(),
        "private_key_is_symlink": private_key_path.is_symlink(),
    }
    if not certificate_exists:
        return CertificateStatus(**base, error="certificate file is missing")
    if not private_key_exists:
        return CertificateStatus(**base, error="private key file is missing")
    try:
        certificate_pem = _bounded_read(certificate_path, MAX_CERTIFICATE_BYTES, "certificate")
        private_key_pem = _bounded_read(private_key_path, MAX_PRIVATE_KEY_BYTES, "private key")
        _validate_pair(certificate_pem, private_key_pem)
        der = ssl.PEM_cert_to_DER_cert(_first_certificate(certificate_pem).decode("ascii"))
        fingerprint_text = hashlib.sha256(der).hexdigest().upper()
        fingerprint = ":".join(
            fingerprint_text[index : index + 2] for index in range(0, len(fingerprint_text), 2)
        )
        decoded = ssl._ssl._test_decode_cert(str(certificate_path))
        before = datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notBefore"]), UTC)
        after = datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notAfter"]), UTC)
        return CertificateStatus(
            **base,
            not_before=before.isoformat(),
            not_after=after.isoformat(),
            days_remaining=int((after - datetime.now(UTC)).total_seconds() // 86400),
            subject=_x509_name(decoded.get("subject")),
            issuer=_x509_name(decoded.get("issuer")),
            serial_number=str(decoded.get("serialNumber", "")) or None,
            sha256_fingerprint=fingerprint,
            dns_names=tuple(
                str(value) for kind, value in decoded.get("subjectAltName", ()) if kind == "DNS"
            ),
            ip_addresses=tuple(
                str(value)
                for kind, value in decoded.get("subjectAltName", ())
                if kind == "IP Address"
            ),
        )
    except (CertificateError, ssl.SSLError, UnicodeError, ValueError, OSError) as exc:
        return CertificateStatus(
            **base,
            error=f"certificate validation failed: {type(exc).__name__}",
        )


@dataclass(slots=True)
class CertificateManager:
    """The complete v1 certificate allow-list exposed to the helper."""

    allowed_names: tuple[str, ...]
    live_dir: Path
    deployed_certificate_path: Path
    deployed_private_key_path: Path
    renewal_dir: Path = Path("/etc/letsencrypt/renewal")
    webroot_roots: tuple[Path, ...] = ()
    timer_unit: str = "certbot-renew.timer"
    runner: ExternalRunner | None = None
    certbot_executable: str = "/usr/bin/certbot"
    nginx_executable: str = "/usr/sbin/nginx"
    systemctl_executable: str = "/usr/bin/systemctl"
    reload_callback: Callable[[], None] | None = None
    deploy_callback: Callable[[str], Callable[[], None] | None] | None = None
    deployed_status_callback: Callable[[], CertificateStatus] | None = None
    deployment_mode: str = "native"
    owner_uid: int | None = None
    owner_gid: int | None = None
    command_timeout: float = 120.0
    audit: Callable[..., None] = _default_audit
    _cached_certbot_version: tuple[int, int, int] | None = field(
        default=None,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if len(set(self.allowed_names)) != len(self.allowed_names):
            raise ValueError("certificate allow-list contains duplicates")
        if any(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", name) is None
            for name in self.allowed_names
        ):
            raise ValueError("certificate allow-list contains an invalid name")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]*\.timer", self.timer_unit) is None:
            raise ValueError("invalid certificate timer unit")
        if self.renewal_dir.name != "renewal":
            raise ValueError("certificate renewal directory must end with /renewal")
        for path in (
            self.renewal_dir,
            self.live_dir,
            self.deployed_certificate_path,
            self.deployed_private_key_path,
            *self.webroot_roots,
        ):
            if not path.is_absolute():
                raise ValueError("certificate paths must be absolute")
        if len(set(self.webroot_roots)) != len(self.webroot_roots):
            raise ValueError("certificate webroot roots must be unique")
        for executable in (
            self.certbot_executable,
            self.nginx_executable,
            self.systemctl_executable,
        ):
            if not executable or any(char in executable for char in "\0\r\n"):
                raise ValueError("invalid fixed certificate executable")
        if self.command_timeout <= 0:
            raise ValueError("command timeout must be positive")
        if self.deployment_mode not in {"native", "docker"}:
            raise ValueError("certificate deployment mode must be native or docker")

    @classmethod
    def from_config(
        cls,
        config: Any,
        *,
        runner: ExternalRunner,
        reload_callback: Callable[[], None] | None = None,
        deploy_callback: Callable[[str], Callable[[], None] | None] | None = None,
        deployed_status_callback: Callable[[], CertificateStatus] | None = None,
        deployment_mode: str = "native",
        owner_uid: int | None = None,
        owner_gid: int | None = None,
        command_timeout: float = 120.0,
    ) -> Self:
        return cls(
            allowed_names=tuple(config.names),
            renewal_dir=Path(config.renewal_dir),
            webroot_roots=tuple(Path(value) for value in config.webroot_roots),
            live_dir=Path(config.live_dir),
            deployed_certificate_path=Path(config.deployed_cert_path),
            deployed_private_key_path=Path(config.deployed_key_path),
            timer_unit=str(config.timer_unit),
            runner=runner,
            certbot_executable=str(config.certbot_binary),
            nginx_executable=str(config.nginx_binary),
            reload_callback=reload_callback,
            deploy_callback=deploy_callback,
            deployed_status_callback=deployed_status_callback,
            deployment_mode=deployment_mode,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            command_timeout=command_timeout,
        )

    def _allow(self, name: str) -> str:
        if name not in self.allowed_names:
            raise UnknownCertificate("certificate name is not allow-listed")
        return name

    def _safe_renewal_profile(
        self,
        name: str,
        *,
        verify_runtime: bool = True,
        fresh_runtime: bool = False,
    ) -> _RenewalProfile:
        name = self._allow(name)
        self._assert_no_ambient_cli_config()
        profile = _safe_renewal_profile(
            self.renewal_dir / f"{name}.conf",
            renewal_dir=self.renewal_dir,
            live_dir=self.live_dir,
            name=name,
            allowed_webroot_roots=self.webroot_roots,
        )
        if verify_runtime:
            self._assert_supported_certbot(fresh=fresh_runtime)
        return profile

    def _assert_supported_certbot(self, *, fresh: bool = False) -> tuple[int, int, int]:
        if not fresh and self._cached_certbot_version is not None:
            return self._cached_certbot_version
        result = self._run((self.certbot_executable, "--version"))
        try:
            output = (result.stdout + result.stderr).decode("ascii", errors="strict").strip()
        except UnicodeError as exc:
            raise CertificateCommandError("Certbot runtime version is unsupported") from exc
        prefix = "certbot "
        if not output.startswith(prefix):
            raise CertificateCommandError("Certbot runtime version is unsupported")
        version = _supported_certbot_version(output.removeprefix(prefix), "runtime")
        self._cached_certbot_version = version
        return version

    def _assert_no_ambient_cli_config(self) -> None:
        try:
            import pwd

            user_home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        except (ImportError, KeyError):
            user_home = Path.home()
        candidates = {
            Path("/etc/letsencrypt/cli.ini"),
            self.renewal_dir.parent / "cli.ini",
            user_home / ".config" / "letsencrypt" / "cli.ini",
        }
        for candidate in candidates:
            try:
                candidate.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise CertificateCommandError(
                    "Certbot default CLI configuration cannot be inspected"
                ) from exc
            raise CertificateCommandError("Certbot default CLI configuration is forbidden")

    def _renewal_is_safe(self, name: str) -> bool:
        try:
            self._safe_renewal_profile(name)
        except Exception:
            return False
        return True

    def _timer_enable_is_safe(self) -> bool:
        return False

    def _renew_argv(self, name: str, *, dry_run: bool) -> tuple[str, ...]:
        arguments = [
            self.certbot_executable,
            "--config",
            _EMPTY_CERTBOT_CONFIG,
            "--config-dir",
            str(self.renewal_dir.parent),
            "renew",
        ]
        if dry_run:
            arguments.append("--dry-run")
        arguments.extend(
            (
                "--no-directory-hooks",
                "--cert-name",
                name,
                "--non-interactive",
            )
        )
        return tuple(arguments)

    def _run(self, argv: Sequence[str], *, allow_nonzero: bool = False) -> Any:
        if self.runner is None:
            raise CertificateCommandError("certificate command runner is not configured")
        result = self.runner.run(
            tuple(argv),
            timeout=self.command_timeout,
            max_output_bytes=1024 * 1024,
            run_as_user=None,
        )
        if result.returncode != 0 and not allow_nonzero:
            raise CertificateCommandError("allow-listed certificate command failed")
        return result

    def _timer_status(self) -> dict[str, Any]:
        if self.runner is None:
            return {
                "unit": self.timer_unit,
                "enabled": None,
                "enabled_state": "unknown",
                "active": None,
                "active_state": "unknown",
            }
        enabled_result = self._run(
            (self.systemctl_executable, "is-enabled", "--", self.timer_unit),
            allow_nonzero=True,
        )
        active_result = self._run(
            (self.systemctl_executable, "is-active", "--", self.timer_unit),
            allow_nonzero=True,
        )
        enabled_text = enabled_result.stdout.decode("utf-8", errors="replace").strip()
        active_text = active_result.stdout.decode("utf-8", errors="replace").strip()
        return {
            "unit": self.timer_unit,
            "enabled": enabled_result.returncode == 0 and enabled_text == "enabled",
            "enabled_state": enabled_text or "unknown",
            "active": active_result.returncode == 0 and active_text == "active",
            "active_state": active_text or "unknown",
        }

    def _source_status(self, name: str) -> CertificateStatus:
        directory = self.live_dir / self._allow(name)
        return _inspect(name, directory / "fullchain.pem", directory / "privkey.pem")

    def _deployed_status(self) -> CertificateStatus:
        if self.deployment_mode == "docker":
            if self.deployed_status_callback is None:
                return CertificateStatus(
                    name="deployed",
                    certificate_path="",
                    private_key_path="",
                    exists=False,
                    private_key_exists=False,
                    error="deployed certificate status is unavailable in Docker mode",
                )
            try:
                status = self.deployed_status_callback()
            except Exception as exc:
                return CertificateStatus(
                    name="deployed",
                    certificate_path="",
                    private_key_path="",
                    exists=False,
                    private_key_exists=False,
                    error=f"Docker deployment status failed: {type(exc).__name__}",
                )
            if not isinstance(status, CertificateStatus):
                raise CertificateCommandError(
                    "Docker deployment status hook returned an invalid result"
                )
            return status
        return _inspect("deployed", self.deployed_certificate_path, self.deployed_private_key_path)

    def deployment_status(self, name: str) -> CertificateReport:
        """Return source/deployed state without launching Certbot or systemctl."""

        name = self._allow(name)
        source = self._source_status(name)
        deployed = self._deployed_status()
        fingerprints_match = bool(
            source.sha256_fingerprint
            and deployed.sha256_fingerprint
            and source.sha256_fingerprint == deployed.sha256_fingerprint
        )
        report = CertificateReport(source.to_dict())
        report.update(
            {
                "name": name,
                "source": source.to_dict(),
                "deployed": deployed.to_dict(),
                "fingerprints_match": fingerprints_match,
            }
        )
        return report

    def status(self, name: str) -> CertificateReport:
        report = self.deployment_status(name)
        report.update(
            {
                "automation_safe": self._renewal_is_safe(name),
                "timer_enable_safe": self._timer_enable_is_safe(),
                "timer": self._timer_status(),
            }
        )
        return report

    def list_certificates(self) -> list[dict[str, Any]]:
        timer = self._timer_status()
        deployed = self._deployed_status()
        timer_enable_safe = self._timer_enable_is_safe()
        records: list[dict[str, Any]] = []
        for name in self.allowed_names:
            source = self._source_status(name)
            records.append(
                {
                    "name": name,
                    "source": source.to_dict(),
                    "deployed": deployed.to_dict(),
                    "fingerprints_match": bool(
                        source.sha256_fingerprint
                        and deployed.sha256_fingerprint
                        and source.sha256_fingerprint == deployed.sha256_fingerprint
                    ),
                    "automation_safe": self._renewal_is_safe(name),
                    "timer_enable_safe": timer_enable_safe,
                    "timer": timer,
                }
            )
        return records

    def health(self) -> dict[str, Any]:
        """Return a fixed, path-free readiness summary for the Web gateway."""

        try:
            self._assert_supported_certbot(fresh=True)
            certbot_available = True
        except Exception:
            certbot_available = False
        try:
            timer = self._timer_status()
        except Exception:
            timer = {"enabled": False, "active": False}
        sources = [self._source_status(name) for name in self.allowed_names]
        try:
            deployed = self._deployed_status()
        except Exception:
            deployed = None
        readable_sources = bool(sources) and all(item.error is None for item in sources)
        match = any(
            item.sha256_fingerprint
            and deployed is not None
            and deployed.sha256_fingerprint
            and item.sha256_fingerprint == deployed.sha256_fingerprint
            for item in sources
        )
        return {
            "certbot_available": certbot_available,
            "timer_enabled": timer.get("enabled") is True,
            "timer_active": timer.get("active") is True,
            "source_readable": readable_sources,
            "deployed_matches_source": bool(match),
        }

    def set_timer_enabled(self, enabled: bool) -> dict[str, Any]:
        if type(enabled) is not bool:
            raise ValueError("enabled must be a boolean")
        if enabled:
            raise CertificateCommandError(
                "timer enable requires a managed MaddyWeb renewal service"
            )
        action = "enable" if enabled else "disable"
        self._run((self.systemctl_executable, action, "--now", "--", self.timer_unit))
        status = self._timer_status()
        if status["enabled"] is not enabled or status["active"] is not enabled:
            raise CertificateCommandError("certificate timer read-back verification failed")
        self.audit("certificates.timer", outcome="ok", fields={"enabled": enabled})
        return status

    def _nginx_test(self) -> None:
        self._run((self.nginx_executable, "-t"))

    def dry_run(self, name: str) -> dict[str, Any]:
        name = self._allow(name)
        before = self._safe_renewal_profile(name, fresh_runtime=True)
        self._nginx_test()
        self._run(self._renew_argv(name, dry_run=True))
        after = self._safe_renewal_profile(name, verify_runtime=False)
        if after.policy_sha256 != before.policy_sha256:
            raise CertificateCommandError("Certbot dry-run changed the renewal profile")
        self._nginx_test()
        self.audit("certificates.renew_dry_run", outcome="ok", fields={"name": name})
        return self.status(name)

    def renew(self, name: str) -> dict[str, Any]:
        name = self._allow(name)
        if self.deployment_mode == "docker" and (
            self.deploy_callback is None or self.deployed_status_callback is None
        ):
            raise CertificateCommandError(
                "Docker certificate renewal requires fixed deployment and status hooks"
            )
        self._safe_renewal_profile(name, fresh_runtime=True)
        before = self._source_status(name)
        if before.error is not None or before.sha256_fingerprint is None:
            raise CertificateCommandError("source certificate is invalid before renewal")
        self._nginx_test()
        self._run(self._renew_argv(name, dry_run=False))
        self._safe_renewal_profile(name, verify_runtime=False)
        self._nginx_test()
        after = self._source_status(name)
        if after.error is not None or after.sha256_fingerprint is None:
            raise CertificateCommandError("source certificate is invalid after renewal")
        if (
            not before.dns_names
            or set(after.dns_names) != set(before.dns_names)
            or set(after.ip_addresses) != set(before.ip_addresses)
        ):
            raise CertificateCommandError("renewed certificate subject names changed unexpectedly")
        source_changed = after.sha256_fingerprint != before.sha256_fingerprint
        current = self.status(name)
        synchronized = not current["fingerprints_match"]
        if synchronized:
            self._deploy_and_reload(name)
        else:
            # A previous reload may have failed after the files were replaced.
            # Reload even for a not-due renewal so a later explicit attempt can
            # repair that ambiguous runtime state without forcing issuance.
            if self.reload_callback is None:
                raise CertificateCommandError("Maddy reload callback is not configured")
            try:
                self.reload_callback()
            except Exception as exc:
                raise CertificateCommandError("Maddy reload failed") from exc
        result = self.status(name)
        if not result["fingerprints_match"]:
            raise CertificateCommandError("deployed certificate fingerprint does not match source")
        result["renewed"] = source_changed
        result["renewal_result"] = (
            "renewed" if source_changed else "synchronized" if synchronized else "not_due"
        )
        self.audit(
            "certificates.renew",
            outcome="ok" if source_changed else "not_due",
            fields={"name": name},
        )
        return result

    def _deploy_and_reload(self, name: str) -> None:
        if self.deployment_mode == "docker" and (
            self.deploy_callback is None or self.deployed_status_callback is None
        ):
            raise CertificateCommandError(
                "Docker certificate deployment requires fixed deployment and status hooks"
            )
        rollback: Callable[[], None] | None
        if self.deploy_callback is not None:
            try:
                rollback = self.deploy_callback(name)
            except Exception as exc:
                raise CertificateCommandError(
                    "configured certificate deployment hook failed"
                ) from exc
        else:
            rollback = self._copy_allowlisted_source(name)
        try:
            source = self._source_status(name)
            deployed = self._deployed_status()
            if (
                source.error is not None
                or deployed.error is not None
                or source.sha256_fingerprint != deployed.sha256_fingerprint
            ):
                raise CertificateCommandError(
                    "deployed certificate fingerprint does not match source"
                )
            if self.reload_callback is None:
                raise CertificateCommandError("Maddy reload callback is not configured")
            self.reload_callback()
        except Exception as exc:
            rollback_succeeded = False
            if rollback is not None:
                try:
                    rollback()
                    if self.reload_callback is None:
                        raise CertificateCommandError("Maddy reload callback is not configured")
                    self.reload_callback()
                    rollback_succeeded = True
                except Exception:
                    rollback_succeeded = False
            outcome = "rolled_back" if rollback_succeeded else "rollback_failed"
            self.audit("certificates.deploy", outcome=outcome, fields={"name": name})
            if rollback_succeeded:
                raise CertificateCommandError(
                    "certificate deployment failed; prior material was restored and reloaded"
                ) from exc
            raise CertificateCommandError(
                "certificate deployment failed and rollback failed"
            ) from exc

    def _atomic_copy(self, path: Path, data: bytes, mode: int) -> None:
        parent_descriptor = _open_trusted_parent(path)
        temporary_name = f".{path.name}.maddyweb-{secrets.token_hex(12)}"
        descriptor = -1
        try:
            _trusted_target_status(parent_descriptor, path.name)
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                mode,
                dir_fd=parent_descriptor,
            )
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("certificate staging write made no progress")
                view = view[written:]
            os.fsync(descriptor)
            os.fchmod(descriptor, mode)
            if self.owner_uid is not None or self.owner_gid is not None:
                os.fchown(
                    descriptor,
                    self.owner_uid if self.owner_uid is not None else -1,
                    self.owner_gid if self.owner_gid is not None else -1,
                )
            os.close(descriptor)
            descriptor = -1
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            os.fsync(parent_descriptor)
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            raise
        finally:
            os.close(parent_descriptor)

    def _remove_deployed_file(self, path: Path) -> None:
        parent_descriptor = _open_trusted_parent(path)
        try:
            status = _trusted_target_status(parent_descriptor, path.name)
            if status is not None:
                os.unlink(path.name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)

    def _copy_allowlisted_source(self, name: str) -> Callable[[], None]:
        if self.deployment_mode == "docker":
            raise CertificateCommandError(
                "refusing to treat Docker deployment paths as host filesystem paths"
            )
        directory = self.live_dir / self._allow(name)
        certificate = _bounded_read(
            directory / "fullchain.pem", MAX_CERTIFICATE_BYTES, "source certificate"
        )
        private_key = _bounded_read(
            directory / "privkey.pem", MAX_PRIVATE_KEY_BYTES, "source private key"
        )
        _validate_pair(certificate, private_key)
        old_certificate = (
            _bounded_trusted_read(
                self.deployed_certificate_path,
                MAX_CERTIFICATE_BYTES,
                "deployed certificate",
            )
            if _trusted_target_exists(self.deployed_certificate_path)
            else None
        )
        old_private_key = (
            _bounded_trusted_read(
                self.deployed_private_key_path,
                MAX_PRIVATE_KEY_BYTES,
                "deployed private key",
            )
            if _trusted_target_exists(self.deployed_private_key_path)
            else None
        )

        def restore_prior_material() -> None:
            if old_certificate is None:
                self._remove_deployed_file(self.deployed_certificate_path)
            else:
                self._atomic_copy(self.deployed_certificate_path, old_certificate, 0o644)
            if old_private_key is None:
                self._remove_deployed_file(self.deployed_private_key_path)
            else:
                self._atomic_copy(self.deployed_private_key_path, old_private_key, 0o600)
            certificate_restored = (
                not _trusted_target_exists(self.deployed_certificate_path)
                if old_certificate is None
                else _bounded_trusted_read(
                    self.deployed_certificate_path,
                    MAX_CERTIFICATE_BYTES,
                    "restored certificate",
                )
                == old_certificate
            )
            private_key_restored = (
                not _trusted_target_exists(self.deployed_private_key_path)
                if old_private_key is None
                else _bounded_trusted_read(
                    self.deployed_private_key_path,
                    MAX_PRIVATE_KEY_BYTES,
                    "restored private key",
                )
                == old_private_key
            )
            if not certificate_restored or not private_key_restored:
                raise CertificateCommandError("native certificate rollback verification failed")

        try:
            self._atomic_copy(self.deployed_certificate_path, certificate, 0o644)
            self._atomic_copy(self.deployed_private_key_path, private_key, 0o600)
            _validate_pair(
                _bounded_trusted_read(
                    self.deployed_certificate_path,
                    MAX_CERTIFICATE_BYTES,
                    "deployed certificate",
                ),
                _bounded_trusted_read(
                    self.deployed_private_key_path,
                    MAX_PRIVATE_KEY_BYTES,
                    "deployed private key",
                ),
            )
            return restore_prior_material
        except BaseException as exc:
            rollback_succeeded = False
            try:
                restore_prior_material()
                rollback_succeeded = True
            except BaseException:
                self.audit("certificates.deploy", outcome="rollback_failed", fields={"name": name})
            if rollback_succeeded:
                raise CertificateCommandError(
                    "certificate deployment failed and prior material was restored"
                ) from exc
            raise CertificateCommandError(
                "certificate deployment failed and rollback failed"
            ) from exc


__all__ = [
    "CertificateCommandError",
    "CertificateError",
    "CertificateManager",
    "CertificateReport",
    "CertificateStatus",
    "CertificateValidationError",
    "UnknownCertificate",
]
