#!/usr/bin/env python3
"""Exercise the real Maddy CLI through MaddyWeb's Docker adapter."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from maddyweb.certificates import CertificateCommandError, CertificateManager
from maddyweb.docker_certificates import DockerCertificateAdapter
from maddyweb.helper import SMTPRejected, SMTPSubmissionClient
from maddyweb.maddy import CommandResult, MaddyService, MaddyTarget, SubprocessRunner

_DOCKER_CERTIFICATE_PATH = "/data/maddyweb-cert-test/fullchain.pem"
_DOCKER_PRIVATE_KEY_PATH = "/data/maddyweb-cert-test/privkey.pem"


@dataclass(frozen=True)
class TimerResult:
    returncode: int
    stdout: bytes
    stderr: bytes = b""


class ReadOnlyTimerRunner:
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        max_output_bytes: int,
        run_as_user: str | None = None,
    ) -> TimerResult:
        del timeout, max_output_bytes, run_as_user
        command = tuple(argv)
        if command[-2:] == ("is-enabled", "certbot-renew.timer"):
            return TimerResult(1, b"disabled\n")
        if command[-2:] == ("is-active", "certbot-renew.timer"):
            return TimerResult(3, b"inactive\n")
        raise RuntimeError("certificate status attempted an unexpected command")


class FailKeyMoveOnceRunner:
    """Inject one failure after the certificate move, then delegate rollback."""

    def __init__(self, delegate: SubprocessRunner, container: str) -> None:
        self.delegate = delegate
        self.container = container
        self.injected = False

    def run(self, argv: Sequence[str], **kwargs: Any) -> CommandResult:
        command = tuple(argv)
        if (
            not self.injected
            and command[:6]
            == (
                "/usr/bin/docker",
                "exec",
                "--user",
                "0:0",
                self.container,
                "/bin/mv",
            )
            and command[-1:] == (_DOCKER_PRIVATE_KEY_PATH,)
        ):
            self.injected = True
            return CommandResult(command, 1, b"", b"", 0.0)
        return self.delegate.run(command, **kwargs)


EXPECTED_CAPABILITIES = {
    "0.8.2": {
        "account_admin",
        "certificate_file_admin",
        "diagnostics",
        "mailbox_admin",
        "message_admin",
        "tls_reload",
    },
    "0.9.0": {
        "account_admin",
        "certificate_file_admin",
        "diagnostics",
        "mailbox_admin",
        "message_admin",
        "tls_reload",
        "verify_config",
        "zero_downtime_reload",
    },
    "0.9.1": {
        "account_admin",
        "certificate_file_admin",
        "diagnostics",
        "mailbox_admin",
        "message_admin",
        "tls_reload",
        "verify_config",
        "zero_downtime_reload",
    },
    "0.9.2": {
        "account_admin",
        "certificate_file_admin",
        "diagnostics",
        "mailbox_admin",
        "message_admin",
        "tls_reload",
        "verify_config",
        "zero_downtime_reload",
    },
    "0.9.3": {
        "account_admin",
        "certificate_file_admin",
        "diagnostics",
        "ldap_auth_safe",
        "mailbox_admin",
        "message_admin",
        "tls_reload",
        "verify_config",
        "zero_downtime_reload",
    },
    "0.9.4": {
        "account_admin",
        "certificate_file_admin",
        "diagnostics",
        "explicit_cli_lifecycle",
        "ldap_auth_safe",
        "mailbox_admin",
        "message_admin",
        "tls_reload",
        "verify_config",
        "zero_downtime_reload",
    },
    "0.9.5": {
        "account_admin",
        "certificate_file_admin",
        "diagnostics",
        "explicit_cli_lifecycle",
        "ldap_auth_safe",
        "mailbox_admin",
        "message_admin",
        "tls_reload",
        "verify_config",
        "zero_downtime_reload",
    },
}


def test_native_certificate_adapter(certificate: Path, private_key: Path) -> str:
    name = "mx.example.invalid"
    live_dir = certificate.parent.parent
    if certificate != live_dir / name / "fullchain.pem":
        raise RuntimeError("temporary certificate fixture has an unexpected path")
    if private_key != live_dir / name / "privkey.pem":
        raise RuntimeError("temporary private-key fixture has an unexpected path")
    manager = CertificateManager(
        allowed_names=(name,),
        live_dir=live_dir,
        deployed_certificate_path=certificate,
        deployed_private_key_path=private_key,
        runner=ReadOnlyTimerRunner(),
    )
    status = manager.status(name)
    source = status.get("source")
    deployed = status.get("deployed")
    if not isinstance(source, dict) or not isinstance(deployed, dict):
        raise RuntimeError("certificate status omitted source/deployed structures")
    if source.get("error") is not None or deployed.get("error") is not None:
        raise RuntimeError("temporary certificate failed real read-only parsing")
    if source.get("private_key_permissions_safe") is not True:
        raise RuntimeError("temporary private key permissions are unsafe")
    fingerprint = source.get("sha256_fingerprint")
    if (
        not isinstance(fingerprint, str)
        or not fingerprint
        or deployed.get("sha256_fingerprint") != fingerprint
        or status.get("fingerprints_match") is not True
    ):
        raise RuntimeError("source/deployed certificate fingerprints do not match")
    timer = status.get("timer")
    if (
        not isinstance(timer, dict)
        or timer.get("enabled") is not False
        or timer.get("active") is not False
    ):
        raise RuntimeError("read-only timer status contract changed")
    return fingerprint


def _docker_command(
    runner: SubprocessRunner,
    container: str,
    *inner: str,
    max_output_bytes: int = 64 * 1024,
) -> CommandResult:
    result = runner.run(
        ("/usr/bin/docker", "exec", container, *inner),
        timeout=30.0,
        max_output_bytes=max_output_bytes,
        max_input_bytes=1,
        run_as_user=None,
    )
    if result.returncode != 0:
        raise RuntimeError("fixed Docker certificate integration command failed")
    return result


def _deployed_bytes(
    runner: SubprocessRunner,
    container: str,
    path: str,
    maximum: int,
) -> bytes:
    value = _docker_command(
        runner,
        container,
        "/bin/cat",
        path,
        max_output_bytes=maximum,
    ).stdout
    if not value or len(value) > maximum:
        raise RuntimeError("Docker certificate integration output has an invalid size")
    return value


def test_docker_certificate_adapter(
    container: str,
    certificate: Path,
    private_key: Path,
    spool_dir: Path,
) -> str:
    name = "mx.example.invalid"
    runner = SubprocessRunner()
    adapter = DockerCertificateAdapter(
        container=container,
        allowed_names=(name,),
        live_dir=certificate.parent.parent,
        data_dir="/data",
        deployed_certificate_path=_DOCKER_CERTIFICATE_PATH,
        deployed_private_key_path=_DOCKER_PRIVATE_KEY_PATH,
        runner=runner,
        spool_dir=spool_dir,
        timeout=30.0,
    )

    adapter.deploy(name)
    status = adapter.status()
    if status.error is not None or not status.sha256_fingerprint:
        raise RuntimeError("Docker deployed certificate status is invalid")
    if status.certificate_path or status.private_key_path:
        raise RuntimeError("Docker deployed certificate status exposed an internal path")
    source_fingerprint = test_native_certificate_adapter(certificate, private_key)
    if status.sha256_fingerprint != source_fingerprint:
        raise RuntimeError("Docker deployed certificate fingerprint does not match source")
    if _deployed_bytes(runner, container, _DOCKER_CERTIFICATE_PATH, 2 * 1024 * 1024) != (
        certificate.read_bytes()
    ):
        raise RuntimeError("Docker deployed certificate bytes do not match source")
    if _deployed_bytes(runner, container, _DOCKER_PRIVATE_KEY_PATH, 1024 * 1024) != (
        private_key.read_bytes()
    ):
        raise RuntimeError("Docker deployed private-key bytes do not match source")

    modes = _docker_command(
        runner,
        container,
        "/bin/stat",
        "-c",
        "%a:%u:%g",
        _DOCKER_CERTIFICATE_PATH,
        _DOCKER_PRIVATE_KEY_PATH,
        max_output_bytes=256,
    ).stdout.splitlines()
    if modes != [b"644:0:0", b"600:0:0"]:
        raise RuntimeError("Docker deployed certificate mode or initial owner is unsafe")

    # Make existing ownership non-default, then inject a failure on the second
    # final mv. The real adapter must restore both exact byte streams and owners.
    _docker_command(
        runner,
        container,
        "/bin/chown",
        "123:456",
        _DOCKER_CERTIFICATE_PATH,
    )
    _docker_command(
        runner,
        container,
        "/bin/chown",
        "234:567",
        _DOCKER_PRIVATE_KEY_PATH,
    )
    old_certificate = _deployed_bytes(runner, container, _DOCKER_CERTIFICATE_PATH, 2 * 1024 * 1024)
    old_private_key = _deployed_bytes(runner, container, _DOCKER_PRIVATE_KEY_PATH, 1024 * 1024)
    certificate.write_bytes(certificate.read_bytes() + b"\n")
    private_key.write_bytes(private_key.read_bytes() + b"\n")
    injected_runner = FailKeyMoveOnceRunner(runner, container)
    failing_adapter = DockerCertificateAdapter(
        container=container,
        allowed_names=(name,),
        live_dir=certificate.parent.parent,
        data_dir="/data",
        deployed_certificate_path=_DOCKER_CERTIFICATE_PATH,
        deployed_private_key_path=_DOCKER_PRIVATE_KEY_PATH,
        runner=injected_runner,
        spool_dir=spool_dir,
        timeout=30.0,
    )
    try:
        failing_adapter.deploy(name)
    except CertificateCommandError as exc:
        if "prior material was restored" not in str(exc):
            raise RuntimeError("Docker certificate rollback result was ambiguous") from exc
    else:
        raise RuntimeError("Docker certificate rollback failure injection did not trigger")
    if not injected_runner.injected:
        raise RuntimeError("Docker certificate rollback failure injection was not reached")
    if (
        _deployed_bytes(runner, container, _DOCKER_CERTIFICATE_PATH, 2 * 1024 * 1024)
        != old_certificate
        or _deployed_bytes(runner, container, _DOCKER_PRIVATE_KEY_PATH, 1024 * 1024)
        != old_private_key
    ):
        raise RuntimeError("Docker certificate rollback did not restore exact prior bytes")
    restored_owners = _docker_command(
        runner,
        container,
        "/bin/stat",
        "-c",
        "%u:%g",
        _DOCKER_CERTIFICATE_PATH,
        _DOCKER_PRIVATE_KEY_PATH,
        max_output_bytes=128,
    ).stdout.splitlines()
    if restored_owners != [b"123:456", b"234:567"]:
        raise RuntimeError("Docker certificate rollback did not restore prior owners")
    listing = _docker_command(
        runner,
        container,
        "/bin/ls",
        "-A",
        "/data/maddyweb-cert-test",
        max_output_bytes=4096,
    ).stdout.splitlines()
    if sorted(listing) != [b"fullchain.pem", b"privkey.pem"]:
        raise RuntimeError("Docker certificate deployment left staging material behind")
    if any(spool_dir.iterdir()):
        raise RuntimeError("Docker certificate deployment left host staging material behind")
    return source_fingerprint


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", required=True)
    parser.add_argument("--expected-version", required=True, choices=tuple(EXPECTED_CAPABILITIES))
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--spool-dir", type=Path, required=True)
    args = parser.parse_args()

    target = MaddyTarget(
        mode="docker",
        container=args.container,
        maddy_executable="/bin/maddy",
        config_path="/data/maddy.conf",
        service_user=None,
    )
    service = MaddyService(target)
    detected = str(service.probe_version(refresh=True))
    if detected != args.expected_version:
        raise RuntimeError(f"detected Maddy {detected}, expected {args.expected_version}")
    capabilities = {capability.value for capability in service.capabilities()}
    if capabilities != EXPECTED_CAPABILITIES[args.expected_version]:
        raise RuntimeError("Maddy capability set differs from the locked compatibility contract")
    if "verify_config" in capabilities:
        service.verify_config()
    safety = service.startup_safety_status()
    if safety.get("writes_enabled") is not True:
        raise RuntimeError("Maddy CLI help/capability fingerprint blocked write operations")
    capability_fingerprint = hashlib.sha256(
        ",".join(sorted(capabilities)).encode("ascii")
    ).hexdigest()
    certificate_fingerprint = test_native_certificate_adapter(args.certificate, args.private_key)
    docker_certificate_fingerprint = test_docker_certificate_adapter(
        args.container,
        args.certificate,
        args.private_key,
        args.spool_dir,
    )

    # The credential is random, short-lived, passed only over docker exec stdin,
    # and never included in output or exception text.
    username = f"matrix-{secrets.token_hex(6)}@example.invalid"
    initial_password = secrets.token_urlsafe(24)
    replacement_password = secrets.token_urlsafe(24)
    credentials_created = False
    imap_created = False
    message_id = f"<{secrets.token_hex(16)}@example.invalid>"
    marker = f"maddyweb-matrix-{secrets.token_hex(16)}"
    message = (
        "From: matrix@example.invalid\r\n"
        f"To: {username}\r\n"
        "Subject: local compatibility fixture\r\n"
        f"Message-ID: {message_id}\r\n"
        "Date: Thu, 01 Jan 1970 00:00:00 +0000\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        f"{marker}\r\n"
    ).encode()

    try:
        account = service.create_account(username, initial_password)
        credentials_created = True
        imap_created = True
        if not account.get("has_credentials") or not account.get("has_mailbox"):
            raise RuntimeError("account create did not read back both records")
        service.change_password(username, replacement_password)
        if service.set_append_limit(username, 1_048_576) != 1_048_576:
            raise RuntimeError("APPENDLIMIT read-back failed")
        smtp = SMTPSubmissionClient(target, timeout=15)
        smtp_id = f"<{secrets.token_hex(16)}@example.invalid>"
        smtp_marker = f"maddyweb-smtp-matrix-{secrets.token_hex(16)}"
        smtp_message = (
            f"From: {username}\r\n"
            f"To: {username}\r\n"
            "Subject: authenticated local SMTP fixture\r\n"
            f"Message-ID: {smtp_id}\r\n"
            "Date: Thu, 01 Jan 1970 00:00:00 +0000\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            f"{smtp_marker}\r\n"
        ).encode()
        try:
            smtp.send(
                username=username,
                password=secrets.token_urlsafe(24),
                mail_from=username,
                recipients=(username,),
                message=io.BytesIO(smtp_message),
                message_length=len(smtp_message),
            )
        except SMTPRejected as exc:
            if exc.stage != "AUTH":
                raise RuntimeError("incorrect SMTP password failed after authentication") from exc
        else:
            raise RuntimeError("managed Submission accepted an incorrect password")
        smtp_result = smtp.send(
            username=username,
            password=replacement_password,
            mail_from=username,
            recipients=(username,),
            message=io.BytesIO(smtp_message),
            message_length=len(smtp_message),
        )
        if smtp_result != {"accepted": True, "recipients": 1}:
            raise RuntimeError("authenticated Docker SMTP did not return explicit acceptance")
        smtp_listing = service.list_messages(username, "INBOX", uid_set="1:*", full=True)
        smtp_record = next(
            (item for item in smtp_listing if item.get("message_id") == smtp_id),
            None,
        )
        if smtp_record is None or not isinstance(smtp_record.get("uid"), int):
            raise RuntimeError("authenticated Docker SMTP delivery was not readable")
        smtp_uid = int(smtp_record["uid"])
        smtp_dump = service.dump_message(username, "INBOX", smtp_uid)
        if smtp_marker.encode("ascii") not in smtp_dump:
            raise RuntimeError("authenticated Docker SMTP message body did not match")
        service.delete_messages(username, "INBOX", str(smtp_uid))

        pagination_uids = [service.append_message(username, "INBOX", message) for _ in range(7)]
        removed_uid = pagination_uids.pop(3)
        service.delete_messages(username, "INBOX", str(removed_uid))
        expected_uids = sorted(pagination_uids, reverse=True)
        observed_uids: list[int] = []
        cursor_uid = 0
        for _ in range(8):
            window = service.list_message_window(
                username,
                "INBOX",
                limit=2,
                cursor_uid=cursor_uid,
            )
            observed_uids.extend(int(item["uid"]) for item in window[:2])
            if len(window) <= 2:
                break
            cursor_uid = int(window[2]["uid"])
        if observed_uids != expected_uids:
            raise RuntimeError("bounded message pagination skipped or duplicated a UID")
        for pagination_uid in pagination_uids:
            service.delete_messages(username, "INBOX", str(pagination_uid))

        service.create_mailbox(username, "MatrixArchive")
        uid = service.append_message(username, "INBOX", message)
        inbox_listing = service.list_messages(username, "INBOX", uid_set=str(uid), full=True)
        if not any(
            item.get("uid") == uid and item.get("message_id") == message_id
            for item in inbox_listing
        ):
            raise RuntimeError("message list did not contain the local fixture")
        dumped = service.dump_message(username, "INBOX", uid)
        if marker.encode("ascii") not in dumped:
            raise RuntimeError("message dump did not match the local fixture")
        service.move_messages(username, "INBOX", str(uid), "MatrixArchive")
        archive_listing = service.list_messages(username, "MatrixArchive", uid_set="1:*", full=True)
        destination = next(
            (item for item in archive_listing if item.get("message_id") == message_id),
            None,
        )
        if destination is None:
            raise RuntimeError("message move did not read back from Archive")
        destination_uid = destination.get("uid")
        if not isinstance(destination_uid, int) or destination_uid <= 0:
            raise RuntimeError("could not parse destination UID after move")
        service.delete_messages(username, "MatrixArchive", str(destination_uid))
        if any(
            item.get("message_id") == message_id
            for item in service.list_messages(username, "MatrixArchive", uid_set="1:*", full=True)
        ):
            raise RuntimeError("message remove read-back failed")
        service.disable_credentials(username)
        credentials_created = False
        service.delete_imap_account(username)
        imap_created = False
        if any(item.get("username") == username for item in service.list_accounts()):
            raise RuntimeError("account remove read-back failed")
    finally:
        if credentials_created:
            # The outer fixture destroys the isolated volume unconditionally.
            with contextlib.suppress(Exception):
                service.disable_credentials(username)
        if imap_created:
            with contextlib.suppress(Exception):
                service.delete_imap_account(username)

    report = {
        "status": "ok",
        "version": detected,
        "capabilities": sorted(capabilities),
        "capability_fingerprint": capability_fingerprint,
        "cli_fingerprint": safety.get("cli_fingerprint"),
        "certificate_fingerprint": certificate_fingerprint,
        "docker_certificate_fingerprint": docker_certificate_fingerprint,
        "operations": [
            "account.create",
            "account.list",
            "account.password",
            "account.appendlimit",
            "smtp.auth.reject",
            "smtp.deliver",
            "message.add",
            "message.list",
            "message.page",
            "message.dump",
            "message.move",
            "message.remove",
            "account.remove",
            "certificate.docker.deploy",
            "certificate.docker.status",
            "certificate.docker.rollback",
        ],
    }
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
