#!/usr/bin/env python3
"""Exercise the guarded host-network SMTP path without external delivery."""

from __future__ import annotations

import argparse
import io
import secrets

from maddyweb.helper import SMTPRejected, SMTPSubmissionClient
from maddyweb.maddy import MaddyService, MaddyTarget


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", required=True)
    args = parser.parse_args()

    target = MaddyTarget(
        mode="docker",
        container=args.container,
        maddy_executable="/bin/maddy",
        config_path="/data/maddy.conf",
        service_user=None,
    )
    service = MaddyService(target)
    if str(service.probe_version(refresh=True)) != "0.8.2":
        raise RuntimeError("host-network fixture did not run locked Maddy 0.8.2")
    safety = service.startup_safety_status()
    if safety.get("writes_enabled") is not True:
        raise RuntimeError("Maddy capability fingerprint blocked fixture writes")

    username = f"host-{secrets.token_hex(6)}@example.invalid"
    password = secrets.token_urlsafe(24)
    message_id = f"<{secrets.token_hex(16)}@example.invalid>"
    marker = f"maddyweb-host-network-{secrets.token_hex(16)}"
    message = (
        f"From: {username}\r\n"
        f"To: {username}\r\n"
        "Subject: guarded host-network fixture\r\n"
        f"Message-ID: {message_id}\r\n"
        "Date: Thu, 01 Jan 1970 00:00:00 +0000\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        f"{marker}\r\n"
    ).encode("ascii")

    account_created = False
    try:
        result = service.create_account(username, password)
        account_created = True
        if not result.get("has_credentials") or not result.get("has_mailbox"):
            raise RuntimeError("fixture account was not verified after creation")

        smtp = SMTPSubmissionClient(
            target,
            docker_submission_scope="host-loopback",
            timeout=15,
        )
        try:
            smtp.send(
                username=username,
                password=secrets.token_urlsafe(24),
                mail_from=username,
                recipients=(username,),
                message=io.BytesIO(message),
                message_length=len(message),
            )
        except SMTPRejected as exc:
            if exc.stage != "AUTH":
                raise RuntimeError("incorrect fixture password failed after AUTH") from exc
        else:
            raise RuntimeError("managed Submission accepted an incorrect password")

        accepted = smtp.send(
            username=username,
            password=password,
            mail_from=username,
            recipients=(username,),
            message=io.BytesIO(message),
            message_length=len(message),
        )
        if accepted != {"accepted": True, "recipients": 1}:
            raise RuntimeError("guarded SMTP did not report explicit acceptance")

        listing = service.list_messages(username, "INBOX", uid_set="1:*", full=True)
        record = next((item for item in listing if item.get("message_id") == message_id), None)
        if record is None or not isinstance(record.get("uid"), int):
            raise RuntimeError("local fixture delivery was not readable")
        uid = int(record["uid"])
        if marker.encode("ascii") not in service.dump_message(username, "INBOX", uid):
            raise RuntimeError("local fixture message body did not match")
        service.delete_messages(username, "INBOX", str(uid))
    finally:
        if account_created:
            service.delete_account(username)

    if username in service.list_credentials() or username in service.list_imap_accounts():
        raise RuntimeError("fixture account cleanup did not read back")


if __name__ == "__main__":
    main()
