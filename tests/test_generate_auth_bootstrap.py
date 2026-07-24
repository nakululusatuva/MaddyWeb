from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from maddyweb.auth import RECOVERY_CODE_COUNT, decode_totp_secret

SCRIPT = Path(__file__).parents[1] / "scripts" / "generate-auth-bootstrap.py"
ACL_SCRIPT = Path(__file__).parents[1] / "scripts" / "protect-secret-bundle.ps1"


def _request() -> dict[str, Any]:
    return {
        "server": "email_example",
        "issuer": "MaddyWeb Example",
        "accounts": [
            {
                "email": "user@example.test",
                "role": "user",
                "create_account": False,
            },
            {
                "email": "admin@example.test",
                "role": "admin",
                "create_account": True,
            },
        ],
    }


def _run_generator(
    tmp_path: Path,
    document: object,
    *,
    bootstrap_name: str = "bootstrap.json",
    bundle_name: str = "handoff.html",
) -> tuple[subprocess.CompletedProcess[bytes], Path, Path]:
    bootstrap = tmp_path / bootstrap_name
    bundle = tmp_path / bundle_name
    result = subprocess.run(  # noqa: S603 - fixed test interpreter and script
        [
            sys.executable,
            str(SCRIPT),
            "--bootstrap-output",
            str(bootstrap),
            "--bundle-output",
            str(bundle),
        ],
        input=json.dumps(document, ensure_ascii=True).encode("ascii"),
        capture_output=True,
        check=False,
        timeout=30,
    )
    return result, bootstrap, bundle


def test_generator_creates_private_import_and_offline_handoff(tmp_path: Path) -> None:
    result, bootstrap, bundle = _run_generator(tmp_path, _request())

    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert result.stdout.startswith(b"generated=ok accounts=2 bundle_sha256=")
    assert result.stderr == b""
    manifest = json.loads(bootstrap.read_text(encoding="ascii"))
    assert set(manifest) == {"accounts"}
    assert len(manifest["accounts"]) == 2
    by_email = {record["email"]: record for record in manifest["accounts"]}

    user = by_email["user@example.test"]
    assert user["role"] == "user"
    assert user["create_account"] is False
    assert user["password_change_required"] is False
    assert "initial_password" not in user

    administrator = by_email["admin@example.test"]
    assert administrator["role"] == "admin"
    assert administrator["create_account"] is True
    assert administrator["password_change_required"] is True
    assert len(administrator["initial_password"]) >= 40
    assert "\r" not in administrator["initial_password"]
    assert "\n" not in administrator["initial_password"]

    secrets_seen: set[str] = set()
    for record in manifest["accounts"]:
        assert len(decode_totp_secret(record["totp_secret"])) == 20
        assert record["totp_secret"] not in secrets_seen
        secrets_seen.add(record["totp_secret"])
        codes = record["recovery_codes"]
        assert len(codes) == RECOVERY_CODE_COUNT
        assert len(set(codes)) == RECOVERY_CODE_COUNT
        assert all(len(code) == 32 and int(code, 16) >= 0 for code in codes)
        secrets_seen.update(codes)

    output = result.stdout + result.stderr
    assert all(secret.encode("ascii") not in output for secret in secrets_seen)
    assert administrator["initial_password"].encode("ascii") not in output

    handoff = bundle.read_text(encoding="ascii")
    assert handoff.startswith("<!doctype html>")
    assert "https://" not in handoff
    assert "<script" not in handoff.casefold()
    assert "default-src 'none'" in handoff
    assert "form-action 'none'" in handoff
    assert handoff.count("<svg ") == 2
    assert "user@example.test" in handoff
    assert "admin@example.test" in handoff
    assert administrator["totp_secret"] in handoff
    assert administrator["initial_password"] in handoff

    if os.name == "posix":
        assert stat.S_IMODE(bootstrap.stat().st_mode) == 0o600
        assert stat.S_IMODE(bundle.stat().st_mode) == 0o600


def test_generator_refuses_overwrite_without_changing_existing_files(
    tmp_path: Path,
) -> None:
    bootstrap = tmp_path / "bootstrap.json"
    bootstrap.write_bytes(b"existing bootstrap")

    result, returned_bootstrap, bundle = _run_generator(tmp_path, _request())

    assert result.returncode == 2
    assert b"output path already exists" in result.stderr
    assert returned_bootstrap.read_bytes() == b"existing bootstrap"
    assert not bundle.exists()


@pytest.mark.parametrize(
    "document",
    [
        {
            "server": "email_example",
            "issuer": "MaddyWeb Example",
            "accounts": [
                {
                    "email": "user@example.test",
                    "role": "user",
                    "create_account": False,
                }
            ],
        },
        {
            "server": "email_example",
            "issuer": "MaddyWeb Example",
            "accounts": [
                {
                    "email": "admin-one@example.test",
                    "role": "admin",
                    "create_account": True,
                },
                {
                    "email": "admin-two@example.test",
                    "role": "admin",
                    "create_account": True,
                },
            ],
        },
    ],
)
def test_generator_requires_exactly_one_administrator(
    tmp_path: Path,
    document: dict[str, Any],
) -> None:
    result, bootstrap, bundle = _run_generator(tmp_path, document)

    assert result.returncode == 2
    assert b"exactly one administrator" in result.stderr
    assert not bootstrap.exists()
    assert not bundle.exists()


def test_generator_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    bootstrap = tmp_path / "bootstrap.json"
    bundle = tmp_path / "handoff.html"
    result = subprocess.run(  # noqa: S603 - fixed test interpreter and script
        [
            sys.executable,
            str(SCRIPT),
            "--bootstrap-output",
            str(bootstrap),
            "--bundle-output",
            str(bundle),
        ],
        input=(b'{"server":"first","server":"second","issuer":"MaddyWeb Example","accounts":[]}'),
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 2
    assert b"invalid JSON" in result.stderr
    assert not bootstrap.exists()
    assert not bundle.exists()


def test_windows_secret_tools_use_trusted_discovery_and_exact_acl_contract() -> None:
    generator_source = SCRIPT.read_text(encoding="ascii")
    acl_source = ACL_SCRIPT.read_text(encoding="ascii")

    assert "GetSystemDirectoryW" in generator_source
    assert "SYSTEMROOT" not in generator_source
    assert "powershell.is_symlink()" in generator_source
    assert "$rules.Count -ne $allowedSids.Count" in acl_source
    assert "$rule.IsInherited" in acl_source
    assert "$rule.InheritanceFlags -ne $ExpectedInheritance" in acl_source
    assert "$rule.FileSystemRights -ne $rights" in acl_source
