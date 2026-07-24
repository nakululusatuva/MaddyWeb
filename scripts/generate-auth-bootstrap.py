#!/usr/bin/env python3
"""Generate a one-time authentication import and an offline handoff bundle."""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import html
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

import segno

from maddyweb.auth import (
    RECOVERY_CODE_COUNT,
    canonicalize_email,
    totp_provisioning_uri,
)

MAX_INPUT_BYTES = 256 * 1024
MAX_ACCOUNTS = 1000
_SERVER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_ISSUER_PATTERN = re.compile(r"[\x20-\x39\x3b-\x7e]{1,64}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _read_request() -> dict[str, Any]:
    content = bytearray(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
    try:
        if not content or len(content) > MAX_INPUT_BYTES:
            raise RuntimeError("generator input is empty or too large")
        try:
            value = json.loads(bytes(content), object_pairs_hook=_unique_object)
        except (UnicodeError, ValueError) as exc:
            raise RuntimeError("generator input is invalid JSON") from exc
    finally:
        content[:] = b"\0" * len(content)
        content.clear()
    if not isinstance(value, dict) or set(value) != {"server", "issuer", "accounts"}:
        raise RuntimeError("generator input fields are invalid")
    return value


def _validated_accounts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > MAX_ACCOUNTS:
        raise RuntimeError("generator account list is invalid")
    accounts: list[dict[str, Any]] = []
    seen: set[str] = set()
    administrators = 0
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "email",
            "role",
            "create_account",
        }:
            raise RuntimeError("generator account fields are invalid")
        try:
            email = canonicalize_email(item["email"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("generator account email is invalid") from exc
        role = item["role"]
        create_account = item["create_account"]
        if role not in {"admin", "user"} or not isinstance(create_account, bool):
            raise RuntimeError("generator account role or creation flag is invalid")
        if email in seen:
            raise RuntimeError("generator account list contains a duplicate")
        seen.add(email)
        administrators += int(role == "admin")
        accounts.append(
            {
                "email": email,
                "role": role,
                "create_account": create_account,
            }
        )
    if administrators != 1:
        raise RuntimeError("generator input must contain exactly one administrator")
    return accounts


def _validated_request(value: dict[str, Any]) -> tuple[str, str, list[dict[str, Any]]]:
    server = value["server"]
    issuer = value["issuer"]
    if not isinstance(server, str) or _SERVER_PATTERN.fullmatch(server) is None:
        raise RuntimeError("generator server name is invalid")
    if not isinstance(issuer, str) or _ISSUER_PATTERN.fullmatch(issuer) is None:
        raise RuntimeError("generator TOTP issuer is invalid")
    return server, issuer, _validated_accounts(value["accounts"])


def _totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _recovery_codes() -> tuple[str, ...]:
    return tuple(secrets.token_hex(16) for _ in range(RECOVERY_CODE_COUNT))


def _initial_password() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")


def _format_recovery_code(value: str) -> str:
    return "-".join(value[index : index + 8] for index in range(0, len(value), 8))


def _qr_svg(uri: str) -> str:
    qr_code = segno.make_qr(uri, error="M", boost_error=True)
    rendered = qr_code.svg_inline(
        scale=5,
        border=4,
        dark="#162033",
        light="#ffffff",
    )
    if not rendered.startswith("<svg ") or len(rendered) > 256 * 1024:
        raise RuntimeError("generated QR image is invalid")
    return rendered


def _generate_material(
    server: str,
    issuer: str,
    accounts: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest_accounts: list[dict[str, Any]] = []
    handoff_accounts: list[dict[str, Any]] = []
    for account in accounts:
        secret = _totp_secret()
        recovery_codes = _recovery_codes()
        password = _initial_password() if account["create_account"] else ""
        uri = totp_provisioning_uri(issuer, account["email"], secret)
        manifest_record: dict[str, Any] = {
            "email": account["email"],
            "role": account["role"],
            "totp_secret": secret,
            "recovery_codes": list(recovery_codes),
            "password_change_required": bool(account["create_account"]),
            "create_account": bool(account["create_account"]),
        }
        if password:
            manifest_record["initial_password"] = password
        manifest_accounts.append(manifest_record)
        handoff_accounts.append(
            {
                "email": account["email"],
                "role": account["role"],
                "secret": secret,
                "recovery_codes": recovery_codes,
                "initial_password": password,
                "qr_svg": _qr_svg(uri),
            }
        )
    return {"accounts": manifest_accounts}, handoff_accounts


def _bundle_html(
    server: str,
    issuer: str,
    accounts: list[dict[str, Any]],
) -> str:
    sections: list[str] = []
    for account in accounts:
        password = (
            f"""
            <div class="credential">
              <span>Initial mailbox password</span>
              <code>{html.escape(account["initial_password"])}</code>
              <p>Change this password during the first login.</p>
            </div>"""
            if account["initial_password"]
            else ""
        )
        codes = "\n".join(
            f"              <li><code>{_format_recovery_code(code)}</code></li>"
            for code in account["recovery_codes"]
        )
        sections.append(
            f"""
        <section class="account">
          <div class="account-copy">
            <p class="role">{html.escape(account["role"].upper())}</p>
            <h2>{html.escape(account["email"])}</h2>
            {password}
            <div class="credential">
              <span>Google Authenticator manual key</span>
              <code>{html.escape(account["secret"])}</code>
            </div>
            <div class="credential">
              <span>One-time recovery codes</span>
              <ol>
{codes}
              </ol>
            </div>
          </div>
          <div class="qr" aria-label="Google Authenticator QR code">
            {account["qr_svg"]}
            <p>Scan with Google Authenticator.</p>
          </div>
        </section>"""
        )
    account_markup = "\n".join(sections)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;
                 base-uri 'none'; form-action 'none'; object-src 'none'">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>MaddyWeb authentication handoff - {html.escape(server)}</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, system-ui, sans-serif; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: #f3f6fb; color: #162033; }}
    main {{ width: min(1120px, calc(100% - 48px)); margin: 48px auto; }}
    header {{ margin-bottom: 30px; }}
    h1 {{ margin: 8px 0; font-size: clamp(2rem, 4vw, 3.25rem); }}
    h2 {{ margin: 4px 0 22px; overflow-wrap: anywhere; }}
    .warning {{ color: #8a321c; font-weight: 700; }}
    .account {{ display: grid; grid-template-columns: minmax(0, 1fr) 300px;
      gap: 32px; margin: 24px 0; padding: 32px; background: white;
      border: 1px solid #d8e0ee; border-radius: 18px;
      box-shadow: 0 12px 40px rgb(29 49 84 / 8%); }}
    .role {{ color: #2e62ce; font-size: .75rem; font-weight: 800;
      letter-spacing: .12em; }}
    .credential {{ margin: 18px 0; }}
    .credential > span {{ display: block; margin-bottom: 7px; color: #5a667b;
      font-weight: 700; }}
    code {{ display: inline-block; max-width: 100%; padding: 5px 8px;
      background: #eef3fb; border-radius: 6px; font-family: ui-monospace, monospace;
      overflow-wrap: anywhere; user-select: all; }}
    ol {{ columns: 2; padding-left: 28px; }}
    li {{ margin: 8px 0; break-inside: avoid; }}
    .qr {{ align-self: start; text-align: center; }}
    .qr svg {{ width: 100%; height: auto; border: 1px solid #e2e8f2;
      border-radius: 12px; }}
    footer {{ margin-top: 30px; color: #5a667b; }}
    @media (max-width: 760px) {{
      main {{ width: min(100% - 24px, 680px); margin: 24px auto; }}
      .account {{ grid-template-columns: 1fr; padding: 22px; }}
      .qr {{ width: min(100%, 300px); }}
      ol {{ columns: 1; }}
    }}
    @media print {{
      body {{ background: white; }}
      main {{ width: 100%; margin: 0; }}
      .account {{ box-shadow: none; break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <p class="role">MADDYWEB AUTHENTICATION HANDOFF</p>
      <h1>{html.escape(server)}</h1>
      <p>TOTP issuer: <strong>{html.escape(issuer)}</strong></p>
      <p class="warning">Keep this file offline. It contains account recovery material.</p>
    </header>
{account_markup}
    <footer>
      Each TOTP key is unique to this server and mailbox. Each recovery code works once.
    </footer>
  </main>
</body>
</html>
"""


def _prepare_output_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise RuntimeError("output paths must be absolute")
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink() or parent.resolve(strict=True) != parent:
        raise RuntimeError("output parent must be an existing real directory")
    if path.exists() or path.is_symlink():
        raise RuntimeError("output path already exists")
    return path


def _system_powershell() -> Path:
    if os.name != "nt":
        raise RuntimeError("Windows PowerShell discovery is unavailable")
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    get_system_directory = kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    get_system_directory.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_system_directory(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        raise RuntimeError("Windows system directory discovery failed")
    powershell = Path(buffer.value) / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not powershell.is_absolute() or not powershell.is_file() or powershell.is_symlink():
        raise RuntimeError("trusted Windows PowerShell executable is unavailable")
    return powershell


def _prepare_windows_output_directory(paths: tuple[Path, Path]) -> bool:
    if os.name != "nt":
        return False
    parents = {path.parent for path in paths}
    if len(parents) != 1:
        raise RuntimeError("Windows secret outputs must share one private directory")
    directory = parents.pop()
    existed = directory.exists()
    if existed and (not directory.is_dir() or directory.is_symlink()):
        raise RuntimeError("secret output directory must be a real directory")
    if not existed:
        parent = directory.parent
        if not parent.is_dir() or parent.is_symlink() or parent.resolve(strict=True) != parent:
            raise RuntimeError("secret output directory parent must be an existing real directory")
    script = Path(__file__).with_name("protect-secret-bundle.ps1")
    powershell = _system_powershell()
    completed = subprocess.run(  # noqa: S603 - fixed executable and argv, no shell
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-Directory",
            str(directory),
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError("Windows private output directory preparation failed")
    return not existed


def _write_exclusive(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("secret output write failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if os.name != "nt":
        os.chmod(path, 0o600, follow_symlinks=False)
        if path.stat(follow_symlinks=False).st_mode & 0o077:
            raise RuntimeError("secret output permissions are not private")


def _protect_windows_outputs(paths: list[Path]) -> None:
    if os.name != "nt":
        return
    script = Path(__file__).with_name("protect-secret-bundle.ps1")
    powershell = _system_powershell()
    for path in paths:
        command = [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-Path",
            str(path),
        ]
        completed = subprocess.run(  # noqa: S603 - fixed executable and argv, no shell
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0:
            raise RuntimeError("Windows secret output ACL restriction failed")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read non-secret account metadata from stdin and generate a one-time "
            "bootstrap manifest plus an offline handoff bundle."
        )
    )
    parser.add_argument("--bootstrap-output", required=True)
    parser.add_argument("--bundle-output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    raw_paths = (
        Path(arguments.bootstrap_output),
        Path(arguments.bundle_output),
    )
    if any(not path.is_absolute() for path in raw_paths):
        raise RuntimeError("output paths must be absolute")
    private_directory_created = _prepare_windows_output_directory(raw_paths)
    bootstrap_path = _prepare_output_path(arguments.bootstrap_output)
    bundle_path = _prepare_output_path(arguments.bundle_output)
    if bootstrap_path == bundle_path:
        raise RuntimeError("bootstrap and bundle outputs must be different")

    server, issuer, accounts = _validated_request(_read_request())
    manifest, handoff = _generate_material(server, issuer, accounts)
    manifest_bytes = (json.dumps(manifest, ensure_ascii=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )
    bundle_bytes = _bundle_html(server, issuer, handoff).encode("ascii")

    created: list[Path] = []
    try:
        _write_exclusive(bootstrap_path, manifest_bytes)
        created.append(bootstrap_path)
        _write_exclusive(bundle_path, bundle_bytes)
        created.append(bundle_path)
        _protect_windows_outputs(created)
    except Exception:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        if private_directory_created:
            bootstrap_path.parent.rmdir()
        raise
    finally:
        manifest_bytes = b""
        bundle_bytes = b""
        manifest.clear()
        handoff.clear()

    bundle_digest = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    print(f"generated=ok accounts={len(accounts)} bundle_sha256={bundle_digest}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2) from None
