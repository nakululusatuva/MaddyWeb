from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from maddyweb.helper import ALLOWED_OPERATIONS
from maddyweb.mail import (
    attachment_download_headers,
    rewrite_cid_images,
    sandboxed_html_document,
    sanitize_html_email,
)
from maddyweb.security import email_document_headers
from maddyweb.web import (
    _ANONYMOUS_PATHS,
    _PASSWORD_CHANGE_PATHS,
    _TOKENLESS_PUBLIC_STATIC_PATHS,
)

ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_anonymous_surface_is_an_explicit_minimal_allowlist() -> None:
    expected_anonymous = {
        "/login",
        "/static/login.css",
        "/static/login.js",
        "/api/v1/auth/csrf",
        "/api/v1/auth/password",
        "/api/v1/auth/enrollment",
        "/api/v1/auth/enrollment/confirm",
        "/api/v1/auth/totp",
        "/api/v1/auth/recovery",
        "/api/v1/auth/passkey/options",
        "/api/v1/auth/passkey",
    }
    expected_public_static = {
        "/static/login.css",
        "/static/login.js",
    }
    expected_password_change = {
        "/security",
        "/api/v1/auth/session",
        "/api/v1/auth/logout",
        "/api/v1/auth/password/change",
        "/api/v1/auth/step-up",
        "/api/v1/auth/passkeys",
        "/api/v1/auth/passkey/step-up/options",
        "/api/v1/auth/passkey/step-up",
        "/api/v1/auth/sessions",
        "/static/app.css",
        "/static/app.js",
        "/static/workspace.js",
        "/static/preview.css",
    }
    assert expected_anonymous == _ANONYMOUS_PATHS
    assert expected_public_static == _TOKENLESS_PUBLIC_STATIC_PATHS
    assert not {
        "/",
        "/mail",
        "/compose",
        "/accounts",
        "/certificates",
        "/security",
        "/static/app.css",
        "/static/app.js",
        "/static/workspace.js",
        "/static/preview.css",
        "/api/v1/health",
        "/api/v1/me/mail",
        "/api/v1/admin/accounts",
    } & _ANONYMOUS_PATHS
    assert expected_password_change == _PASSWORD_CHANGE_PATHS


def test_helper_permissions_keep_public_session_admin_and_mail_scopes_separate() -> None:
    public_operations = {
        name for name, operation in ALLOWED_OPERATIONS.items() if operation.permission == "public"
    }
    assert public_operations == {
        "maddy.health",
        "maddy.version",
        "auth.password_begin",
        "auth.enrollment_begin",
        "auth.enrollment_complete",
        "auth.totp_complete",
        "auth.recovery_complete",
        "auth.passkey_login_begin",
        "auth.passkey_login_complete",
    }

    account_operations = {
        name for name, operation in ALLOWED_OPERATIONS.items() if operation.permission == "account"
    }
    assert account_operations == {
        "mailboxes.list",
        "mailboxes.create",
        "mailboxes.delete",
        "mailboxes.rename",
        "messages.list",
        "messages.latest",
        "messages.get",
        "messages.append",
        "messages.delete",
        "messages.delete_many",
        "messages.copy",
        "messages.move",
        "messages.set_flags",
        "messages.add_flags",
        "messages.remove_flags",
        "messages.send",
    }
    assert all(
        ALLOWED_OPERATIONS[name].permission in {"admin", "admin_account"}
        for name in ALLOWED_OPERATIONS
        if name.startswith(("accounts.", "certificates."))
    )
    assert all(
        operation.permission != "public"
        for operation in ALLOWED_OPERATIONS.values()
        if operation.stream_in or operation.stream_out
    )


def test_sensitive_helper_mutations_require_recent_authentication() -> None:
    protected = {
        "auth.change_password",
        "auth.passkey_register_begin",
        "auth.passkey_register_complete",
        "auth.passkey_delete",
        "auth.session_revoke_other",
        "auth.admin_rotate_totp",
        "accounts.create",
        "accounts.change_password",
        "accounts.disable_credentials",
        "accounts.delete_imap_account",
        "accounts.set_append_limit",
        "certificates.timer_enable",
        "certificates.timer_disable",
        "certificates.renew_dry_run",
        "certificates.renew",
        "messages.delete",
        "messages.delete_many",
    }
    assert protected <= ALLOWED_OPERATIONS.keys()
    assert all(ALLOWED_OPERATIONS[name].mutating for name in protected)
    assert all(ALLOWED_OPERATIONS[name].step_up for name in protected)


def test_runtime_python_has_no_direct_shell_or_dynamic_code_execution() -> None:
    violations: list[str] = []
    for path in sorted((ROOT / "src" / "maddyweb").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                violations.append(f"{path.name}:{node.lineno}:{node.func.id}")
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr in {"system", "popen"}
            ):
                violations.append(f"{path.name}:{node.lineno}:os.{node.func.attr}")
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    violations.append(f"{path.name}:{node.lineno}:shell=True")
    assert violations == []


def test_mail_preview_and_download_contracts_remain_inert() -> None:
    cleaned = sanitize_html_email(
        '<script>run()</script><form action="https://outside.invalid/">x</form>'
        '<img src="https://outside.invalid/pixel">'
        '<img src="cid:logo" onerror="run()">'
        '<table width="640" height="120" align="center" '
        'style="color:#123456;background-color:#f5f7fa;border:2px solid #345678;'
        'font-family:Arial,sans-serif;width:640px;min-width:320px;height:120px;'
        'text-align:center"><tr><td style="border:1px solid #789abc;padding:8px;'
        'vertical-align:middle">Quarterly summary</td></tr></table>'
        '<div style="position:fixed;color:#112233">position probe</div>'
        '<div style="background-image:url(https://css.invalid/pixel)">network probe</div>'
        '<span style="width:expression(run())">expression probe</span>'
        '<style>@import url(https://sheet.invalid/layout.css);</style>'
        '<a href="javascript:run()">bad</a>'
        '<a href="https://example.test/path" target="_self" rel="opener">safe</a>'
    )
    rewritten = rewrite_cid_images(cleaned, {"logo": "data:image/png;base64,AAAA"})
    assert "<script" not in rewritten
    assert "<form" not in rewritten
    assert "outside.invalid" not in rewritten
    assert "javascript:" not in rewritten
    assert "onerror" not in rewritten
    assert "color:#123456" in rewritten
    assert "background-color:#f5f7fa" in rewritten
    assert "border:2px solid #345678" in rewritten
    assert "font-family:" in rewritten
    assert "width:640px" in rewritten
    assert "min-width:320px" in rewritten
    assert "height:120px" in rewritten
    assert "text-align:center" in rewritten
    assert "vertical-align:middle" in rewritten
    assert "position:" not in rewritten
    assert "background-image" not in rewritten
    assert "url(" not in rewritten
    assert "expression(" not in rewritten
    assert "<style" not in rewritten
    assert "css.invalid" not in rewritten
    assert "sheet.invalid" not in rewritten
    assert 'target="_blank"' in rewritten
    assert 'rel="noopener noreferrer nofollow"' in rewritten

    document = sandboxed_html_document(rewritten, already_sanitized=True)
    response_headers = email_document_headers()
    assert "default-src 'none'" in document
    assert "form-action 'none'" in document
    assert "color:#123456" in document
    assert "background-color:#f5f7fa" in document
    assert "sandbox" in response_headers["Content-Security-Policy"]
    assert "default-src 'none'" in response_headers["Content-Security-Policy"]
    assert response_headers["Referrer-Policy"] == "no-referrer"

    download_headers = attachment_download_headers("../../page.html")
    assert download_headers["Content-Type"] == "application/octet-stream"
    assert download_headers["Content-Disposition"].startswith("attachment;")
    assert download_headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'none'" in download_headers["Content-Security-Policy"]


def test_deployment_templates_preserve_privilege_and_proxy_boundaries() -> None:
    web_unit = _read("deploy/systemd/maddyweb.service")
    helper_unit = _read("deploy/systemd/maddyweb-helper.service")
    helper_socket = _read("deploy/systemd/maddyweb-helper.socket")

    for directive in (
        "User=maddyweb",
        "Group=maddyweb",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "SocketBindAllow=tcp:8787",
        "SocketBindDeny=any",
        "IPAddressDeny=any",
        "IPAddressAllow=localhost",
        "InaccessiblePaths=-/run/docker.sock -/var/run/docker.sock",
    ):
        assert directive in web_unit
    assert "ListenStream=/run/maddyweb/helper.sock" in helper_socket
    assert "SocketUser=root" in helper_socket
    assert "SocketGroup=maddyweb" in helper_socket
    assert "SocketMode=0660" in helper_socket
    assert "User=root" in helper_unit
    assert "NoNewPrivileges=yes" in helper_unit
    assert "ProtectSystem=strict" in helper_unit
    assert "RestrictAddressFamilies=AF_UNIX AF_INET" in helper_unit
    assert "InaccessiblePaths=-/run/docker.sock -/var/run/docker.sock" in helper_unit
    assert "BindReadOnlyPaths=" not in helper_unit

    edge_templates = (
        "deploy/public-edge/nginx/maddy.custom.example.test.conf",
        "deploy/public-edge/nginx/maddy.standalone.example.test.conf",
    )
    for relative in edge_templates:
        edge = _read(relative)
        host = re.search(r"server_name ([a-z0-9.-]+);", edge)
        assert host is not None
        expected_host = host.group(1)
        for directive in (
            "if ($maddyweb_cloudflare_peer = 0)",
            "return 444;",
            f"proxy_set_header Host {expected_host};",
            "proxy_set_header X-Forwarded-Host \"\";",
            "proxy_set_header X-Forwarded-Proto https;",
            "proxy_set_header X-Forwarded-For \"\";",
            "proxy_set_header X-Real-IP $remote_addr;",
            "proxy_set_header Forwarded \"\";",
            "proxy_set_header CF-Connecting-IP \"\";",
            "location = /healthz {\n        return 404;",
            "proxy_pass http://127.0.0.1:8787;",
        ):
            assert directive in edge
        assert "proxy_pass http://0.0.0.0" not in edge


def test_release_installation_remains_hash_bound_and_fail_closed() -> None:
    verifier = _read("scripts/verify-release-artifact.py")
    installer = _read("scripts/install.sh")
    requirements = _read("requirements.lock")

    for contract in (
        "O_NOFOLLOW",
        "metadata.st_nlink != 1",
        "--expected-sha256",
        'required_keys = {"format", "commit", "artifact", "sha256"}',
        "artifact content checksum mismatch",
    ):
        assert contract in verifier
    verification = installer.index('artifact_report=$("$python_binary"')
    installation = installer.index('"$staging/bin/python" -m pip install')
    release_switch = installer.index('ln -s -- "$release_path" "$temporary_link"')
    assert verification < installation < release_switch
    install_contract = installer[installation:release_switch]
    assert "--no-index" in install_contract
    assert "--require-hashes" in install_contract
    assert "--hash=sha256:" in requirements
    assert "git+" not in requirements
    assert "http://" not in requirements


def _verify_release(
    artifact: Path,
    manifest: Path,
    checksum: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts" / "verify-release-artifact.py"),
            "--artifact",
            str(artifact),
            "--manifest",
            str(manifest),
            "--expected-sha256",
            checksum,
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_release_manifest_rejects_ambiguity_and_content_tampering(tmp_path: Path) -> None:
    artifact = tmp_path / "maddyweb-1.0.0-py3-none-any.whl"
    content = b"fixed release fixture"
    artifact.write_bytes(content)
    checksum = hashlib.sha256(content).hexdigest()
    record = {
        "format": "maddyweb-release-v1",
        "commit": "0" * 40,
        "artifact": artifact.name,
        "sha256": checksum,
    }
    manifest = tmp_path / "release.json"
    manifest.write_text(json.dumps(record), encoding="utf-8")
    assert _verify_release(artifact, manifest, checksum).returncode == 0

    duplicate_manifest = tmp_path / "duplicate.json"
    duplicate_manifest.write_text(
        "{"
        '"format":"maddyweb-release-v1",'
        f'"commit":"{"0" * 40}",'
        f'"commit":"{"1" * 40}",'
        f'"artifact":"{artifact.name}",'
        f'"sha256":"{checksum}"'
        "}",
        encoding="utf-8",
    )
    duplicate = _verify_release(artifact, duplicate_manifest, checksum)
    assert duplicate.returncode != 0
    assert "duplicate object keys" in duplicate.stderr

    artifact.write_bytes(b"changed release fixture")
    tampered = _verify_release(artifact, manifest, checksum)
    assert tampered.returncode != 0
    assert "checksum mismatch" in tampered.stderr


def test_github_security_workflow_runs_on_every_change_and_fails_closed() -> None:
    workflow = _read(".github/workflows/security.yml")
    assert re.search(r"^on:\n(?:.*\n)*?  push:\n  pull_request:", workflow, re.MULTILINE)
    assert "pull_request_target:" not in workflow
    assert "permissions:\n  contents: read" in workflow
    python_job = workflow[
        workflow.index("  python-security:") : workflow.index("\n  trivy:")
    ]
    assert "continue-on-error:" not in python_job
    for command in (
        "python -m ruff check .",
        "python -m pip_audit -r requirements.lock --no-deps --disable-pip",
        "python -m bandit -q -lll -r src scripts",
        "python -m pytest -q tests/test_security_audit.py",
        "tests/test_security.py",
        "tests/test_web_auth.py",
        "tests/test_mail.py",
        "tests/test_helper.py",
        "tests/test_web.py",
        "tests/integration/test_deployment_contracts.py",
    ):
        assert command in workflow
    action_references = re.findall(r"^\s+(?:uses):\s+[^@\s]+@([^\s#]+)", workflow, re.MULTILINE)
    assert action_references
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in action_references)
