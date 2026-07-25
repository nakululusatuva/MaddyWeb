from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "deploy/public-edge/validate-renewal-profile.py"


def _document(*parameters: str) -> str:
    return "\n".join(
        (
            "version = 5.5.0",
            "archive_dir = /var/lib/maddyweb-web-cert/config/archive/example.test",
            "",
            "[renewalparams]",
            *parameters,
            "webroot_path = /var/www/maddyweb-web-acme",
            "",
        )
    )


def _run_validator(tmp_path: Path, document: str) -> subprocess.CompletedProcess[str]:
    renewal = tmp_path / "example.test.conf"
    renewal.write_text(document, encoding="utf-8")
    return subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [sys.executable, "-I", str(VALIDATOR), str(renewal)],
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    "parameters",
    [
        ("authenticator = webroot",),
        ("authenticator = webroot", "installer = None"),
    ],
)
def test_supported_no_installer_representations_are_accepted(
    tmp_path: Path,
    parameters: tuple[str, ...],
) -> None:
    result = _run_validator(tmp_path, _document(*parameters))

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


@pytest.mark.parametrize(
    "installer_lines",
    [
        ("installer = none",),
        ("installer = NONE",),
        ("installer = null",),
        ("installer =",),
        ("installer = nginx",),
        ("installer = None", "installer = None"),
        ("installer = None", "installer = nginx"),
    ],
)
def test_ambiguous_or_active_installer_is_rejected(
    tmp_path: Path,
    installer_lines: tuple[str, ...],
) -> None:
    result = _run_validator(
        tmp_path,
        _document("authenticator = webroot", *installer_lines),
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert "renewal installer is not absent or exact None" in result.stderr


@pytest.mark.parametrize(
    "parameters",
    [
        (),
        ("authenticator = nginx",),
        ("authenticator = webroot", "authenticator = webroot"),
        ("authenticator = webroot", "pre_hook = /bin/true"),
        ("authenticator = webroot", "post_hook = /bin/true"),
        ("authenticator = webroot", "renew_hook = /bin/true"),
        ("authenticator = webroot", "deploy_hook = /bin/true"),
    ],
)
def test_non_webroot_or_hooked_profile_is_rejected(
    tmp_path: Path,
    parameters: tuple[str, ...],
) -> None:
    result = _run_validator(tmp_path, _document(*parameters))

    assert result.returncode == 1
    assert result.stdout == ""
    assert "renewal policy error:" in result.stderr


def test_only_direct_renewal_parameters_control_the_policy(tmp_path: Path) -> None:
    document = "\n".join(
        (
            "installer = nginx",
            _document("authenticator = webroot"),
            "[[webroot_map]]",
            "installer = nginx",
            "",
        )
    )

    result = _run_validator(tmp_path, document)

    assert result.returncode == 0
