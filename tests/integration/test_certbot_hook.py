from __future__ import annotations

import importlib.util
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "scripts/certbot-deploy-hook.py"
WRAPPER = ROOT / "scripts/certbot-deploy-hook.sh"
FINGERPRINT = ":".join(["A5"] * 32)
BASH = shutil.which("bash")
OPENSSL = shutil.which("openssl")


def _load_driver() -> Any:
    specification = importlib.util.spec_from_file_location("certbot_deploy_hook", DRIVER)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


HOOK = _load_driver()


@pytest.mark.parametrize(
    "value",
    (
        "",
        "relative/live/mx.example.invalid",
        "/etc/letsencrypt/live/mx example.invalid",
        "/etc/letsencrypt/live/mx\texample.invalid",
        "/etc/letsencrypt/live/mx\nexample.invalid",
        "/etc/letsencrypt/live/mx\x7fexample.invalid",
        "/etc/letsencrypt/live/mx%2eexample.invalid",
        "/etc/letsencrypt/live/../archive",
        "/etc/letsencrypt/live/./mx.example.invalid",
        "/etc/letsencrypt//live/mx.example.invalid",
        "/etc/letsencrypt/live/mx.example.invalid/",
        "/etc/letsencrypt/live/-mx.example.invalid",
        "/etc/letsencrypt/live/mx\\example.invalid",
    ),
)
def test_lineage_parser_rejects_unsafe_text(value: str) -> None:
    with pytest.raises(HOOK.HookError):
        HOOK._lineage_from_environment({"RENEWED_LINEAGE": value})


def test_lineage_parser_requires_the_certbot_variable() -> None:
    with pytest.raises(HOOK.HookError):
        HOOK._lineage_from_environment({})


def test_lineage_parser_returns_only_a_strict_basename() -> None:
    lineage, name = HOOK._lineage_from_environment(
        {"RENEWED_LINEAGE": "/etc/letsencrypt/live/mx.example.invalid"}
    )
    assert lineage == Path("/etc/letsencrypt/live/mx.example.invalid")
    assert name == "mx.example.invalid"


@pytest.mark.skipif(os.name != "posix", reason="lineage ownership is a POSIX contract")
def test_lineage_must_be_real_secure_and_allowlisted(tmp_path: Path) -> None:
    live_dir = tmp_path / "live"
    lineage = live_dir / "mx.example.invalid"
    live_dir.mkdir(mode=0o700)
    lineage.mkdir(mode=0o700)
    config = SimpleNamespace(
        enabled=True,
        names=("mx.example.invalid",),
        live_dir=live_dir,
    )
    HOOK._validate_lineage_location(
        lineage,
        "mx.example.invalid",
        config,
        owner_uid=os.geteuid(),
    )

    config.names = ("other.example.invalid",)
    with pytest.raises(HOOK.HookError, match="allow-listed"):
        HOOK._validate_lineage_location(
            lineage,
            "mx.example.invalid",
            config,
            owner_uid=os.geteuid(),
        )


@pytest.mark.skipif(os.name != "posix", reason="symlink ownership is a POSIX contract")
def test_lineage_directory_cannot_be_a_symlink(tmp_path: Path) -> None:
    live_dir = tmp_path / "live"
    target = tmp_path / "target"
    live_dir.mkdir(mode=0o700)
    target.mkdir(mode=0o700)
    lineage = live_dir / "mx.example.invalid"
    lineage.symlink_to(target, target_is_directory=True)
    config = SimpleNamespace(
        enabled=True,
        names=("mx.example.invalid",),
        live_dir=live_dir,
    )
    with pytest.raises(HOOK.HookError, match="real directory"):
        HOOK._validate_lineage_location(
            lineage,
            "mx.example.invalid",
            config,
            owner_uid=os.geteuid(),
        )


@pytest.mark.skipif(os.name != "posix", reason="secure open requires POSIX O_NOFOLLOW")
def test_fixture_config_is_securely_opened_and_strictly_parsed(tmp_path: Path) -> None:
    config_root = tmp_path / "config"
    config_root.mkdir(mode=0o700)
    config_path = config_root / "config.toml"
    source = (ROOT / "deploy/examples/config.native.toml").read_text(encoding="utf-8")
    source = source.replace("enabled = false", "enabled = true", 1)
    source = source.replace("names = []", 'names = ["mx.example.invalid"]', 1)
    source = source.replace(
        'live_dir = "/etc/letsencrypt/live"',
        f'live_dir = "{tmp_path.as_posix()}/live"',
        1,
    )
    config_path.write_text(source, encoding="utf-8")
    config_path.chmod(0o600)

    config = HOOK._load_secure_config(
        config_path,
        fixture=True,
        effective_uid=os.geteuid(),
    )
    assert config.certificates.enabled is True
    assert config.certificates.names == ("mx.example.invalid",)

    hardlink = config_root / "config-hardlink.toml"
    os.link(config_path, hardlink)
    with pytest.raises(HOOK.HookError, match="metadata is unsafe"):
        HOOK._load_secure_config(
            config_path,
            fixture=True,
            effective_uid=os.geteuid(),
        )


def _report(*, deployed_matches: bool) -> dict[str, object]:
    deployed_fingerprint = FINGERPRINT if deployed_matches else ":".join(["B6"] * 32)
    return {
        "source": {"error": None, "sha256_fingerprint": FINGERPRINT},
        "deployed": {"error": None, "sha256_fingerprint": deployed_fingerprint},
        "fingerprints_match": deployed_matches,
    }


def test_deploy_uses_existing_transaction_path_and_rechecks_fingerprint() -> None:
    calls: list[tuple[str, str]] = []

    class Manager:
        deployed = False

        def status(self, name: str) -> dict[str, object]:
            calls.append(("status", name))
            return _report(deployed_matches=self.deployed)

        def _deploy_and_reload(self, name: str) -> None:
            calls.append(("deploy", name))
            self.deployed = True

    HOOK._deploy_and_verify(
        object(),
        "mx.example.invalid",
        manager_factory=lambda _config: Manager(),
    )
    assert calls == [
        ("status", "mx.example.invalid"),
        ("deploy", "mx.example.invalid"),
        ("status", "mx.example.invalid"),
    ]


@pytest.mark.skipif(
    os.name != "posix" or OPENSSL is None,
    reason="the real certificate deployment fixture requires POSIX and OpenSSL",
)
def test_real_deploy_path_copies_valid_pair_reloads_and_reads_back(tmp_path: Path) -> None:
    from maddyweb.certificates import CertificateManager

    assert OPENSSL is not None
    name = "mx.example.invalid"
    live_dir = tmp_path / "live"
    lineage = live_dir / name
    deployed_dir = tmp_path / "deployed"
    lineage.mkdir(parents=True, mode=0o700)
    deployed_dir.mkdir(mode=0o700)
    certificate = lineage / "fullchain.pem"
    private_key = lineage / "privkey.pem"
    subprocess.run(  # noqa: S603
        [
            OPENSSL,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=mx.example.invalid",
            "-addext",
            "subjectAltName=DNS:mx.example.invalid",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
        ],
        check=True,
        capture_output=True,
    )
    certificate.chmod(0o644)
    private_key.chmod(0o600)

    class TimerRunner:
        @staticmethod
        def run(_argv: object, **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(returncode=1, stdout=b"disabled\n")

    reloads: list[bool] = []
    deployed_certificate = deployed_dir / "fullchain.pem"
    deployed_private_key = deployed_dir / "privkey.pem"
    manager = CertificateManager(
        allowed_names=(name,),
        live_dir=live_dir,
        deployed_certificate_path=deployed_certificate,
        deployed_private_key_path=deployed_private_key,
        runner=TimerRunner(),
        reload_callback=lambda: reloads.append(True),
        deployment_mode="native",
        owner_uid=os.geteuid(),
        owner_gid=os.getegid(),
        command_timeout=30,
    )

    HOOK._deploy_and_verify(
        object(),
        name,
        manager_factory=lambda _config: manager,
    )
    assert reloads == [True]
    assert deployed_certificate.read_bytes() == certificate.read_bytes()
    assert deployed_private_key.read_bytes() == private_key.read_bytes()
    assert stat_mode(deployed_certificate) == 0o644
    assert stat_mode(deployed_private_key) == 0o600


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_deploy_fails_closed_when_private_api_is_missing() -> None:
    manager = SimpleNamespace(status=lambda _name: _report(deployed_matches=True))
    with pytest.raises(HOOK.HookError, match="API is unavailable"):
        HOOK._deploy_and_verify(
            object(),
            "mx.example.invalid",
            manager_factory=lambda _config: manager,
        )


def test_deploy_fails_closed_on_post_deploy_fingerprint_mismatch() -> None:
    class Manager:
        def status(self, _name: str) -> dict[str, object]:
            return _report(deployed_matches=False)

        @staticmethod
        def _deploy_and_reload(_name: str) -> None:
            return None

    with pytest.raises(HOOK.HookError, match="does not match"):
        HOOK._deploy_and_verify(
            object(),
            "mx.example.invalid",
            manager_factory=lambda _config: Manager(),
        )


def test_driver_context_cannot_be_switched_by_production_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(HOOK, "_effective_uid", lambda: 0)
    missing_config = ROOT / "missing-certbot-hook-fixture.toml"
    assert HOOK.main(["--fixture", "--config", str(missing_config)]) == 1
    monkeypatch.setattr(HOOK, "_effective_uid", lambda: 1000)
    assert HOOK.main(["--config", "/etc/maddyweb/config.toml"]) == 1


def test_hook_sources_have_fixed_non_shell_deployment_contract() -> None:
    wrapper = WRAPPER.read_text(encoding="utf-8")
    driver = DRIVER.read_text(encoding="utf-8")
    assert wrapper.startswith("#!/bin/bash -p\n")
    assert 'PRODUCTION_PYTHON="/opt/maddyweb/current/bin/python"' in wrapper
    assert 'PRODUCTION_DRIVER="/opt/maddyweb/current/libexec/certbot-deploy-hook.py"' in wrapper
    assert 'PRODUCTION_CONFIG="/etc/maddyweb/config.toml"' in wrapper
    assert "/usr/bin/env -i" in wrapper
    assert '"RENEWED_LINEAGE=$lineage"' in wrapper
    assert "fixture overrides are forbidden for the root production hook" in wrapper
    assert "eval " not in wrapper
    assert "/bin/sh -c" not in wrapper
    assert "/bin/bash -c" not in wrapper
    assert "certbot renew" not in wrapper.lower()
    assert "nginx" not in wrapper.lower()
    assert 'getattr(manager, "_deploy_and_reload", None)' in driver
    assert "deploy(name)" in driver
    assert "_verify_deployed_report(status(name))" in driver
    assert ".renew(" not in driver
    assert "subprocess" not in driver
    assert "os.system" not in driver


@pytest.mark.skipif(
    os.name != "posix" or BASH is None,
    reason="the shell wrapper contract requires a POSIX bash runtime",
)
@pytest.mark.parametrize(
    "lineage",
    (
        "relative/name",
        "/etc/letsencrypt/live/name with-space",
        "/etc/letsencrypt/live/name%20escape",
        "/etc/letsencrypt/live/../escape",
        "/etc/letsencrypt//live/name",
        "/etc/letsencrypt/live/-name",
        "/etc/letsencrypt/live/name\x1bescape",
    ),
)
def test_shell_wrapper_rejects_lineage_before_any_production_action(lineage: str) -> None:
    assert BASH is not None
    result = subprocess.run(  # noqa: S603
        [BASH, str(WRAPPER)],
        env={"PATH": os.environ.get("PATH", ""), "RENEWED_LINEAGE": lineage},
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "RENEWED_LINEAGE" in result.stderr
    assert "fixed MaddyWeb Python is unavailable" not in result.stderr


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() != 0 or BASH is None,
    reason="root production-environment guard requires a POSIX root fixture",
)
def test_root_wrapper_rejects_fixture_environment() -> None:
    assert BASH is not None
    result = subprocess.run(  # noqa: S603
        [BASH, str(WRAPPER)],
        env={
            "PATH": os.environ.get("PATH", ""),
            "RENEWED_LINEAGE": "/etc/letsencrypt/live/mx.example.invalid",
            "MADDYWEB_CERTBOT_HOOK_FIXTURE": "1",
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "fixture overrides are forbidden" in result.stderr
    assert "fixed MaddyWeb Python is unavailable" not in result.stderr


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0 or BASH is None,
    reason="the isolated wrapper fixture is intentionally non-root only",
)
def test_nonroot_wrapper_fixture_cleans_environment_and_uses_fixed_argv(
    tmp_path: Path,
) -> None:
    assert BASH is not None
    record = tmp_path / "record.txt"
    fake_python = tmp_path / "python"
    fake_python.write_text(
        f"#!/bin/sh\n{{ printf '%s\\n' \"$@\"; /usr/bin/env; }} > {shlex.quote(str(record))}\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o700)
    fixture_driver = tmp_path / "driver.py"
    fixture_driver.write_text("raise SystemExit(99)\n", encoding="utf-8")
    fixture_driver.chmod(0o600)
    fixture_config = tmp_path / "config.toml"
    fixture_config.write_text("fixture = true\n", encoding="utf-8")
    fixture_config.chmod(0o600)
    lineage = "/fixture/live/mx.example.invalid"
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": "/untrusted/python",
        "RENEWED_LINEAGE": lineage,
        "MADDYWEB_CERTBOT_HOOK_FIXTURE": "1",
        "MADDYWEB_CERTBOT_HOOK_PYTHON": str(fake_python),
        "MADDYWEB_CERTBOT_HOOK_DRIVER": str(fixture_driver),
        "MADDYWEB_CERTBOT_HOOK_CONFIG": str(fixture_config),
    }
    subprocess.run(  # noqa: S603
        [BASH, str(WRAPPER)],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    recorded = record.read_text(encoding="utf-8")
    assert f"-I\n{fixture_driver}\n--fixture\n--config\n{fixture_config}\n" in recorded
    assert f"RENEWED_LINEAGE={lineage}" in recorded
    assert "PATH=/usr/sbin:/usr/bin:/sbin:/bin" in recorded
    assert "PYTHONPATH=" not in recorded
