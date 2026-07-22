from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from maddyweb import cli
from maddyweb.certificates import CertificateCommandError
from maddyweb.config import AppConfig
from maddyweb.gateway import HelperGateway


def test_validate_config_command_has_no_sensitive_or_path_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "config.toml"
    config.write_text('[maddy]\nmode = "docker"\n', encoding="utf-8")
    cli.main(["validate-config", "--config", str(config)])
    output = capsys.readouterr().out
    assert output == "config=ok\n"
    assert str(config) not in output


def test_web_refuses_root_without_explicit_development_switch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not hasattr(os, "geteuid"):
        pytest.skip("POSIX uid contract")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(RuntimeError, match="refuses to run as root"):
        cli._run_web(
            AppConfig.from_dict({"maddy": {"mode": "docker"}}),
            allow_root_development=False,
        )


def test_disabled_certificate_manager_fails_closed() -> None:
    manager = cli._DisabledCertificateManager()
    assert manager.list_certificates() == []
    assert not any(manager.health().values())
    with pytest.raises(CertificateCommandError, match="disabled"):
        manager.renew("mx.example.test")


@pytest.mark.asyncio
async def test_diagnose_shape_is_serializable_without_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {
        "status": "degraded",
        "version": "0.1.0",
        "maddy_version": "unknown",
        "maddy_write_enabled": False,
        "storage_available": False,
        "certbot_available": False,
        "certificate_management_enabled": False,
    }

    async def health(_self: HelperGateway) -> dict[str, object]:
        return expected

    monkeypatch.setattr(HelperGateway, "health", health)
    encoded = json.dumps(
        await HelperGateway(AppConfig.from_dict({"maddy": {"mode": "docker"}})).health()
    )
    assert json.loads(encoded) == expected
    assert "/run/" not in encoded
