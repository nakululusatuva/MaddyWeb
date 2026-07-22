from pathlib import Path

import pytest

from maddyweb.config import AppConfig, ConfigError, load_config


def _config(document: dict[str, object] | None = None) -> AppConfig:
    values: dict[str, object] = {"maddy": {"mode": "docker"}}
    for section, raw in (document or {}).items():
        if section == "maddy" and isinstance(raw, dict):
            values[section] = {"mode": "docker", **raw}
        else:
            values[section] = raw
    return AppConfig.from_dict(values)


def test_safe_defaults_are_loopback_and_small_after_explicit_mode() -> None:
    config = _config()
    assert config.server.host_port == ("127.0.0.1", 8787)
    assert config.server.concurrency == 8
    assert config.server.request_body_timeout_seconds == 15
    assert config.server.max_upload_bytes == 20 * 1024 * 1024
    assert config.maddy.mode == "docker"


@pytest.mark.parametrize(
    "listen", ["0.0.0.0:8787", "127.0.0.2:8787", "localhost:8787", "[::1]:8787"]
)
def test_non_exact_loopback_is_rejected(listen: str) -> None:
    with pytest.raises(ConfigError, match=r"127\.0\.0\.1|IPv4"):
        _config({"server": {"listen": listen}})


def test_unknown_keys_are_rejected() -> None:
    with pytest.raises(ConfigError, match="unknown key"):
        _config({"server": {"lissten": "127.0.0.1:8787"}})


@pytest.mark.parametrize("timeout", (0.5, 121))
def test_request_body_timeout_is_bounded(timeout: float) -> None:
    with pytest.raises(ConfigError, match="request_body_timeout_seconds"):
        _config({"server": {"request_body_timeout_seconds": timeout}})


def test_unsafe_container_name_is_rejected() -> None:
    with pytest.raises(ConfigError, match="container"):
        _config({"maddy": {"container": "maddy; reboot"}})


def test_maddy_mode_must_be_explicit() -> None:
    with pytest.raises(ConfigError, match="explicit mode"):
        AppConfig.from_dict({})
    with pytest.raises(ConfigError, match="explicitly configured"):
        AppConfig.from_dict({"maddy": {}})


def test_load_toml(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('[maddy]\nmode = "native"\n', encoding="utf-8")
    assert load_config(path).maddy.mode == "native"


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"server": {"concurrency": True}}, "integer"),
        ({"server": {"allowed_hosts": "127.0.0.1"}}, "array"),
        ({"certificates": {"enabled": "false"}}, "boolean"),
        ({"certificates": {"names": "mx.example.test"}}, "array"),
        ({"security": {"cookie_name": "unprefixed"}}, "cookie_name"),
        ({"maddy": {"helper_socket": "../helper.sock"}}, "absolute"),
    ],
)
def test_security_relevant_types_and_paths_are_not_coerced(
    document: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ConfigError, match=message):
        _config(document)


def test_enabled_certificates_require_a_nonempty_allowlist() -> None:
    with pytest.raises(ConfigError, match="cannot be empty"):
        _config({"certificates": {"enabled": True}})


def test_docker_paths_default_inside_container_data_and_cannot_escape() -> None:
    config = _config()
    assert str(config.maddy.config_path) == "/data/maddy.conf"
    assert str(config.maddy.data_dir) == "/data"
    assert str(config.certificates.deployed_cert_path).startswith("/data/")
    with pytest.raises(ConfigError, match=r"inside maddy\.data_dir"):
        _config(
            {
                "certificates": {
                    "enabled": True,
                    "names": ["mx.example.test"],
                    "deployed_cert_path": "/etc/maddy/fullchain.pem",
                }
            }
        )


def test_native_paths_have_native_defaults() -> None:
    config = AppConfig.from_dict({"maddy": {"mode": "native"}})
    assert str(config.maddy.config_path) == "/etc/maddy/maddy.conf"
    assert str(config.maddy.data_dir) == "/var/lib/maddy"
    assert str(config.certificates.deployed_cert_path).startswith("/var/lib/maddy/")


def test_posix_deployment_paths_stay_posix_on_every_development_platform() -> None:
    config = _config()
    assert str(config.server.temp_dir) == "/var/tmp/maddyweb"  # noqa: S108 - expected policy
    assert str(config.maddy.helper_socket) == "/run/maddyweb/helper.sock"
