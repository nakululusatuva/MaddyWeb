from __future__ import annotations

import hashlib
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from maddyweb.config import load_config

ROOT = Path(__file__).resolve().parents[2]
CONFIGS = (
    ROOT / "deploy/examples/config.native.toml",
    ROOT / "deploy/examples/config.wsl.toml",
    ROOT / "docker/config.toml",
)
TESTED_MADDY_RELEASES = ("0.8.2", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "0.9.4", "0.9.5")


def test_operational_shell_scripts_are_executable_in_git_tree() -> None:
    scripts = sorted(path.relative_to(ROOT).as_posix() for path in (ROOT / "scripts").glob("*.sh"))
    git_binary = shutil.which("git")
    assert git_binary is not None
    result = subprocess.run(  # noqa: S603 - fixed git command over repository-owned paths
        [git_binary, "ls-files", "--stage", "--", *scripts],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    modes = {
        line.split(maxsplit=1)[1].split("\t", 1)[1]: line.split()[0]
        for line in result.stdout.splitlines()
    }

    assert set(modes) == set(scripts)
    assert set(modes.values()) == {"100755"}


def test_smoke_and_performance_gates_match_the_public_health_schema() -> None:
    expected = {
        "status",
        "version",
        "maddy_version",
        "maddy_write_enabled",
        "storage_available",
        "certbot_available",
        "certificate_management_enabled",
    }
    smoke = runpy.run_path(str(ROOT / "scripts/smoke-test.py"))
    performance = runpy.run_path(str(ROOT / "scripts/performance-test.py"))
    assert smoke["HEALTH_FIELDS"] == expected
    assert performance["HEALTH_FIELDS"] == expected

    payload = {
        "status": "ok",
        "version": "0.1.0",
        "maddy_version": "0.9.5",
        "maddy_write_enabled": True,
        "storage_available": True,
        "certbot_available": False,
        "certificate_management_enabled": False,
    }
    smoke["assert_health"](payload, None)
    with pytest.raises(SystemExit):
        smoke["assert_health"]({**payload, "storage_available": False}, None)


def test_smoke_waits_for_the_loopback_listener(monkeypatch: pytest.MonkeyPatch) -> None:
    smoke = runpy.run_path(str(ROOT / "scripts/smoke-test.py"))
    results = iter(
        (
            SimpleNamespace(stdout=""),
            SimpleNamespace(stdout="LISTEN 0 16 127.0.0.1:8787 0.0.0.0:*\n"),
        )
    )
    calls = 0

    def fake_run(*_args: object, **_kwargs: object) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        return next(results)

    monkeypatch.setattr(smoke["subprocess"], "run", fake_run)
    monkeypatch.setattr(smoke["time"], "sleep", lambda _seconds: None)
    smoke["assert_loopback_listener"](1.0)
    assert calls == 2


def test_smoke_bounds_each_listener_probe_by_remaining_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    smoke = runpy.run_path(str(ROOT / "scripts/smoke-test.py"))
    times = iter((10.0, 10.25))
    observed_timeout: float | None = None

    def fake_run(*_args: object, **kwargs: object) -> SimpleNamespace:
        nonlocal observed_timeout
        observed_timeout = float(kwargs["timeout"])
        return SimpleNamespace(stdout="LISTEN 0 16 127.0.0.1:8787 0.0.0.0:*\n")

    monkeypatch.setattr(smoke["time"], "monotonic", lambda: next(times))
    monkeypatch.setattr(smoke["subprocess"], "run", fake_run)
    smoke["assert_loopback_listener"](1.0)
    assert observed_timeout == pytest.approx(0.75)


def test_smoke_listener_deadline_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    smoke = runpy.run_path(str(ROOT / "scripts/smoke-test.py"))
    times = iter((10.0, 10.0, 11.0))
    monkeypatch.setattr(smoke["time"], "monotonic", lambda: next(times))
    monkeypatch.setattr(
        smoke["subprocess"],
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=""),
    )
    with pytest.raises(SystemExit):
        smoke["assert_loopback_listener"](1.0)


@pytest.mark.parametrize("listener", ("0.0.0.0:8787", "[::]:8787"))
def test_smoke_rejects_public_listener_without_grace(
    monkeypatch: pytest.MonkeyPatch,
    listener: str,
) -> None:
    smoke = runpy.run_path(str(ROOT / "scripts/smoke-test.py"))
    slept = False

    def fake_sleep(_seconds: float) -> None:
        nonlocal slept
        slept = True

    monkeypatch.setattr(
        smoke["subprocess"],
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            stdout=f"LISTEN 0 16 {listener} 0.0.0.0:*\n"
        ),
    )
    monkeypatch.setattr(smoke["time"], "sleep", fake_sleep)
    with pytest.raises(SystemExit):
        smoke["assert_loopback_listener"](20.0)
    assert slept is False


def test_smoke_uses_separate_startup_and_operation_timeouts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    smoke = runpy.run_path(str(ROOT / "scripts/smoke-test.py"))
    main_globals = smoke["main"].__globals__
    calls: dict[str, float] = {}
    payload = {
        "status": "ok",
        "version": "0.1.0",
        "maddy_version": "0.9.5",
        "maddy_write_enabled": True,
        "storage_available": True,
        "certbot_available": False,
        "certificate_management_enabled": False,
    }

    monkeypatch.setitem(
        main_globals,
        "assert_loopback_listener",
        lambda timeout: calls.__setitem__("listener", timeout),
    )
    monkeypatch.setitem(
        main_globals,
        "assert_helper_socket",
        lambda _path, timeout: calls.__setitem__("socket", timeout),
    )

    def fake_health(_url: str, timeout: float) -> dict[str, object]:
        calls["health"] = timeout
        return payload

    monkeypatch.setitem(main_globals, "get_health", fake_health)
    monkeypatch.setattr(sys, "argv", ["smoke-test.py"])
    smoke["main"]()
    capsys.readouterr()
    assert calls == {"listener": 20.0, "socket": 3.0, "health": 10.0}


@pytest.mark.parametrize("startup_timeout", (0, 30.1))
def test_smoke_rejects_invalid_startup_timeout(
    monkeypatch: pytest.MonkeyPatch,
    startup_timeout: float,
) -> None:
    smoke = runpy.run_path(str(ROOT / "scripts/smoke-test.py"))
    monkeypatch.setattr(
        sys,
        "argv",
        ["smoke-test.py", "--startup-timeout-seconds", str(startup_timeout)],
    )
    with pytest.raises(SystemExit):
        smoke["main"]()


@pytest.mark.parametrize("health_timeout", (0, 30.1))
def test_smoke_rejects_invalid_health_timeout(
    monkeypatch: pytest.MonkeyPatch,
    health_timeout: float,
) -> None:
    smoke = runpy.run_path(str(ROOT / "scripts/smoke-test.py"))
    monkeypatch.setattr(
        sys,
        "argv",
        ["smoke-test.py", "--health-timeout-seconds", str(health_timeout)],
    )
    with pytest.raises(SystemExit):
        smoke["main"]()


@pytest.mark.parametrize("path", CONFIGS)
def test_example_config_is_accepted_by_application_and_deploy_validator(path: Path) -> None:
    config = load_config(path)
    assert config.server.listen == "127.0.0.1:8787"
    assert config.server.request_body_timeout_seconds == 15
    assert config.maddy.helper_socket == PurePosixPath("/run/maddyweb/helper.sock")
    assert config.maddy.docker_submission_scope == "container"
    assert config.certificates.command_timeout_seconds == 300
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts/validate-config.py"),
            "--config",
            str(path),
            "--expected-maddy-mode",
            config.maddy.mode,
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def test_deploy_validator_defaults_missing_webroot_roots_to_read_only(tmp_path: Path) -> None:
    source = CONFIGS[0].read_text(encoding="utf-8")
    source = re.sub(r"^webroot_roots = \[\]\n", "", source, flags=re.MULTILINE)
    candidate = tmp_path / "config.toml"
    candidate.write_text(source, encoding="utf-8")
    assert load_config(candidate).certificates.webroot_roots == ()
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts/validate-config.py"),
            "--config",
            str(candidate),
            "--expected-maddy-mode",
            "native",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def test_deploy_validator_defaults_missing_docker_submission_scope_to_container(
    tmp_path: Path,
) -> None:
    source = (ROOT / "docker/config.toml").read_text(encoding="utf-8")
    source = re.sub(
        r'^docker_submission_scope = "container"\n',
        "",
        source,
        flags=re.MULTILINE,
    )
    candidate = tmp_path / "config.toml"
    candidate.write_text(source, encoding="utf-8")
    assert load_config(candidate).maddy.docker_submission_scope == "container"
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts/validate-config.py"),
            "--config",
            str(candidate),
            "--expected-maddy-mode",
            "docker",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("path", "scope", "expected_mode", "message"),
    (
        (
            ROOT / "docker/config.toml",
            "host",
            "docker",
            "must be container or host-loopback",
        ),
        (
            ROOT / "deploy/examples/config.native.toml",
            "host-loopback",
            "native",
            "when maddy.mode is native",
        ),
    ),
)
def test_deploy_validator_rejects_unsafe_docker_submission_scope(
    tmp_path: Path,
    path: Path,
    scope: str,
    expected_mode: str,
    message: str,
) -> None:
    source = path.read_text(encoding="utf-8")
    candidate = tmp_path / "config.toml"
    candidate.write_text(
        source.replace(
            'docker_submission_scope = "container"',
            f'docker_submission_scope = "{scope}"',
        ),
        encoding="utf-8",
    )
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts/validate-config.py"),
            "--config",
            str(candidate),
            "--expected-maddy-mode",
            expected_mode,
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert message in result.stderr


@pytest.mark.parametrize(
    ("old", "new", "message"),
    (
        (
            'submission_host = "127.0.0.1"',
            'submission_host = "::1"',
            "must be exactly 127.0.0.1",
        ),
        (
            "submission_port = 1587",
            "submission_port = 587",
            "must be exactly 1587",
        ),
    ),
)
def test_deploy_validator_requires_the_fixed_submission_endpoint(
    tmp_path: Path,
    old: str,
    new: str,
    message: str,
) -> None:
    source = (ROOT / "docker/config.toml").read_text(encoding="utf-8")
    candidate = tmp_path / "config.toml"
    candidate.write_text(source.replace(old, new), encoding="utf-8")
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts/validate-config.py"),
            "--config",
            str(candidate),
            "--expected-maddy-mode",
            "docker",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert message in result.stderr


@pytest.mark.parametrize("timeout", (29, 901))
def test_deploy_validator_rejects_certificate_timeout_outside_range(
    tmp_path: Path,
    timeout: int,
) -> None:
    source = CONFIGS[0].read_text(encoding="utf-8")
    candidate = tmp_path / "config.toml"
    candidate.write_text(
        source.replace(
            "command_timeout_seconds = 300",
            f"command_timeout_seconds = {timeout}",
        ),
        encoding="utf-8",
    )
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts/validate-config.py"),
            "--config",
            str(candidate),
            "--expected-maddy-mode",
            "native",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "certificates.command_timeout_seconds" in result.stderr


@pytest.mark.parametrize("timeout", (0.5, 121))
def test_deploy_validator_rejects_request_body_timeout_outside_range(
    tmp_path: Path,
    timeout: float,
) -> None:
    source = CONFIGS[0].read_text(encoding="utf-8")
    candidate = tmp_path / "config.toml"
    candidate.write_text(
        source.replace(
            "request_body_timeout_seconds = 15",
            f"request_body_timeout_seconds = {timeout}",
        ),
        encoding="utf-8",
    )
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts/validate-config.py"),
            "--config",
            str(candidate),
            "--expected-maddy-mode",
            "native",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "server.request_body_timeout_seconds" in result.stderr


@pytest.mark.parametrize(
    "unsafe_path",
    (
        "",
        "-/srv/maddyweb",
        "/srv/-maddyweb",
        "/srv/maddy web",
        "/srv/maddy%h",
        "/srv/maddy\nweb",
    ),
)
def test_deploy_validator_rejects_systemd_path_injection(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    source = CONFIGS[0].read_text(encoding="utf-8")
    candidate = tmp_path / "config.toml"
    candidate.write_text(
        source.replace(
            'temp_dir = "/var/tmp/maddyweb"',
            f"temp_dir = {json.dumps(unsafe_path)}",
        ),
        encoding="utf-8",
    )
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts/validate-config.py"),
            "--config",
            str(candidate),
            "--expected-maddy-mode",
            "native",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "server.temp_dir" in result.stderr


@pytest.mark.parametrize("config", CONFIGS)
def test_private_temp_paths_do_not_render_host_write_allowlists(
    tmp_path: Path,
    config: Path,
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts/render-systemd-sandbox.py"),
            "--config",
            str(config),
            "--output-dir",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    web = (output / "SYSTEMD-WEB-PATHS.conf").read_text(encoding="utf-8")
    assert "ReadWritePaths=" not in web


def test_docker_helper_does_not_gain_native_host_paths(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts/render-systemd-sandbox.py"),
            "--config",
            str(ROOT / "docker/config.toml"),
            "--output-dir",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    helper_drop_in = (output / "SYSTEMD-HELPER-PATHS.conf").read_text(encoding="utf-8")
    helper_base = (ROOT / "deploy/systemd/maddyweb-helper.service").read_text(encoding="utf-8")
    write_line = next(
        line for line in helper_base.splitlines() if line.startswith("ReadWritePaths=")
    )
    write_paths = set(write_line.removeprefix("ReadWritePaths=").split())
    assert write_paths == {
        "/var/backups/maddyweb",
        "/run/maddyweb",
    }
    assert "ReadOnlyPaths=" not in helper_drop_in
    assert "ReadWritePaths=" not in helper_drop_in


def test_certificate_enabled_helper_gets_only_configured_certificate_write_roots(
    tmp_path: Path,
) -> None:
    source = (ROOT / "docker/config.toml").read_text(encoding="utf-8")
    source = source.replace("enabled = false", "enabled = true", 1)
    source = source.replace("names = []", 'names = ["mx.example.invalid"]', 1)
    source = source.replace(
        "webroot_roots = []",
        'webroot_roots = ["/var/www/mail", "/srv/www/acme"]',
        1,
    )
    config = tmp_path / "config.toml"
    config.write_text(source, encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts/render-systemd-sandbox.py"),
            "--config",
            str(config),
            "--output-dir",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    helper = (output / "SYSTEMD-HELPER-PATHS.conf").read_text(encoding="utf-8")
    assert helper.splitlines() == [
        "# Managed by MaddyWeb install.sh; do not edit.",
        "[Service]",
        "ReadWritePaths=-/etc/letsencrypt",
        "ReadWritePaths=-/var/lib/letsencrypt",
        "ReadWritePaths=-/var/log/letsencrypt",
        "ReadWritePaths=-/var/www/mail",
        "ReadWritePaths=-/srv/www/acme",
    ]


def test_certificate_read_only_mode_gets_no_certbot_write_paths(tmp_path: Path) -> None:
    source = (ROOT / "docker/config.toml").read_text(encoding="utf-8")
    source = source.replace("enabled = false", "enabled = true", 1)
    source = source.replace("names = []", 'names = ["mx.example.invalid"]', 1)
    config = tmp_path / "config.toml"
    config.write_text(source, encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts/render-systemd-sandbox.py"),
            "--config",
            str(config),
            "--output-dir",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    helper = (output / "SYSTEMD-HELPER-PATHS.conf").read_text(encoding="utf-8")
    assert "ReadWritePaths=" not in helper


def test_nondefault_paths_render_exact_systemd_sandbox_allowlists(tmp_path: Path) -> None:
    source = CONFIGS[0].read_text(encoding="utf-8")
    replacements = {
        'temp_dir = "/var/tmp/maddyweb"': 'temp_dir = "/srv/maddyweb-runtime/spool"',
        'config_path = "/etc/maddy/maddy.conf"': 'config_path = "/srv/maddy/etc/maddy.conf"',
        'data_dir = "/var/lib/maddy"': 'data_dir = "/srv/maddy/state"',
        "enabled = false": "enabled = true",
        "names = []": 'names = ["mx.example.invalid"]',
        'live_dir = "/etc/letsencrypt/live"': (
            'live_dir = "/srv/maddyweb/certbot/live"'
        ),
        'renewal_dir = "/etc/letsencrypt/renewal"': (
            'renewal_dir = "/srv/maddyweb/certbot/renewal"'
        ),
        "webroot_roots = []": 'webroot_roots = ["/srv/www/mail"]',
        'deployed_cert_path = "/etc/maddy/certs/fullchain.pem"': (
            'deployed_cert_path = "/srv/maddy/tls/fullchain.pem"'
        ),
        'deployed_key_path = "/etc/maddy/certs/privkey.pem"': (
            'deployed_key_path = "/srv/maddy/tls/privkey.pem"'
        ),
    }
    for old, new in replacements.items():
        source = source.replace(old, new)
    config = tmp_path / "config.toml"
    config.write_text(source, encoding="utf-8")
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts/validate-config.py"),
            "--config",
            str(config),
            "--expected-maddy-mode",
            "native",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    output = tmp_path / "output"
    output.mkdir()
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts/render-systemd-sandbox.py"),
            "--config",
            str(config),
            "--output-dir",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    web = (output / "SYSTEMD-WEB-PATHS.conf").read_text(encoding="utf-8")
    helper = (output / "SYSTEMD-HELPER-PATHS.conf").read_text(encoding="utf-8")
    assert "ReadWritePaths=/srv/maddyweb-runtime/spool" in web
    assert "ReadOnlyPaths=/srv/maddy/etc/maddy.conf" in helper
    assert "ReadWritePaths=-/srv/maddyweb/certbot" in helper
    assert "ReadWritePaths=-/srv/www/mail" in helper
    assert "ReadWritePaths=/srv/maddy/state" in helper
    assert helper.count("ReadWritePaths=/srv/maddy/tls") == 1
    assert "ReadOnlyPaths=/srv/maddyweb/certbot/live" not in helper
    assert "/run/docker.sock" not in web + helper


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="secure production staging copy is root-only",
)
def test_release_artifact_is_securely_copied_and_rehashed(tmp_path: Path) -> None:
    artifact = tmp_path / "maddyweb-1.0.0-py3-none-any.whl"
    content = b"fixed local wheel fixture"
    artifact.write_bytes(content)
    checksum = hashlib.sha256(content).hexdigest()
    manifest = tmp_path / "release.json"
    manifest.write_text(
        json.dumps(
            {
                "format": "maddyweb-release-v1",
                "commit": "0" * 40,
                "artifact": artifact.name,
                "sha256": checksum,
            }
        ),
        encoding="utf-8",
    )
    staging = tmp_path / "staging"
    staging.mkdir(mode=0o700)
    destination = staging / artifact.name
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts/verify-release-artifact.py"),
            "--artifact",
            str(artifact),
            "--manifest",
            str(manifest),
            "--expected-sha256",
            checksum,
            "--copy-to",
            str(destination),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert destination.read_bytes() == content
    assert destination.stat().st_nlink == 1
    assert destination.stat().st_mode & 0o777 == 0o600


def test_systemd_privilege_boundary() -> None:
    web = (ROOT / "deploy/systemd/maddyweb.service").read_text(encoding="utf-8")
    helper = (ROOT / "deploy/systemd/maddyweb-helper.service").read_text(encoding="utf-8")
    socket = (ROOT / "deploy/systemd/maddyweb-helper.socket").read_text(encoding="utf-8")
    assert "User=maddyweb" in web
    assert "python -I -m maddyweb serve" in web
    assert "IPAddressDeny=any" in web
    assert "IPAddressAllow=localhost" in web
    assert "PrivateTmp=yes" in web
    assert "ReadWritePaths=/var/tmp/maddyweb" not in web
    assert "Environment=MALLOC_ARENA_MAX=1" in web
    assert "Environment=MALLOC_TRIM_THRESHOLD_=65536" in web
    env_example = (ROOT / "deploy/systemd/maddyweb.env.example").read_text(encoding="utf-8")
    assert "MALLOC_ARENA_MAX" not in env_example
    assert "MALLOC_TRIM_THRESHOLD_" not in env_example
    assert "User=root" in helper
    assert "python -I -m maddyweb helper" in helper
    assert "EnvironmentFile=" not in helper
    assert "RestrictAddressFamilies=AF_UNIX AF_INET" in helper
    helper_write_line = next(
        line for line in helper.splitlines() if line.startswith("ReadWritePaths=")
    )
    helper_write_paths = set(helper_write_line.removeprefix("ReadWritePaths=").split())
    assert helper_write_paths == {
        "/var/backups/maddyweb",
        "/run/maddyweb",
    }
    assert "ListenStream=/run/maddyweb/helper.sock" in socket
    assert "SocketUser=root" in socket
    assert "SocketGroup=maddyweb" in socket
    assert "SocketMode=0660" in socket
    tmpfiles = (ROOT / "deploy/systemd/maddyweb.tmpfiles").read_text(encoding="utf-8")
    assert "d /run/maddyweb         0750 root     maddyweb -" in tmpfiles
    assert "d /run/maddyweb-approval 0700 root     root     -" in tmpfiles
    authorization = (ROOT / "scripts/authorize-production.sh").read_text(encoding="utf-8")
    common = (ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    assert 'MADDYWEB_APPROVAL_ROOT="/run/maddyweb-approval"' in common
    assert 'install -d -o root -g root -m 0700 -- "$MADDYWEB_APPROVAL_ROOT"' in authorization


def test_docker_mode_is_for_managed_maddy_not_maddyweb() -> None:
    assert not (ROOT / "docker/Dockerfile").exists()
    assert not (ROOT / "docker/compose.yaml").exists()
    config = load_config(ROOT / "docker/config.toml")
    assert config.maddy.mode == "docker"
    assert config.maddy.container == "maddy"
    explanation = (ROOT / "docker/README.md").read_text(encoding="utf-8")
    assert "MaddyWeb itself is **not containerized**" in explanation


def test_mutating_scripts_are_dry_run_and_approval_gated() -> None:
    for name in ("install.sh", "backup.sh", "rollback.sh"):
        source = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        assert "apply=false" in source
        assert "--apply" in source
        assert "consume_production_approval" in source
        assert "--host" in source
    install_source = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    rollback_source = (ROOT / "scripts/rollback.sh").read_text(encoding="utf-8")
    assert "--artifact" in install_source and "--sha256" in install_source
    assert 'require_regular_file "$DEPENDENCY_LOCK" "dependency lock"' in install_source
    assert "--require-hashes" in install_source
    assert "--only-binary=:all:" in install_source
    assert '--requirement "$staging/REQUIREMENTS.lock"' in install_source
    assert "--no-index --no-deps" in install_source
    assert '--copy-to "$artifact_copy"' in install_source
    assert "staged artifact checksum changed after secure copy" in install_source
    assert "assert_config_root_metadata" in install_source
    assert 'assert_managed_config_file "$CONFIG_ROOT/config.toml"' in install_source
    assert 'assert_managed_config_file "$CONFIG_ROOT/maddyweb.env"' in install_source
    assert 'preflight_config="$CONFIG_ROOT/config.toml"' in install_source
    assert 'run_preflight "$preflight_config"' in install_source
    assert 'run_preflight "$CONFIG_ROOT/config.toml"' in install_source
    assert "--artifact-sha256" in rollback_source
    preflight_source = (ROOT / "scripts/preflight.sh").read_text(encoding="utf-8")
    assert "Docker must not publish MaddyWeb's managed port 1587" in preflight_source
    assert "/usr/bin/nc" in preflight_source


@pytest.mark.parametrize(
    "network_mode",
    ("host", "bridge", "default", "maddy_private"),
)
def test_container_inspectors_accept_supported_network_modes(network_mode: str) -> None:
    for script in ("check-maddy-container.py", "inspect-maddy-container.py"):
        namespace = runpy.run_path(str(ROOT / "scripts" / script))
        assert namespace["validated_network_mode"](network_mode) == network_mode


@pytest.mark.parametrize(
    "network_mode",
    (None, "", "none", "container:maddy", "unsafe network"),
)
def test_container_inspectors_reject_unsupported_network_modes(
    network_mode: object,
) -> None:
    for script in ("check-maddy-container.py", "inspect-maddy-container.py"):
        namespace = runpy.run_path(str(ROOT / "scripts" / script))
        with pytest.raises(SystemExit):
            namespace["validated_network_mode"](network_mode)


def test_preflight_binds_submission_scope_to_docker_network_mode() -> None:
    source = (ROOT / "scripts/preflight.sh").read_text(encoding="utf-8")
    validation = '"$python_binary" "$SCRIPT_DIR/validate-config.py" "${validate_args[@]}"'
    scope_read = 'config["maddy"].get("docker_submission_scope", "container")'

    assert source.index(validation) < source.index(scope_read)
    assert '--container-config "$maddy_config"' in source
    assert "container Submission scope requires a non-host Docker network mode" in source
    assert "host-loopback Submission scope requires Docker network mode host" in source
    assert "Docker must not publish MaddyWeb's managed port 1587" in source
    assert "network_mode=%s" in source
    assert "docker_submission_scope=%s" in source


def test_submission_transactions_enforce_scope_and_network_mode() -> None:
    configure = (ROOT / "scripts/configure-submission.sh").read_text(encoding="utf-8")
    rollback = (ROOT / "scripts/rollback.sh").read_text(encoding="utf-8")
    backup = (ROOT / "scripts/backup.sh").read_text(encoding="utf-8")

    for source in (configure, rollback):
        assert "--app-config" in source
        assert "production requires --app-config exactly /etc/maddyweb/config.toml" in source
        assert "production MaddyWeb config must be single-link root-owned mode 0640" in source
        assert "--docker-submission-scope" in source
        assert "--docker-submission-scope must match maddy.docker_submission_scope" in source
        assert "host-loopback scope requires Docker host networking" in source
        assert "container scope requires an isolated Docker network namespace" in source
        assert '"network_mode"' in source
        assert "/proc/net/tcp /proc/net/tcp6" in source
        assert '[[ "$listener_summary" == 1:1 ]]' in source
        assert '[[ "$listener_summary" == 0:0 ]]' in source
        assert '[[ "$listeners" == "127.0.0.1:1587" ]]' in source

    assert "managed host-network listener is not exactly 127.0.0.1:1587" in configure
    assert '"network_mode", "config_kind"' in configure
    assert '"restart_policy_sha256", "network_mode")' in backup
    assert "rollback release cannot load the effective MaddyWeb configuration" in rollback
    compatibility_gate = (
        "'import sys; from maddyweb.config import load_config; "
        "load_config(sys.argv[1])'"
    )
    assert compatibility_gate in rollback
    assert '["id"])' in rollback
    assert '--container "$container_id"' in rollback
    assert 'container_snapshot_matches "$container_after_approval"' in rollback
    assert "Maddy container identity changed after the reviewed rollback plan" in rollback


def test_install_activation_is_transactional() -> None:
    source = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    assert "unit_existed" in source
    assert "unit_enabled" in source
    assert "unit_active" in source
    assert "restore_install_transaction" in source
    assert "on_install_transaction_exit" in source
    assert "trap on_install_transaction_exit EXIT" in source
    assert "systemctl daemon-reload || status=1" in source
    assert "systemctl is-active --quiet" in source
    assert "systemctl is-enabled --quiet" in source
    assert 'cmp -s -- "$unit_backup/$unit" "$unit_path"' in source
    assert '"$release_path/bin/python" "$SCRIPT_DIR/smoke-test.py"' in source
    assert "CRITICAL: install rollback was incomplete" in source


def test_certbot_hook_install_and_release_rollback_are_fail_closed() -> None:
    install_source = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    rollback_source = (ROOT / "scripts/rollback.sh").read_text(encoding="utf-8")
    wrapper = (ROOT / "scripts/certbot-deploy-hook.sh").read_text(encoding="utf-8")

    assert 'CERTBOT_DEPLOY_HOOK="$CERTBOT_DEPLOY_HOOKS/maddyweb"' in install_source
    assert "certbot_hook_action=install" in install_source
    assert "certbot_hook_action=remove" in install_source
    assert "refusing to overwrite an unmanaged Certbot deploy hook" in install_source
    assert "install -o root -g root -m 0755 --" in install_source
    assert '"$release_path/CERTBOT-DEPLOY-HOOK" "$CERTBOT_DEPLOY_HOOK"' in install_source
    assert 'cmp -s -- "$release_path/CERTBOT-DEPLOY-HOOK"' in install_source
    assert '"$unit_backup/CERTBOT-DEPLOY-HOOK"' in install_source
    assert 'certbot_hook_is_managed "$CERTBOT_DEPLOY_HOOK" || status=1' in install_source
    assert 'rmdir -- "$CERTBOT_DEPLOY_HOOKS" || status=1' in install_source
    assert 'rmdir -- "$CERTBOT_RENEWAL_HOOKS" || status=1' in install_source
    assert "/opt/maddyweb/current/libexec/certbot-deploy-hook.py" in wrapper
    assert "/usr/libexec/maddyweb" not in wrapper

    assert 'certbot_driver="$release/libexec/certbot-deploy-hook.py"' in rollback_source
    assert "rollback release lacks the managed Certbot deploy-hook driver" in rollback_source
    assert "driver permissions are unsafe" in rollback_source


def test_submission_configuration_rollback_has_readback_gates() -> None:
    source = (ROOT / "scripts/configure-submission.sh").read_text(encoding="utf-8")
    rollback = source[source.index("rollback_candidate()") : source.index("on_error()")]
    assert "local status=0" in rollback
    assert "config_verify" in rollback
    assert "reload_or_restart" in rollback
    assert "systemctl is-active --quiet maddy.service || status=1" in rollback
    assert "container_snapshot_matches" in rollback
    assert "managed_listener_gate" in rollback
    assert 'return "$status"' in rollback
    assert "trap on_error EXIT" in source
    assert "edit_attempted=true" in source


def test_backup_cleanup_fails_if_runtime_state_is_not_restored() -> None:
    source = (ROOT / "scripts/backup.sh").read_text(encoding="utf-8")
    cleanup = source[source.index("cleanup()") : source.index("trap cleanup EXIT")]
    assert "restore_status=0" in cleanup
    assert "restore_docker_running_state" in cleanup
    assert "restore_native_maddy_active_state" in cleanup
    assert "restore_maddyweb_unit_states" in cleanup
    unit_state = (ROOT / "scripts/lib/backup-unit-state.sh").read_text(encoding="utf-8")
    assert "MADDYWEB_BACKUP_UNIT_PRESENT" in unit_state
    assert "MADDYWEB_BACKUP_UNIT_ACTIVE" in unit_state
    assert '[[ "$load_state" == not-found' in unit_state
    assert "CRITICAL: backup completed or failed" in cleanup
    assert "status=1" in cleanup


@pytest.mark.skipif(os.name == "nt", reason="backup unit-state helper requires bash")
def test_first_install_backup_skips_missing_maddyweb_units(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    state_dir = tmp_path / "state"
    fake_bin.mkdir()
    state_dir.mkdir()
    log = tmp_path / "systemctl.log"
    systemctl = fake_bin / "systemctl"
    systemctl.write_text(
        """#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\\n' "$*" >> "$SYSTEMCTL_LOG"
command=$1
shift
case "$command" in
    show)
        property=""
        unit=""
        while (($#)); do
            case "$1" in
                --property=*) property=${1#--property=} ;;
                --value) ;;
                *) unit=$1 ;;
            esac
            shift
        done
        case "$property" in
            LoadState) cat "$STATE_DIR/$unit.load" ;;
            ActiveState) cat "$STATE_DIR/$unit.active" ;;
            *) exit 2 ;;
        esac
        ;;
    start|stop)
        for unit in "$@"; do
            if [[ "$command" == start ]]; then
                printf 'active\\n' > "$STATE_DIR/$unit.active"
            else
                printf 'inactive\\n' > "$STATE_DIR/$unit.active"
            fi
        done
        ;;
    *) exit 2 ;;
esac
""",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    units = ("maddyweb.service", "maddyweb-helper.socket", "maddyweb-helper.service")
    for unit in units:
        (state_dir / f"{unit}.load").write_text("not-found\n", encoding="utf-8")
        (state_dir / f"{unit}.active").write_text("inactive\n", encoding="utf-8")

    script = """
set -Eeuo pipefail
source "$REPO_ROOT/scripts/lib/common.sh"
source "$REPO_ROOT/scripts/lib/backup-unit-state.sh"
capture_maddyweb_unit_states
stop_active_maddyweb_units
restore_maddyweb_unit_states
for unit in "${MADDYWEB_BACKUP_UNITS[@]}"; do
    [[ "${MADDYWEB_BACKUP_UNIT_PRESENT[$unit]}" == false ]]
    [[ "${MADDYWEB_BACKUP_UNIT_ACTIVE[$unit]}" == false ]]
done
"""
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "REPO_ROOT": str(ROOT),
        "STATE_DIR": str(state_dir),
        "SYSTEMCTL_LOG": str(log),
    }
    subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", script],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    mutations = [
        line
        for line in log.read_text(encoding="utf-8").splitlines()
        if line.startswith(("start ", "stop "))
    ]
    assert mutations == []


def test_backup_arms_cleanup_before_quiescing_maddy() -> None:
    source = (ROOT / "scripts/backup.sh").read_text(encoding="utf-8")
    assert (
        'source_quiesced=true\n    if [[ "$maddy_was_active" == true ]]; then systemctl stop'
        in source
    )
    assert 'source_quiesced=true\n    "$docker_binary" pause "$container"' in source


def test_release_rollback_reports_only_verified_restoration() -> None:
    source = (ROOT / "scripts/rollback.sh").read_text(encoding="utf-8")
    restore = source[
        source.index("restore_previous_release_state()") : source.index(
            "abort_rollback_transaction()"
        )
    ]
    assert "restore_submission || status=1" in restore
    assert "systemctl restart maddyweb-helper.socket maddyweb.service || status=1" in restore
    assert "systemctl try-restart maddyweb-helper.service || status=1" in restore
    assert "systemctl is-active --quiet" in restore
    assert '"$current/bin/python" "$SCRIPT_DIR/smoke-test.py" || status=1' in restore
    assert "CRITICAL:" in restore
    assert "restore_submission || true" not in source
    assert "systemctl restart maddyweb-helper.socket maddyweb.service || true" not in source


def test_ci_third_party_actions_are_pinned_to_full_commits() -> None:
    workflow = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / ".github/workflows").glob("*.yml"))
    )
    uses = re.findall(r"uses:\s+(actions/(?:checkout|setup-python))@([^\s#]+)", workflow)
    assert uses
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for _, reference in uses)
    assert {action for action, _ in uses} == {"actions/checkout", "actions/setup-python"}


def test_operational_scripts_do_not_accept_passwords_or_modify_nginx() -> None:
    text_suffixes = {
        ".conf",
        ".env",
        ".json",
        ".md",
        ".py",
        ".service",
        ".sh",
        ".socket",
        ".toml",
        ".yaml",
    }
    text_names = {"maddyweb.sysusers", "maddyweb.tmpfiles"}
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for root in (ROOT / "scripts", ROOT / "deploy", ROOT / "docker")
        for path in root.rglob("*")
        if path.is_file() and (path.suffix in text_suffixes or path.name in text_names)
    )
    assert "--password" not in sources
    assert not re.search(r"systemctl\s+(?:reload|restart)\s+nginx", sources)
    assert not re.search(r"nginx\s+-s\s+reload", sources)


def test_locked_maddy_image_matrix_is_complete_and_digest_pinned() -> None:
    lock_path = ROOT / "tests/integration/maddy-image-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    assert tuple(lock["images"]) == TESTED_MADDY_RELEASES
    for image in lock["images"].values():
        assert re.fullmatch(r"ghcr\.io/foxcpp/maddy@sha256:[0-9a-f]{64}", image)


def test_security_workflow_keeps_only_upstream_maddy_scan_informational() -> None:
    workflow = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
    repository_scan, maddy_scan = workflow.split(
        "- name: Scan the exact Maddy 0.9.5 reference image (informational)", maxsplit=1
    )

    assert 'exit-code: "1"' in repository_scan
    assert "id: maddy-scan" in maddy_scan
    assert "continue-on-error: true" in maddy_scan
    assert 'exit-code: "0"' in maddy_scan
    assert "Summarize informational Maddy image scan" in maddy_scan
    assert "Repository, Python dependency, source, secret, configuration" in maddy_scan


def test_named_volume_submission_is_identity_bound_and_has_no_volume_argument() -> None:
    checker = (ROOT / "scripts/check-maddy-container.py").read_text(encoding="utf-8")
    volume_tool = (ROOT / "scripts/docker-volume-config.py").read_text(encoding="utf-8")
    configure = (ROOT / "scripts/configure-submission.sh").read_text(encoding="utf-8")

    assert 'str(selected_config) != "/data/maddy.conf"' in checker
    assert 'config_group.add_argument("--host-config"' in checker
    assert 'config_group.add_argument("--container-config"' in checker
    assert "not mounted_config.is_file()" in checker
    assert "mounted_config.is_symlink()" in checker
    assert 'data_mount.get("Source") != mountpoint' in checker
    assert 'data_mount.get("Source") != mountpoint' in volume_tool
    assert "named volume must be referenced only by the selected Maddy container" in checker
    assert "named volume must be referenced only by the selected Maddy container" in volume_tool
    assert "--volume" not in volume_tool
    assert "--docker-data-volume" not in configure
    assert "expected_container_id: str" in volume_tool
    assert "container_id != expected_container_id" in volume_tool
    snapshot = configure[
        configure.index("container_snapshot_matches()") : configure.index(
            "named_volume_snapshot()"
        )
    ]
    for key in (
        "network_mode",
        "config_kind",
        "config_source",
        "volume_name",
        "volume_sha256",
    ):
        assert f'"{key}"' in snapshot


def test_named_volume_dry_run_uses_only_fixed_read_only_execs() -> None:
    volume_tool = (ROOT / "scripts/docker-volume-config.py").read_text(encoding="utf-8")
    running_export = volume_tool[
        volume_tool.index("def run_running_export") : volume_tool.index("def run_helper_export")
    ]
    dispatcher = volume_tool[
        volume_tool.index("def run_export(") : volume_tool.index("def write_snapshot")
    ]

    assert '"exec", "--user", "0:0", container_id' in volume_tool
    for executable in ("/bin/stat", "/usr/bin/readlink", "/usr/bin/sha256sum", "/bin/cat"):
        assert executable in running_export
    assert "docker_run_base" not in running_export
    assert 'if required_state == "running":\n        return run_running_export' in dispatcher
    assert "return run_helper_export" in dispatcher


def test_named_volume_replace_has_minimal_helper_caps_and_three_state_recovery() -> None:
    volume_tool = (ROOT / "scripts/docker-volume-config.py").read_text(encoding="utf-8")
    helper = (ROOT / "scripts/docker-volume-config-helper.sh").read_text(encoding="utf-8")
    configure = (ROOT / "scripts/configure-submission.sh").read_text(encoding="utf-8")

    replace = volume_tool[volume_tool.index("def run_replace") : volume_tool.index("def main")]
    assert '"--cap-drop",\n        "ALL"' in volume_tool
    assert replace.count('"--cap-add"') == 2
    assert '"CHOWN"' in replace
    assert '"DAC_OVERRIDE"' in replace
    assert '"FOWNER"' not in replace
    assert '"--network",\n        "none"' in volume_tool
    assert '"--read-only"' in volume_tool
    assert "--volumes-from" not in volume_tool
    assert 'mv -f -- "$temporary" "$config"' in helper
    assert "configuration changed during replacement" in helper
    assert "replacement ownership or mode read-back failed" in helper
    assert "configuration mode must not contain special bits" in helper
    assert "configuration mode must not be group/world writable" in helper

    assert "rollback_needed=true" in configure
    assert '== "$candidate_hash"' in configure
    assert '== "$original_hash"' in configure
    assert "automatic configuration restoration failed" in configure
    assert "rollback_state=stopped" in configure
    assert "rollback_state=paused" in configure
    assert "submission_lock=/run/lock/maddyweb-submission.lock" in configure
    assert 'flock -n "$submission_lock_fd"' in configure


def test_named_volume_docker_daemon_and_legacy_downtime_are_fail_closed() -> None:
    checker = (ROOT / "scripts/check-maddy-container.py").read_text(encoding="utf-8")
    volume_tool = (ROOT / "scripts/docker-volume-config.py").read_text(encoding="utf-8")
    configure = (ROOT / "scripts/configure-submission.sh").read_text(encoding="utf-8")

    for source in (checker, volume_tool):
        assert 'os.environ.get("DOCKER_HOST")' in source
        assert 'os.environ.get("DOCKER_CONTEXT")' in source
        assert 'endpoint != "unix:///var/run/docker.sock"' in source
    assert "paused_value is True" in checker
    assert "Maddy container must be running and unpaused" in checker
    assert '"stopped": (False, False)' in volume_tool
    assert '"paused": (True, True)' in volume_tool
    assert '"0.8.2" && "$apply" == true && "$allow_downtime" != true' in configure
    assert 'restart --time 10 "$container_id"' in configure


def test_named_volume_helper_cleanup_is_proven_and_not_global() -> None:
    volume_tool = (ROOT / "scripts/docker-volume-config.py").read_text(encoding="utf-8")
    integration = (ROOT / "tests/integration/test-named-volume-submission.sh").read_text(
        encoding="utf-8"
    )

    cleanup = volume_tool[
        volume_tool.index("def cleanup_helper") : volume_tool.index("def parse_exported_config")
    ]
    assert '"rm", "--force", name' in cleanup
    assert '"container",' in cleanup
    assert 'f"name=^/{name}$"' in cleanup
    assert "maximum=1024" in cleanup
    assert '"inspect", name' not in cleanup
    assert "helper still exists after cleanup" in cleanup
    assert "label=io.maddyweb.purpose=submission-volume-config" not in integration
    assert '--filter "volume=$volume"' in integration


def test_named_volume_helper_cleanup_fails_if_absence_query_cannot_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    volume_tool = runpy.run_path(str(ROOT / "scripts/docker-volume-config.py"))
    cleanup = volume_tool["cleanup_helper"]
    error_type = volume_tool["VolumeConfigError"]
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs):
        calls.append(argv)
        if argv[1:3] == ["rm", "--force"]:
            return subprocess.CompletedProcess(argv, 1, b"", b"daemon unavailable")
        raise error_type("fixed Docker operation failed")

    monkeypatch.setitem(cleanup.__globals__, "run", fake_run)
    with pytest.raises(error_type, match="fixed Docker operation failed"):
        cleanup(Path("/usr/bin/docker"), "maddyweb-submission-replace-deadbeef")

    assert calls[0][1:3] == ["rm", "--force"]
    assert calls[1][1:4] == ["container", "ls", "--all"]


def test_combined_release_rollback_explicitly_rejects_named_volume_submission() -> None:
    rollback = (ROOT / "scripts/rollback.sh").read_text(encoding="utf-8")

    assert 'json.loads(sys.argv[1])["config_kind"]' in rollback
    assert '[[ "$rollback_config_kind" == bind ]]' in rollback
    assert "remove named-volume Submission separately" in rollback
    rejection = rollback.index('[[ "$rollback_config_kind" == bind ]]')
    editor = rollback.index('--action check-remove --config "$maddy_config"', rejection)
    assert rejection < editor
