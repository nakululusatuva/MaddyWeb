from __future__ import annotations

import hashlib
import json
import os
import re
import runpy
import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest

from maddyweb.config import load_config

ROOT = Path(__file__).resolve().parents[2]
CONFIGS = (
    ROOT / "deploy/examples/config.native.toml",
    ROOT / "deploy/examples/config.wsl.toml",
    ROOT / "docker/config.toml",
)
TESTED_MADDY_RELEASES = ("0.8.2", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "0.9.4", "0.9.5")


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


@pytest.mark.parametrize("path", CONFIGS)
def test_example_config_is_accepted_by_application_and_deploy_validator(path: Path) -> None:
    config = load_config(path)
    assert config.server.listen == "127.0.0.1:8787"
    assert config.server.request_body_timeout_seconds == 15
    assert config.maddy.helper_socket == PurePosixPath("/run/maddyweb/helper.sock")
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


def test_nondefault_paths_render_exact_systemd_sandbox_allowlists(tmp_path: Path) -> None:
    source = CONFIGS[0].read_text(encoding="utf-8")
    replacements = {
        'temp_dir = "/var/tmp/maddyweb"': 'temp_dir = "/srv/maddyweb-runtime/spool"',
        'config_path = "/etc/maddy/maddy.conf"': 'config_path = "/srv/maddy/etc/maddy.conf"',
        'data_dir = "/var/lib/maddy"': 'data_dir = "/srv/maddy/state"',
        "enabled = false": "enabled = true",
        "names = []": 'names = ["mx.example.invalid"]',
        'live_dir = "/etc/letsencrypt/live"': 'live_dir = "/srv/acme/live"',
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
    assert "ReadWritePaths=/srv/maddy/state" in helper
    assert helper.count("ReadWritePaths=/srv/maddy/tls") == 1
    assert "ReadOnlyPaths=/srv/acme/live" in helper
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
    assert "ReadWritePaths=/var/tmp/maddyweb" in web
    assert "Environment=MALLOC_ARENA_MAX=1" in web
    assert "Environment=MALLOC_TRIM_THRESHOLD_=65536" in web
    env_example = (ROOT / "deploy/systemd/maddyweb.env.example").read_text(encoding="utf-8")
    assert "MALLOC_ARENA_MAX" not in env_example
    assert "MALLOC_TRIM_THRESHOLD_" not in env_example
    assert "User=root" in helper
    assert "python -I -m maddyweb helper" in helper
    assert "EnvironmentFile=" not in helper
    assert "RestrictAddressFamilies=AF_UNIX AF_INET" in helper
    assert "/etc/letsencrypt" in helper
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
    assert "--artifact-sha256" in rollback_source
    preflight_source = (ROOT / "scripts/preflight.sh").read_text(encoding="utf-8")
    assert "Docker must not publish MaddyWeb's managed port 1587" in preflight_source
    assert "/usr/bin/nc" in preflight_source


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
