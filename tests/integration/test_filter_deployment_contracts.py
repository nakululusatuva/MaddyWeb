from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_filter_service_is_unprivileged_private_and_read_only() -> None:
    unit = _read("deploy/systemd/maddyweb-filter.service")
    assert "User=maddyweb-filter" in unit
    assert "Group=maddyweb-filter" in unit
    assert "--listen ${MADDYWEB_FILTER_LISTEN}" in unit
    assert "--token-file ${MADDYWEB_FILTER_TOKEN_FILE}" in unit
    assert "MADDYWEB_CONFIG" not in unit
    assert "--config" not in unit
    assert "SocketBindAllow=tcp:18787" in unit
    assert "SocketBindDeny=any" in unit
    assert "IPAddressDeny=any" in unit
    for network in ("localhost", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
        assert f"IPAddressAllow={network}" in unit
    assert "NoNewPrivileges=yes" in unit
    assert "ProtectSystem=strict" in unit
    assert "ReadOnlyPaths=/var/lib/maddyweb-filter" in unit
    assert "/run/docker.sock" in unit
    assert "-/etc/maddyweb/config.toml" in unit


def test_filter_identity_and_snapshot_tree_are_separate() -> None:
    sysusers = _read("deploy/systemd/maddyweb.sysusers")
    tmpfiles = _read("deploy/systemd/maddyweb.tmpfiles")
    assert "g maddyweb-filter" in sysusers
    assert "u maddyweb-filter" in sysusers
    assert "m maddyweb-filter maddyweb-filter" in sysusers
    assert "g maddyweb-filter-client" in sysusers
    assert "m maddyweb maddyweb-filter" not in sysusers
    assert "m maddyweb-filter-client" not in sysusers
    assert "d /var/lib/maddyweb-filter 0750 root maddyweb-filter" in tmpfiles
    assert "d /var/lib/maddyweb-filter/snapshots 0750 root maddyweb-filter" in tmpfiles


def test_installer_retains_filter_assets_and_preserves_active_service() -> None:
    install = _read("scripts/install.sh")
    assert '"$REPO_ROOT/deploy/maddyweb-filter-docker"' in install
    assert '"$SCRIPT_DIR/manage-imap-filter.py"' in install
    assert '"$staging/libexec/maddyweb-filter-docker"' in install
    assert '"$staging/libexec/manage-imap-filter.py"' in install
    assert "maddyweb-filter.service" in install
    assert '${unit_active[maddyweb-filter.service]}' in install
    assert "systemctl restart maddyweb-filter.service" in install


def test_native_and_docker_managed_commands_do_not_invoke_a_shell() -> None:
    editor = _read("scripts/manage-imap-filter.py")
    assert (
        '"command /opt/maddyweb/current/bin/python -I -m "\n'
        '        "maddyweb.filter_client {account_name}"'
    ) in editor
    assert '"command /data/maddyweb-filter/maddyweb-filter-client {account_name}"' in editor
    assert "sh -c" not in editor
    assert "shell=True" not in editor


def test_docker_wrapper_is_fixed_fail_open_and_rejects_unsafe_accounts() -> None:
    wrapper = _read("deploy/maddyweb-filter-docker")
    assert wrapper.startswith("#!/bin/sh\n")
    assert "readonly endpoint_file=$state_dir/client.endpoint" in wrapper
    assert "readonly token_file=$state_dir/client.token" in wrapper
    assert '"0:0:400:1"' in wrapper
    assert "/usr/bin/nc -w 5 \"$host\" 18787" in wrapper
    assert "MADDYWEB-FILTER/1" in wrapper
    assert 'printf \'%s %s %s\\n\'' in wrapper
    assert "\neval " not in wrapper
    assert "exit 0" in wrapper


def test_filter_environment_contains_no_token_value() -> None:
    environment = _read("deploy/systemd/maddyweb.env.example")
    assert "MADDYWEB_FILTER_LISTEN=127.0.0.1:18787" in environment
    assert "MADDYWEB_FILTER_TOKEN=" not in environment


def test_filter_production_approval_scopes_are_authorized_and_consumed() -> None:
    authorization = _read("scripts/authorize-production.sh")
    lifecycle = _read("scripts/configure-filter.sh")
    assert "filter-add|filter-remove" in authorization
    assert 'consume_production_approval "$approval_file" "filter-$action"' in lifecycle


def test_filter_lifecycle_uses_the_shared_non_waiting_deployment_lock() -> None:
    lifecycle = _read("scripts/configure-filter.sh")
    lock = lifecycle.index('deployment_lock="$MADDYWEB_APPROVAL_ROOT/deployment.lock"')
    source_snapshot = lifecycle.index('install -m 0600 -- "$maddy_config" "$source_config"')
    assert lock < source_snapshot
    assert 'require_command flock' in lifecycle
    assert 'flock -n "$deployment_lock_fd"' in lifecycle
    assert '"0:0:600:1"' in lifecycle


def test_filter_lifecycle_arms_and_verifies_every_live_config_change() -> None:
    lifecycle = _read("scripts/configure-filter.sh")
    replacement = lifecycle.index("replace_config() {")
    armed = lifecycle.index("config_replaced=true", replacement)
    install = lifecycle.index("install_native_config", armed)
    assert armed < install
    assert 'verify_live_config "$1"' in lifecycle
    assert 'maddy_state_gate "$source_config"' in lifecycle
    assert 'verify_live_config "$source_config"' in lifecycle
    assert 'maddy_state_gate "$candidate_config"' in lifecycle
    assert '"$docker_binary" exec "$container_id" /bin/busybox sync' in lifecycle
    assert "trap cleanup EXIT" in lifecycle
    assert 'declare -F restore_config' in lifecycle


def test_filter_config_changes_and_restoration_use_controlled_restarts() -> None:
    lifecycle = _read("scripts/configure-filter.sh")
    assert "SIGUSR2" not in lifecycle
    assert "reload_maddy" not in lifecycle

    restart = lifecycle.index("restart_maddy() {")
    restart_end = lifecycle.index("\n}\n\nverify_candidate()", restart)
    restart_body = lifecycle[restart:restart_end]
    assert "systemctl restart maddy.service" in restart_body
    assert '"$docker_binary" restart --time 10 "$container_id"' in restart_body
    assert "maddy_restart_expected=true" in restart_body
    assert "maddy_restart_identity_before" in restart_body

    restoration = lifecycle.index("restore_config() {")
    restoration_end = lifecycle.index('if [[ "$action" == add ]]', restoration)
    restoration_body = lifecycle[restoration:restoration_end]
    restore_replace = restoration_body.index('replace_config "$source_config"')
    restore_restart = restoration_body.index("restart_maddy", restore_replace)
    restore_gate = restoration_body.index(
        'maddy_state_gate "$source_config"', restore_restart
    )
    restore_readback = restoration_body.index(
        'verify_live_config "$source_config"', restore_gate
    )
    assert restore_replace < restore_restart < restore_gate < restore_readback

    addition = lifecycle.index('if [[ "$action" == add ]]', restoration_end)
    add_replace = lifecycle.index('replace_config "$candidate_config"', addition)
    add_restart = lifecycle.index("restart_maddy", add_replace)
    add_gate = lifecycle.index('maddy_state_gate "$candidate_config"', add_restart)
    assert add_replace < add_restart < add_gate

    removal = lifecycle.index(
        'if [[ "$filter_config_present" == true ]]', add_gate
    )
    remove_replace = lifecycle.index('replace_config "$candidate_config"', removal)
    remove_restart = lifecycle.index("restart_maddy", remove_replace)
    remove_gate = lifecycle.index('maddy_state_gate "$candidate_config"', remove_restart)
    assert remove_replace < remove_restart < remove_gate


def test_filter_lifecycle_checks_service_state_version_config_and_listeners() -> None:
    lifecycle = _read("scripts/configure-filter.sh")
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
        assert f'ipaddress.ip_network("{network}")' in lifecycle
    assert "systemctl is-active --quiet maddy.service" in lifecycle
    assert 'record.get("Id") == sys.argv[2]' in lifecycle
    assert 'state.get("Running") is True' in lifecycle
    assert 'state.get("Paused") is not True' in lifecycle
    assert 'state.get("Restarting") is not True' in lifecycle
    assert 'observed_version" == "$maddy_version' in lifecycle
    assert 'listeners" == "$initial_maddy_listeners' in lifecycle
    assert '"$pid" != "$maddy_restart_identity_before"' in lifecycle
    assert "'{{.State.StartedAt}}'" in lifecycle
    assert '"$started_at" != "$maddy_restart_identity_before"' in lifecycle
    assert "verify_candidate /data/maddy.conf" in lifecycle


def test_filter_lifecycle_preflights_tokens_and_restarts_bridge() -> None:
    lifecycle = _read("scripts/configure-filter.sh")
    for path in (
        "/var/lib/maddyweb-filter/bridge.token",
        "/etc/maddyweb/maddyweb-filter.env",
        "/etc/maddyweb-filter/client.token",
        "/etc/maddyweb-filter/client.endpoint",
        "/data/maddyweb-filter/client.token",
        "/data/maddyweb-filter/client.endpoint",
        "/data/maddyweb-filter/maddyweb-filter-client",
    ):
        assert path in lifecycle
    assert 're.fullmatch(rb"[0-9a-f]{64}\\n", payload)' in lifecycle
    assert "systemctl restart maddyweb-filter.service" in lifecycle
    assert "systemctl enable --now maddyweb-filter.service" not in lifecycle
    listener_wait = lifecycle.index("wait_for_filter_listener() {")
    listener_restart = lifecycle.index("systemctl restart maddyweb-filter.service")
    listener_gate = lifecycle.index("wait_for_filter_listener", listener_restart)
    config_replace = lifecycle.index('replace_config "$candidate_config"', listener_gate)
    assert "for _ in {1..50}" in lifecycle[listener_wait:listener_restart]
    assert "systemctl is-active --quiet maddyweb-filter.service || return 1" in lifecycle[
        listener_wait:listener_restart
    ]
    assert "sleep 0.1" in lifecycle[listener_wait:listener_restart]
    assert listener_restart < listener_gate < config_replace
    assert "maddyweb-filter-client" in lifecycle
    assert '"$(id -gn "$service_user")" != maddyweb-filter-client' in lifecycle
    assert '"$refreshed_members" == "$service_user"' in lifecycle
    assert "usermod -a -G maddyweb-filter-client" in lifecycle
    assert "gpasswd -d" in lifecycle


def test_filter_removal_can_resume_after_post_reload_cleanup_failure() -> None:
    lifecycle = _read("scripts/configure-filter.sh")
    fallback = lifecycle.index('--action check-add')
    absent = lifecycle.index('filter_config_present=false', fallback)
    removal = lifecycle.index('if [[ "$filter_config_present" == true ]]', absent)
    disarm = lifecycle.index('config_replaced=false', removal)
    cleanup = lifecycle.index('systemctl disable --now maddyweb-filter.service', disarm)
    assert fallback < absent < removal < disarm < cleanup
    assert 'maddy_state_gate "$source_config"' in lifecycle[removal:cleanup]


def test_delivery_integration_covers_fail_open_and_real_snapshot_match() -> None:
    integration = _read("tests/integration/test-filter-maddy-delivery.sh")
    supported_versions = (
        'for version in ("0.8.2", "0.9.0", "0.9.1", "0.9.2", '
        '"0.9.3", "0.9.4", "0.9.5")'
    )
    assert supported_versions in integration
    assert supported_versions in _read("tests/integration/test-filter-docker-client.sh")
    assert "python@sha256:" in integration
    assert '"target_mailbox": "RuleMatches"' in integration
    assert "serve_filter_bridge(" in integration
    assert 'Subject: fail-open delivery %s' in integration
    assert 'Subject: matched delivery %s' in integration
    assert 'grep -Fc "matched delivery $version"' in integration
    assert 'grep -Fq "matched delivery $version" <<< "$inbox_messages"' in integration
    assert "then\n        exit 1" in integration


def test_release_rollback_preserves_or_requires_exact_filter_removal() -> None:
    rollback = _read("scripts/rollback.sh")
    assert "target_filter_capability=unsupported" in rollback
    assert "maddyweb.filter_bridge" in rollback
    assert "maddyweb.filter_client" in rollback
    assert 'target_filter_help" != *--config*' in rollback
    assert "# BEGIN MADDYWEB MANAGED IMAP FILTER v1" in rollback
    assert "configure-filter.sh --action remove first" in rollback
    assert "systemctl is-enabled --quiet maddyweb-filter.service" in rollback
    assert 'units=(maddyweb-filter.service "${units[@]}")' in rollback
    assert "systemctl restart maddyweb-filter.service" in rollback


def test_quiesced_backup_contains_filter_snapshots_and_checksums() -> None:
    backup = _read("scripts/backup.sh")
    assert 'readonly FILTER_SNAPSHOT_DIR="/var/lib/maddyweb-filter/snapshots"' in backup
    assert "quiesce_all_maddyweb_units_for_snapshot" in backup
    assert "snapshot_filter_state" in backup
    assert 'tar --create --file "$staging/filter-snapshots.tar"' in backup
    assert "^[0-9a-f]{64}\\.json$" in backup
    assert "0:${filter_gid}:640:1" in backup
    assert "sha256_file filter-snapshots.tar > filter-snapshots.tar.sha256" in backup
    assert "sha256_file filter-snapshots.status > filter-snapshots.status.sha256" in backup
