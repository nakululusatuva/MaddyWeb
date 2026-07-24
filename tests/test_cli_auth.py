from __future__ import annotations

import io
import json
import os
import stat
import sys
import sysconfig
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import maddyweb.auth as auth_module
import maddyweb.helper as helper_module
import maddyweb.maddy as maddy_module
from maddyweb import cli
from maddyweb.auth import Role
from maddyweb.config import AppConfig

ROOT = Path(__file__).resolve().parents[1]
TOTP_SECRET = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # noqa: S105 - fixed test vector.
RECOVERY_CODES = tuple(f"{value:032x}" for value in range(10))
INITIAL_PASSWORD = "bootstrap-password-that-is-not-logged"  # noqa: S105 - test input.


def test_auth_import_preserves_requested_gil_off_lane() -> None:
    if not (sysconfig.get_config_var("Py_GIL_DISABLED") and os.environ.get("PYTHON_GIL") == "0"):
        pytest.skip("free-threaded GIL-off lane")
    assert sys._is_gil_enabled() is False


class FakeMaddy:
    def __init__(self, accounts: list[dict[str, Any]]) -> None:
        self.accounts = [dict(account) for account in accounts]
        self.created: list[tuple[str, str]] = []
        self.deleted: list[str] = []

    def list_accounts(self, *, include_append_limits: bool = True) -> list[dict[str, Any]]:
        assert include_append_limits is False
        return [dict(account) for account in self.accounts]

    def create_account(self, email: str, password: str) -> None:
        self.created.append((email, password))
        self.accounts.append(
            {
                "username": email,
                "has_credentials": True,
                "has_mailbox": True,
            }
        )

    def delete_account(self, email: str) -> None:
        self.deleted.append(email)
        self.accounts = [account for account in self.accounts if account["username"] != email]


class FakeAuthStore:
    def __init__(self, *, fail_email: str = "") -> None:
        self.fail_email = fail_email
        self.bootstrapped: list[dict[str, Any]] = []
        self.synced: list[tuple[tuple[str, ...], bool]] = []
        self.roles: list[tuple[str, Role, bool]] = []
        self.accounts_by_email: dict[str, SimpleNamespace] = {}
        self.purged: list[str] = []
        self.closed = False

    def bootstrap_active_accounts(self, records: Any) -> None:
        prepared = list(records)
        if any(record.email == self.fail_email for record in prepared):
            raise RuntimeError("metadata bootstrap failed")
        self.bootstrapped.extend(
            {
                "email": record.email,
                "role": record.role,
                "totp_secret": record.totp_secret,
                "recovery_codes": record.recovery_codes,
                "password_change_required": record.password_change_required,
            }
            for record in prepared
        )

    def sync_accounts(
        self,
        emails: tuple[str, ...],
        *,
        password_change_required: bool,
    ) -> tuple[SimpleNamespace, ...]:
        self.synced.append((emails, password_change_required))
        return (SimpleNamespace(account_id="0" * 32),)

    def set_role(
        self,
        account_id: str,
        role: Role,
        *,
        revoke_sessions: bool,
    ) -> None:
        self.roles.append((account_id, role, revoke_sessions))

    def get_account(self, email: str) -> SimpleNamespace | None:
        return self.accounts_by_email.get(email)

    def delete_account(self, account_id: str) -> None:
        self.purged.append(account_id)
        self.accounts_by_email = {
            email: account
            for email, account in self.accounts_by_email.items()
            if account.account_id != account_id
        }

    def close(self) -> None:
        self.closed = True


def _config() -> AppConfig:
    return AppConfig.from_dict({"maddy": {"mode": "docker"}})


def _account(
    email: str,
    *,
    has_credentials: bool = True,
    has_mailbox: bool = True,
) -> dict[str, Any]:
    return {
        "username": email,
        "has_credentials": has_credentials,
        "has_mailbox": has_mailbox,
    }


def _record(
    email: str = "admin@example.test",
    *,
    role: str = "admin",
    create_account: bool = False,
    initial_password: str = "",
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "email": email,
        "role": role,
        "totp_secret": TOTP_SECRET,
        "recovery_codes": list(RECOVERY_CODES),
        "password_change_required": create_account,
        "create_account": create_account,
    }
    if initial_password:
        record["initial_password"] = initial_password
    return record


def _stdin(monkeypatch: pytest.MonkeyPatch, document: object) -> None:
    payload = json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    monkeypatch.setattr(cli.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))


def _install_bootstrap_fakes(
    monkeypatch: pytest.MonkeyPatch,
    maddy: FakeMaddy,
    store: FakeAuthStore,
) -> None:
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(
        maddy_module.MaddyService,
        "from_config",
        lambda *_args, **_kwargs: maddy,
    )
    monkeypatch.setattr(
        helper_module.SMTPSubmissionClient,
        "from_config",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(cli, "_auth_store", lambda _config: store)


def test_auth_bootstrap_refuses_non_root_before_reading_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnreadableInput:
        @staticmethod
        def read(_size: int) -> bytes:
            raise AssertionError("non-root bootstrap must not consume secrets")

    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(cli.sys, "stdin", SimpleNamespace(buffer=UnreadableInput()))

    with pytest.raises(RuntimeError, match="must run as root"):
        cli._run_auth_bootstrap(_config())


def test_bootstrap_json_rejects_duplicate_object_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b'{"accounts":[],"accounts":[{}]}'
    monkeypatch.setattr(cli.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))

    with pytest.raises(RuntimeError, match="invalid JSON"):
        cli._read_bootstrap_document()


def test_bootstrap_validation_rejects_non_text_recovery_code_cleanly() -> None:
    record = _record()
    record["recovery_codes"][0] = []

    with pytest.raises(RuntimeError, match="recovery codes are invalid"):
        cli._validated_bootstrap_records([record])


def test_bootstrap_rejects_secret_fields_outside_stdin() -> None:
    parser = cli._parser()
    option_strings = {option for action in parser._actions for option in action.option_strings}
    for subparser in parser._subparsers._group_actions[0].choices.values():
        option_strings.update(
            option for action in subparser._actions for option in action.option_strings
        )

    assert not any("password" in option or "secret" in option for option in option_strings)


def test_existing_enabled_account_bootstrap_has_safe_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    maddy = FakeMaddy([_account("user@example.test")])
    store = FakeAuthStore()
    _install_bootstrap_fakes(monkeypatch, maddy, store)
    document = {"accounts": [_record("user@example.test", role="user")]}
    _stdin(monkeypatch, document)

    cli._run_auth_bootstrap(_config())

    captured = capsys.readouterr()
    combined = captured.out + captured.err + caplog.text
    assert captured.out == "bootstrap=ok accounts=1 maddy_accounts_created=0\n"
    assert TOTP_SECRET not in combined
    assert all(code not in combined for code in RECOVERY_CODES)
    assert INITIAL_PASSWORD not in combined
    assert maddy.created == []
    assert store.closed is True
    assert store.bootstrapped[0]["email"] == "user@example.test"
    assert store.bootstrapped[0]["role"] is Role.USER


def test_new_account_bootstrap_passes_password_only_to_maddy(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    maddy = FakeMaddy([])
    store = FakeAuthStore()
    _install_bootstrap_fakes(monkeypatch, maddy, store)
    _stdin(
        monkeypatch,
        {
            "accounts": [
                _record(
                    create_account=True,
                    initial_password=INITIAL_PASSWORD,
                )
            ]
        },
    )

    cli._run_auth_bootstrap(_config())

    output = capsys.readouterr().out
    assert output == "bootstrap=ok accounts=1 maddy_accounts_created=1\n"
    assert INITIAL_PASSWORD not in output
    assert maddy.created == [("admin@example.test", INITIAL_PASSWORD)]
    assert "initial_password" not in store.bootstrapped[0]
    assert store.closed is True


def test_new_account_bootstrap_rejects_preexisting_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    maddy = FakeMaddy([_account("admin@example.test")])
    store = FakeAuthStore()
    _install_bootstrap_fakes(monkeypatch, maddy, store)
    _stdin(
        monkeypatch,
        {
            "accounts": [
                _record(
                    create_account=True,
                    initial_password=INITIAL_PASSWORD,
                )
            ]
        },
    )

    with pytest.raises(RuntimeError, match="already exists"):
        cli._run_auth_bootstrap(_config())

    assert maddy.created == []
    assert store.bootstrapped == []
    assert store.closed is True


@pytest.mark.parametrize(
    "account",
    (
        _account("user@example.test", has_credentials=False),
        _account("user@example.test", has_mailbox=False),
    ),
)
def test_existing_account_bootstrap_rejects_partial_identity(
    monkeypatch: pytest.MonkeyPatch,
    account: dict[str, Any],
) -> None:
    maddy = FakeMaddy([account])
    store = FakeAuthStore()
    _install_bootstrap_fakes(monkeypatch, maddy, store)
    _stdin(monkeypatch, {"accounts": [_record("user@example.test", role="user")]})

    with pytest.raises(RuntimeError, match="not a complete enabled Maddy account"):
        cli._run_auth_bootstrap(_config())

    assert store.bootstrapped == []
    assert store.closed is True


def test_bootstrap_compensates_new_maddy_account_on_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    maddy = FakeMaddy([])
    store = FakeAuthStore(fail_email="admin@example.test")
    _install_bootstrap_fakes(monkeypatch, maddy, store)
    _stdin(
        monkeypatch,
        {
            "accounts": [
                _record(
                    create_account=True,
                    initial_password=INITIAL_PASSWORD,
                )
            ]
        },
    )

    with pytest.raises(RuntimeError, match="metadata bootstrap failed"):
        cli._run_auth_bootstrap(_config())

    assert maddy.deleted == ["admin@example.test"]
    assert store.closed is True


def test_auth_role_requires_root_and_an_enabled_mailbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(RuntimeError, match="must run as root"):
        cli._run_auth_role(_config(), "user@example.test", "admin")

    maddy = FakeMaddy([_account("user@example.test", has_mailbox=False)])
    store = FakeAuthStore()
    _install_bootstrap_fakes(monkeypatch, maddy, store)
    with pytest.raises(RuntimeError, match="enabled Maddy account"):
        cli._run_auth_role(_config(), "user@example.test", "admin")
    assert store.synced == []


def test_auth_role_invalid_email_is_a_clean_cli_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = tmp_path / "config.toml"
    config.write_text('[maddy]\nmode = "docker"\n', encoding="utf-8")
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(cli, "_validate_python_runtime", lambda: None)

    with pytest.raises(SystemExit) as error:
        cli.main(
            [
                "auth-role",
                "--config",
                str(config),
                "--email",
                "not-an-email",
                "--role",
                "admin",
            ]
        )

    assert error.value.code == 2
    assert "not-an-email" not in caplog.text
    assert "authentication role identity is invalid" in caplog.text


def test_auth_role_syncs_metadata_and_revokes_sessions(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    maddy = FakeMaddy([_account("user@example.test")])
    store = FakeAuthStore()
    _install_bootstrap_fakes(monkeypatch, maddy, store)

    cli._run_auth_role(_config(), "USER@EXAMPLE.TEST", "admin")

    assert capsys.readouterr().out == ("role=ok email=user@example.test value=admin\n")
    assert store.synced == [(("user@example.test",), False)]
    assert store.roles == [("0" * 32, Role.ADMIN, True)]
    assert store.closed is True


def test_auth_purge_requires_root_absent_mailbox_and_exact_confirmation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(RuntimeError, match="must run as root"):
        cli._run_auth_purge(
            _config(),
            "user@example.test",
            "user@example.test",
        )

    maddy = FakeMaddy([_account("user@example.test")])
    store = FakeAuthStore()
    _install_bootstrap_fakes(monkeypatch, maddy, store)
    with pytest.raises(RuntimeError, match="confirmation does not match"):
        cli._run_auth_purge(
            _config(),
            "user@example.test",
            "other@example.test",
        )
    with pytest.raises(RuntimeError, match="still exists"):
        cli._run_auth_purge(
            _config(),
            "user@example.test",
            "USER@EXAMPLE.TEST",
        )
    assert store.purged == []

    maddy.accounts.clear()
    store.accounts_by_email["user@example.test"] = SimpleNamespace(account_id="f" * 32)
    cli._run_auth_purge(
        _config(),
        "USER@EXAMPLE.TEST",
        "user@example.test",
    )

    assert capsys.readouterr().out == ("auth_purge=ok email=user@example.test removed=1\n")
    assert store.purged == ["f" * 32]
    assert store.closed is True


def test_auth_purge_blocks_partial_maddy_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    maddy = FakeMaddy([_account("user@example.test", has_credentials=False, has_mailbox=False)])
    store = FakeAuthStore()
    _install_bootstrap_fakes(monkeypatch, maddy, store)

    with pytest.raises(RuntimeError, match="still exists"):
        cli._run_auth_purge(
            _config(),
            "user@example.test",
            "user@example.test",
        )

    assert store.closed is False
    assert store.purged == []


def test_auth_store_revalidates_runtime_after_auth_module_load(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []

    class RecordingStore:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            events.append("store")

    monkeypatch.setattr(auth_module, "AuthStore", RecordingStore)
    monkeypatch.setattr(cli, "_private_auth_directory", lambda _config: tmp_path)
    monkeypatch.setattr(cli, "_auth_master_key", lambda _directory: b"k" * 32)
    monkeypatch.setattr(
        cli,
        "_validate_python_runtime",
        lambda: events.append("runtime"),
    )

    cli._auth_store(_config())

    assert events == ["store", "runtime"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode contract")
def test_private_auth_directory_requires_root_owned_mode_0700(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = tmp_path / "auth"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    original_lstat = Path.lstat

    def root_lstat(path: Path) -> SimpleNamespace:
        metadata = original_lstat(path)
        return SimpleNamespace(st_mode=metadata.st_mode, st_uid=0)

    monkeypatch.setattr(Path, "lstat", root_lstat)
    config = SimpleNamespace(security=SimpleNamespace(auth_state_dir=directory))
    assert cli._private_auth_directory(config) == directory

    directory.chmod(0o750)
    with pytest.raises(RuntimeError, match="root-owned mode 0700"):
        cli._private_auth_directory(config)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode contract")
def test_auth_master_key_is_exactly_32_bytes_and_mode_0600(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original_fstat = os.fstat

    def root_fstat(descriptor: int) -> SimpleNamespace:
        metadata = original_fstat(descriptor)
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_uid=0,
            st_nlink=metadata.st_nlink,
            st_size=metadata.st_size,
        )

    monkeypatch.setattr(cli.os, "fstat", root_fstat)
    first = cli._auth_master_key(tmp_path)
    second = cli._auth_master_key(tmp_path)
    key_path = tmp_path / "master.key"

    assert first == second
    assert len(first) == 32
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    os.link(key_path, tmp_path / "master-key-hard-link")
    with pytest.raises(RuntimeError, match="one link"):
        cli._auth_master_key(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory durability contract")
def test_new_auth_master_key_fsyncs_file_and_parent_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original_fstat = os.fstat
    original_fsync = os.fsync
    fsynced_modes: list[int] = []

    def root_fstat(descriptor: int) -> SimpleNamespace:
        metadata = original_fstat(descriptor)
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_uid=0,
            st_nlink=metadata.st_nlink,
            st_size=metadata.st_size,
        )

    def recording_fsync(descriptor: int) -> None:
        fsynced_modes.append(original_fstat(descriptor).st_mode)
        original_fsync(descriptor)

    monkeypatch.setattr(cli.os, "fstat", root_fstat)
    monkeypatch.setattr(cli.os, "fsync", recording_fsync)

    cli._auth_master_key(tmp_path)

    assert any(stat.S_ISREG(mode) for mode in fsynced_modes)
    assert any(stat.S_ISDIR(mode) for mode in fsynced_modes)


def test_helper_systemd_unit_owns_private_auth_state() -> None:
    source = (ROOT / "deploy/systemd/maddyweb-helper.service").read_text(encoding="utf-8")

    assert "User=root" in source
    assert "Group=root" in source
    assert "UMask=0077" in source
    assert "StateDirectory=maddyweb-auth" in source
    assert "StateDirectoryMode=0700" in source
    write_line = next(line for line in source.splitlines() if line.startswith("ReadWritePaths="))
    assert "/var/lib/maddyweb-auth" in write_line.split()
    assert "ProtectSystem=strict" in source
    assert "LimitCORE=0" in source


def test_web_systemd_unit_cannot_impersonate_submission_listener() -> None:
    source = (ROOT / "deploy/systemd/maddyweb.service").read_text(encoding="utf-8")

    assert "LimitCORE=0" in source
    assert "SocketBindAllow=tcp:8787" in source
    assert "SocketBindDeny=any" in source
