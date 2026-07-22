from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

if os.name != "posix":
    pytest.skip("atomic Maddy config editing is Linux-only", allow_module_level=True)

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/manage-submission.py"
FIXTURE = ROOT / "tests/integration/fixtures/maddy-default-submission.conf"

SPEC = importlib.util.spec_from_file_location("maddyweb_manage_submission", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
EDITOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EDITOR
SPEC.loader.exec_module(EDITOR)


def default_config() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def run_editor(*args: str, success: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is success, result.stderr
    return result


def test_add_remove_is_byte_for_byte_roundtrip_and_bounded() -> None:
    original = default_config()
    managed = EDITOR.build_managed(original)
    assert managed.count(EDITOR.BEGIN_MARKER) == 1
    assert managed.count("submission tcp://127.0.0.1:1587 {") == 1
    assert managed.count("all concurrency 2") == 1
    assert "tls off" in managed
    assert managed.count("auth &local_authdb") == 2
    assert "auth dummy" not in managed
    assert EDITOR.remove_managed(managed) == original


def test_crlf_is_preserved_and_roundtrips() -> None:
    original = default_config().replace("\n", "\r\n")
    managed = EDITOR.build_managed(original)
    assert "\r\n" in managed
    assert "\n" not in managed.replace("\r\n", "")
    assert EDITOR.remove_managed(managed) == original


@pytest.mark.parametrize(
    "mutator",
    (
        lambda value: value + "\n# BEGIN MADDYWEB MANAGED SUBMISSION v1\n",
        lambda value: value.replace("tcp://0.0.0.0:587", "tcp://0.0.0.0:587 tcp://127.0.0.1:1587"),
        lambda value: value.replace("deliver_to &remote_queue", "deliver_to &unknown_queue"),
        lambda value: value.replace("auth &local_authdb", "auth &another_authdb"),
        lambda value: value.replace("all rate 50 1s", "all rate 50 1s\n        all concurrency 9"),
    ),
)
def test_add_rejects_duplicate_marker_occupied_port_and_unknown_layout(mutator) -> None:
    with pytest.raises(EDITOR.EditError):
        EDITOR.build_managed(mutator(default_config()))


def test_remove_rejects_modified_marker() -> None:
    managed = EDITOR.build_managed(default_config())
    damaged = managed.replace("all concurrency 2", "all concurrency 3")
    with pytest.raises(EDITOR.EditError):
        EDITOR.remove_managed(damaged)


def test_remove_rejects_dummy_auth_downgrade() -> None:
    managed = EDITOR.build_managed(default_config())
    begin = managed.index(EDITOR.BEGIN_MARKER)
    damaged = managed[:begin] + managed[begin:].replace(
        "auth &local_authdb",
        "auth dummy",
        1,
    )
    with pytest.raises(EDITOR.EditError):
        EDITOR.remove_managed(damaged)


def test_cli_add_remove_preserves_mode_and_creates_private_backups(tmp_path: Path) -> None:
    config = tmp_path / "maddy.conf"
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(mode=0o700)
    original = FIXTURE.read_bytes()
    config.write_bytes(original)
    config.chmod(0o640)

    added = run_editor(
        "--action",
        "add",
        "--config",
        str(config),
        "--backup-dir",
        str(backup_dir),
    )
    added_report = json.loads(added.stdout)
    first_backup = Path(added_report["backup"])
    assert first_backup.read_bytes() == original
    assert stat.S_IMODE(first_backup.stat().st_mode) == 0o600
    assert stat.S_IMODE(config.stat().st_mode) == 0o640

    run_editor(
        "--action",
        "remove",
        "--config",
        str(config),
        "--backup-dir",
        str(backup_dir),
    )
    assert config.read_bytes() == original
    assert stat.S_IMODE(config.stat().st_mode) == 0o640


def test_backup_write_all_handles_short_writes_and_reads_back_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "maddy.conf"
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(mode=0o700)
    original = FIXTURE.read_bytes()
    config.write_bytes(original)
    real_write = EDITOR.write_backup_chunk
    writes = 0

    def short_write(descriptor: int, data) -> int:
        nonlocal writes
        writes += 1
        chunk = data[: max(1, len(data) // 3)]
        return real_write(descriptor, chunk)

    monkeypatch.setattr(EDITOR, "write_backup_chunk", short_write)
    with EDITOR.locked_snapshot(config) as snapshot:
        backup = EDITOR.create_backup(snapshot, backup_dir)
    assert writes > 1
    assert backup.read_bytes() == FIXTURE.read_bytes()
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600


def test_backup_disk_full_removes_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "maddy.conf"
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(mode=0o700)
    original = FIXTURE.read_bytes()
    config.write_bytes(original)
    real_write = EDITOR.write_backup_chunk
    calls = 0

    def disk_full(descriptor: int, data) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, data[:32])
        raise OSError(28, "simulated disk full")

    monkeypatch.setattr(EDITOR, "write_backup_chunk", disk_full)
    with (
        EDITOR.locked_snapshot(config) as snapshot,
        pytest.raises(OSError, match="simulated disk full"),
    ):
        EDITOR.create_backup(snapshot, backup_dir)
    assert config.read_bytes() == original
    assert list(backup_dir.iterdir()) == []


def test_symlink_hardlink_and_oversize_are_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real.conf"
    real.write_bytes(FIXTURE.read_bytes())
    symlink = tmp_path / "symlink.conf"
    symlink.symlink_to(real)
    run_editor("--action", "check-add", "--config", str(symlink), success=False)

    hardlink = tmp_path / "hardlink.conf"
    os.link(real, hardlink)
    run_editor("--action", "check-add", "--config", str(real), success=False)

    oversized = tmp_path / "oversized.conf"
    with oversized.open("wb") as handle:
        handle.truncate(EDITOR.MAX_CONFIG_BYTES + 1)
    run_editor("--action", "check-add", "--config", str(oversized), success=False)


def test_atomic_replace_detects_same_size_same_mtime_content_change(tmp_path: Path) -> None:
    config = tmp_path / "maddy.conf"
    config.write_bytes(FIXTURE.read_bytes())
    with EDITOR.locked_snapshot(config) as snapshot:
        changed = bytearray(snapshot.data)
        changed[0] = ord("S")
        config.write_bytes(changed)
        os.utime(config, ns=(snapshot.mtime_ns, snapshot.mtime_ns))
        with pytest.raises(EDITOR.EditError):
            EDITOR.atomic_replace(snapshot, EDITOR.build_managed(default_config()).encode())


def test_restore_hash_mismatch_is_rejected_without_change(tmp_path: Path) -> None:
    config = tmp_path / "maddy.conf"
    backup = tmp_path / "backup.conf"
    config.write_bytes(FIXTURE.read_bytes())
    shutil.copyfile(config, backup)
    before = config.read_bytes()
    run_editor(
        "--action",
        "restore",
        "--config",
        str(config),
        "--backup",
        str(backup),
        "--expected-current-sha256",
        "0" * 64,
        success=False,
    )
    assert config.read_bytes() == before
