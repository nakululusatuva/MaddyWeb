from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import maddyweb.rule_snapshots as snapshot_module
from maddyweb.rule_snapshots import (
    MAX_SNAPSHOT_BYTES,
    RuleSnapshotError,
    build_snapshot,
    load_snapshot,
    publish_snapshot,
    remove_snapshot,
    replace_snapshot_set,
    snapshot_name,
)


def _directory(tmp_path: Path) -> Path:
    directory = tmp_path / "snapshots"
    directory.mkdir(mode=0o750)
    if os.name == "posix":
        directory.chmod(0o750)
    return directory


def test_snapshot_path_hides_account_and_round_trips(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    account = "private@example.test"
    rules = [
        {
            "rule_id": "a" * 32,
            "enabled": True,
            "position": 0,
            "match": {"field": "subject", "test": "contains", "value": "invoice"},
            "target_mailbox": "Finance",
            "stop_processing": True,
        }
    ]

    path = publish_snapshot(directory, account, rules)
    assert account not in path.name
    assert path.name == snapshot_name(account)
    assert load_snapshot(directory, account) == {
        "version": 1,
        "account": account,
        "rules": rules,
    }
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o640

    remove_snapshot(directory, account)
    assert load_snapshot(directory, account) is None


def test_snapshot_replace_is_exact_and_deterministic(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    account = "user@example.test"
    first = [{"b": 2, "a": 1}]
    second = [{"enabled": False}]
    path = publish_snapshot(directory, account, first)
    assert path.read_bytes() == build_snapshot(account, first)
    inode = path.stat().st_ino

    replaced = publish_snapshot(directory, account, second)
    assert replaced.read_bytes() == build_snapshot(account, second)
    if os.name == "posix":
        assert replaced.stat().st_ino != inode


def test_snapshot_set_replacement_purges_stale_accounts_before_republish(
    tmp_path: Path,
) -> None:
    directory = _directory(tmp_path)
    stale = "stale@example.test"
    current = "current@example.test"
    publish_snapshot(directory, stale, [{"enabled": True}])

    replace_snapshot_set(directory, {current: [{"enabled": False}]})

    assert load_snapshot(directory, stale) is None
    assert load_snapshot(directory, current) == {
        "version": 1,
        "account": current,
        "rules": [{"enabled": False}],
    }


def test_snapshot_set_replacement_rejects_unexpected_entries(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    account = "user@example.test"
    publish_snapshot(directory, account, [{"enabled": True}])
    unexpected = directory / "unexpected"
    unexpected.write_text("not a snapshot", encoding="ascii")
    if os.name == "posix":
        unexpected.chmod(0o640)

    with pytest.raises(RuleSnapshotError, match="unexpected"):
        replace_snapshot_set(directory, {})
    assert load_snapshot(directory, account) is None
    assert unexpected.exists()


def test_snapshot_set_failure_never_preserves_an_older_account_view(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = _directory(tmp_path)
    first_account = "a@example.test"
    second_account = "b@example.test"
    publish_snapshot(directory, first_account, [{"revision": 1}])
    publish_snapshot(directory, second_account, [{"revision": 1}])
    real_publish = snapshot_module.publish_snapshot
    calls = 0

    def fail_second_publish(*args: object, **kwargs: object) -> Path:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated storage failure")
        return real_publish(*args, **kwargs)

    monkeypatch.setattr(snapshot_module, "publish_snapshot", fail_second_publish)
    with pytest.raises(OSError, match="storage failure"):
        replace_snapshot_set(
            directory,
            {
                first_account: [{"revision": 2}],
                second_account: [{"revision": 2}],
            },
        )

    assert load_snapshot(directory, first_account) == {
        "version": 1,
        "account": first_account,
        "rules": [{"revision": 2}],
    }
    assert load_snapshot(directory, second_account) is None


def test_snapshot_set_replacement_cleans_interrupted_temporary_file(
    tmp_path: Path,
) -> None:
    directory = _directory(tmp_path)
    interrupted = directory / ".snapshot-interrupted"
    interrupted.write_bytes(b"partial")
    if os.name == "posix":
        interrupted.chmod(0o640)

    replace_snapshot_set(directory, {})

    assert list(directory.iterdir()) == []


def test_snapshot_rejects_duplicate_keys_and_wrong_account(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    account = "user@example.test"
    path = directory / snapshot_name(account)
    path.write_text(
        '{"version":1,"account":"user@example.test","account":"other@example.test","rules":[]}',
        encoding="utf-8",
    )
    if os.name == "posix":
        path.chmod(0o640)
    with pytest.raises(RuleSnapshotError, match="JSON"):
        load_snapshot(directory, account)

    path.write_text(
        json.dumps({"version": 1, "account": "other@example.test", "rules": []}),
        encoding="utf-8",
    )
    if os.name == "posix":
        path.chmod(0o640)
    with pytest.raises(RuleSnapshotError, match="document"):
        load_snapshot(directory, account)


def test_snapshot_bounds_and_directory_permissions(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    with pytest.raises(ValueError, match="size"):
        build_snapshot("user@example.test", [{"value": "x" * MAX_SNAPSHOT_BYTES}])
    if os.name == "posix":
        directory.chmod(0o777)
        with pytest.raises(RuleSnapshotError, match="permissions"):
            publish_snapshot(directory, "user@example.test", [])
