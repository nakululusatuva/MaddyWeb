from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check-english-policy.py"
NON_ASCII_MARK = chr(0x2603)


def git(repository: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - test arguments are passed without a shell
        ["git", *args],  # noqa: S607 - Git is a required test dependency
        cwd=repository,
        check=True,
        text=True,
        capture_output=True,
    )


def initialize(repository: Path) -> None:
    git(repository, "init", "--quiet", "--initial-branch=main")
    git(repository, "config", "user.name", "Policy Test")
    git(repository, "config", "user.email", "policy@example.test")


def commit_file(repository: Path, content: str, message: str = "test: English change") -> None:
    (repository / "sample.py").write_text(content, encoding="utf-8")
    git(repository, "add", "sample.py")
    git(repository, "commit", "--quiet", "-m", message)


def run_checker(repository: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - the checked interpreter is trusted
        [sys.executable, str(CHECKER), "--repository", str(repository), "--ref", "HEAD"],
        check=False,
        text=True,
        capture_output=True,
    )


def test_accepts_english_history(tmp_path: Path) -> None:
    initialize(tmp_path)
    commit_file(tmp_path, 'MESSAGE = "English only"\n')

    result = run_checker(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "English policy passed" in result.stdout


def test_rejects_non_ascii_content_in_earlier_snapshot(tmp_path: Path) -> None:
    initialize(tmp_path)
    commit_file(tmp_path, f'MESSAGE = "{NON_ASCII_MARK}"\n')
    commit_file(tmp_path, 'MESSAGE = "English now"\n', "fix: translate current file")

    result = run_checker(tmp_path)

    assert result.returncode == 1
    assert "Non-ASCII text" in result.stderr


def test_rejects_non_ascii_commit_message(tmp_path: Path) -> None:
    initialize(tmp_path)
    commit_file(tmp_path, 'MESSAGE = "English"\n', f"test: {NON_ASCII_MARK}")

    result = run_checker(tmp_path)

    assert result.returncode == 1
    assert "Non-ASCII commit message" in result.stderr


def test_rejects_non_ascii_path(tmp_path: Path) -> None:
    initialize(tmp_path)
    path = tmp_path / f"{NON_ASCII_MARK}.py"
    path.write_text('MESSAGE = "English"\n', encoding="utf-8")
    git(tmp_path, "add", "--all")
    git(tmp_path, "commit", "--quiet", "-m", "test: add file")

    result = run_checker(tmp_path)

    assert result.returncode == 1
    assert "Non-ASCII tracked path" in result.stderr
