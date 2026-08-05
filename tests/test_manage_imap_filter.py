from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/manage-imap-filter.py"
SPEC = importlib.util.spec_from_file_location("manage_imap_filter", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

BASE = """$(hostname) = mail.example.test

storage.imapsql local_mailboxes {
    driver sqlite3
    dsn imapsql.db
}

smtp tcp://0.0.0.0:25 {
}
"""


@pytest.mark.parametrize("mode", ("native", "docker"))
def test_managed_filter_round_trip_is_exact(mode: str) -> None:
    rendered = MODULE.build_managed(BASE, mode)
    MODULE.verify_managed(rendered, mode)
    assert MODULE.remove_managed(rendered, mode) == BASE
    assert rendered.count("{account_name}") == 1
    assert "sh -c" not in rendered


def test_native_filter_uses_python_module_as_separate_arguments() -> None:
    rendered = MODULE.build_managed(BASE, "native")
    assert (
        "command /opt/maddyweb/current/bin/python -I -m "
        "maddyweb.filter_client {account_name}"
    ) in rendered


def test_docker_filter_uses_fixed_busybox_wrapper_path() -> None:
    rendered = MODULE.build_managed(BASE, "docker")
    assert "command /data/maddyweb-filter/maddyweb-filter-client {account_name}" in rendered


def test_editor_rejects_existing_unmanaged_filter() -> None:
    source = BASE.replace(
        "    dsn imapsql.db\n",
        "    dsn imapsql.db\n"
        "    imap_filter {\n"
        "        command /tmp/filter {account_name}\n"
        "    }\n",
    )
    with pytest.raises(MODULE.EditError, match="unmanaged imap_filter"):
        MODULE.build_managed(source, "native")


def test_editor_rejects_modified_managed_command() -> None:
    rendered = MODULE.build_managed(BASE, "native")
    tampered = rendered.replace("maddyweb.filter_client", "maddyweb.other_client")
    with pytest.raises(MODULE.EditError, match="was modified"):
        MODULE.verify_managed(tampered, "native")


def test_editor_preserves_crlf() -> None:
    source = BASE.replace("\n", "\r\n")
    rendered = MODULE.build_managed(source, "docker")
    assert "\r\n" in rendered
    assert rendered.replace("\r\n", "").find("\n") == -1
    assert MODULE.remove_managed(rendered, "docker") == source
