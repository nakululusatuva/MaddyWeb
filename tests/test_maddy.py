from __future__ import annotations

import io
import sys
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from maddyweb.maddy import (
    Capability,
    CapabilityFingerprintError,
    CliFingerprint,
    CommandFailed,
    CommandInputError,
    CommandOutputLimit,
    CommandResult,
    CommandTimeout,
    InvalidMaddyArgument,
    MaddyService,
    MaddyTarget,
    PartialOperationError,
    RuntimeConfigUnsafe,
    SemVer,
    StaleMessageCursor,
    SubprocessRunner,
    UnsupportedCapability,
    UnsupportedVersion,
    VersionParseError,
    capabilities_for,
    parse_message_list,
    require_supported_version,
)


class QueueRunner:
    def __init__(self, outputs: Sequence[tuple[bytes, bytes, int]]) -> None:
        self.outputs = list(outputs)
        self.calls: list[dict[str, Any]] = []

    def run(self, argv: Sequence[str], **kwargs: Any) -> CommandResult:
        self.calls.append({"argv": tuple(argv), **kwargs})
        stdout, stderr, returncode = self.outputs.pop(0)
        sink = kwargs.get("output_sink")
        streamed = 0
        if sink is not None:
            sink.write(stdout)
            streamed = len(stdout)
        return CommandResult(tuple(argv), returncode, stdout, stderr, 0.001, streamed)


class PrevalidatedMaddyService(MaddyService):
    """Keep command-shape unit tests independent from the live safety probe."""

    def require_write_safety(self, capability: Capability) -> SemVer:
        version = self.probe_version()
        if self._output_contract_failure is not None:
            raise CapabilityFingerprintError("runtime output adapter failed")
        if capability not in capabilities_for(version):
            raise UnsupportedCapability
        return version


def service_with(
    runner: QueueRunner,
    *,
    version: str = "0.9.5",
    target: MaddyTarget | None = None,
) -> MaddyService:
    return PrevalidatedMaddyService(
        target or MaddyTarget(mode="native", service_user=None),
        runner=runner,
        version=SemVer.parse(version),
        cli_fingerprint=CliFingerprint("locked", ()),
    )


def full_message_record(uid: int, sequence_number: int, subject: str = "fixture") -> bytes:
    return f"""- Server meta-data:
UID: {uid}
Sequence number: {sequence_number}
Flags: []
Body size: 100
Internal date: 1721600000 2024-07-22 00:00:00 +0000 UTC
- Envelope:
From: sender@example.test
To: user@example.test
Subject: {subject}

""".encode()


def test_semver_and_release_gate() -> None:
    assert SemVer.from_maddy_output(
        "0.8.2 linux/amd64 go1.23.12\ndefault config: /etc/maddy/maddy.conf\n"
    ) == SemVer.parse("0.8.2")
    assert SemVer.from_maddy_output("maddy v0.9.5 linux/amd64 go1.24") == SemVer.parse("0.9.5")
    assert SemVer.parse("0.9.5-rc.1") < SemVer.parse("0.9.5")
    with pytest.raises(UnsupportedVersion):
        require_supported_version(SemVer.parse("0.8.3"))
    with pytest.raises(UnsupportedVersion):
        require_supported_version(SemVer.parse("0.9.5-rc.1"))
    with pytest.raises(UnsupportedVersion):
        require_supported_version(SemVer.parse("0.9.6"))
    with pytest.raises(UnsupportedVersion):
        require_supported_version(SemVer.parse("0.8.2+local"))
    with pytest.raises(UnsupportedVersion):
        require_supported_version(SemVer.parse("0.9.5+vendor.1"))


@pytest.mark.parametrize("installed", ["0.8.1", "0.8.3", "0.9.6"])
def test_unsupported_installed_version_is_diagnostic_but_blocks_business_ops(
    installed: str,
) -> None:
    runner = QueueRunner([(f"{installed} linux/amd64 go1.24\n".encode(), b"", 0)])
    service = MaddyService(
        MaddyTarget(mode="native", service_user=None),
        runner=runner,
    )
    assert service.version_info() == {
        "version": installed,
        "mode": "native",
        "capabilities": [],
        "writes_enabled": False,
        "cli_fingerprint": None,
        "write_block_reason": "UnsupportedVersion",
    }
    with pytest.raises(UnsupportedVersion):
        service.list_credentials()
    assert len(runner.calls) == 1


def test_unparseable_version_output_is_diagnostic_but_blocks_business_ops() -> None:
    runner = QueueRunner([(b"development build\n", b"", 0)])
    service = MaddyService(
        MaddyTarget(mode="native", service_user=None),
        runner=runner,
    )
    assert service.version_info() == {
        "version": "unknown",
        "mode": "native",
        "capabilities": [],
        "writes_enabled": False,
        "cli_fingerprint": None,
        "write_block_reason": "VersionParseError",
    }
    with pytest.raises(VersionParseError, match="valid SemVer"):
        service.list_credentials()
    assert len(runner.calls) == 1


def test_capabilities_are_version_specific() -> None:
    old = capabilities_for(SemVer.parse("0.8.2"))
    assert Capability.TLS_RELOAD in old
    assert Capability.VERIFY_CONFIG not in old
    assert Capability.LDAP_AUTH_SAFE not in old
    current = capabilities_for(SemVer.parse("0.9.5"))
    assert Capability.VERIFY_CONFIG in current
    assert Capability.ZERO_DOWNTIME_RELOAD in current
    assert Capability.LDAP_AUTH_SAFE in current


def test_native_and_docker_argv_are_fixed() -> None:
    native = MaddyTarget(
        mode="native",
        maddy_executable="/usr/bin/maddy",
        config_path="/etc/maddy/maddy.conf",
        service_user="maddy",
    )
    assert native.argv(("creds", "list")) == (
        "/usr/bin/maddy",
        "-config",
        "/etc/maddy/maddy.conf",
        "creds",
        "list",
    )
    config = SimpleNamespace(
        mode="docker",
        container="maddy-1",
        binary=Path("/host/unused"),
        config_path=Path("/host/unused.conf"),
        service_user="maddy",
    )
    docker = MaddyTarget.from_config(config)
    assert docker.argv(("creds", "create", "user@example.test"), has_stdin=True) == (
        "/usr/bin/docker",
        "exec",
        "-i",
        "maddy-1",
        "/bin/maddy",
        "-config",
        "/data/maddy.conf",
        "creds",
        "create",
        "user@example.test",
    )
    assert docker.config_read_argv() == (
        "/usr/bin/docker",
        "exec",
        "maddy-1",
        "/bin/cat",
        "/data/maddy.conf",
    )


def test_zero_exit_app_run_failed_is_still_failure() -> None:
    runner = QueueRunner([(b"", b'app.Run failed {"reason":"missing TLS"}\n', 0)])
    with pytest.raises(CommandFailed, match="application failure"):
        service_with(runner).list_credentials()


def test_empty_lists_and_appendlimit_no_limit_are_normalized() -> None:
    runner = QueueRunner(
        [
            (b"No users.\n", b"", 0),
            (b"No users.\n", b"", 0),
            (b"No limit\n", b"", 0),
        ]
    )
    service = service_with(runner)
    assert service.list_credentials() == []
    assert service.list_imap_accounts() == []
    assert service.get_append_limit("user@example.test") is None


def test_account_list_can_skip_appendlimit_queries_for_health() -> None:
    runner = QueueRunner(
        [
            (b"user@example.test\n", b"", 0),
            (b"user@example.test\n", b"", 0),
        ]
    )
    service = service_with(runner)
    assert service.list_accounts(include_append_limits=False) == [
        {
            "id": "user@example.test",
            "address": "user@example.test",
            "username": "user@example.test",
            "has_credentials": True,
            "has_mailbox": True,
            "append_limit": None,
        }
    ]
    assert len(runner.calls) == 2
    with pytest.raises(InvalidMaddyArgument, match="boolean"):
        service.list_accounts(include_append_limits=1)  # type: ignore[arg-type]
    assert len(runner.calls) == 2


def test_appendlimit_zero_uses_write_then_readback() -> None:
    runner = QueueRunner([(b"", b"", 0), (b"No limit\n", b"", 0)])
    service = service_with(runner)
    assert service.set_append_limit("user@example.test", 0) is None
    assert runner.calls[0]["argv"][-7:] == (
        "imap-acct",
        "appendlimit",
        "--cfg-block",
        "local_mailboxes",
        "--value",
        "0",
        "user@example.test",
    )


def test_password_is_stdin_only_and_verified_by_list() -> None:
    runner = QueueRunner([(b"", b"", 0), (b"user@example.test\n", b"", 0)])
    service_with(runner).change_password("user@example.test", "not-in-argv")
    assert all("not-in-argv" not in item for item in runner.calls[0]["argv"])
    assert runner.calls[0]["input_data"] == b"not-in-argv\n"


def test_account_deletion_is_two_separate_operations() -> None:
    runner = QueueRunner(
        [
            (b"", b"", 0),
            (b"No users.\n", b"", 0),
            (b"", b"", 0),
            (b"No users.\n", b"", 0),
        ]
    )
    service = service_with(runner)
    service.disable_credentials("user@example.test")
    assert runner.calls[0]["argv"][-2:] == ("-y", "user@example.test")
    assert "imap-acct" not in runner.calls[0]["argv"]
    service.delete_imap_account("user@example.test")
    assert "imap-acct" in runner.calls[2]["argv"]


class StatefulAccountService(PrevalidatedMaddyService):
    """Exercise account compensation against observable mutable state."""

    def __init__(
        self,
        *,
        credentials: set[str] | None = None,
        mailboxes: set[str] | None = None,
        create_failure: str,
        credential_remove: str = "success",
        mailbox_remove: str = "success",
    ) -> None:
        super().__init__(
            MaddyTarget(mode="native", service_user=None),
            runner=QueueRunner([]),
            version=SemVer.parse("0.9.5"),
            cli_fingerprint=CliFingerprint("locked", ()),
        )
        self.credentials = set(credentials or ())
        self.mailboxes = set(mailboxes or ())
        self.create_failure = create_failure
        self.credential_remove = credential_remove
        self.mailbox_remove = mailbox_remove
        self.account_calls: list[str] = []

    @staticmethod
    def _result() -> CommandResult:
        return CommandResult((), 0, b"", b"", 0.001)

    @staticmethod
    def _definite_failure() -> CommandFailed:
        return CommandFailed(CommandResult((), 1, b"", b"", 0.001))

    def _credentials(
        self,
        action: str,
        *args: str,
        input_data: bytes | None = None,
        write: bool | None = None,
    ) -> CommandResult:
        del input_data, write
        self.account_calls.append(f"credentials.{action}")
        if action == "list":
            output = "".join(f"{value}\n" for value in sorted(self.credentials)).encode()
            return CommandResult((), 0, output, b"", 0.001)
        username = args[-1]
        if action == "create":
            if self.create_failure == "credentials.definite":
                raise self._definite_failure()
            self.credentials.add(username)
            if self.create_failure == "credentials.timeout":
                raise CommandTimeout("credentials create timed out")
        elif action == "remove":
            if self.credential_remove != "no_effect":
                self.credentials.discard(username)
            if self.credential_remove == "timeout":
                raise CommandTimeout("credentials remove timed out")
        return self._result()

    def _imap_accounts(
        self,
        action: str,
        *args: str,
        write: bool | None = None,
    ) -> CommandResult:
        del write
        self.account_calls.append(f"mailbox.{action}")
        if action == "list":
            output = "".join(f"{value}\n" for value in sorted(self.mailboxes)).encode()
            return CommandResult((), 0, output, b"", 0.001)
        username = args[-1]
        if action == "create":
            if self.create_failure == "mailbox.definite":
                raise self._definite_failure()
            self.mailboxes.add(username)
            if self.create_failure == "mailbox.timeout":
                raise CommandTimeout("mailbox create timed out")
        elif action == "remove":
            if self.mailbox_remove != "no_effect":
                self.mailboxes.discard(username)
            if self.mailbox_remove == "timeout":
                raise CommandTimeout("mailbox remove timed out")
        return self._result()


def test_credential_create_timeout_is_compensated_from_readback() -> None:
    service = StatefulAccountService(create_failure="credentials.timeout")

    with pytest.raises(PartialOperationError) as raised:
        service.create_account("user@example.test", "fixture-password")

    assert raised.value.completed == ("credentials.create",)
    assert raised.value.rollback_succeeded is True
    assert isinstance(raised.value.__cause__, CommandTimeout)
    assert service.credentials == set()
    assert service.mailboxes == set()


def test_mailbox_create_timeout_rolls_back_both_observed_resources() -> None:
    service = StatefulAccountService(create_failure="mailbox.timeout")

    with pytest.raises(PartialOperationError) as raised:
        service.create_account("user@example.test", "fixture-password")

    assert raised.value.completed == ("credentials.create", "mailbox.create")
    assert raised.value.rollback_succeeded is True
    assert service.credentials == set()
    assert service.mailboxes == set()
    assert service.account_calls.index("mailbox.remove") < service.account_calls.index(
        "credentials.remove"
    )


def test_definite_mailbox_failure_rolls_back_new_credentials() -> None:
    service = StatefulAccountService(create_failure="mailbox.definite")

    with pytest.raises(PartialOperationError) as raised:
        service.create_account("user@example.test", "fixture-password")

    assert raised.value.completed == ("credentials.create",)
    assert raised.value.rollback_succeeded is True
    assert isinstance(raised.value.__cause__, CommandFailed)
    assert service.credentials == set()
    assert service.mailboxes == set()


def test_compensation_preserves_resources_that_existed_in_baseline() -> None:
    username = "user@example.test"
    service = StatefulAccountService(
        credentials={username},
        create_failure="mailbox.timeout",
    )

    with pytest.raises(PartialOperationError) as raised:
        service.create_account(username, "fixture-password")

    assert raised.value.completed == ("mailbox.create",)
    assert raised.value.rollback_succeeded is True
    assert service.credentials == {username}
    assert service.mailboxes == set()
    assert "credentials.remove" not in service.account_calls


def test_compensation_preserves_mailbox_that_existed_in_baseline() -> None:
    username = "user@example.test"
    service = StatefulAccountService(
        mailboxes={username},
        create_failure="mailbox.timeout",
    )

    with pytest.raises(PartialOperationError) as raised:
        service.create_account(username, "fixture-password")

    assert raised.value.completed == ("credentials.create",)
    assert raised.value.rollback_succeeded is True
    assert service.credentials == set()
    assert service.mailboxes == {username}
    assert "mailbox.remove" not in service.account_calls


def test_cleanup_timeout_after_effect_is_accepted_only_after_verification() -> None:
    service = StatefulAccountService(
        create_failure="credentials.timeout",
        credential_remove="timeout",
    )

    with pytest.raises(PartialOperationError) as raised:
        service.create_account("user@example.test", "fixture-password")

    assert raised.value.rollback_succeeded is True
    assert service.credentials == set()


def test_cleanup_readback_distinguishes_unverified_rollback() -> None:
    service = StatefulAccountService(
        create_failure="credentials.timeout",
        credential_remove="no_effect",
    )

    with pytest.raises(PartialOperationError, match="rollback could not be verified") as raised:
        service.create_account("user@example.test", "fixture-password")

    assert raised.value.completed == ("credentials.create",)
    assert raised.value.rollback_succeeded is False
    assert service.credentials == {"user@example.test"}


def test_definite_first_stage_failure_with_verified_clean_state_is_preserved() -> None:
    service = StatefulAccountService(create_failure="credentials.definite")

    with pytest.raises(CommandFailed):
        service.create_account("user@example.test", "fixture-password")

    # Both resources are read before the operation and again during recovery
    # and final verification, even though the failing command made no change.
    assert service.account_calls.count("credentials.list") >= 3
    assert service.account_calls.count("mailbox.list") >= 3
    assert service.credentials == set()
    assert service.mailboxes == set()


def test_mailbox_list_is_structured() -> None:
    runner = QueueRunner([(b"INBOX\nSent\t[\\Sent]\n", b"", 0)])
    assert service_with(runner).list_mailboxes("user@example.test") == [
        {"name": "INBOX", "attributes": []},
        {"name": "Sent", "attributes": ["\\Sent"]},
    ]


def test_special_mailbox_resolution_uses_server_attributes_and_custom_names() -> None:
    runner = QueueRunner([(b"Archive/Sent\t[\\Sent]\nDeleted Items\t[\\Trash]\n", b"", 0)])
    assert service_with(runner).resolve_special_mailbox("user@example.test", "trash") == (
        "Deleted Items"
    )


def test_single_message_mutations_reject_uid_sets_before_invocation() -> None:
    runner = QueueRunner([])
    service = service_with(runner)
    with pytest.raises(InvalidMaddyArgument, match="single IMAP UID"):
        service.delete_message("user@example.test", "INBOX", "1:*")
    with pytest.raises(InvalidMaddyArgument, match="single IMAP UID"):
        service.move_message("user@example.test", "INBOX", "1,2", "Trash")
    assert runner.calls == []


@pytest.mark.parametrize("uid", ("9" * 5000, "\u0661", "4294967296"))
def test_single_message_mutations_reject_unbounded_or_non_ascii_uids(uid: str) -> None:
    runner = QueueRunner([])
    service = service_with(runner)
    with pytest.raises(InvalidMaddyArgument, match="single IMAP UID"):
        service.delete_message("user@example.test", "INBOX", uid)
    assert runner.calls == []


def test_full_message_list_parser_matches_real_082_shape() -> None:
    output = """- Server meta-data:
UID: 1
Sequence number: 1
Flags: [\\Recent \\Seen]
Body size: 218
Internal date: 1721600000 2024-07-22 00:00:00 +0000 UTC
- Envelope:
From: Sender <sender@example.test>
To: User <user@example.test>
Message-Id: <fixture@example.test>
Date: 0 1970-01-01 00:00:00 +0000 UTC
Subject: fixture subject

"""
    assert parse_message_list(output) == [
        {
            "uid": 1,
            "sequence_number": 1,
            "flags": ["\\Recent", "\\Seen"],
            "body_size": 218,
            "internal_date_unix": 1721600000,
            "internal_date": "2024-07-22 00:00:00 +0000 UTC",
            "from": "Sender <sender@example.test>",
            "to": "User <user@example.test>",
            "message_id": "<fixture@example.test>",
            "date_unix": 0,
            "date": "1970-01-01 00:00:00 +0000 UTC",
            "subject": "fixture subject",
        }
    ]


@pytest.mark.parametrize(
    "output",
    (
        b"unexpected compact output\n",
        b"- Server meta-data:\nUID: 1\n",
        b"\xff\xfe",
    ),
)
def test_message_parser_fails_closed_on_unrecognized_output(output: bytes) -> None:
    with pytest.raises(CapabilityFingerprintError):
        parse_message_list(output)


@pytest.mark.parametrize(
    "output",
    (
        "UID " + "9" * 5000 + ": sender@example.test - subject",
        "UID 4294967296: sender@example.test - subject",
        "- Server meta-data:\nUID: 1\nSequence number: nope\n- Envelope:\nSubject: x\n",
        "\ud800",
    ),
)
def test_message_parser_rejects_oversized_or_invalid_scalars(output: str) -> None:
    with pytest.raises(CapabilityFingerprintError):
        parse_message_list(output)


def test_runtime_output_mismatch_disables_later_writes() -> None:
    service = service_with(QueueRunner([(b"unexpected output\n", b"", 0)]))
    with pytest.raises(CapabilityFingerprintError):
        service.list_messages("user@example.test", "INBOX", full=False)
    with pytest.raises(CapabilityFingerprintError, match="runtime output"):
        service.require_write_safety(Capability.MESSAGE_ADMIN)


def test_message_window_uses_stable_uid_anchor_and_bounded_sequence_range() -> None:
    runner = QueueRunner(
        [
            (full_message_record(10, 10), b"", 0),
            (
                b"".join(
                    [
                        full_message_record(8, 8, "eight"),
                        full_message_record(10, 10, "ten"),
                        full_message_record(9, 9, "nine"),
                    ]
                ),
                b"",
                0,
            ),
        ]
    )

    records = service_with(runner).list_message_window(
        "user@example.test",
        "INBOX",
        limit=2,
        cursor_uid=0,
    )

    assert [record["uid"] for record in records] == [10, 9, 8]
    assert runner.calls[0]["argv"][-3:] == ("user@example.test", "INBOX", "*")
    assert "--uid" in runner.calls[0]["argv"]
    assert runner.calls[1]["argv"][-3:] == ("user@example.test", "INBOX", "8:10")
    assert "--uid" not in runner.calls[1]["argv"]
    assert "1:*" not in runner.calls[0]["argv"]
    assert "1:*" not in runner.calls[1]["argv"]


def test_message_window_rejects_cursor_race_instead_of_skipping() -> None:
    runner = QueueRunner(
        [
            (full_message_record(10, 10), b"", 0),
            (full_message_record(10, 9), b"", 0),
        ]
    )

    with pytest.raises(StaleMessageCursor, match="mailbox changed"):
        service_with(runner).list_message_window(
            "user@example.test",
            "INBOX",
            limit=2,
            cursor_uid=10,
        )


def test_empty_mailbox_window_needs_only_the_newest_uid_probe() -> None:
    runner = QueueRunner([(b"", b"", 0)])

    assert (
        service_with(runner).list_message_window(
            "user@example.test",
            "INBOX",
            limit=50,
        )
        == []
    )
    assert len(runner.calls) == 1


class HelpRunner:
    def __init__(
        self,
        *,
        extra_option: bool = False,
        verify_config: bool = False,
        version: str = "0.9.5",
        config_text: str | None = None,
    ) -> None:
        self.extra_option = extra_option
        self.verify_config = verify_config
        self.version = version
        self.config_text = config_text
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], **_kwargs: Any) -> CommandResult:
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[-2:] == ("/bin/cat", "/data/maddy.conf"):
            assert self.config_text is not None
            return CommandResult(argv, 0, self.config_text.encode(), b"", 0.001)
        suffix = argv[argv.index("-config") + 2 :] if "-config" in argv else argv[1:]
        if suffix == ("version",):
            text = f"{self.version} linux/amd64 go1.24\n"
        elif suffix == ("--help",):
            names = [*MaddyService._ADMIN_GROUP_ACTIONS, "run"]
            if self.verify_config:
                names.append("verify-config")
            text = "COMMANDS:\n" + "".join(f"   {name}   description\n" for name in names)
            text += "\nOPTIONS:\n   --help\n"
        elif len(suffix) == 2 and suffix[1] == "--help":
            actions = MaddyService._ADMIN_GROUP_ACTIONS[suffix[0]]
            text = "COMMANDS:\n" + "".join(f"   {name}   description\n" for name in sorted(actions))
            text += "\nOPTIONS:\n   --help\n"
        else:
            key = (suffix[0], suffix[1])
            usage, options = MaddyService._ACTION_PROFILE[key]
            if self.extra_option and key == ("creds", "create"):
                options = frozenset({*options, "surprise"})
            text = f"USAGE:\n   maddy {' '.join(key)} {usage}\n\nOPTIONS:\n"
            text += "".join(f"   --{name} value\n" for name in sorted(options))
            text += "   --help\n"
        return CommandResult(argv, 0, text.encode(), b"", 0.001)


def test_exact_help_profile_enables_safe_082_writes(tmp_path: Path) -> None:
    config = tmp_path / "maddy.conf"
    config.write_text("auth.pass_table local_authdb {}\n", encoding="utf-8")
    runner = HelpRunner(version="0.8.2")
    service = MaddyService(
        MaddyTarget(
            mode="native",
            maddy_executable="/usr/bin/maddy",
            config_path=str(config),
            service_user=None,
        ),
        runner=runner,
        version=SemVer.parse("0.8.2"),
    )
    status = service.startup_safety_status()
    assert status["writes_enabled"] is True
    assert len(status["cli_fingerprint"]) == 64
    assert not any("verify-config" in call for call in runner.calls)


def test_extra_help_option_disables_writes() -> None:
    service = MaddyService(
        MaddyTarget(mode="native", config_path="/unused", service_user=None),
        runner=HelpRunner(extra_option=True, verify_config=True),
        version=SemVer.parse("0.9.5"),
    )
    with pytest.raises(CapabilityFingerprintError, match="option set"):
        service.probe_cli_fingerprint()
    assert service.startup_safety_status()["writes_enabled"] is False


@pytest.mark.parametrize(
    "declaration",
    (
        "auth.ldap local_authdb {\n}\n",
        '"auth.ldap" local_authdb {\n}\n',
        "table.ldap ldap_users {\n  urls ldap://127.0.0.1\n}\n"
        "auth.pass_table local_authdb {\n  table &ldap_users\n}\n",
        "imap tcp://127.0.0.1:143 {\n  auth ldap\n}\n",
        'imap tcp://127.0.0.1:143 {\n  "auth" "ldap"\n}\n',
        "auth.plain_separate local_authdb {\n  pass ldap {}\n}\n",
        "auth.plain_separate local_authdb {\n  user ldap {}\n}\n",
        "$(part) = ld\n$(backend) = $(part)ap\n"
        "auth.plain_separate local_authdb {\n  pass $(backend) {}\n}\n",
        "$(backend) = ldap\ntable.chain chain {\n  optional_step $(backend) {}\n}\n",
        "$(p@) = ld\n$(b@) = $(p@)ap\nauth.plain_separate local_authdb {\n  pass $(b@) {}\n}\n",
        "$(9) = ld\n$(backend) = $(9)ap\n"
        "auth.plain_separate local_authdb {\n  pass $(backend) {}\n}\n",
    ),
)
def test_legacy_ldap_config_disables_writes(tmp_path: Path, declaration: str) -> None:
    config = tmp_path / "maddy.conf"
    config.write_text(declaration, encoding="utf-8")
    service = MaddyService(
        MaddyTarget(mode="native", config_path=str(config), service_user=None),
        runner=HelpRunner(version="0.8.2"),
        version=SemVer.parse("0.8.2"),
    )
    status = service.startup_safety_status()
    assert status == {
        "version": "0.8.2",
        "writes_enabled": False,
        "reason": "LegacyLDAPUnsafe",
    }


def test_legacy_config_import_disables_writes_even_if_ldap_is_imported(tmp_path: Path) -> None:
    imported = tmp_path / "ldap.conf"
    imported.write_text("auth.ldap local_authdb {\n}\n", encoding="utf-8")
    config = tmp_path / "maddy.conf"
    config.write_text('"import" ldap.conf\n', encoding="utf-8")
    service = MaddyService(
        MaddyTarget(mode="native", config_path=str(config), service_user=None),
        runner=HelpRunner(version="0.9.2", verify_config=True),
        version=SemVer.parse("0.9.2"),
    )

    assert service.startup_safety_status() == {
        "version": "0.9.2",
        "writes_enabled": False,
        "reason": "LegacyLDAPUnsafe",
    }


def test_legacy_config_commented_import_is_not_active(tmp_path: Path) -> None:
    config = tmp_path / "maddy.conf"
    config.write_text("# import ldap.conf\n", encoding="utf-8")
    service = MaddyService(
        MaddyTarget(mode="native", config_path=str(config), service_user=None),
        runner=HelpRunner(version="0.9.2", verify_config=True),
        version=SemVer.parse("0.9.2"),
    )

    assert service.startup_safety_status()["writes_enabled"] is True


@pytest.mark.parametrize(
    "contents",
    ("auth {env:BACKEND} {\n}\n", 'auth "{env:BACKEND}" {\n}\n'),
)
def test_legacy_dynamic_auth_backend_is_read_only(tmp_path: Path, contents: str) -> None:
    config = tmp_path / "maddy.conf"
    config.write_text(contents, encoding="utf-8")
    service = MaddyService(
        MaddyTarget(mode="native", config_path=str(config), service_user=None),
        runner=HelpRunner(version="0.8.2"),
    )
    assert service.startup_safety_status()["reason"] == "LegacyLDAPUnsafe"


def _legacy_docker_service(config_text: str) -> MaddyService:
    return MaddyService(
        MaddyTarget(
            mode="docker",
            maddy_executable="/bin/maddy",
            config_path="/data/maddy.conf",
            container="maddy-test",
            service_user=None,
        ),
        runner=HelpRunner(version="0.8.2", config_text=config_text),
        version=SemVer.parse("0.8.2"),
    )


def test_legacy_official_docker_identity_env_assignments_allow_writes() -> None:
    config_text = """$(hostname) = {env:MADDY_HOSTNAME}
$(primary_domain) = {env:MADDY_DOMAIN}
auth.pass_table local_authdb {}
"""

    assert _legacy_docker_service(config_text).startup_safety_status()["writes_enabled"] is True


def test_legacy_docker_dynamic_auth_backend_is_read_only() -> None:
    service = _legacy_docker_service(
        """$(hostname) = {env:MADDY_HOSTNAME}
auth {env:BACKEND} {}
"""
    )

    assert service.startup_safety_status()["reason"] == "LegacyLDAPUnsafe"


@pytest.mark.parametrize(
    "auth_config",
    (
        "auth $(hostname) {}\n",
        "auth.pass_table $(primary_domain) {}\n",
        "$(backend) = $(hostname)\nauth $(backend) {}\n",
        "auth.plain_separate local_authdb {\n  pass $(hostname) {}\n}\n",
        "auth.plain_separate local_authdb {\n  user $(primary_domain) {}\n}\n",
        "auth.plain_separate local_authdb {\n  table $(hostname) {}\n}\n",
        "auth.plain_separate local_authdb {\n  auth_map $(primary_domain) {}\n}\n",
        "$(hostname) local_authdb {}\n",
        "$(backend) = $(hostname)\n$(backend) local_authdb {}\n",
    ),
)
def test_legacy_docker_identity_env_macros_cannot_select_auth(auth_config: str) -> None:
    service = _legacy_docker_service(
        """$(hostname) = {env:MADDY_HOSTNAME}
$(primary_domain) = {env:MADDY_DOMAIN}
"""
        + auth_config
    )

    assert service.startup_safety_status()["reason"] == "LegacyLDAPUnsafe"


def test_legacy_docker_identity_env_macros_remain_available_outside_auth() -> None:
    service = _legacy_docker_service(
        """$(hostname) = {env:MADDY_HOSTNAME}
$(primary_domain) = {env:MADDY_DOMAIN}
$(local_domains) = $(primary_domain)
hostname $(hostname)
tls file /etc/maddy/certs/$(hostname)/fullchain.pem /etc/maddy/certs/$(hostname)/privkey.pem
table.chain local_rewrites {
  optional_step regexp "(.+)\\+(.+)@(.+)" "$1@$3"
  optional_step static {
    entry postmaster postmaster@$(primary_domain)
  }
}
smtp tcp://127.0.0.1:25 {
  source $(local_domains) {
    destination postmaster $(primary_domain) {}
    dkim $(primary_domain) $(local_domains) default
  }
  auth &local_authdb
}
target.queue remote_queue {
  autogenerated_msg_domain $(primary_domain)
}
"""
    )

    assert service.startup_safety_status()["writes_enabled"] is True


def test_current_native_official_static_macro_contexts_allow_writes(tmp_path: Path) -> None:
    config = tmp_path / "maddy.conf"
    config.write_text(
        """$(hostname) = mx.example.test
$(primary_domain) = example.test
$(local_domains) = $(primary_domain)
hostname $(hostname)
tls file /etc/maddy/certs/$(hostname)/fullchain.pem /etc/maddy/certs/$(hostname)/privkey.pem
smtp tcp://127.0.0.1:25 {
  source $(local_domains) {
    destination postmaster $(primary_domain) {}
  }
}
""",
        encoding="utf-8",
    )
    service = MaddyService(
        MaddyTarget(mode="native", config_path=str(config), service_user=None),
        runner=HelpRunner(version="0.9.5", verify_config=True),
    )

    assert service.startup_safety_status()["writes_enabled"] is True


@pytest.mark.parametrize(
    "contents",
    (
        '"$(hostname)" = {env:MADDY_HOSTNAME}\n',
        '$(hostname) = "{env:MADDY_HOSTNAME}"\n',
        "$(hostname) = {env:MADDY_HOSTNAME} # trailing comment\n",
        "$(hostname) = {env:MADDY_HOSTNAME} auth.pass_table local_authdb {}\n",
        "imap tcp://127.0.0.1:143 {\n  $(hostname) = {env:MADDY_HOSTNAME}\n}\n",
        "$(hostname) = {env:MADDY_DOMAIN}\n",
        "$(hostname) = {env:MADDY_HOSTNAME}{env:AUTH_BACKEND}\n",
        '$(prefix) = "{env"\n$(backend) = "$(prefix):AUTH_BACKEND}"\nauth $(backend) {}\n',
        '$(left) = "{"\n$(middle) = "env:"\n$(right) = "}"\n'
        '$(backend) = "$(left)$(middle)AUTH_BACKEND$(right)"\n'
        "auth $(backend) {}\n",
        "$(middle) = env:\nhostname {$(middle)MADDY_HOSTNAME}\n",
    ),
)
def test_legacy_docker_env_allowlist_rejects_ambiguous_or_mixed_lines(contents: str) -> None:
    assert _legacy_docker_service(contents).startup_safety_status()["writes_enabled"] is False


@pytest.mark.parametrize(
    "contents",
    (
        "$(hostname) = {env:MADDY_HOSTNAME}\nauth \\\n$(hostname) {}\n",
        "auth \\\nldap local_authdb {}\n",
    ),
)
def test_legacy_line_continuations_are_fail_closed(contents: str) -> None:
    status = _legacy_docker_service(contents).startup_safety_status()

    assert status["writes_enabled"] is False
    assert status["reason"] == "RuntimeConfigUnsafe"


@pytest.mark.parametrize(
    "contents",
    (
        "\ufeffauth.ldap local_authdb {}\n",
        "\ufefftable.ldap ldap_users {}\nauth.pass_table local_authdb { table &ldap_users }\n",
    ),
)
def test_legacy_bom_is_fail_closed(contents: str) -> None:
    status = _legacy_docker_service(contents).startup_safety_status()

    assert status["writes_enabled"] is False
    assert status["reason"] == "RuntimeConfigUnsafe"


def test_current_native_env_or_import_config_is_read_only(tmp_path: Path) -> None:
    for contents in ("hostname {env:HOSTNAME}\n", "import other.conf\n"):
        config = tmp_path / "maddy.conf"
        config.write_text(contents, encoding="utf-8")
        service = MaddyService(
            MaddyTarget(mode="native", config_path=str(config), service_user=None),
            runner=HelpRunner(version="0.9.5", verify_config=True),
        )
        with pytest.raises(RuntimeConfigUnsafe):
            service.require_write_safety(Capability.MESSAGE_ADMIN)


def test_every_write_safety_gate_refreshes_version_and_help_profile(tmp_path: Path) -> None:
    config = tmp_path / "maddy.conf"
    config.write_text("auth.pass_table local_authdb {}\n", encoding="utf-8")
    runner = HelpRunner(verify_config=True)
    service = MaddyService(
        MaddyTarget(mode="native", config_path=str(config), service_user=None),
        runner=runner,
    )
    service.require_write_safety(Capability.MESSAGE_ADMIN)
    service.require_write_safety(Capability.MESSAGE_ADMIN)
    assert sum(call[-1] == "version" for call in runner.calls) == 2
    top_level_help = [
        call
        for call in runner.calls
        if call[-1] == "--help" and "-config" in call and call[-2] != "version"
    ]
    assert len(top_level_help) >= 2


def test_write_gate_blocks_a_version_changed_after_startup(tmp_path: Path) -> None:
    config = tmp_path / "maddy.conf"
    config.write_text("auth.pass_table local_authdb {}\n", encoding="utf-8")
    runner = HelpRunner(verify_config=True)
    service = MaddyService(
        MaddyTarget(mode="native", config_path=str(config), service_user=None),
        runner=runner,
    )
    service.require_write_safety(Capability.ACCOUNT_ADMIN)
    runner.version = "0.9.6"
    with pytest.raises(UnsupportedVersion):
        service.require_write_safety(Capability.ACCOUNT_ADMIN)


def test_082_verify_config_is_rejected_without_invoking_unknown_command() -> None:
    runner = QueueRunner([])
    service = service_with(runner, version="0.8.2")
    with pytest.raises(UnsupportedCapability):
        service.verify_config()
    assert runner.calls == []


def test_subprocess_runner_streams_exact_input_and_caps_deadline() -> None:
    runner = SubprocessRunner(audit=lambda *_args, **_kwargs: None)
    source = io.BytesIO(b"streamed input")
    result = runner.run(
        [sys.executable, "-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"],
        input_stream=source,
        input_length=14,
        timeout=5,
    )
    assert result.stdout == b"streamed input"
    with pytest.raises(CommandInputError):
        runner.run(
            [sys.executable, "-c", "import sys;sys.stdin.buffer.read()"],
            input_stream=io.BytesIO(b"short"),
            input_length=10,
            timeout=5,
        )
    with pytest.raises(CommandTimeout):
        runner.run(
            [sys.executable, "-c", "import time;time.sleep(2)"],
            timeout=0.05,
        )
    with pytest.raises(CommandOutputLimit):
        runner.run(
            [sys.executable, "-c", "import sys;sys.stdout.write('x'*1024)"],
            max_output_bytes=16,
            timeout=5,
        )
