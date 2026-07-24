from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_host_network_success_harness_covers_the_runtime_boundary() -> None:
    harness = (
        ROOT / "tests/integration/test-host-network-submission.sh"
    ).read_text(encoding="ascii")
    runtime = (
        ROOT / "tests/integration/host_network_submission_case.py"
    ).read_text(encoding="ascii")

    for token in (
        "--network host",
        "--container-config /data/maddy.conf",
        "--container-config /data/not-maddy.conf",
        '"$release/preflight.sh"',
        '"$release/configure-submission.sh" --action add',
        '"$release/configure-submission.sh" --action remove',
        "assert_exact_submission_listener",
        "assert_submission_listener_absent",
        "assert_public_listeners_unchanged",
        "maddy-image-lock.json",
    ):
        assert token in harness

    assert 'docker_submission_scope="host-loopback"' in runtime
    assert "SMTPSubmissionClient" in runtime
    assert "SMTPRejected" in runtime
    assert "recipients=(username,)" in runtime
    assert "service.dump_message" in runtime
    assert "service.delete_account" in runtime

    workflow = (
        ROOT / ".github/workflows/wsl-maddy-matrix.yml"
    ).read_text(encoding="ascii")
    assert "Run host-network Submission integration" in workflow
    assert "test-host-network-submission.sh" in workflow
    assert "--user root --exec bash" in workflow


def test_host_network_fixture_rebinds_only_the_legacy_source_endpoint() -> None:
    source = (
        ROOT / "tests/integration/fixtures/maddy-host-network.conf"
    ).read_text(encoding="ascii")
    entrypoint = (
        ROOT / "tests/integration/fixtures/maddy-host-network-entrypoint.sh"
    ).read_text(encoding="ascii")

    assert source.count("submission tls://0.0.0.0:465 tcp://0.0.0.0:587 {") == 1
    assert "submission tcp://127.0.0.1:1587 {" not in source
    assert "deliver_to &local_mailboxes" in source
    assert "source_header='submission tls://0.0.0.0:465 tcp://0.0.0.0:587 {'" in entrypoint
    assert 'runtime_header="submission tcp://127.0.0.1:' in entrypoint
    assert "/data/maddy.conf >" in entrypoint
    assert "exec /bin/maddy -config /data/runtime.conf run" in entrypoint
