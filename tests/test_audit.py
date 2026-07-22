import json
import logging

from maddyweb.audit import record


def test_audit_recursively_redacts_sensitive_values(caplog) -> None:
    caplog.set_level(logging.INFO, logger="maddyweb.audit")
    record(
        "account.change",
        outcome="ok",
        fields={
            "username": "alice@example.test",
            "nested": {"private_key": "never-log", "password_hash": "never-log"},
            "raw_body": b"never-log",
        },
    )
    payload = json.loads(caplog.records[-1].message)
    encoded = json.dumps(payload)
    assert "alice@example.test" in encoded
    assert "never-log" not in encoded
    assert payload["fields"]["nested"]["private_key"] == "[REDACTED]"
