from __future__ import annotations

from dataclasses import FrozenInstanceError
from email import policy
from email.message import EmailMessage

import pytest

from maddyweb import rules
from maddyweb.rules import (
    AndCondition,
    BooleanCondition,
    BooleanField,
    BooleanOperator,
    NotCondition,
    NumericCondition,
    NumericField,
    NumericOperator,
    OrCondition,
    Rule,
    RuleMessageError,
    RuleValidationError,
    StringCondition,
    StringField,
    StringOperator,
    canonical_rule_json,
    compile_rule,
    compile_rules,
    evaluate_rules,
    parse_rule_message,
)


def _raw_message(*headers: str, body: str = "Message body") -> bytes:
    return ("\r\n".join(headers) + "\r\n\r\n" + body).encode("utf-8")


def _compiled(condition: object, target: str = "Filed") -> tuple[rules.CompiledRule, ...]:
    return compile_rules(({"condition": condition, "target_mailbox": target},))


def _leaf(
    field: str,
    operator: str,
    value: object = None,
    *,
    header: str | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {"field": field, "operator": operator}
    if operator != "exists" or value is not None:
        result["value"] = value
    if header is not None:
        result["header"] = header
    return result


def test_typed_ast_is_immutable_and_compiles() -> None:
    condition = AndCondition(
        (
            StringCondition(StringField.SUBJECT, StringOperator.CONTAINS, "invoice"),
            NotCondition(
                BooleanCondition(
                    BooleanField.HAS_ATTACHMENT,
                    BooleanOperator.EQ,
                    False,
                )
            ),
        )
    )
    rule = Rule(condition, "Receipts")
    compiled = rule.compile()

    assert compiled.target_mailbox == "Receipts"
    with pytest.raises(FrozenInstanceError):
        rule.target_mailbox = "Changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        condition.conditions = ()  # type: ignore[misc]


def test_canonical_json_is_stable_strict_and_round_trips() -> None:
    source = {
        "target_mailbox": "Receipts",
        "condition": {
            "conditions": [
                _leaf("subject", "contains", "CAFÉ"),
                _leaf("header", "exists", header="X-Project"),
            ],
            "op": "and",
        },
    }
    canonical = canonical_rule_json(source)

    assert canonical == (
        '{"condition":{"conditions":[{"field":"subject","operator":"contains",'
        '"value":"CAFÉ"},{"field":"header","header":"x-project",'
        '"operator":"exists"}],"op":"and"},"target_mailbox":"Receipts"}'
    )
    assert Rule.from_json(canonical).canonical_json() == canonical
    assert canonical_rule_json(canonical.encode()) == canonical

    with pytest.raises(RuleValidationError, match="duplicate JSON key"):
        Rule.from_json(
            '{"condition":{"field":"subject","field":"from",'
            '"operator":"exists"},"target_mailbox":"Filed"}'
        )
    with pytest.raises(RuleValidationError, match="unknown rule key"):
        Rule.from_mapping({**source, "command": "anything"})
    with pytest.raises(RuleValidationError, match="unknown rule key"):
        compile_rule(
            {
                "condition": {
                    "field": "subject",
                    "header": None,
                    "operator": "exists",
                },
                "target_mailbox": "Filed",
            }
        )
    with pytest.raises(RuleValidationError, match="valid Unicode"):
        Rule.from_json("\ud800")


def test_nested_boolean_ast_and_first_match_order() -> None:
    first = {
        "condition": {
            "op": "and",
            "conditions": [
                _leaf("subject", "starts_with", "build"),
                {
                    "op": "or",
                    "conditions": [
                        _leaf("from", "ends_with", "@example.test>"),
                        {"op": "not", "condition": _leaf("list_id", "exists")},
                    ],
                },
            ],
        },
        "target_mailbox": "First",
    }
    second = {
        "condition": _leaf("subject", "contains", "build"),
        "target_mailbox": "Second",
    }
    raw = _raw_message(
        "From: Example <sender@example.test>",
        "Subject: Build finished",
    )

    assert evaluate_rules(compile_rules((first, second)), raw) == "First"
    assert evaluate_rules(compile_rules((second, first)), raw) == "Second"


@pytest.mark.parametrize(
    ("operator", "value", "expected"),
    (
        ("equals", "release ready", True),
        ("not_equals", "different", True),
        ("contains", "lease rea", True),
        ("not_contains", "blocked", True),
        ("starts_with", "release", True),
        ("ends_with", "ready", True),
        ("equals", "different", False),
        ("not_equals", "release ready", False),
    ),
)
def test_string_operators_use_unicode_casefold(
    operator: str,
    value: str,
    expected: bool,
) -> None:
    raw = _raw_message("Subject: Release Ready")
    target = evaluate_rules(_compiled(_leaf("subject", operator, value)), raw)
    assert (target == "Filed") is expected


def test_rfc2047_duplicate_headers_and_custom_header_semantics() -> None:
    raw = (
        b"Subject: =?utf-8?b?Q0FGw4k=?=\r\n"
        b"X-Project: Alpha\r\n"
        b"X-Project: Release-42\r\n"
        b"X-Empty:\r\n\r\nbody"
    )

    assert evaluate_rules(_compiled(_leaf("subject", "equals", "café")), raw) == "Filed"
    assert (
        evaluate_rules(
            _compiled(_leaf("header", "contains", "release", header="X-Project")),
            raw,
        )
        == "Filed"
    )
    assert (
        evaluate_rules(
            _compiled(_leaf("header", "not_contains", "alpha", header="X-Project")),
            raw,
        )
        is None
    )
    assert (
        evaluate_rules(_compiled(_leaf("header", "exists", header="X-Empty")), raw)
        == "Filed"
    )


def test_envelope_sender_and_recipients_are_runner_inputs() -> None:
    condition = {
        "op": "and",
        "conditions": [
            _leaf("from", "equals", "bounce@example.test"),
            _leaf("to", "equals", "second@example.test"),
        ],
    }
    raw = _raw_message("From: Visible <visible@example.test>", "To: first@example.test")

    assert (
        evaluate_rules(
            _compiled(condition),
            raw,
            envelope_sender="BOUNCE@example.test",
            envelope_recipient=("first@example.test", "SECOND@example.test"),
        )
        == "Filed"
    )
    assert evaluate_rules(_compiled(condition), raw) is None


@pytest.mark.parametrize("operator", ("eq", "lt", "lte", "gt", "gte"))
def test_numeric_size_operators(operator: str) -> None:
    raw = _raw_message("Subject: Size")
    size = len(raw)
    values = {
        "eq": size,
        "lt": size + 1,
        "lte": size,
        "gt": size - 1,
        "gte": size,
    }
    assert evaluate_rules(_compiled(_leaf("size", operator, values[operator])), raw) == "Filed"


def test_attachment_detection_is_bounded_mime_metadata_only() -> None:
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["To"] = "recipient@example.test"
    message["Subject"] = "Report"
    message.set_content("Body")
    message.add_attachment(
        b"data",
        maintype="application",
        subtype="octet-stream",
        filename="x.bin",
    )
    raw = message.as_bytes(policy=policy.SMTP)

    assert (
        evaluate_rules(_compiled(_leaf("has_attachment", "eq", True)), raw) == "Filed"
    )
    assert (
        evaluate_rules(_compiled(_leaf("has_attachment", "eq", False)), raw) is None
    )

    attached_message = (
        b"Subject: Forwarded message\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=outer\r\n\r\n"
        b"--outer\r\nContent-Type: message/rfc822\r\n\r\n"
        b"From: nested@example.test\r\n\r\nNested body\r\n"
        b"--outer--\r\n"
    )
    assert (
        evaluate_rules(
            _compiled(_leaf("has_attachment", "eq", True)),
            attached_message,
        )
        == "Filed"
    )


def test_missing_values_and_parse_failures_are_fail_closed() -> None:
    raw = _raw_message("From: sender@example.test")
    missing_negative = _compiled(_leaf("subject", "not_contains", "blocked"))
    negated_missing = _compiled(
        {"op": "not", "condition": _leaf("subject", "contains", "blocked")}
    )

    assert evaluate_rules(missing_negative, raw) is None
    assert evaluate_rules(negated_missing, raw) is None
    assert (
        evaluate_rules(_compiled(_leaf("subject", "exists")), raw)
        is None
    )

    invalid_encoded_word = b"Subject: =?unknown-charset?b?QQ==?=\r\n\r\nbody"
    assert evaluate_rules(_compiled(_leaf("subject", "exists")), invalid_encoded_word) is None
    with pytest.raises(RuleMessageError):
        parse_rule_message(invalid_encoded_word)


def test_rule_depth_and_node_count_are_bounded() -> None:
    condition: dict[str, object] = _leaf("subject", "exists")
    for _ in range(rules.MAX_RULE_DEPTH):
        condition = {"op": "not", "condition": condition}
    with pytest.raises(RuleValidationError, match="nesting"):
        compile_rule({"condition": condition, "target_mailbox": "Filed"})

    too_many = [_leaf("subject", "exists") for _ in range(rules.MAX_RULE_NODES)]
    with pytest.raises(RuleValidationError, match="nodes"):
        compile_rule(
            {
                "condition": {"op": "and", "conditions": too_many},
                "target_mailbox": "Filed",
            }
        )


@pytest.mark.parametrize(
    "condition",
    (
        _leaf("subject", "matches", "danger"),
        _leaf("unknown", "equals", "value"),
        _leaf("header", "contains", "value", header="Bad: Header"),
        _leaf("subject", "contains", "line\nbreak"),
        _leaf("has_attachment", "eq", 1),
        _leaf("size", "eq", True),
        {"op": [], "condition": _leaf("subject", "exists")},
        {"field": [], "operator": "exists"},
    ),
)
def test_unsafe_or_untyped_leaves_are_rejected(condition: dict[str, object]) -> None:
    with pytest.raises(RuleValidationError):
        compile_rule({"condition": condition, "target_mailbox": "Filed"})


def test_message_header_and_envelope_limits_fail_closed() -> None:
    oversized_line = b"Subject: " + b"x" * rules.MAX_HEADER_LINE_BYTES + b"\r\n\r\nbody"
    compiled = _compiled(_leaf("subject", "exists"))

    assert evaluate_rules(compiled, oversized_line) is None
    assert (
        evaluate_rules(
            compiled,
            _raw_message("Subject: present"),
            envelope_recipient=("x@example.test",) * (rules.MAX_ENVELOPE_VALUES + 1),
        )
        is None
    )


def test_parsed_message_preserves_all_normalized_header_values() -> None:
    parsed = parse_rule_message(
        _raw_message("Cc: First@example.test", "Cc: SECOND@example.test"),
        envelope_sender="Sender@example.test",
        envelope_recipient="Recipient@example.test",
    )

    assert parsed.header_values("CC") == ("first@example.test", "second@example.test")
    assert parsed.envelope_sender == "sender@example.test"
    assert parsed.envelope_recipients == ("recipient@example.test",)


def test_direct_or_condition_matches_any_present_value() -> None:
    rule = Rule(
        OrCondition(
            (
                NumericCondition(NumericField.SIZE, NumericOperator.GT, 2**20),
                StringCondition(StringField.LIST_ID, StringOperator.EXISTS),
            )
        ),
        "Lists",
    )
    raw = _raw_message("List-Id: Project Updates <updates.example.test>")

    assert evaluate_rules((compile_rule(rule),), raw) == "Lists"
