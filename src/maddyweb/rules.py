"""Bounded, deterministic matching for user-defined mail filing rules.

The module deliberately contains no storage, subprocess, network, or mailbox
mutation code.  A privileged runner can compile trusted rule documents during
configuration loading, evaluate an RFC 5322 message once, and then perform the
returned mailbox move through its own fixed operation interface.
"""

from __future__ import annotations

import io
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header
from email.message import EmailMessage, Message
from email.parser import BytesParser
from enum import Enum, StrEnum
from typing import Any

MAX_RULE_DEPTH = 8
MAX_RULE_NODES = 100
MAX_RULE_JSON_BYTES = 64 * 1024
MAX_RULE_VALUE_CHARACTERS = 2_048
MAX_RULE_VALUE_BYTES = 8 * 1024
MAX_HEADER_NAME_CHARACTERS = 78
MAX_TARGET_MAILBOX_CHARACTERS = 255
MAX_TARGET_MAILBOX_BYTES = 1_024

MAX_RAW_MESSAGE_BYTES = 25 * 1024 * 1024
MAX_BODY_BYTES = MAX_RAW_MESSAGE_BYTES
MAX_TOP_LEVEL_HEADER_BYTES = 128 * 1024
MAX_HEADER_LINE_BYTES = 16 * 1024
MAX_HEADERS_PER_PART = 256
MAX_MESSAGE_HEADERS = 1_024
MAX_MESSAGE_HEADER_CHARACTERS = 256 * 1024
MAX_DECODED_HEADER_CHARACTERS = 128 * 1024
MAX_MIME_PARTS = 128
MAX_MIME_DEPTH = 32
MAX_ENVELOPE_VALUES = 100
MAX_ENVELOPE_VALUE_CHARACTERS = 998

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$", re.ASCII)
_FOLD_RE = re.compile(r"\r?\n[ \t]+")


class RuleError(ValueError):
    """Base exception for invalid rules or messages."""


class RuleValidationError(RuleError):
    """A rule document is invalid or exceeds its configured bounds."""


class RuleMessageError(RuleError):
    """A message cannot be safely evaluated."""


class RuleMessageLimitError(RuleMessageError):
    """A message exceeds a parser resource bound."""


class StringField(StrEnum):
    FROM = "from"
    TO = "to"
    CC = "cc"
    BCC = "bcc"
    REPLY_TO = "reply_to"
    SUBJECT = "subject"
    LIST_ID = "list_id"
    HEADER = "header"


class NumericField(StrEnum):
    SIZE = "size"


class BooleanField(StrEnum):
    HAS_ATTACHMENT = "has_attachment"


class StringOperator(StrEnum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    EXISTS = "exists"


class NumericOperator(StrEnum):
    EQ = "eq"
    LT = "lt"
    LTE = "lte"
    GT = "gt"
    GTE = "gte"


class BooleanOperator(StrEnum):
    EQ = "eq"


def _enum_value(enum_type: type[StrEnum], value: object, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise RuleValidationError(f"unsupported {label}") from exc


def _validate_text(
    value: object,
    *,
    label: str,
    maximum_characters: int = MAX_RULE_VALUE_CHARACTERS,
    maximum_bytes: int = MAX_RULE_VALUE_BYTES,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise RuleValidationError(f"{label} must be a string")
    if not value and not allow_empty:
        raise RuleValidationError(f"{label} cannot be empty")
    if any(unicodedata.category(character) in {"Cc", "Cs"} for character in value):
        raise RuleValidationError(f"{label} contains unsafe characters")
    if len(value) > maximum_characters or len(value.encode("utf-8")) > maximum_bytes:
        raise RuleValidationError(f"{label} is too long")
    return value


def _validate_header_name(value: object) -> str:
    name = _validate_text(
        value,
        label="custom header name",
        maximum_characters=MAX_HEADER_NAME_CHARACTERS,
        maximum_bytes=MAX_HEADER_NAME_CHARACTERS,
    )
    if _HEADER_NAME_RE.fullmatch(name) is None:
        raise RuleValidationError("custom header name is invalid")
    return name.casefold()


def _validate_target_mailbox(value: object) -> str:
    mailbox = _validate_text(
        value,
        label="target mailbox",
        maximum_characters=MAX_TARGET_MAILBOX_CHARACTERS,
        maximum_bytes=MAX_TARGET_MAILBOX_BYTES,
    )
    if mailbox != mailbox.strip():
        raise RuleValidationError("target mailbox cannot start or end with whitespace")
    return mailbox


@dataclass(frozen=True, slots=True)
class AndCondition:
    conditions: tuple[Condition, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "conditions", tuple(self.conditions))
        if not self.conditions:
            raise RuleValidationError("and requires at least one condition")


@dataclass(frozen=True, slots=True)
class OrCondition:
    conditions: tuple[Condition, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "conditions", tuple(self.conditions))
        if not self.conditions:
            raise RuleValidationError("or requires at least one condition")


@dataclass(frozen=True, slots=True)
class NotCondition:
    condition: Condition


@dataclass(frozen=True, slots=True)
class StringCondition:
    field: StringField
    operator: StringOperator
    value: str | None = None
    header: str | None = None

    def __post_init__(self) -> None:
        string_field = _enum_value(StringField, self.field, "string field")
        operator = _enum_value(StringOperator, self.operator, "string operator")
        object.__setattr__(self, "field", string_field)
        object.__setattr__(self, "operator", operator)

        if string_field is StringField.HEADER:
            object.__setattr__(self, "header", _validate_header_name(self.header))
        elif self.header is not None:
            raise RuleValidationError("header is valid only for the header field")

        if operator is StringOperator.EXISTS:
            if self.value is not None:
                raise RuleValidationError("exists does not accept a value")
        else:
            object.__setattr__(
                self,
                "value",
                _validate_text(self.value, label="string test value"),
            )


@dataclass(frozen=True, slots=True)
class NumericCondition:
    field: NumericField
    operator: NumericOperator
    value: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "field", _enum_value(NumericField, self.field, "numeric field"))
        object.__setattr__(
            self,
            "operator",
            _enum_value(NumericOperator, self.operator, "numeric operator"),
        )
        if type(self.value) is not int or not 0 <= self.value <= 2**63 - 1:
            raise RuleValidationError("numeric test value must be a non-negative 64-bit integer")


@dataclass(frozen=True, slots=True)
class BooleanCondition:
    field: BooleanField
    operator: BooleanOperator
    value: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "field", _enum_value(BooleanField, self.field, "boolean field"))
        object.__setattr__(
            self,
            "operator",
            _enum_value(BooleanOperator, self.operator, "boolean operator"),
        )
        if type(self.value) is not bool:
            raise RuleValidationError("boolean test value must be a boolean")


type Condition = (
    AndCondition
    | OrCondition
    | NotCondition
    | StringCondition
    | NumericCondition
    | BooleanCondition
)


def _validate_condition_budget(condition: Condition) -> None:
    stack: list[tuple[Condition, int]] = [(condition, 1)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_RULE_NODES:
            raise RuleValidationError("rule has too many condition nodes")
        if depth > MAX_RULE_DEPTH:
            raise RuleValidationError("rule condition nesting is too deep")
        if isinstance(node, (AndCondition, OrCondition)):
            stack.extend((child, depth + 1) for child in node.conditions)
        elif isinstance(node, NotCondition):
            stack.append((node.condition, depth + 1))
        elif not isinstance(node, (StringCondition, NumericCondition, BooleanCondition)):
            raise RuleValidationError("rule contains an unsupported condition node")


@dataclass(frozen=True, slots=True)
class Rule:
    """An immutable validated filing rule."""

    condition: Condition
    target_mailbox: str

    def __post_init__(self) -> None:
        _validate_condition_budget(self.condition)
        object.__setattr__(self, "target_mailbox", _validate_target_mailbox(self.target_mailbox))

    @classmethod
    def from_mapping(cls, document: Mapping[str, object]) -> Rule:
        mapping = _require_mapping(document, label="rule")
        _require_keys(mapping, required={"condition", "target_mailbox"})
        return cls(
            condition=condition_from_mapping(mapping["condition"]),
            target_mailbox=mapping["target_mailbox"],
        )

    @classmethod
    def from_json(cls, document: str | bytes) -> Rule:
        return cls.from_mapping(_load_rule_json(document))

    def to_mapping(self) -> dict[str, object]:
        return {
            "condition": condition_to_mapping(self.condition),
            "target_mailbox": self.target_mailbox,
        }

    def canonical_json(self) -> str:
        """Return stable UTF-8 JSON with sorted object keys and no whitespace."""

        return json.dumps(
            self.to_mapping(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    def compile(self) -> CompiledRule:
        return compile_rule(self)


def _require_mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise RuleValidationError(f"{label} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise RuleValidationError(f"{label} keys must be strings")
    return value


def _require_keys(
    mapping: Mapping[str, object],
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    keys = set(mapping)
    if keys != required | (keys & optional) or not required <= keys:
        missing = required - keys
        unknown = keys - required - optional
        if missing:
            raise RuleValidationError(f"missing rule key: {sorted(missing)[0]}")
        raise RuleValidationError(f"unknown rule key: {sorted(unknown)[0]}")


def condition_from_mapping(document: object, *, _depth: int = 1) -> Condition:
    """Parse one strict condition object into the immutable typed AST."""

    if _depth > MAX_RULE_DEPTH:
        raise RuleValidationError("rule condition nesting is too deep")
    mapping = _require_mapping(document, label="condition")

    if "op" in mapping:
        operation = mapping["op"]
        if not isinstance(operation, str):
            raise RuleValidationError("logical operator must be a string")
        if operation in {"and", "or"}:
            _require_keys(mapping, required={"op", "conditions"})
            children = mapping["conditions"]
            if not isinstance(children, list | tuple):
                raise RuleValidationError(f"{operation} conditions must be an array")
            if len(children) > MAX_RULE_NODES:
                raise RuleValidationError("rule has too many condition nodes")
            parsed = tuple(
                condition_from_mapping(child, _depth=_depth + 1) for child in children
            )
            condition: Condition = (
                AndCondition(parsed) if operation == "and" else OrCondition(parsed)
            )
            _validate_condition_budget(condition)
            return condition
        if operation == "not":
            _require_keys(mapping, required={"op", "condition"})
            condition = NotCondition(
                condition_from_mapping(mapping["condition"], _depth=_depth + 1)
            )
            _validate_condition_budget(condition)
            return condition
        raise RuleValidationError("unsupported logical operator")

    field_value = mapping.get("field")
    if isinstance(field_value, str) and field_value in {
        field.value for field in StringField
    }:
        string_field = _enum_value(StringField, field_value, "string field")
        string_operator = _enum_value(
            StringOperator,
            mapping.get("operator"),
            "string operator",
        )
        required = {"field", "operator"}
        if string_field is StringField.HEADER:
            required.add("header")
        if string_operator is not StringOperator.EXISTS:
            required.add("value")
        _require_keys(mapping, required=required)
        condition = StringCondition(
            field=string_field,
            operator=string_operator,
            value=mapping.get("value"),
            header=mapping.get("header"),
        )
    elif field_value == NumericField.SIZE.value:
        _require_keys(mapping, required={"field", "operator", "value"})
        condition = NumericCondition(
            field=field_value,
            operator=mapping["operator"],
            value=mapping["value"],
        )
    elif field_value == BooleanField.HAS_ATTACHMENT.value:
        _require_keys(mapping, required={"field", "operator", "value"})
        condition = BooleanCondition(
            field=field_value,
            operator=mapping["operator"],
            value=mapping["value"],
        )
    else:
        raise RuleValidationError("unsupported condition field")
    _validate_condition_budget(condition)
    return condition


def condition_to_mapping(condition: Condition) -> dict[str, object]:
    if isinstance(condition, AndCondition):
        return {
            "conditions": [condition_to_mapping(child) for child in condition.conditions],
            "op": "and",
        }
    if isinstance(condition, OrCondition):
        return {
            "conditions": [condition_to_mapping(child) for child in condition.conditions],
            "op": "or",
        }
    if isinstance(condition, NotCondition):
        return {"condition": condition_to_mapping(condition.condition), "op": "not"}
    if isinstance(condition, StringCondition):
        result: dict[str, object] = {
            "field": condition.field.value,
            "operator": condition.operator.value,
        }
        if condition.header is not None:
            result["header"] = condition.header
        if condition.value is not None:
            result["value"] = condition.value
        return result
    if isinstance(condition, NumericCondition | BooleanCondition):
        return {
            "field": condition.field.value,
            "operator": condition.operator.value,
            "value": condition.value,
        }
    raise RuleValidationError("rule contains an unsupported condition node")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RuleValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise RuleValidationError(f"invalid JSON constant: {value}")


def _load_rule_json(document: str | bytes) -> Mapping[str, object]:
    if isinstance(document, bytes):
        if len(document) > MAX_RULE_JSON_BYTES:
            raise RuleValidationError("rule JSON is too large")
        try:
            rendered = document.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise RuleValidationError("rule JSON must be UTF-8") from exc
    elif isinstance(document, str):
        rendered = document
        try:
            encoded_length = len(rendered.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise RuleValidationError("rule JSON must be valid Unicode") from exc
        if encoded_length > MAX_RULE_JSON_BYTES:
            raise RuleValidationError("rule JSON is too large")
    else:
        raise RuleValidationError("rule JSON must be text or bytes")
    try:
        loaded = json.loads(
            rendered,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except RuleValidationError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise RuleValidationError("rule JSON is invalid") from exc
    return _require_mapping(loaded, label="rule")


def canonical_rule_json(rule: Rule | Mapping[str, object] | str | bytes) -> str:
    """Validate and canonicalize a rule document."""

    if isinstance(rule, Rule):
        parsed = rule
    elif isinstance(rule, str | bytes):
        parsed = Rule.from_json(rule)
    else:
        parsed = Rule.from_mapping(rule)
    return parsed.canonical_json()


@dataclass(frozen=True, slots=True)
class _CompiledAnd:
    conditions: tuple[_CompiledCondition, ...]


@dataclass(frozen=True, slots=True)
class _CompiledOr:
    conditions: tuple[_CompiledCondition, ...]


@dataclass(frozen=True, slots=True)
class _CompiledNot:
    condition: _CompiledCondition


@dataclass(frozen=True, slots=True)
class _CompiledString:
    field: StringField
    operator: StringOperator
    value: str | None
    header: str | None


@dataclass(frozen=True, slots=True)
class _CompiledNumeric:
    operator: NumericOperator
    value: int


@dataclass(frozen=True, slots=True)
class _CompiledBoolean:
    value: bool


type _CompiledCondition = (
    _CompiledAnd
    | _CompiledOr
    | _CompiledNot
    | _CompiledString
    | _CompiledNumeric
    | _CompiledBoolean
)


def _compile_condition(condition: Condition) -> _CompiledCondition:
    if isinstance(condition, AndCondition):
        return _CompiledAnd(tuple(_compile_condition(child) for child in condition.conditions))
    if isinstance(condition, OrCondition):
        return _CompiledOr(tuple(_compile_condition(child) for child in condition.conditions))
    if isinstance(condition, NotCondition):
        return _CompiledNot(_compile_condition(condition.condition))
    if isinstance(condition, StringCondition):
        return _CompiledString(
            field=condition.field,
            operator=condition.operator,
            value=condition.value.casefold() if condition.value is not None else None,
            header=condition.header,
        )
    if isinstance(condition, NumericCondition):
        return _CompiledNumeric(operator=condition.operator, value=condition.value)
    if isinstance(condition, BooleanCondition):
        return _CompiledBoolean(value=condition.value)
    raise RuleValidationError("rule contains an unsupported condition node")


@dataclass(frozen=True, slots=True)
class CompiledRule:
    """An immutable rule with normalized operands ready for repeated matching."""

    rule: Rule
    _condition: _CompiledCondition = field(repr=False)

    @property
    def target_mailbox(self) -> str:
        return self.rule.target_mailbox

    def canonical_json(self) -> str:
        return self.rule.canonical_json()

    def matches(self, message: RuleMessage) -> bool:
        if not isinstance(message, RuleMessage):
            return False
        try:
            return _evaluate_condition(self._condition, message) is _Truth.TRUE
        except (LookupError, TypeError, UnicodeError, ValueError):
            return False

    def matches_raw(
        self,
        raw_message: bytes,
        *,
        envelope_sender: str | None = None,
        envelope_recipient: str | Iterable[str] | None = None,
    ) -> bool:
        try:
            message = parse_rule_message(
                raw_message,
                envelope_sender=envelope_sender,
                envelope_recipient=envelope_recipient,
            )
        except Exception:
            return False
        return self.matches(message)


def compile_rule(rule: Rule | Mapping[str, object] | str | bytes) -> CompiledRule:
    if not isinstance(rule, Rule):
        rule = (
            Rule.from_json(rule)
            if isinstance(rule, str | bytes)
            else Rule.from_mapping(rule)
        )
    _validate_condition_budget(rule.condition)
    return CompiledRule(rule=rule, _condition=_compile_condition(rule.condition))


def compile_rules(
    rules: Iterable[Rule | Mapping[str, object] | str | bytes],
) -> tuple[CompiledRule, ...]:
    """Compile rules without changing caller order."""

    compiled: list[CompiledRule] = []
    for rule in rules:
        compiled.append(compile_rule(rule))
    return tuple(compiled)


@dataclass(frozen=True, slots=True)
class RuleMessage:
    """Bounded normalized message facts used by compiled rules."""

    headers: tuple[tuple[str, str], ...]
    size: int
    has_attachment: bool
    envelope_sender: str | None = None
    envelope_recipients: tuple[str, ...] = ()

    def header_values(self, name: str) -> tuple[str, ...]:
        normalized = name.casefold()
        return tuple(value for key, value in self.headers if key == normalized)

    def string_values(self, field_name: StringField, header: str | None) -> tuple[str, ...]:
        header_name = {
            StringField.FROM: "from",
            StringField.TO: "to",
            StringField.CC: "cc",
            StringField.BCC: "bcc",
            StringField.REPLY_TO: "reply-to",
            StringField.SUBJECT: "subject",
            StringField.LIST_ID: "list-id",
            StringField.HEADER: header or "",
        }[field_name]
        values = list(self.header_values(header_name))
        if field_name is StringField.FROM and self.envelope_sender is not None:
            values.append(self.envelope_sender)
        elif field_name is StringField.TO:
            values.extend(self.envelope_recipients)
        return tuple(values)


def _normalize_decoded_text(value: str, *, label: str) -> str:
    unfolded = _FOLD_RE.sub(" ", value)
    if "\r" in unfolded or "\n" in unfolded:
        raise RuleMessageError(f"invalid {label}")
    unfolded = re.sub(r"[ \t]+", " ", unfolded)
    if any(unicodedata.category(character) in {"Cc", "Cs"} for character in unfolded):
        raise RuleMessageError(f"invalid {label}")
    return unfolded


def _decode_header_value(value: str) -> str:
    try:
        fragments = decode_header(_normalize_decoded_text(value, label="header value"))
    except (LookupError, TypeError, UnicodeError, ValueError) as exc:
        raise RuleMessageError("invalid encoded header") from exc
    decoded: list[str] = []
    for fragment, charset in fragments:
        if isinstance(fragment, str):
            rendered = fragment
        else:
            encoding = charset or "ascii"
            try:
                rendered = fragment.decode(encoding, "strict")
            except (LookupError, UnicodeError) as exc:
                raise RuleMessageError("invalid encoded header") from exc
        decoded.append(rendered)
    return _normalize_decoded_text("".join(decoded), label="decoded header").casefold()


def _validate_top_level_headers(raw: bytes) -> int:
    stream = io.BytesIO(raw)
    total = 0
    count = 0
    have_header = False
    while True:
        line = stream.readline(MAX_HEADER_LINE_BYTES + 1)
        if len(line) > MAX_HEADER_LINE_BYTES:
            raise RuleMessageLimitError("message header line is too long")
        if not line:
            return stream.tell()
        total += len(line)
        if total > MAX_TOP_LEVEL_HEADER_BYTES:
            raise RuleMessageLimitError("top-level message headers are too large")
        content = line.rstrip(b"\r\n")
        if not content:
            return stream.tell()
        if content[:1] in {b" ", b"\t"}:
            if not have_header:
                raise RuleMessageError("invalid folded message header")
            continue
        name, separator, _value = content.partition(b":")
        if not separator:
            raise RuleMessageError("invalid message header")
        try:
            decoded_name = name.decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise RuleMessageError("invalid message header name") from exc
        if (
            not decoded_name
            or len(decoded_name) > MAX_HEADER_NAME_CHARACTERS
            or _HEADER_NAME_RE.fullmatch(decoded_name) is None
        ):
            raise RuleMessageError("invalid message header name")
        have_header = True
        count += 1
        if count > MAX_HEADERS_PER_PART:
            raise RuleMessageLimitError("too many top-level message headers")


def _validate_envelope_value(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise RuleMessageError(f"{label} must be a string")
    if len(value) > MAX_ENVELOPE_VALUE_CHARACTERS:
        raise RuleMessageLimitError(f"{label} is too long")
    normalized = _normalize_decoded_text(value, label=label).strip()
    if not normalized:
        raise RuleMessageError(f"{label} cannot be empty")
    return normalized.casefold()


def _normalize_envelope_recipients(
    value: str | Iterable[str] | None,
) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        source: Iterable[str] = (value,)
    elif isinstance(value, bytes):
        raise RuleMessageError("envelope recipient must be text")
    else:
        source = value
    recipients: list[str] = []
    try:
        for recipient in source:
            recipients.append(_validate_envelope_value(recipient, label="envelope recipient"))
            if len(recipients) > MAX_ENVELOPE_VALUES:
                raise RuleMessageLimitError("too many envelope recipients")
    except RuleMessageError:
        raise
    except (TypeError, ValueError) as exc:
        raise RuleMessageError("invalid envelope recipients") from exc
    return tuple(recipients)


def _bounded_parts(message: Message) -> tuple[Message, ...]:
    parts: list[Message] = []
    stack: list[tuple[Message, int]] = [(message, 0)]
    total_headers = 0
    total_header_characters = 0
    while stack:
        part, depth = stack.pop()
        if depth > MAX_MIME_DEPTH:
            raise RuleMessageLimitError("MIME nesting is too deep")
        parts.append(part)
        if len(parts) > MAX_MIME_PARTS:
            raise RuleMessageLimitError("too many MIME parts")
        if part.defects:
            raise RuleMessageError("malformed MIME message")
        for part_header_count, (name, value) in enumerate(part.raw_items(), start=1):
            total_headers += 1
            total_header_characters += len(name) + len(value)
            if (
                not name
                or len(name) > MAX_HEADER_NAME_CHARACTERS
                or _HEADER_NAME_RE.fullmatch(name) is None
            ):
                raise RuleMessageError("invalid MIME header name")
            if part_header_count > MAX_HEADERS_PER_PART or total_headers > MAX_MESSAGE_HEADERS:
                raise RuleMessageLimitError("too many message headers")
            if total_header_characters > MAX_MESSAGE_HEADER_CHARACTERS:
                raise RuleMessageLimitError("message headers are too large")
        if not part.is_multipart():
            continue
        payload = part.get_payload()
        if not isinstance(payload, list) or any(
            not isinstance(child, Message) for child in payload
        ):
            raise RuleMessageError("invalid multipart message")
        stack.extend((child, depth + 1) for child in reversed(payload))
    return tuple(parts)


def _has_attachment(parts: Sequence[Message]) -> bool:
    root = parts[0]
    for part in parts:
        try:
            disposition = part.get_content_disposition()
            filename = part.get_filename()
        except (LookupError, TypeError, UnicodeError, ValueError) as exc:
            raise RuleMessageError("invalid attachment metadata") from exc
        if (
            disposition == "attachment"
            or (part is not root and filename is not None)
            or (part is not root and part.get_content_type().casefold() == "message/rfc822")
        ):
            return True
    return False


def parse_rule_message(
    raw_message: bytes,
    *,
    envelope_sender: str | None = None,
    envelope_recipient: str | Iterable[str] | None = None,
) -> RuleMessage:
    """Parse bounded RFC 5322 bytes into normalized facts for rule matching."""

    if not isinstance(raw_message, bytes):
        raise RuleMessageError("raw message must be bytes")
    if len(raw_message) > MAX_RAW_MESSAGE_BYTES:
        raise RuleMessageLimitError("raw message is too large")
    body_offset = _validate_top_level_headers(raw_message)
    if len(raw_message) - body_offset > MAX_BODY_BYTES:
        raise RuleMessageLimitError("message body is too large")

    parsed_parts = 0

    def bounded_factory(*args: Any, **kwargs: Any) -> EmailMessage:
        nonlocal parsed_parts
        parsed_parts += 1
        if parsed_parts > MAX_MIME_PARTS:
            raise RuleMessageLimitError("too many MIME parts")
        return EmailMessage(*args, **kwargs)

    try:
        message = BytesParser(_class=bounded_factory, policy=policy.default).parsebytes(raw_message)
    except RuleMessageError:
        raise
    except RecursionError as exc:
        raise RuleMessageLimitError("MIME nesting is too deep") from exc
    except (LookupError, TypeError, UnicodeError, ValueError) as exc:
        raise RuleMessageError("invalid message") from exc

    parts = _bounded_parts(message)
    normalized_headers: list[tuple[str, str]] = []
    decoded_characters = 0
    for name, value in message.raw_items():
        decoded = _decode_header_value(value)
        decoded_characters += len(decoded)
        if decoded_characters > MAX_DECODED_HEADER_CHARACTERS:
            raise RuleMessageLimitError("decoded message headers are too large")
        normalized_headers.append((name.casefold(), decoded))

    normalized_sender = (
        _validate_envelope_value(envelope_sender, label="envelope sender")
        if envelope_sender is not None
        else None
    )
    normalized_recipients = _normalize_envelope_recipients(envelope_recipient)
    return RuleMessage(
        headers=tuple(normalized_headers),
        size=len(raw_message),
        has_attachment=_has_attachment(parts),
        envelope_sender=normalized_sender,
        envelope_recipients=normalized_recipients,
    )


class _Truth(Enum):
    FALSE = 0
    TRUE = 1
    UNKNOWN = 2


def _string_result(condition: _CompiledString, message: RuleMessage) -> _Truth:
    values = message.string_values(condition.field, condition.header)
    if condition.operator is StringOperator.EXISTS:
        return _Truth.TRUE if values else _Truth.FALSE
    if not values or condition.value is None:
        return _Truth.UNKNOWN

    value = condition.value
    if condition.operator is StringOperator.EQUALS:
        matched = any(candidate == value for candidate in values)
    elif condition.operator is StringOperator.NOT_EQUALS:
        matched = all(candidate != value for candidate in values)
    elif condition.operator is StringOperator.CONTAINS:
        matched = any(value in candidate for candidate in values)
    elif condition.operator is StringOperator.NOT_CONTAINS:
        matched = all(value not in candidate for candidate in values)
    elif condition.operator is StringOperator.STARTS_WITH:
        matched = any(candidate.startswith(value) for candidate in values)
    elif condition.operator is StringOperator.ENDS_WITH:
        matched = any(candidate.endswith(value) for candidate in values)
    else:  # pragma: no cover - all enum values are compiled explicitly
        return _Truth.UNKNOWN
    return _Truth.TRUE if matched else _Truth.FALSE


def _numeric_result(condition: _CompiledNumeric, message: RuleMessage) -> _Truth:
    size = message.size
    value = condition.value
    matched = {
        NumericOperator.EQ: size == value,
        NumericOperator.LT: size < value,
        NumericOperator.LTE: size <= value,
        NumericOperator.GT: size > value,
        NumericOperator.GTE: size >= value,
    }[condition.operator]
    return _Truth.TRUE if matched else _Truth.FALSE


def _evaluate_condition(condition: _CompiledCondition, message: RuleMessage) -> _Truth:
    if isinstance(condition, _CompiledString):
        return _string_result(condition, message)
    if isinstance(condition, _CompiledNumeric):
        return _numeric_result(condition, message)
    if isinstance(condition, _CompiledBoolean):
        return _Truth.TRUE if message.has_attachment is condition.value else _Truth.FALSE
    if isinstance(condition, _CompiledNot):
        result = _evaluate_condition(condition.condition, message)
        return {
            _Truth.TRUE: _Truth.FALSE,
            _Truth.FALSE: _Truth.TRUE,
            _Truth.UNKNOWN: _Truth.UNKNOWN,
        }[result]
    if isinstance(condition, _CompiledAnd):
        saw_unknown = False
        for child in condition.conditions:
            result = _evaluate_condition(child, message)
            if result is _Truth.FALSE:
                return _Truth.FALSE
            saw_unknown = saw_unknown or result is _Truth.UNKNOWN
        return _Truth.UNKNOWN if saw_unknown else _Truth.TRUE
    if isinstance(condition, _CompiledOr):
        saw_unknown = False
        for child in condition.conditions:
            result = _evaluate_condition(child, message)
            if result is _Truth.TRUE:
                return _Truth.TRUE
            saw_unknown = saw_unknown or result is _Truth.UNKNOWN
        return _Truth.UNKNOWN if saw_unknown else _Truth.FALSE
    return _Truth.UNKNOWN


def evaluate_message(rules: Sequence[CompiledRule], message: RuleMessage) -> str | None:
    """Return the first matching target mailbox, preserving rule order."""

    if not isinstance(message, RuleMessage):
        return None
    for rule in rules:
        if not isinstance(rule, CompiledRule):
            raise TypeError("evaluate_message requires compiled rules")
        if rule.matches(message):
            return rule.target_mailbox
    return None


def evaluate_rules(
    rules: Sequence[CompiledRule],
    raw_message: bytes,
    *,
    envelope_sender: str | None = None,
    envelope_recipient: str | Iterable[str] | None = None,
) -> str | None:
    """Fail closed and return the first target for one raw message, if any."""

    try:
        message = parse_rule_message(
            raw_message,
            envelope_sender=envelope_sender,
            envelope_recipient=envelope_recipient,
        )
    except Exception:
        return None
    return evaluate_message(rules, message)


__all__ = [
    "MAX_RULE_DEPTH",
    "MAX_RULE_NODES",
    "AndCondition",
    "BooleanCondition",
    "BooleanField",
    "BooleanOperator",
    "CompiledRule",
    "Condition",
    "NotCondition",
    "NumericCondition",
    "NumericField",
    "NumericOperator",
    "OrCondition",
    "Rule",
    "RuleError",
    "RuleMessage",
    "RuleMessageError",
    "RuleMessageLimitError",
    "RuleValidationError",
    "StringCondition",
    "StringField",
    "StringOperator",
    "canonical_rule_json",
    "compile_rule",
    "compile_rules",
    "condition_from_mapping",
    "condition_to_mapping",
    "evaluate_message",
    "evaluate_rules",
    "parse_rule_message",
]
