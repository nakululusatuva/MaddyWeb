"""Deterministic mutation fuzzing for every untrusted text/binary parser.

The normal suite runs a small corpus on every interpreter.  The security CI
raises ``MADDYWEB_FUZZ_CASES`` for a longer, reproducible run without adding a
native fuzzing dependency to the free-threaded Python matrix.
"""

from __future__ import annotations

import os
import random
from collections.abc import Iterator
from contextlib import suppress

from maddyweb.maddy import (
    CapabilityFingerprintError,
    RuntimeConfigUnsafe,
    _config_tokens_and_text,
    parse_message_list,
)
from maddyweb.mail import MailError, parse_message
from maddyweb.protocol import ProtocolError, decode_payload

_SEED = 0x4D41444459574542
_DEFAULT_CASES = 1_500
_MAX_CASES = 100_000
_BASES = (
    b"",
    b"{}",
    b'{"version":1,"operation":"messages.list"}',
    b"UID 1: sender@example.test - subject\n[], 2026-07-22\n",
    (
        b"- Server meta-data:\nUID: 1\nSequence number: 1\nFlags: []\n"
        b"Body size: 4\nInternal date: 0 epoch\n- Envelope:\n"
        b"From: sender@example.test\nSubject: fixture\n"
    ),
    b"auth.ldap local_authdb { }\n",
    b'"auth.ldap" local_authdb { } # comment\n',
    b"From: sender@example.test\r\nTo: user@example.test\r\n\r\nbody\r\n",
)


def _case_count() -> int:
    raw = os.environ.get("MADDYWEB_FUZZ_CASES", str(_DEFAULT_CASES))
    try:
        count = int(raw)
    except ValueError as exc:
        raise AssertionError("MADDYWEB_FUZZ_CASES must be an integer") from exc
    if not 1 <= count <= _MAX_CASES:
        raise AssertionError(f"MADDYWEB_FUZZ_CASES must be in 1..{_MAX_CASES}")
    return count


def _mutations(count: int) -> Iterator[bytes]:
    # Determinism is the point here; this generator does not create secrets.
    generator = random.Random(_SEED)  # noqa: S311
    for index in range(count):
        if index % 5 == 0:
            yield generator.randbytes(generator.randrange(0, 513))
            continue
        candidate = bytearray(generator.choice(_BASES))
        for _ in range(generator.randrange(1, 9)):
            operation = generator.randrange(3)
            if operation == 0 and len(candidate) < 2_048:
                position = generator.randrange(len(candidate) + 1)
                candidate[position:position] = generator.randbytes(generator.randrange(1, 17))
            elif operation == 1 and candidate:
                start = generator.randrange(len(candidate))
                del candidate[start : start + generator.randrange(1, 17)]
            elif candidate:
                candidate[generator.randrange(len(candidate))] ^= generator.randrange(1, 256)
        yield bytes(candidate)


def test_untrusted_parsers_fail_closed_under_deterministic_mutation() -> None:
    for payload in _mutations(_case_count()):
        with suppress(ProtocolError):
            decode_payload(payload)

        with suppress(CapabilityFingerprintError):
            parse_message_list(payload)

        config_text = payload.decode("utf-8", errors="surrogateescape")
        with suppress(RuntimeConfigUnsafe):
            _config_tokens_and_text(config_text)

        with suppress(MailError):
            parse_message(payload)
