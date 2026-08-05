#!/usr/bin/env python3
"""Render a narrowly managed Maddy imapsql delivery-filter block."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Never

MAX_CONFIG_BYTES = 4 * 1024 * 1024
BEGIN_MARKER = "# BEGIN MADDYWEB MANAGED IMAP FILTER v1"
END_MARKER = "# END MADDYWEB MANAGED IMAP FILTER v1"
STORAGE_RE = re.compile(r"^\s*storage\.imapsql\s+local_mailboxes\s*\{\s*$")
FILTER_RE = re.compile(r"^\s*imap_filter\s*\{\s*$")
COMMANDS = {
    "native": (
        "command /opt/maddyweb/current/bin/python -I -m "
        "maddyweb.filter_client {account_name}"
    ),
    "docker": "command /data/maddyweb-filter/maddyweb-filter-client {account_name}",
}


class EditError(RuntimeError):
    """The Maddy configuration is outside the managed editor contract."""


@dataclass(frozen=True)
class Block:
    start: int
    end: int


def fail(message: str) -> Never:
    raise EditError(message)


def strip_comments_and_strings(line: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escaped = False
    for character in line:
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            output.append(" ")
            continue
        if character in {'"', "'"}:
            quote = character
            output.append(" ")
        elif character == "#":
            break
        else:
            output.append(character)
    if quote is not None:
        fail("multiline or unterminated quoted strings are not supported")
    return "".join(output)


def _find_storage_blocks(lines: list[str]) -> list[Block]:
    blocks: list[Block] = []
    depth = 0
    active_start: int | None = None
    for index, line in enumerate(lines):
        code = strip_comments_and_strings(line).strip()
        if depth == 0 and STORAGE_RE.fullmatch(code):
            active_start = index
        depth += code.count("{") - code.count("}")
        if depth < 0:
            fail("configuration has an unmatched closing brace")
        if active_start is not None and depth == 0:
            blocks.append(Block(active_start, index))
            active_start = None
    if depth != 0 or active_start is not None:
        fail("configuration has an unmatched opening brace")
    return blocks


def _storage_block(lines: list[str]) -> Block:
    blocks = _find_storage_blocks(lines)
    if len(blocks) != 1:
        fail("expected exactly one top-level storage.imapsql local_mailboxes block")
    return blocks[0]


def _marker_range(lines: list[str]) -> tuple[int, int] | None:
    begins = [index for index, line in enumerate(lines) if line.strip() == BEGIN_MARKER]
    ends = [index for index, line in enumerate(lines) if line.strip() == END_MARKER]
    if not begins and not ends:
        return None
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        fail("managed IMAP filter markers are incomplete, duplicated, or out of order")
    return begins[0], ends[0]


def _expected_lines(indent: str, newline: str, mode: str) -> list[str]:
    command = COMMANDS[mode]
    return [
        f"{indent}{BEGIN_MARKER}{newline}",
        f"{indent}imap_filter {{{newline}",
        f"{indent}    {command}{newline}",
        f"{indent}}}{newline}",
        f"{indent}{END_MARKER}{newline}",
    ]


def build_managed(source: str, mode: str) -> str:
    if mode not in COMMANDS:
        fail("filter mode is invalid")
    lines = source.splitlines(keepends=True)
    if not lines:
        fail("configuration is empty")
    if _marker_range(lines) is not None:
        fail("managed IMAP filter block already exists")
    block = _storage_block(lines)
    for line in lines[block.start + 1 : block.end]:
        if FILTER_RE.fullmatch(strip_comments_and_strings(line).strip()):
            fail("an unmanaged imap_filter directive already exists")
    newline = "\r\n" if "\r\n" in source else "\n"
    opening_indent = re.match(r"^\s*", lines[block.start])
    if opening_indent is None:
        fail("cannot determine storage indentation")
    indent = opening_indent.group(0) + "    "
    insertion = _expected_lines(indent, newline, mode)
    if block.end > block.start + 1 and lines[block.end - 1].strip():
        insertion.insert(0, newline)
    result = "".join(lines[: block.end] + insertion + lines[block.end :])
    verify_managed(result, mode)
    return result


def verify_managed(source: str, mode: str) -> None:
    if mode not in COMMANDS:
        fail("filter mode is invalid")
    lines = source.splitlines(keepends=True)
    block = _storage_block(lines)
    marker = _marker_range(lines)
    if marker is None:
        fail("managed IMAP filter block does not exist")
    begin, end = marker
    if not (block.start < begin < end < block.end):
        fail("managed IMAP filter block is outside local_mailboxes")
    indent_match = re.match(r"^\s*", lines[begin])
    if indent_match is None:
        fail("cannot determine managed filter indentation")
    newline = "\r\n" if lines[begin].endswith("\r\n") else "\n"
    expected = _expected_lines(indent_match.group(0), newline, mode)
    if lines[begin : end + 1] != expected:
        fail("managed IMAP filter block was modified")
    filters = [
        index
        for index, line in enumerate(lines[block.start + 1 : block.end], block.start + 1)
        if FILTER_RE.fullmatch(strip_comments_and_strings(line).strip())
    ]
    if filters != [begin + 1]:
        fail("local_mailboxes must contain exactly the managed imap_filter directive")


def remove_managed(source: str, mode: str) -> str:
    verify_managed(source, mode)
    lines = source.splitlines(keepends=True)
    marker = _marker_range(lines)
    if marker is None:  # pragma: no cover - verify_managed already rejects this.
        fail("managed IMAP filter block does not exist")
    begin, end = marker
    result_lines = lines[:begin] + lines[end + 1 :]
    if begin and lines[begin - 1].strip() == "" and end + 1 < len(lines):
        result_lines = lines[: begin - 1] + lines[end + 1 :]
    result = "".join(result_lines)
    if _marker_range(result.splitlines(keepends=True)) is not None:
        fail("managed IMAP filter markers survived removal")
    _storage_block(result.splitlines(keepends=True))
    return result


def _load(path: Path) -> str:
    if not path.is_absolute() or path == Path("/") or path.is_symlink():
        fail("configuration path must be a specific non-symlink absolute path")
    data = path.read_bytes()
    if not 1 <= len(data) <= MAX_CONFIG_BYTES or b"\0" in data:
        fail("configuration size or content is invalid")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EditError("configuration is not UTF-8") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--action",
        choices=("check-add", "check-remove", "render-add", "render-remove"),
        required=True,
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--mode", choices=tuple(COMMANDS), required=True)
    arguments = parser.parse_args()
    try:
        source = _load(arguments.config)
        if arguments.action == "check-add":
            build_managed(source, arguments.mode)
        elif arguments.action == "check-remove":
            verify_managed(source, arguments.mode)
        elif arguments.action == "render-add":
            sys.stdout.buffer.write(build_managed(source, arguments.mode).encode("utf-8"))
        else:
            sys.stdout.buffer.write(remove_managed(source, arguments.mode).encode("utf-8"))
    except (EditError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
