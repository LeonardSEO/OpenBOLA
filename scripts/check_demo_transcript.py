#!/usr/bin/env python3
"""Validate an offline, sanitized asciinema-v2-style demo transcript."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

_ERROR = "demo transcript validation failed"
_MAX_BYTES = 256 * 1024
_MAX_EVENTS = 128
_MAX_OUTPUT = 48 * 1024
_ALLOWED_HEADER_KEYS = frozenset({"version", "width", "height", "duration", "command", "title"})
_ALLOWED_PLACEHOLDERS = frozenset({"${MOCK_PORT}", "${alice.record_id}", "${bob.record_id}"})
_PLACEHOLDER = re.compile(r"\$\{[A-Za-z][A-Za-z0-9_.-]{0,63}\}")
_UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_TOKEN = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_COOKIE = re.compile(r"(?i)\b(?:cookie|set-cookie)\s*[:=]")
_HOME = re.compile(r"(?:^|[\s=:])(?:/Users/|/home/|C:\\\\Users\\\\|%USERPROFILE%)")
_DATE = re.compile(r"\b(?:19|20)\d{2}[-/]\d{2}[-/]\d{2}(?:[T ]\d{2}:\d{2}:\d{2})?\b")
_EPOCH = re.compile(r"\b1[5-9]\d{9}\b")
_RAW_ID = re.compile(
    r"(?i)\b(?:raw[ _-]*)?(?:object|record|run)[ _-]*id\s*[:=]\s*(?!\$\{)[A-Za-z0-9_-]+"
)


def _fail() -> None:
    raise ValueError(_ERROR)


def _reject_constant(_: str) -> object:
    _fail()


def _safe_text(value: str) -> None:
    if "\x1b" in value or "\x00" in value:
        _fail()
    if _TOKEN.search(value) or _COOKIE.search(value) or _UUID.search(value):
        _fail()
    if _HOME.search(value) or _DATE.search(value) or _EPOCH.search(value) or _RAW_ID.search(value):
        _fail()
    placeholders = set(_PLACEHOLDER.findall(value))
    if placeholders and not placeholders.issubset(_ALLOWED_PLACEHOLDERS):
        _fail()
    if "${" in value and not placeholders:
        _fail()
    for match in re.finditer(r"https?://[^\s\"']+", value, re.IGNORECASE):
        try:
            host = urlsplit(match.group(0)).hostname
        except ValueError:
            _fail()
        if host not in {"127.0.0.1", "localhost", "::1"}:
            _fail()


def validate_transcript(path: Path) -> None:
    """Validate a transcript without executing its command or contacting a URL."""

    try:
        raw = path.read_bytes()
        if not raw or len(raw) > _MAX_BYTES:
            _fail()
        lines = raw.decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError, ValueError):
        raise ValueError(_ERROR) from None
    if not lines or len(lines) > _MAX_EVENTS + 1:
        _fail()
    try:
        header = json.loads(lines[0], parse_constant=_reject_constant)
    except (TypeError, ValueError, json.JSONDecodeError):
        raise ValueError(_ERROR) from None
    if not isinstance(header, dict) or set(header) - _ALLOWED_HEADER_KEYS:
        _fail()
    if header.get("version") != 2 or not isinstance(header.get("width"), int) or not isinstance(
        header.get("height"), int
    ):
        _fail()
    if not (40 <= header["width"] <= 240 and 10 <= header["height"] <= 100):
        _fail()
    for key in ("command", "title"):
        if not isinstance(header.get(key), str) or not header[key].strip():
            _fail()
        _safe_text(header[key])
    if "duration" in header and (
        not isinstance(header["duration"], (int, float))
        or isinstance(header["duration"], bool)
        or not math.isfinite(header["duration"])
        or header["duration"] < 0
    ):
        _fail()

    total_output = 0
    previous_delay = 0.0
    output_parts: list[str] = []
    for line in lines[1:]:
        if len(line.encode("utf-8")) > 8192:
            _fail()
        try:
            event = json.loads(line, parse_constant=_reject_constant)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise ValueError(_ERROR) from None
        if not isinstance(event, list) or len(event) != 3:
            _fail()
        delay, event_type, output = event
        if (
            not isinstance(delay, (int, float))
            or isinstance(delay, bool)
            or not math.isfinite(delay)
            or delay < 0
            or delay > 2
            or delay < previous_delay
        ):
            _fail()
        previous_delay = float(delay)
        if event_type != "o" or not isinstance(output, str) or not output:
            _fail()
        _safe_text(output)
        total_output += len(output.encode("utf-8"))
        if total_output > _MAX_OUTPUT:
            _fail()
        output_parts.append(output.casefold())

    joined = "".join(output_parts)
    required = (
        "discovery",
        "mutation grant",
        "restore verification",
        "report output",
        "alice",
        "bob",
        "read-only",
        "patch",
        "cleanup",
        "zero findings",
        "not proof of safety",
    )
    if any(label not in joined for label in required):
        _fail()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check an offline OpenBOLA demo transcript")
    parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        validate_transcript(args.path)
    except ValueError:
        print(_ERROR, file=sys.stderr)
        return 1
    print(f"ok: transcript {args.path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
