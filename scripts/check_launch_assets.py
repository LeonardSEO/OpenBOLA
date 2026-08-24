#!/usr/bin/env python3
"""Validate the checked-in, offline OpenBOLA launch SVGs.

This is intentionally a small standard-library check.  It parses XML before
inspecting content so malformed markup and external references fail closed.
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Literal

AssetKind = Literal["hero", "social"]

MAX_ASSET_BYTES = 512 * 1024
APPROVED_PALETTE = frozenset({"#F7F4ED", "#1B2230", "#1D436E", "#697386", "#0A0E13"})
_SVG_NAMESPACE = "http://www.w3.org/2000/svg"
_FORBIDDEN_TEXT = ("@import", "<script", "data:", "base64,")
_EXTERNAL_URL = re.compile(r"(?:https?:|//)", re.IGNORECASE)
_NAV_TAGS = frozenset({"nav", "header", "footer", "menu"})
_ERROR = "launch asset validation failed"


def _fail() -> None:
    raise ValueError(_ERROR)


def validate_asset(path: Path, *, kind: AssetKind) -> None:
    """Validate one canonical launch asset without exposing file contents."""

    try:
        if kind not in {"hero", "social"} or not path.is_file():
            _fail()
        raw = path.read_bytes()
        if not raw or len(raw) > MAX_ASSET_BYTES:
            _fail()
        root = ET.fromstring(raw)  # noqa: S314 - bounded, local SVG with external URLs rejected below
        text = raw.decode("utf-8", errors="strict")
    except (OSError, ET.ParseError, UnicodeDecodeError, ValueError):
        raise ValueError(_ERROR) from None

    if root.tag != f"{{{_SVG_NAMESPACE}}}svg":
        _fail()
    expected_viewbox = "0 0 1600 520" if kind == "hero" else "0 0 1280 640"
    if root.attrib.get("viewBox") != expected_viewbox:
        _fail()

    title = root.find(f"{{{_SVG_NAMESPACE}}}title")
    desc = root.find(f"{{{_SVG_NAMESPACE}}}desc")
    if (
        title is None
        or not (title.text or "").strip()
        or desc is None
        or not (desc.text or "").strip()
    ):
        _fail()

    if any(marker in text.casefold() for marker in _FORBIDDEN_TEXT):
        _fail()
    if any(f"<{tag}" in text.casefold() for tag in _NAV_TAGS):
        _fail()

    for element in root.iter():
        local_tag = element.tag.rsplit("}", 1)[-1]
        if local_tag in _NAV_TAGS or not isinstance(element.tag, str):
            _fail()
        for name, value in element.attrib.items():
            # The SVG namespace declaration is a harmless XML vocabulary URI;
            # all other URL-bearing values must remain local and self-contained.
            if name.casefold() not in {"xmlns", "xmlns:xlink"} and _EXTERNAL_URL.search(value):
                _fail()
            if (
                name.rsplit("}", 1)[-1].casefold() in {"href", "src"}
                and value.casefold().startswith(("http:", "https:", "//", "data:"))
            ):
                _fail()

    lowered = text.casefold()
    if any(color.casefold() not in lowered for color in APPROVED_PALETTE):
        _fail()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check an offline OpenBOLA SVG asset")
    parser.add_argument("path", type=Path)
    parser.add_argument("--kind", choices=("hero", "social"), required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        validate_asset(args.path, kind=args.kind)
    except ValueError:
        print(_ERROR, file=sys.stderr)
        return 1
    print(f"ok: {args.kind} {args.path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
