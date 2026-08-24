#!/usr/bin/env python3
"""Render the social-preview SVG locally when Playwright is already present.

No browser is downloaded and no remote URL is contacted.  The destination is
replaced atomically only after a complete screenshot has been written.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path
from typing import Any

_ASSETS_ROOT = Path(__file__).resolve().parents[1] / "docs" / "assets"


def _asset_path(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(_ASSETS_ROOT)
    except ValueError:
        raise ValueError("launch renderer accepts paths under docs/assets") from None
    return resolved


async def _render(source: Path, destination: Path) -> None:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise RuntimeError("Playwright is required for local launch rendering") from None

    destination.parent.mkdir(parents=False, exist_ok=True)
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 640}, java_script_enabled=False
                )

                async def block_remote(route: Any) -> None:
                    request = route.request
                    url = request.url
                    if not url.startswith("file:"):
                        await route.abort()
                    else:
                        await route.continue_()

                await context.route("**/*", block_remote)
                page = await context.new_page()
                await page.goto(source.as_uri(), wait_until="load")
                await page.screenshot(path=str(temporary), type="png", full_page=True)
                await context.close()
            finally:
                await browser.close()
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def render_social_preview(source: Path, destination: Path) -> None:
    """Render a repository-local SVG to PNG using an installed browser only."""

    checked_source = _asset_path(source)
    checked_destination = _asset_path(destination)
    if (
        checked_source.suffix.casefold() != ".svg"
        or checked_destination.suffix.casefold() != ".png"
    ):
        raise ValueError("launch renderer accepts an SVG source and PNG destination")
    if not checked_source.is_file():
        raise ValueError("launch renderer source is missing")
    asyncio.run(_render(checked_source, checked_destination))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Render the local OpenBOLA social preview")
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    options = parser.parse_args()
    render_social_preview(options.source, options.destination)
