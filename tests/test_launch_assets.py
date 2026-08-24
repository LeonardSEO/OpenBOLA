from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from scripts.check_launch_assets import APPROVED_PALETTE, validate_asset

ROOT = Path(__file__).parents[1]
ASSETS = ROOT / "docs" / "assets"
README = ROOT / "README.md"


def test_canonical_assets_are_offline_and_accessible() -> None:
    validate_asset(ASSETS / "openbola-hero.svg", kind="hero")
    validate_asset(ASSETS / "openbola-social-preview.svg", kind="social")


@pytest.mark.parametrize(
    "replacement",
    [
        '<image href="https://example.test/remote.png"/>',
        "<script>alert(1)</script>",
        '<image href="data:image/png;base64,AAAA"/>',
    ],
)
def test_asset_validator_rejects_external_or_active_content(
    tmp_path: Path, replacement: str
) -> None:
    source = (ASSETS / "openbola-hero.svg").read_text(encoding="utf-8")
    candidate = tmp_path / "candidate.svg"
    candidate.write_text(source.replace("</svg>", replacement + "</svg>"), encoding="utf-8")
    with pytest.raises(ValueError, match="^launch asset validation failed$"):
        validate_asset(candidate, kind="hero")


def test_asset_validator_rejects_wrong_dimensions_and_missing_palette(tmp_path: Path) -> None:
    source = (ASSETS / "openbola-social-preview.svg").read_text(encoding="utf-8")
    wrong_size = tmp_path / "wrong.svg"
    wrong_size.write_text(
        source.replace('viewBox="0 0 1280 640"', 'viewBox="0 0 640 320"'), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="^launch asset validation failed$"):
        validate_asset(wrong_size, kind="social")

    missing = tmp_path / "missing.svg"
    missing.write_text(source.replace(next(iter(APPROVED_PALETTE)), "#FFFFFF"), encoding="utf-8")
    with pytest.raises(ValueError, match="^launch asset validation failed$"):
        validate_asset(missing, kind="social")


def test_launch_checklist_has_separate_approval_gates() -> None:
    checklist = (ROOT / "docs" / "launch" / "github-launch-checklist.md").read_text(
        encoding="utf-8"
    )
    for marker in (
        "rename/transfer",
        "local remote",
        "Repository topics",
        "Private vulnerability-reporting URL",
        "Release metadata",
        "Social-preview upload",
    ):
        assert marker.casefold() in checklist.casefold()
    assert "STOP" in checklist
    assert "force-push" in checklist
    assert "history rewrite" in checklist
    assert "gh repo rename" in checklist
    assert "gh release create" in checklist
    assert "token" in checklist.casefold()
    assert "pending approval" in checklist.casefold()


def test_readme_launch_contract_is_complete_and_secret_free() -> None:
    """Keep the public launch surface aligned with the P11 local contract."""

    readme = README.read_text(encoding="utf-8")
    first_line = next(line for line in readme.splitlines() if line.strip())
    assert first_line == "![OpenBOLA — proof, not permission.](docs/assets/openbola-hero.svg)"

    for badge in ("status", "platform", "python", "license"):
        assert f"img.shields.io/badge/{badge}-" in readme
    for install_example in (
        "uv sync --extra dev",
        "openbola setup",
        "openbola-VERSION-windows-x64.zip",
        "openbola-VERSION-macos-arm64.tar.gz",
        "openbola-VERSION-macos-x64.tar.gz",
        "SHA256SUMS",
    ):
        assert install_example in readme

    assert "examples/demo/openbola-demo.cast" in readme
    assert "docs/assets/openbola-social-preview.svg" in readme
    for artifact in (
        "report.html",
        "report.csv",
        "report.json",
        "report.md",
        "junit.xml",
        "report.sarif",
    ):
        assert artifact in readme
    for provider in ("generic HTTP", "Hasura", "Supabase", "PostgREST", "Firebase"):
        assert provider.casefold() in readme.casefold()

    for command in (
        "openbola",
        "openbola scan",
        "openbola setup",
        "openbola doctor",
        "openbola report RUN",
        "openbola update",
        "openbola mcp",
    ):
        assert command in readme
    for safety_phrase in (
        "ScopeGuard",
        "redirects are never followed implicitly",
        "credential vault",
        "mutation grant",
        "restore",
        "AI",
        "no target-network access",
        "append-only",
        "no telemetry",
    ):
        assert safety_phrase.casefold() in readme.casefold()
    assert "headless" in readme.casefold()
    assert "[CONTRIBUTING.md](CONTRIBUTING.md)" in readme
    assert "[SECURITY.md](SECURITY.md)" in readme

    limitations_start = readme.casefold().index("## limitations")
    limitations_end = readme.find("\n## ", limitations_start + 1)
    limitations = (
        readme[limitations_start:]
        if limitations_end == -1
        else readme[limitations_start:limitations_end]
    )
    assert "zero findings" in limitations.casefold()
    assert "not proof of safety" in limitations.casefold()

    assert "bola_checker" not in readme.casefold()
    assert "litellm" not in readme.casefold()
    assert "OpenBOLA scan" not in readme
    assert not re.search(r"https?://localhost(?::\d+)?(?:/|\b)", readme, re.IGNORECASE)
    assert not re.search(r"(?i)\b(?:bearer|cookie):\s*\S+", readme)
    assert not re.search(
        r"(?i)\b(?:api[_-]?key|token|password)\s*[=:]\s*['\"]?"
        r"[A-Za-z0-9+/._-]{12,}",
        readme,
    )
    assert not re.search(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
        readme,
        re.IGNORECASE,
    )
