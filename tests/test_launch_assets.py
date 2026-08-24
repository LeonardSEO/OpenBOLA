from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from scripts.check_launch_assets import APPROVED_PALETTE, validate_asset

ROOT = Path(__file__).parents[1]
ASSETS = ROOT / "docs" / "assets"


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
