from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from scripts.check_demo_transcript import validate_transcript

ROOT = Path(__file__).parents[1]
TRANSCRIPT = ROOT / "examples" / "demo" / "openbola-demo.cast"


def test_demo_transcript_is_valid_and_deterministic() -> None:
    validate_transcript(TRANSCRIPT)
    lines = TRANSCRIPT.read_text(encoding="utf-8").splitlines()
    assert "timestamp" not in lines[0]
    assert all(json.loads(line)[1] == "o" for line in lines[1:])


@pytest.mark.parametrize(
    "unsafe",
    [
        "Authorization: Bearer super-secret-token",
        "Cookie: session=secret",
        "raw object id: 123e4567-e89b-12d3-a456-426614174000",
        "https://attacker.example.test/api/documents",
        "/Users/leonard/private/scope.yaml",
    ],
)
def test_demo_transcript_rejects_sensitive_or_external_output(tmp_path: Path, unsafe: str) -> None:
    lines = TRANSCRIPT.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[2])
    event[2] = unsafe
    candidate = tmp_path / "unsafe.cast"
    candidate.write_text(
        "\n".join([lines[0], lines[1], json.dumps(event), *lines[3:]]) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="^demo transcript validation failed$"):
        validate_transcript(candidate)
