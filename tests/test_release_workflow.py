from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]


def test_release_workflow_is_tagged_native_and_protected() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text())
    trigger = workflow.get("on", workflow.get(True))
    assert "workflow_dispatch" in trigger
    assert trigger["push"]["tags"] == ["v*"]
    build = workflow["jobs"]["build"]
    hosts = {item["os"] for item in build["strategy"]["matrix"]["include"]}
    assert hosts == {"windows-2022", "macos-14", "macos-13"}
    publish = workflow["jobs"]["publish"]
    assert publish["environment"] == "release"
    assert "startsWith(github.ref, 'refs/tags/v')" in publish["if"]
