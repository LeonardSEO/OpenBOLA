from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_reporting import _bundle

from openbola.reporting import write_reports
from openbola.reports import (
    MANIFEST_FILENAME,
    ReportError,
    ReportLocator,
    load_published_report,
    write_run_manifest,
)
from openbola.state import StateStore


def _private(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _published(root: Path, *, run_id: int = 7) -> Path:
    directory = root / "runs" / str(run_id)
    _private(directory.parent)
    write_reports(_bundle(), output_dir=directory)
    write_run_manifest(directory, run_id=run_id, created_at="2026-08-24T12:00:00+00:00")
    return directory


def _db(path: Path, run_id: int = 7) -> Path:
    store = StateStore(path)
    for _ in range(run_id):
        store.start_run("local-test")
    return path


def test_numeric_and_explicit_report_resolution_is_read_only(tmp_path: Path) -> None:
    root = _private(tmp_path / "data")
    directory = _published(root)
    db_path = _db(tmp_path / "state.db")
    before = db_path.stat().st_mtime_ns

    resolved = ReportLocator().resolve("7", db_path=db_path, data_root=root)
    assert resolved == directory
    assert ReportLocator().resolve(str(directory), db_path=db_path, data_root=root) == directory
    assert (
        ReportLocator().resolve("runs/7/report.json", db_path=db_path, data_root=root).name
        == "report.json"
    )
    assert db_path.stat().st_mtime_ns == before


def test_loader_rejects_missing_manifest_partial_bundle_and_schema(tmp_path: Path) -> None:
    root = _private(tmp_path / "data")
    directory = _published(root)
    (directory / MANIFEST_FILENAME).unlink()
    with pytest.raises(ReportError) as missing:
        load_published_report(directory)
    assert missing.value.code == "path_not_found"

    write_run_manifest(directory, run_id=7, created_at="2026-08-24T12:00:00+00:00")
    (directory / "report.csv").unlink()
    with pytest.raises(ReportError) as partial:
        load_published_report(directory)
    assert partial.value.code == "report_partial"

    directory = _published(root, run_id=8)
    payload = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    payload["format"] = "wrong-schema"
    (directory / "report.json").write_text(json.dumps(payload), encoding="utf-8")
    (directory / "report.json").chmod(0o600)
    with pytest.raises(ReportError) as schema:
        load_published_report(directory)
    assert schema.value.code == "report_schema_mismatch"


def test_loader_rejects_symlinks_non_private_artifacts_and_secret_sentinels(tmp_path: Path) -> None:
    root = _private(tmp_path / "data")
    directory = _published(root)
    target = tmp_path / "outside"
    target.write_bytes((directory / "report.json").read_bytes())
    target.chmod(0o600)
    (directory / "report.json").unlink()
    (directory / "report.json").symlink_to(target)
    with pytest.raises(ReportError) as link:
        load_published_report(directory)
    assert link.value.code == "path_symlink"

    directory = _published(root, run_id=8)
    payload = (directory / "report.json").read_text(encoding="utf-8").replace(
        "Example staging API", "RAW_ID"
    )
    (directory / "report.json").write_text(payload, encoding="utf-8")
    (directory / "report.json").chmod(0o600)
    with pytest.raises(ReportError) as sentinel:
        load_published_report(directory)
    assert sentinel.value.code == "report_unsafe"

    directory = _published(root, run_id=9)
    (directory / "report.json").chmod(0o640)
    with pytest.raises(ReportError) as private:
        load_published_report(directory)
    assert private.value.code == "path_not_private"


@pytest.mark.parametrize("format_name", ["json", "html", "junit", "markdown", "csv", "sarif"])
def test_every_p7_artifact_is_reopened_without_returning_raw_text(
    tmp_path: Path, format_name: str
) -> None:
    root = _private(tmp_path / "data")
    directory = _published(root)
    path = directory / {
        "json": "report.json",
        "html": "report.html",
        "junit": "junit.xml",
        "markdown": "report.md",
        "csv": "report.csv",
        "sarif": "report.sarif",
    }[format_name]
    loaded = load_published_report(path)
    assert isinstance(loaded, dict)
    assert "RAW_ID" not in repr(loaded)


def test_numeric_run_without_manifest_or_unknown_run_is_not_guessed(tmp_path: Path) -> None:
    root = _private(tmp_path / "data")
    db_path = _db(tmp_path / "state.db", run_id=1)
    with pytest.raises(ReportError) as missing:
        ReportLocator().resolve("1", db_path=db_path, data_root=root)
    assert missing.value.code == "run_not_found"
    with pytest.raises(ReportError) as unknown:
        ReportLocator().resolve("7", db_path=db_path, data_root=root)
    assert unknown.value.code == "run_not_found"


def test_locator_rejects_traversal_and_outside_absolute_path(tmp_path: Path) -> None:
    root = _private(tmp_path / "data")
    db_path = _db(tmp_path / "state.db")
    with pytest.raises(ReportError) as traversal:
        ReportLocator().resolve("../data", db_path=db_path, data_root=root)
    assert traversal.value.code == "path_traversal"
    with pytest.raises(ReportError) as outside:
        ReportLocator().resolve(str(tmp_path / "outside"), db_path=db_path, data_root=root)
    assert outside.value.code == "path_denied"
