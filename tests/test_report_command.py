from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_reporting import _bundle
from typer.testing import CliRunner

from openbola.cli import app
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
    write_run_manifest(directory, run_id=run_id)
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
    before = (db_path.stat().st_mtime_ns, db_path.stat().st_size, db_path.read_bytes())
    sidecars = (db_path.with_name(f"{db_path.name}-wal"), db_path.with_name(f"{db_path.name}-shm"))
    for sidecar in sidecars:
        assert not sidecar.exists()

    resolved = ReportLocator().resolve("7", db_path=db_path, data_root=root)
    assert resolved == directory
    assert ReportLocator().resolve(str(directory), db_path=db_path, data_root=root) == directory
    assert (
        ReportLocator().resolve("runs/7/report.json", db_path=db_path, data_root=root).name
        == "report.json"
    )
    assert (db_path.stat().st_mtime_ns, db_path.stat().st_size, db_path.read_bytes()) == before
    for sidecar in sidecars:
        assert not sidecar.exists()


def test_loader_rejects_missing_manifest_partial_bundle_and_schema(tmp_path: Path) -> None:
    root = _private(tmp_path / "data")
    directory = _published(root)
    (directory / MANIFEST_FILENAME).unlink()
    with pytest.raises(ReportError) as missing:
        load_published_report(directory)
    assert missing.value.code == "path_not_found"

    write_run_manifest(directory, run_id=7)
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


def test_loader_rejects_unknown_nested_fields_and_non_private_ancestor(
    tmp_path: Path,
) -> None:
    root = _private(tmp_path / "data")
    nested = root / "nested"
    nested.mkdir()
    nested.chmod(0o755)
    directory = nested / "run"
    write_reports(_bundle(), output_dir=directory)
    write_run_manifest(directory, run_id=7)
    with pytest.raises(ReportError) as private:
        ReportLocator().resolve(
            "nested/run", db_path=_db(tmp_path / "state.db", run_id=7), data_root=root
        )
    assert private.value.code == "path_not_private"

    nested.chmod(0o700)
    payload = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    payload["findings"][0]["unexpected"] = "value"
    (directory / "report.json").write_text(json.dumps(payload), encoding="utf-8")
    (directory / "report.json").chmod(0o600)
    with pytest.raises(ReportError) as unknown:
        load_published_report(directory)
    assert unknown.value.code == "report_schema_mismatch"

    payload = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    payload["findings"][0]["evidence"]["cleanup"] = []
    (directory / "report.json").write_text(json.dumps(payload), encoding="utf-8")
    (directory / "report.json").chmod(0o600)
    with pytest.raises(ReportError) as malformed:
        load_published_report(directory)
    assert malformed.value.code == "report_schema_mismatch"


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


def test_manifest_publication_is_no_replace_and_cleans_stage(tmp_path: Path) -> None:
    root = _private(tmp_path / "data")
    directory = _published(root)
    with pytest.raises(ReportError) as duplicate:
        write_run_manifest(directory, run_id=7)
    assert duplicate.value.code == "manifest_exists"
    assert not (directory / ".manifest.json.stage").exists()


def test_report_cli_returns_only_safe_summary_and_artifact_metadata(tmp_path: Path) -> None:
    root = _private(tmp_path / "data")
    _published(root)
    db_path = _db(tmp_path / "state.db")
    result = CliRunner().invoke(
        app,
        [
            "report",
            "7",
            "--db",
            str(db_path),
            "--data-root",
            str(root),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["artifact"] == "report.json"
    assert payload["summary"]["bola"] == 1
    assert "outcomes" not in payload


def test_sarif_and_html_unknown_or_malformed_content_fails_closed(tmp_path: Path) -> None:
    root = _private(tmp_path / "data")
    directory = _published(root)
    sarif = json.loads((directory / "report.sarif").read_text(encoding="utf-8"))
    sarif["runs"][0]["unexpected"] = "value"
    (directory / "report.sarif").write_text(json.dumps(sarif), encoding="utf-8")
    (directory / "report.sarif").chmod(0o600)
    with pytest.raises(ReportError) as sarif_error:
        load_published_report(directory / "report.sarif")
    assert sarif_error.value.code == "report_schema_mismatch"

    directory = _published(root, run_id=8)
    (directory / "report.html").write_text(
        "<!doctype html><html><body><p>unclosed</body></html>", encoding="utf-8"
    )
    (directory / "report.html").chmod(0o600)
    with pytest.raises(ReportError) as html_error:
        load_published_report(directory / "report.html")
    assert html_error.value.code == "report_malformed"


def test_stale_manifest_is_rejected_when_artifacts_are_newer(tmp_path: Path) -> None:
    root = _private(tmp_path / "data")
    directory = _published(root)
    manifest = json.loads((directory / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    manifest["created_at"] = "2000-01-01T00:00:00+00:00"
    (directory / MANIFEST_FILENAME).write_text(json.dumps(manifest), encoding="utf-8")
    (directory / MANIFEST_FILENAME).chmod(0o600)
    with pytest.raises(ReportError) as stale:
        load_published_report(directory)
    assert stale.value.code == "manifest_stale"


def test_report_display_text_rejects_secret_like_scope_label(tmp_path: Path) -> None:
    root = _private(tmp_path / "data")
    directory = _published(root)
    payload = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    payload["scope"]["target_label"] = "token: TOPSECRET"
    (directory / "report.json").write_text(json.dumps(payload), encoding="utf-8")
    (directory / "report.json").chmod(0o600)
    with pytest.raises(ReportError) as secret:
        load_published_report(directory)
    assert secret.value.code == "report_unsafe"
