from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from openbola.doctor import Diagnostic, DiagnosticReport, run_doctor
from openbola.state import StateStore


class _Recovery:
    def __init__(self, state: str) -> None:
        self.state = state

    def status(self) -> str:
        return self.state


def _ready_report(root: Path, *, recovery: str = "clear") -> DiagnosticReport:
    return run_doctor(
        data_root_path=root,
        browser_probe=lambda: True,
        vault_probe=lambda: True,
        package_probe=lambda: True,
        state_probe=lambda _path: True,
        recovery_gate=_Recovery(recovery),
        platform="darwin",
    )


def test_doctor_returns_sorted_bounded_json_without_local_path(tmp_path: Path) -> None:
    report = _ready_report(tmp_path)
    assert report.ok
    assert [item.name for item in report.diagnostics] == sorted(
        item.name for item in report.diagnostics
    )
    payload = report.to_json()
    assert json.loads(payload) == report.public_dict()
    assert str(tmp_path) not in payload
    assert "TOKEN" not in payload
    assert report.exit_code == 0


@pytest.mark.parametrize("state", ["required", "escalated"])
def test_recovery_warning_is_read_only_and_bounded(tmp_path: Path, state: str) -> None:
    report = _ready_report(tmp_path, recovery=state)
    recovery = next(item for item in report.diagnostics if item.name == "recovery")
    assert recovery.status == "warning"
    assert recovery.code == f"recovery_{state}"
    assert report.recovery_state == state
    assert report.exit_code == 0


def test_blocked_recovery_stops_assessment_but_keeps_diagnostics(tmp_path: Path) -> None:
    report = _ready_report(tmp_path, recovery="blocked")
    assert report.recovery_state == "blocked"
    assert report.blocked
    assert report.exit_code == 2
    assert {item.name for item in report.diagnostics} == {
        "browser",
        "data_root",
        "package",
        "platform",
        "recovery",
        "state",
        "vault",
    }


def test_missing_windows_environment_is_blocked_without_exposing_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    report = _ready_report(tmp_path)
    report = run_doctor(
        data_root_path=tmp_path,
        platform="win32",
        browser_probe=lambda: True,
        vault_probe=lambda: True,
        package_probe=lambda: True,
        state_probe=lambda _path: True,
        recovery_gate=_Recovery("clear"),
    )
    platform = next(item for item in report.diagnostics if item.name == "platform")
    assert platform.status == "blocked"
    assert platform.code == "localappdata_missing"
    assert str(tmp_path) not in report.to_json()


def test_unsupported_platform_and_missing_root_fail_closed(tmp_path: Path) -> None:
    report = run_doctor(
        data_root_path=tmp_path / "missing",
        platform="linux",
        browser_probe=lambda: (_ for _ in ()).throw(RuntimeError("SECRET")),
        vault_probe=lambda: (_ for _ in ()).throw(RuntimeError("TOKEN")),
        package_probe=lambda: True,
        state_probe=lambda _path: False,
        recovery_gate=_Recovery("clear"),
    )
    values = report.to_json()
    assert "SECRET" not in values and "TOKEN" not in values
    assert any(item.code == "platform_unsupported" for item in report.diagnostics)
    assert any(item.code == "data_root_missing" for item in report.diagnostics)


def test_probe_tuple_cannot_publish_arbitrary_detail(tmp_path: Path) -> None:
    report = run_doctor(
        data_root_path=tmp_path,
        platform="darwin",
        browser_probe=lambda: ("warning", "TOKEN_SECRET_VALUE"),
        vault_probe=lambda: True,
        package_probe=lambda: True,
        state_probe=lambda _path: True,
        recovery_gate=_Recovery("clear"),
    )
    browser = next(item for item in report.diagnostics if item.name == "browser")
    assert browser.code == "browser_unavailable"
    assert "TOKEN_SECRET_VALUE" not in report.to_json()


def test_symlinked_data_root_is_blocked(tmp_path: Path) -> None:
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    report = _ready_report(link)
    root = next(item for item in report.diagnostics if item.name == "data_root")
    assert root.status == "blocked"
    assert root.code == "data_root_symlink"


def test_non_directory_data_root_and_nonregular_state_are_blocked(tmp_path: Path) -> None:
    root_file = tmp_path / "root-file"
    root_file.write_text("not a directory", encoding="utf-8")
    report = _ready_report(root_file)
    root = next(item for item in report.diagnostics if item.name == "data_root")
    assert root.status == "blocked"
    assert root.code == "data_root_untrusted"

    state_dir = tmp_path / "state-dir"
    state_dir.mkdir()
    report = run_doctor(
        data_root_path=tmp_path,
        db_path=state_dir,
        browser_probe=lambda: True,
        vault_probe=lambda: True,
        recovery_gate=_Recovery("clear"),
        platform="darwin",
    )
    state = next(item for item in report.diagnostics if item.name == "state")
    assert state.status == "blocked"
    assert state.code == "state_not_regular"


def test_data_root_requires_private_leaf_mode(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o755)  # noqa: S103 - deliberately unprivate fixture
    report = _ready_report(tmp_path)
    root = next(item for item in report.diagnostics if item.name == "data_root")
    assert root.status == "blocked"
    assert root.code == "data_root_not_private"


def test_default_state_probe_is_read_only_and_checks_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    StateStore(db_path)
    before = db_path.stat().st_mtime_ns
    report = run_doctor(
        data_root_path=tmp_path,
        db_path=db_path,
        browser_probe=lambda: True,
        vault_probe=lambda: True,
        recovery_gate=_Recovery("clear"),
        platform="darwin",
    )
    state = next(item for item in report.diagnostics if item.name == "state")
    assert state.status == "ok"
    assert state.code == "state_ready"
    assert db_path.stat().st_mtime_ns == before


def test_default_state_probe_rejects_symlink_and_bad_schema(tmp_path: Path) -> None:
    target = tmp_path / "real.db"
    target.write_bytes(b"not sqlite")
    link = tmp_path / "state.db"
    link.symlink_to(target)
    report = run_doctor(
        data_root_path=tmp_path,
        db_path=link,
        browser_probe=lambda: True,
        vault_probe=lambda: True,
        recovery_gate=_Recovery("clear"),
        platform="darwin",
    )
    state = next(item for item in report.diagnostics if item.name == "state")
    assert state.status == "blocked" and state.code == "state_symlink"

    bad = tmp_path / "bad.db"
    with sqlite3.connect(bad) as connection:
        connection.execute("CREATE TABLE schema_version(singleton INTEGER, version INTEGER)")
        connection.execute("INSERT INTO schema_version VALUES (1, 2)")
    os.chmod(bad, 0o600)
    report = run_doctor(
        data_root_path=tmp_path,
        db_path=bad,
        browser_probe=lambda: True,
        vault_probe=lambda: True,
        recovery_gate=_Recovery("clear"),
        platform="darwin",
    )
    state = next(item for item in report.diagnostics if item.name == "state")
    assert state.code == "state_schema_mismatch"


def test_marker_and_default_probes_use_only_safe_statuses(tmp_path: Path) -> None:
    marker = tmp_path / "setup-status.json"
    marker.write_text(
        json.dumps(
            {
                "schema": "openbola-setup-v1",
                "version": "0.1.0",
                "browser": "already_ready",
                "vault": "ready",
                "self_test": "passed",
            }
        ),
        encoding="utf-8",
    )
    os.chmod(marker, 0o600)
    report = run_doctor(
        data_root_path=tmp_path,
        platform="darwin",
        recovery_gate=_Recovery("clear"),
    )
    codes = {item.name: item.code for item in report.diagnostics}
    assert codes["vault"] == "vault_ready"
    assert codes["browser"] in {"browser_ready", "browser_dependency_missing"}


def test_diagnostic_constructor_rejects_unbounded_protocol() -> None:
    with pytest.raises(ValueError):
        Diagnostic("unsafe name", "ok", "safe")
    with pytest.raises(ValueError):
        DiagnosticReport(
            (
                Diagnostic("state", "ok", "state_ready"),
                Diagnostic("browser", "ok", "browser_ready"),
            ),
            "clear",
        )
