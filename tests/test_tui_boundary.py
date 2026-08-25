"""Boundary checks: the TUI only delegates typed calls and bounded labels."""

from __future__ import annotations

import ast
from pathlib import Path

from openbola import recovery
from openbola.mutations import RecoveryStatus
from openbola.tui import _default_recovery_callbacks


def test_tui_does_not_import_or_construct_a_network_client() -> None:
    tree = ast.parse(Path("src/openbola/tui.py").read_text(encoding="utf-8"))
    imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    names = {
        alias.name.split(".")[0]
        for node in imports
        for alias in node.names
    }
    assert "httpx" not in names
    assert "requests" not in names


def test_tui_source_has_no_known_secret_or_raw_value_rendering_paths() -> None:
    source = Path("src/openbola/tui.py").read_text(encoding="utf-8")
    assert "response_body" not in source
    assert "object_id" not in source
    assert "clipboard" not in source


def test_default_tui_recovery_uses_central_gate_and_refreshes_status(
    monkeypatch,
) -> None:
    class Gate:
        def recovery_status(self):
            return RecoveryStatus("required", True, "journal_present")

    called = []
    monkeypatch.setattr(recovery, "default_recovery_gate", lambda: called.append(True) or Gate())
    status, recover, escalate = _default_recovery_callbacks()
    assert called == [True]
    assert status() == RecoveryStatus("required", True, "journal_present")
    assert recover().state == "blocked"
    assert escalate().state == "blocked"
