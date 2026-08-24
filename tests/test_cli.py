from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

import openbola.cli as cli_module
from openbola import __version__
from openbola.cli import app
from openbola.doctor import Diagnostic, DiagnosticReport
from openbola.mcp_server import MCPServiceError
from openbola.mock_target import DEMO_OBJECT_ID, MockTarget
from openbola.scope import ScopeGuard
from openbola.setup import SetupResult
from openbola.updates import UpdateResult


def _scope(path: Path) -> Path:
    now = datetime.now(UTC)
    path.write_text(
        yaml.safe_dump(
            {
                "client_name": "CLI fixture",
                "authorization_reference": "CLI-AUTHZ",
                "confirmed": True,
                "starts_at": (now - timedelta(minutes=1)).isoformat(),
                "expires_at": (now + timedelta(minutes=5)).isoformat(),
                "allowed_hosts": [],
                "allowed_cidrs": ["127.0.0.0/8"],
                "allowed_paths": ["glob:/api/**"],
                "read_methods": ["GET"],
                "mutation_grants": [],
            }
        ),
        encoding="utf-8",
    )
    return path


def _har(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "http://127.0.0.1:8899/api/documents/812",
                                "headers": [
                                    {"name": "Authorization", "value": "Bearer CLI_SECRET"}
                                ],
                            },
                            "response": {"status": 200, "headers": []},
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )


def test_cli_json_mode_is_machine_safe_and_requires_explicit_credentials(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    alice, bob = root / "alice.har", root / "bob.har"
    _har(alice)
    _har(bob)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--scope",
            str(_scope(root / "scope.yaml")),
            "--base-url",
            "http://127.0.0.1:8899",
            "--identity",
            f"alice={alice}",
            "--identity",
            f"bob={bob}",
            "--credential",
            "alice=BOLA_ALICE_TOKEN",
            "--credential",
            "bob=BOLA_BOB_TOKEN",
            "--db",
            str(root / "state.db"),
            "--report-dir",
            str(root / "reports"),
            "--json",
        ],
        env={"BOLA_ALICE_TOKEN": "CLI_SECRET_A", "BOLA_BOB_TOKEN": "CLI_SECRET_B"},
    )
    assert result.exit_code == 0, result.stdout
    document = json.loads(result.stdout)
    assert document["outcomes"]["bola"] == 0
    assert document["outcomes"]["protected"] == 0
    assert document["skipped_candidates"] == 1
    assert document["skip_reasons"]["no_strong_ownership_evidence"] == 1
    assert set(document["reports"]) == {"json", "markdown", "csv", "html", "junit", "sarif"}
    assert {Path(path).name for path in document["reports"].values()} == {
        "report.json",
        "report.md",
        "report.csv",
        "report.html",
        "junit.xml",
        "report.sarif",
    }
    assert "CLI_SECRET" not in result.stdout


def test_cli_records_json_can_execute_path_evidence_against_local_mock(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    with MockTarget() as target:
        def write_records(path: Path, identity: str, *, secure_status: int) -> None:
            path.write_text(
                json.dumps(
                    [
                        {
                            "url": f"{target.base_url}/api/documents/{DEMO_OBJECT_ID}",
                            "method": "GET",
                            "headers": {},
                            "response_status": 200,
                            "response_body": {"id": DEMO_OBJECT_ID, "owner_id": "alice"},
                        },
                        {
                            "url": f"{target.base_url}/api/secure/{DEMO_OBJECT_ID}",
                            "method": "GET",
                            "headers": {},
                            "response_status": secure_status,
                            "response_body": (
                                {"id": DEMO_OBJECT_ID, "owner_id": "alice"}
                                if identity == "alice"
                                else None
                            ),
                        },
                    ]
                ),
                encoding="utf-8",
            )
        alice, bob = root / "alice.json", root / "bob.json"
        write_records(alice, "alice", secure_status=200)
        write_records(bob, "bob", secure_status=403)
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--scope",
                str(_scope(root / "scope.yaml")),
                "--base-url",
                target.base_url,
                "--identity",
                f"alice={alice}",
                "--identity",
                f"bob={bob}",
                "--credential",
                "alice=BOLA_ALICE_TOKEN",
                "--credential",
                "bob=BOLA_BOB_TOKEN",
                "--db",
                str(root / "state.db"),
                "--report-dir",
                str(root / "reports"),
                "--json",
            ],
            env={
                "BOLA_ALICE_TOKEN": target.alice_token,
                "BOLA_BOB_TOKEN": target.bob_token,
            },
        )
    assert result.exit_code == 0, result.stdout
    document = json.loads(result.stdout)
    assert document["outcomes"]["bola"] == 1
    assert document["outcomes"]["protected"] == 1
    assert target.alice_token not in result.stdout
    assert target.bob_token not in result.stdout


def test_cli_rejects_missing_scope_without_network_output(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--scope",
            str(root / "missing.yaml"),
            "--base-url",
            "http://127.0.0.1:8899",
            "--identity",
            "alice=/missing.har",
            "--identity",
            "bob=/missing.har",
            "--credential",
            "alice=BOLA_ALICE_TOKEN",
            "--credential",
            "bob=BOLA_BOB_TOKEN",
            "--json",
        ],
    )
    assert result.exit_code != 0
    assert "BOLA_ALICE_TOKEN" not in result.stdout


def test_cli_json_rejects_missing_or_symlinked_database_parent(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    alice, bob = root / "alice.har", root / "bob.har"
    _har(alice)
    _har(bob)
    common = [
        "scan",
        "--scope",
        str(_scope(root / "scope.yaml")),
        "--base-url",
        "http://127.0.0.1:8899",
        "--identity",
        f"alice={alice}",
        "--identity",
        f"bob={bob}",
        "--credential",
        "alice=BOLA_ALICE_TOKEN",
        "--credential",
        "bob=BOLA_BOB_TOKEN",
        "--report-dir",
        str(root / "reports"),
        "--json",
    ]
    runner = CliRunner()
    missing = runner.invoke(app, [*common, "--db", str(root / "missing" / "state.db")])
    assert missing.exit_code == 2
    assert json.loads(missing.stdout) == {"ok": False, "error": "scan_denied"}
    real = root / "real"
    real.mkdir()
    link = root / "link"
    os.symlink(real, link)
    linked = runner.invoke(app, [*common, "--db", str(link / "state.db")])
    assert linked.exit_code == 2
    assert json.loads(linked.stdout) == {"ok": False, "error": "scan_denied"}


def test_cli_json_rejects_deep_records_without_traceback(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    nested: object = "leaf"
    for _ in range(40):
        nested = {"nested": nested}
    payload = [
        {
            "url": "http://127.0.0.1:8899/api/documents/812",
            "method": "GET",
            "headers": {},
            "response_status": 200,
            "response_body": nested,
        }
    ]
    alice, bob = root / "alice.json", root / "bob.json"
    alice.write_text(json.dumps(payload), encoding="utf-8")
    bob.write_text(json.dumps(payload), encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--scope",
            str(_scope(root / "scope.yaml")),
            "--base-url",
            "http://127.0.0.1:8899",
            "--identity",
            f"alice={alice}",
            "--identity",
            f"bob={bob}",
            "--credential",
            "alice=BOLA_ALICE_TOKEN",
            "--credential",
            "bob=BOLA_BOB_TOKEN",
            "--db",
            str(root / "state.db"),
            "--report-dir",
            str(root / "reports"),
            "--json",
        ],
        env={"BOLA_ALICE_TOKEN": "runtime-a", "BOLA_BOB_TOKEN": "runtime-b"},
    )
    assert result.exit_code == 2
    assert json.loads(result.stdout) == {"ok": False, "error": "scan_denied"}


def test_admin_commands_and_version_are_registered_without_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()
    version = runner.invoke(app, ["--version"])
    assert version.exit_code == 0
    assert version.stdout.strip() == __version__

    help_result = runner.invoke(app, ["--help"])
    assert help_result.exit_code == 0
    for command in ("setup", "doctor", "report", "update", "mcp"):
        assert command in help_result.stdout

    monkeypatch.setattr(
        cli_module,
        "run_doctor",
        lambda **kwargs: DiagnosticReport(
            (Diagnostic("platform", "ok", "platform_supported"),), "clear"
        ),
    )
    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "diagnostics": [{"code": "platform_supported", "name": "platform", "status": "ok"}],
        "ok": True,
        "recovery_state": "clear",
    }
    assert "SECRET" not in result.stdout


def test_setup_json_is_bounded_and_forwards_force_browser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[bool] = []

    def fake_setup(*, force_browser: bool) -> SetupResult:
        calls.append(force_browser)
        return SetupResult("already_ready", "ready", "passed")

    monkeypatch.setattr(cli_module, "run_setup", fake_setup)
    result = CliRunner().invoke(app, ["setup", "--force-browser", "--json"])
    assert result.exit_code == 0
    assert calls == [True]
    assert json.loads(result.stdout) == {
        "browser": "already_ready",
        "ok": True,
        "self_test": "passed",
        "vault": "ready",
    }


def test_setup_failure_hides_untrusted_reason_in_both_output_modes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "SETUP_LOCAL_SECRET_SENTINEL"
    monkeypatch.setattr(
        cli_module,
        "run_setup",
        lambda *, force_browser: SetupResult(
            "unavailable", "unavailable", "failed", sentinel
        ),
    )
    json_result = CliRunner().invoke(app, ["setup", "--json"])
    rich_result = CliRunner().invoke(app, ["setup"])
    assert json_result.exit_code == 2
    assert rich_result.exit_code == 2
    assert sentinel not in json_result.stdout
    assert sentinel not in rich_result.stdout
    assert json.loads(json_result.stdout) == {
        "browser": "unavailable",
        "ok": False,
        "self_test": "failed",
        "vault": "unavailable",
    }


def test_doctor_blocked_report_preserves_diagnostics_and_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = DiagnosticReport(
        (Diagnostic("recovery", "blocked", "recovery_blocked"),), "blocked"
    )
    monkeypatch.setattr(cli_module, "run_doctor", lambda **kwargs: report)
    result = CliRunner().invoke(app, ["doctor", "--db", "state.db", "--json"])
    assert result.exit_code == 2
    assert json.loads(result.stdout) == {
        "diagnostics": [
            {"code": "recovery_blocked", "name": "recovery", "status": "blocked"}
        ],
        "ok": False,
        "recovery_state": "blocked",
    }


def test_doctor_service_exception_is_generic_without_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "DOCTOR_LOCAL_SECRET_SENTINEL"

    def fail(**kwargs: object) -> DiagnosticReport:
        raise RuntimeError(sentinel)

    monkeypatch.setattr(cli_module, "run_doctor", fail)
    result = CliRunner().invoke(app, ["doctor", "--json"])
    assert result.exit_code == 2
    assert json.loads(result.stdout) == {"ok": False, "error": "diagnostics_blocked"}
    assert sentinel not in result.stdout


def test_mcp_command_starts_renamed_read_only_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, object] = {}

    class FakeServer:
        def run(self, **kwargs: object) -> None:
            calls["run"] = kwargs

    def fake_factory(*, read_only: bool = False) -> FakeServer:
        calls["read_only"] = read_only
        return FakeServer()

    monkeypatch.setattr(cli_module, "create_mcp_server", fake_factory)

    result = CliRunner().invoke(app, ["mcp", "--json"])

    assert result.exit_code == 0, result.stdout
    assert calls == {"read_only": True, "run": {"transport": "stdio"}}
    assert result.stdout == ""


def test_mcp_command_maps_optional_or_transport_failures_to_safe_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_factory(*, read_only: bool = False) -> object:
        del read_only
        raise MCPServiceError("MCP_SECRET_SENTINEL local path")

    monkeypatch.setattr(cli_module, "create_mcp_server", fail_factory)

    result = CliRunner().invoke(app, ["mcp", "--json"])

    assert result.exit_code == 2
    assert json.loads(result.stdout) == {"ok": False, "error": "mcp_unavailable"}
    assert "MCP_SECRET_SENTINEL" not in result.stdout
    assert "local path" not in result.stdout


def test_update_check_maps_bounded_available_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "check_for_update",
        lambda *, force_check: UpdateResult("available", "0.1.0", "0.1.1"),
    )
    result = CliRunner().invoke(app, ["update", "--check", "--json", "--force-check"])
    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "candidate_version": "0.1.1",
        "current_version": "0.1.0",
        "ok": True,
        "status": "available",
    }


def test_update_scope_option_loads_confirmed_guard_for_distribution_check(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    seen: list[ScopeGuard] = []

    def fake_check(*, force_check: bool, scope_guard: ScopeGuard) -> UpdateResult:
        assert force_check is True
        seen.append(scope_guard)
        return UpdateResult("available", "0.1.0", "0.1.1")

    monkeypatch.setattr(cli_module, "check_for_update", fake_check)
    scope_path = _scope(tmp_path / "distribution-scope.yaml")
    result = CliRunner().invoke(
        app,
        [
            "update",
            "--check",
            "--force-check",
            "--distribution-scope",
            str(scope_path),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert len(seen) == 1
    assert seen[0].scope_digest
    assert json.loads(result.stdout)["status"] == "available"


def test_update_scope_option_rejects_invalid_scope_before_service_call(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    called = False

    def fake_check(*, force_check: bool) -> UpdateResult:
        nonlocal called
        called = True
        return UpdateResult("available", "0.1.0", "0.1.1")

    monkeypatch.setattr(cli_module, "check_for_update", fake_check)
    result = CliRunner().invoke(
        app,
        [
            "update",
            "--check",
            "--scope",
            str(tmp_path / "missing-scope.yaml"),
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert json.loads(result.stdout) == {"ok": False, "error": "update_denied"}
    assert called is False


def test_update_apply_maps_denial_without_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "RELEASE_RESPONSE_SECRET_SENTINEL"
    monkeypatch.setattr(
        cli_module,
        "apply_update",
        lambda *, confirm: UpdateResult("denied", "0.1.0", "0.1.1", sentinel),
    )
    result = CliRunner().invoke(app, ["update", "--json"])
    assert result.exit_code == 2
    document = json.loads(result.stdout)
    assert document["ok"] is False
    assert document["error"] == "update_denied"
    assert sentinel not in result.stdout


def test_update_service_exception_is_generic_in_both_output_modes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "LOCAL_UPDATE_SECRET_SENTINEL"

    def fail(*, confirm: bool) -> UpdateResult:
        raise RuntimeError(sentinel)

    monkeypatch.setattr(cli_module, "apply_update", fail)
    json_result = CliRunner().invoke(app, ["update", "--yes", "--json"])
    rich_result = CliRunner().invoke(app, ["update", "--yes"])
    assert json_result.exit_code == 2
    assert rich_result.exit_code == 2
    assert json.loads(json_result.stdout) == {"ok": False, "error": "update_denied"}
    assert sentinel not in json_result.stdout
    assert sentinel not in rich_result.stdout
