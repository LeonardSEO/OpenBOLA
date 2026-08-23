from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from typer.testing import CliRunner

from bola_checker.cli import app
from bola_checker.mock_target import DEMO_OBJECT_ID, MockTarget


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
