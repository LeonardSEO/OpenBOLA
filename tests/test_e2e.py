from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from openbola.mock_target import DEMO_OBJECT_ID, MockTarget
from openbola.models import RequestRecord, Verdict
from openbola.pipeline import IdentityInput, PipelineError, run_pipeline


def _scope(
    path: Path,
    *,
    paths: list[str] | None = None,
    confirmed: bool = True,
    expires_seconds: int = 300,
) -> Path:
    now = datetime.now(UTC)
    document = {
        "client_name": "OpenBOLA local E2E",
        "authorization_reference": "LOCAL-E2E-AUTHZ",
        "confirmed": confirmed,
        "starts_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(seconds=expires_seconds)).isoformat(),
        "allowed_hosts": [],
        "allowed_cidrs": ["127.0.0.0/8"],
        "allowed_paths": paths or ["glob:/api/**"],
        "read_methods": ["GET"],
        "mutation_grants": [],
    }
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _record(
    identity: str,
    base_url: str,
    path: str,
    token: str,
    *,
    status: int = 200,
    body: dict[str, str] | None = None,
) -> RequestRecord:
    return RequestRecord(
        identity=identity,
        method="GET",
        url=base_url + path,
        headers={"Authorization": f"Bearer {token}"},
        response_status=status,
        response_headers={"content-type": "application/json"},
        response_body=body,
    )


def _inputs(target: MockTarget) -> list[IdentityInput]:
    base_url = target.base_url
    return [
        IdentityInput(
            "alice",
            records=(
                _record(
                    "alice",
                    base_url,
                    f"/api/documents/{DEMO_OBJECT_ID}",
                    target.alice_token,
                    body={"id": DEMO_OBJECT_ID, "owner_id": "alice"},
                ),
                _record(
                    "alice",
                    base_url,
                    f"/api/secure/{DEMO_OBJECT_ID}",
                    target.alice_token,
                    body={"id": DEMO_OBJECT_ID, "owner_id": "alice"},
                ),
            ),
        ),
        IdentityInput(
            "bob",
            records=(
                _record(
                    "bob",
                    base_url,
                    f"/api/documents/{DEMO_OBJECT_ID}",
                    target.bob_token,
                    body={"id": DEMO_OBJECT_ID, "owner_id": "alice"},
                ),
                _record(
                    "bob",
                    base_url,
                    f"/api/secure/{DEMO_OBJECT_ID}",
                    target.bob_token,
                    status=403,
                ),
            ),
        ),
    ]


def test_local_mock_e2e_finds_bola_and_protected_without_secret_material(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    with MockTarget() as target:
        result = run_pipeline(
            _scope(root / "scope.yaml"),
            target.base_url,
            _inputs(target),
            root / "state.db",
            root / "reports",
        )

    assert {outcome.verdict for outcome in result.outcomes} == {
        Verdict.BOLA,
        Verdict.PROTECTED,
    }
    assert len(result.report_paths) == 4
    assert all(path.is_file() for path in result.report_paths.values())
    assert result.report_paths["json"].parent.is_dir()

    material = b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file())
    assert target.alice_token.encode() not in material
    assert target.bob_token.encode() not in material
    assert DEMO_OBJECT_ID.encode() not in material
    report = json.loads(result.report_paths["json"].read_text(encoding="utf-8"))
    assert report["summary"]["bola"] == 1
    assert report["summary"]["protected"] == 1
    assert "Zero findings does not mean" not in result.report_paths["markdown"].read_text(
        encoding="utf-8"
    )


def test_scope_invalid_or_out_of_scope_fails_closed(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    with MockTarget() as target:
        with pytest.raises(PipelineError):
            run_pipeline(
                _scope(root / "invalid.yaml", confirmed=False),
                target.base_url,
                _inputs(target),
                root / "invalid.db",
                root / "invalid-reports",
            )
        with pytest.raises(PipelineError):
            run_pipeline(
                _scope(root / "valid.yaml"),
                "http://192.0.2.55:443",
                _inputs(target),
                root / "out.db",
                root / "out-reports",
            )


def test_mixed_origins_fail_closed_before_any_probe(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    with MockTarget() as target:
        inputs = _inputs(target)
        bob_records = tuple(
            replace(record, url=record.url.replace("127.0.0.1", "127.0.0.2"))
            for record in inputs[1].records
        )
        mixed = [inputs[0], IdentityInput("bob", records=bob_records)]
        with pytest.raises(PipelineError, match="exact base URL origin"):
            run_pipeline(
                _scope(root / "mixed.yaml"),
                target.base_url,
                mixed,
                root / "mixed.db",
                root / "mixed-reports",
            )
        assert target.request_count == 0


def test_pipeline_samples_callable_clock_for_attacker_request(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    with MockTarget() as target:
        scope = _scope(root / "expiring.yaml", expires_seconds=1)
        initial = datetime.now(UTC)
        calls = 0

        def advancing_clock() -> datetime:
            nonlocal calls
            calls += 1
            # Scope loading, import checks, and the owner request are valid;
            # the next sample expires before the attacker request.
            return initial if calls <= 5 else initial + timedelta(seconds=10)

        inputs = [replace(identity, records=(identity.records[0],)) for identity in _inputs(target)]
        result = run_pipeline(
            scope,
            target.base_url,
            inputs,
            root / "expiring.db",
            root / "expiring-reports",
            now=advancing_clock,
        )

    assert len(result.outcomes) == 1
    outcome = result.outcomes[0]
    assert outcome.verdict is Verdict.INCONCLUSIVE
    assert outcome.owner_status == 200
    assert outcome.attacker_status is None
    assert outcome.evidence["error_code"] == "scope_denied"
    assert target.request_count == 1


def test_non_path_candidates_are_skipped_without_requests(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    with MockTarget() as target:
        records = [
            RequestRecord(
                identity="alice",
                method="GET",
                url=target.base_url + "/api/search?document_id=" + DEMO_OBJECT_ID,
                headers={"Authorization": "Bearer " + target.alice_token},
                response_status=200,
                response_body={"id": DEMO_OBJECT_ID, "owner_id": "alice"},
            ),
            RequestRecord(
                identity="bob",
                method="GET",
                url=target.base_url + "/api/search?document_id=" + DEMO_OBJECT_ID,
                headers={"Authorization": "Bearer " + target.bob_token},
                response_status=200,
                response_body={"id": DEMO_OBJECT_ID, "owner_id": "alice"},
            ),
        ]
        result = run_pipeline(
            _scope(root / "query.yaml"),
            target.base_url,
            [
                IdentityInput("alice", records=[records[0]]),
                IdentityInput("bob", records=[records[1]]),
            ],
            root / "query.db",
            root / "query-reports",
        )
        assert result.outcomes == ()
        assert result.skipped_candidates == 1
        assert result.skip_reasons == {"non_path_or_multiple_placeholders": 1}
        assert target.request_count == 0
        report = result.report_paths["markdown"].read_text(encoding="utf-8")
        assert "non path or multiple placeholders" in report


def test_pipeline_normalizes_relative_database_and_rejects_symlink_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path.resolve()
    with MockTarget() as target:
        monkeypatch.chdir(root)
        run_pipeline(
            _scope(root / "scope.yaml"),
            target.base_url,
            _inputs(target),
            "state.db",
            root / "reports-relative",
        )
        real = root / "real"
        real.mkdir()
        link = root / "link"
        link.symlink_to(real, target_is_directory=True)
        with pytest.raises(PipelineError, match="new database path"):
            run_pipeline(
                _scope(root / "scope-2.yaml"),
                target.base_url,
                _inputs(target),
                root / "state.db",
                root / "reports-2",
            )
        with pytest.raises(PipelineError, match="real directory"):
            run_pipeline(
                _scope(root / "scope-3.yaml"),
                target.base_url,
                _inputs(target),
                link / "state.db",
                root / "reports-3",
            )
def test_zero_tests_are_reported_as_zero_tests(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    with MockTarget() as target:
        records = [
            _record(
                "alice",
                target.base_url,
                f"/api/documents/{DEMO_OBJECT_ID}",
                target.alice_token,
                body={"id": DEMO_OBJECT_ID},
            ),
            _record(
                "bob",
                target.base_url,
                f"/api/documents/{DEMO_OBJECT_ID}",
                target.bob_token,
                body={"name": "not ownership evidence"},
            ),
        ]
        result = run_pipeline(
            _scope(root / "scope.yaml"),
            target.base_url,
            [
                IdentityInput("alice", records=[records[0]]),
                IdentityInput("bob", records=[records[1]]),
            ],
            root / "state.db",
            root / "reports",
        )
    assert result.outcomes == ()
    markdown = result.report_paths["markdown"].read_text(encoding="utf-8")
    assert "Executed outcomes | 0" in markdown
    assert "Zero findings does not mean this target was tested." in markdown
