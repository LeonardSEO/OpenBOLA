from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from openbola.handles import ValueHandle
from openbola.models import CredentialKind, CredentialRef, ProbeMode, ProbeTarget
from openbola.mutations import (
    MAX_MUTATION_REQUESTS,
    MutationCandidate,
    MutationCandidateInventory,
    MutationOperation,
    MutationPreflightError,
    MutationSweepExecutor,
    preflight_sweep,
)
from openbola.scope import MutationRecordScope, ScopeGuard

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)


def _scope_file(
    path: Path,
    *,
    record_scope: str = "all_discovered",
    methods: list[str] | None = None,
    allowed_fields: list[str] | None = None,
    path_patterns: list[str] | None = None,
    max_records: int = 100,
    max_requests: int = 500,
) -> Path:
    document: dict[str, Any] = {
        "client_name": "Mutation fixture",
        "authorization_reference": "TEST-MUTATION",
        "confirmed": True,
        "starts_at": "2026-08-23T10:00:00Z",
        "expires_at": "2026-08-30T14:00:00Z",
        "allowed_hosts": [],
        "allowed_cidrs": ["127.0.0.0/8"],
        "allowed_paths": ["glob:/v1/**"],
        "read_methods": ["GET", "HEAD", "OPTIONS"],
        "mutation_grants": [
            {
                "methods": methods or ["PATCH"],
                "path_patterns": path_patterns or ["glob:/v1/users/*"],
                "allowed_fields": allowed_fields or ["email"],
                "record_scope": record_scope,
                "max_records": max_records,
                "max_requests": max_requests,
                "allow_canary_create_delete": False,
            }
        ],
    }
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _guard(tmp_path: Path, **kwargs: Any) -> ScopeGuard:
    return ScopeGuard.from_file(_scope_file(tmp_path / "scope.yaml", **kwargs), now=NOW)


def _candidate(
    *,
    record: str = "record-1",
    field: str = "email",
    object_id: str = "one",
    endpoint: str = "/v1/users/{id}",
    method: str = "PATCH",
    owner: str = "owner",
    attacker: str = "attacker",
    original: str | None = None,
) -> MutationCandidate:
    operation = MutationOperation(
        method=method,
        endpoint_template=endpoint,
        field=field,
        allowed_path=endpoint,
    )
    return MutationCandidate(
        endpoint_handle=f"endpoint-{record}",
        record_handle=record,
        owner_identity_handle=f"identity-{owner}",
        attacker_identity_handle=f"identity-{attacker}",
        target=ProbeTarget(
            base_url="http://127.0.0.1",
            endpoint_template=endpoint,
            method=method,
            object_id=object_id,
            owner_identity=owner,
            attacker_identity=attacker,
            owner_credential=CredentialRef(
                identity=owner,
                kind=CredentialKind.BEARER,
                name="authorization",
                secret_ref=f"secret-{owner}",
            ),
            attacker_credential=CredentialRef(
                identity=attacker,
                kind=CredentialKind.BEARER,
                name="authorization",
                secret_ref=f"secret-{attacker}",
            ),
            mode=ProbeMode.MUTATION,
        ),
        field=field,
        original_value=ValueHandle(
            id=original or f"value-{record}",
            kind="field_value",
        ),
        canary_value=f"canary-{record}",
        mutation=operation,
    )


def test_preflight_freezes_and_sorts_one_explicit_candidate(tmp_path: Path) -> None:
    guard = _guard(tmp_path, record_scope="explicit")
    candidate = _candidate()

    plan = preflight_sweep((candidate,), guard, now=NOW)

    assert plan.candidates == (candidate,)
    assert type(plan.candidates) is tuple
    assert plan.grant.record_scope is MutationRecordScope.EXPLICIT
    assert plan.request_count == 5
    assert plan.scope_digest == guard.scope_digest


def test_all_discovered_requires_and_expands_complete_inventory(tmp_path: Path) -> None:
    guard = _guard(tmp_path)
    candidates = tuple(
        _candidate(record=f"record-{index}", object_id=f"object-{index}")
        for index in range(3)
    )

    plan = preflight_sweep(MutationCandidateInventory(candidates, True), guard, now=NOW)

    assert tuple(item.record_handle for item in plan.candidates) == (
        "record-0",
        "record-1",
        "record-2",
    )
    assert plan.request_count == 15

    with pytest.raises(MutationPreflightError, match="complete discovery"):
        preflight_sweep(MutationCandidateInventory(candidates, False), guard, now=NOW)
    with pytest.raises(MutationPreflightError, match="complete discovery"):
        preflight_sweep(candidates, guard, now=NOW)


@pytest.mark.parametrize(
    "factory, message",
    [
        (lambda: (), "requires at least one"),
        (lambda: (_candidate(), _candidate()), "duplicate"),
        (
            lambda: (
                _candidate(original="value-a"),
                _candidate(record="record-2", original="value-a"),
            ),
            "duplicate",
        ),
    ],
)
def test_preflight_rejects_empty_or_duplicate_candidates(
    tmp_path: Path, factory: Any, message: str
) -> None:
    guard = _guard(tmp_path, record_scope="explicit")
    with pytest.raises(MutationPreflightError, match=message):
        preflight_sweep(factory(), guard)


def test_missing_handle_and_field_bindings_fail_at_construction(tmp_path: Path) -> None:
    guard = _guard(tmp_path, record_scope="explicit")
    with pytest.raises(MutationPreflightError, match="candidate set"):
        candidate = _candidate()
        object.__setattr__(candidate, "original_value", ValueHandle(id="", kind="field_value"))
        preflight_sweep((candidate,), guard)

    with pytest.raises(MutationPreflightError, match="field"):
        _candidate(field=" ")


def test_owner_and_attacker_identity_bindings_must_differ(tmp_path: Path) -> None:
    guard = _guard(tmp_path, record_scope="explicit")
    with pytest.raises(MutationPreflightError, match="must differ"):
        _candidate(owner="same", attacker="same")

    with pytest.raises(MutationPreflightError, match="candidate set"):
        candidate = _candidate()
        object.__setattr__(candidate.target.owner_credential, "identity", "other")
        preflight_sweep((candidate,), guard)


@pytest.mark.parametrize(
    "scope_kwargs, message",
    [
        ({"methods": ["PUT"]}, "method or path"),
        ({"path_patterns": ["glob:/v1/orders/*"]}, "method or path"),
        ({"allowed_fields": ["name"]}, "field"),
    ],
)
def test_preflight_rejects_denied_method_path_or_field(
    tmp_path: Path, scope_kwargs: dict[str, Any], message: str
) -> None:
    del message
    guard = _guard(tmp_path, record_scope="explicit", **scope_kwargs)
    candidate = _candidate(field="email")
    with pytest.raises(MutationPreflightError, match="grant|method|field"):
        preflight_sweep((candidate,), guard, now=NOW)


def test_expired_scope_is_checked_before_dispatch(tmp_path: Path) -> None:
    guard = _guard(tmp_path, record_scope="explicit")
    candidate = _candidate()
    with pytest.raises(MutationPreflightError, match="scope"):
        preflight_sweep((candidate,), guard, now=NOW + timedelta(days=8))


def test_record_and_request_budgets_fail_before_any_transport_or_journal(tmp_path: Path) -> None:
    guard = _guard(tmp_path, max_records=2, max_requests=10)
    candidates = tuple(
        _candidate(record=f"record-{index}", object_id=f"object-{index}")
        for index in range(3)
    )
    calls: list[str] = []
    journal = tmp_path / "mutation.journal"

    with pytest.raises(MutationPreflightError, match="record budget"):
        preflight_sweep(MutationCandidateInventory(candidates, True), guard)
    assert calls == []
    assert not journal.exists()

    (tmp_path / "requests").mkdir()
    guard = _guard(tmp_path / "requests", max_records=10, max_requests=10)
    with pytest.raises(MutationPreflightError, match="request budget"):
        preflight_sweep(MutationCandidateInventory(candidates[:3], True), guard, now=NOW)
    assert calls == []
    assert not journal.exists()


def test_global_request_cap_is_enforced(tmp_path: Path) -> None:
    guard = _guard(tmp_path, max_records=MAX_MUTATION_REQUESTS, max_requests=MAX_MUTATION_REQUESTS)
    candidates = tuple(
        _candidate(record=f"record-{index}", object_id=f"object-{index}")
        for index in range(MAX_MUTATION_REQUESTS // 5 + 1)
    )

    with pytest.raises(MutationPreflightError, match="request budget"):
        preflight_sweep(MutationCandidateInventory(candidates, True), guard)


def test_executor_facade_only_preflights_and_does_not_dispatch(tmp_path: Path) -> None:
    guard = _guard(tmp_path, record_scope="explicit")
    executor = MutationSweepExecutor(guard)
    plan = executor.preflight((_candidate(),), now=NOW)
    assert plan.request_count == 5
