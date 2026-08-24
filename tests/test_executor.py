from __future__ import annotations

import asyncio
import json
import math
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from openbola.credentials import CredentialVault
from openbola.executor import (
    ExecutorLimits,
    MutationSafetyError,
    MutationSpec,
    ProbeExecutor,
)
from openbola.models import CredentialKind, ProbeMode, ProbeTarget, Verdict
from openbola.scope import ScopeGuard
from openbola.state import StateStore

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)


def _scope_file(path: Path, *, mutation: bool = False, hostname: bool = False) -> Path:
    document: dict[str, Any] = {
        "client_name": "Executor fixture",
        "authorization_reference": "TEST-EXECUTOR",
        "confirmed": True,
        "starts_at": "2026-08-23T10:00:00Z",
        "expires_at": "2026-08-23T14:00:00Z",
        "allowed_hosts": ["api.example.test"] if hostname else [],
        "allowed_cidrs": ["192.0.2.0/24"] if hostname else ["127.0.0.0/8"],
        "allowed_paths": ["glob:/v1/**"],
    }
    if mutation:
        document["mutation_grants"] = [
            {"methods": ["POST", "DELETE"], "path_patterns": ["glob:/v1/**"]}
        ]
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _credential(vault: CredentialVault, identity: str, value: str) -> Any:
    return vault.store(
        identity=identity,
        kind=CredentialKind.BEARER,
        name="authorization",
        secret=value,
    )


def _fixture(tmp_path: Path, *, mutation: bool = False) -> tuple[ScopeGuard, CredentialVault]:
    guard = ScopeGuard.from_file(_scope_file(tmp_path / "scope.yaml", mutation=mutation), now=NOW)
    vault = CredentialVault()
    _credential(vault, "owner", "owner-secret")
    _credential(vault, "attacker", "attacker-secret")
    return guard, vault


def _target(vault: CredentialVault, *, mode: ProbeMode = ProbeMode.READ) -> ProbeTarget:
    owner = _credential(vault, "owner", "owner-token")
    attacker = _credential(vault, "attacker", "attacker-token")
    return ProbeTarget(
        base_url="http://127.0.0.1",
        endpoint_template="/v1/documents/{id}",
        method="GET" if mode is ProbeMode.READ else "POST",
        object_id="doc-1",
        owner_identity="owner",
        attacker_identity="attacker",
        owner_credential=owner,
        attacker_credential=attacker,
        mode=mode,
    )


def _executor(
    tmp_path: Path,
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    mutation: bool = False,
    **kwargs: Any,
) -> tuple[ProbeExecutor, CredentialVault]:
    guard, vault = _fixture(tmp_path, mutation=mutation)
    transport = httpx.MockTransport(handler)
    return (
        ProbeExecutor(
            guard,
            vault,
            transport=transport,
            now=NOW,
            limits=ExecutorLimits(requests_per_second=1_000, **kwargs),
        ),
        vault,
    )


def test_owner_and_attacker_same_object_is_bola(tmp_path: Path) -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.headers["authorization"]))
        return httpx.Response(200, json={"id": "doc-1", "name": "safe"})

    executor, vault = _executor(tmp_path, handler)
    result = executor.run(_target(vault))

    assert result.verdict is Verdict.BOLA
    assert result.owner_status == result.attacker_status == 200
    assert calls == [("GET", "Bearer owner-token"), ("GET", "Bearer attacker-token")]


def test_protected_response_is_not_a_bola(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["authorization"] == "Bearer owner-token":
            return httpx.Response(200, json={"id": "doc-1"})
        return httpx.Response(403)

    executor, vault = _executor(tmp_path, handler)
    result = executor.run(_target(vault))

    assert result.verdict is Verdict.PROTECTED
    assert result.evidence["comparison"] == "response_shape_mismatch"


def test_different_object_is_inconclusive(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        value = "doc-1" if request.headers["authorization"] == "Bearer owner-token" else "doc-2"
        return httpx.Response(200, json={"id": value})

    executor, vault = _executor(tmp_path, handler)
    result = executor.run(_target(vault))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.evidence["comparison"] == "object_id_mismatch"


def test_each_initial_request_is_scope_checked(tmp_path: Path) -> None:
    class CountingGuard(ScopeGuard):
        count = 0

        def require_allowed(self, *args: Any, **kwargs: Any) -> Any:
            self.count += 1
            return super().require_allowed(*args, **kwargs)

    scope = ScopeGuard.from_file(_scope_file(tmp_path / "scope.yaml"), now=NOW)
    guard = CountingGuard(scope.config, now=NOW)
    vault = CredentialVault()
    owner = _credential(vault, "owner", "a")
    attacker = _credential(vault, "attacker", "b")
    target = ProbeTarget(
        base_url="http://127.0.0.1",
        endpoint_template="/v1/documents/{id}",
        method="GET",
        object_id="doc-1",
        owner_identity="owner",
        attacker_identity="attacker",
        owner_credential=owner,
        attacker_credential=attacker,
    )
    executor = ProbeExecutor(
        guard,
        vault,
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"id": "doc-1"})),
        now=NOW,
        limits=ExecutorLimits(requests_per_second=1_000),
    )

    executor.run(target)

    assert guard.count == 2


def test_redirects_are_manual_and_each_hop_is_checked(tmp_path: Path) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/v1/documents/doc-1" and request.url.query == b"":
            return httpx.Response(302, headers={"Location": "/v1/final/doc-1"})
        return httpx.Response(200, json={"id": "doc-1"})

    executor, vault = _executor(tmp_path, handler)
    result = executor.run(_target(vault))

    assert result.verdict is Verdict.BOLA
    assert calls == [
        "/v1/documents/doc-1",
        "/v1/final/doc-1",
        "/v1/documents/doc-1",
        "/v1/final/doc-1",
    ]


def test_redirect_outside_scope_is_blocked_without_following(tmp_path: Path) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(302, headers={"Location": "/admin/doc-1"})

    executor, vault = _executor(tmp_path, handler)
    result = executor.run(_target(vault))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.evidence["error_code"] == "redirect_blocked"
    assert calls == ["/v1/documents/doc-1", "/v1/documents/doc-1"]


def test_hostname_with_cidr_fails_closed_without_peer_pinning(tmp_path: Path) -> None:
    guard = ScopeGuard.from_file(
        _scope_file(tmp_path / "scope.yaml", hostname=True),
        resolver=lambda _: ["192.0.2.10"],
        now=NOW,
    )
    vault = CredentialVault()
    owner = _credential(vault, "owner", "a")
    attacker = _credential(vault, "attacker", "b")
    target = ProbeTarget(
        base_url="http://api.example.test",
        endpoint_template="/v1/documents/{id}",
        method="GET",
        object_id="doc-1",
        owner_identity="owner",
        attacker_identity="attacker",
        owner_credential=owner,
        attacker_credential=attacker,
    )
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"id": "doc-1"})

    result = ProbeExecutor(
        guard,
        vault,
        transport=httpx.MockTransport(handler),
        now=NOW,
        limits=ExecutorLimits(requests_per_second=1_000),
    ).run(target)

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.evidence["error_code"] == "scope_denied"
    assert not called


def test_mutation_requires_canary_and_cleanup(tmp_path: Path) -> None:
    with pytest.raises(MutationSafetyError):
        MutationSpec(method="POST", canary="", cleanup_method="DELETE")

    calls: list[tuple[str, str, bytes]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content
        calls.append((request.method, request.url.path, body))
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(200, json={"id": "doc-1"})

    executor, vault = _executor(tmp_path, handler, mutation=True)
    result = executor.run(
        _target(vault, mode=ProbeMode.MUTATION),
        mutation=MutationSpec(
            method="POST",
            canary="bola-canary",
            cleanup_method="DELETE",
            cleanup_path="/v1/documents/{id}/canary",
            body={"canary": "bola-canary"},
            cleanup_body={"canary": "bola-canary"},
        ),
    )

    assert result.verdict is Verdict.BOLA
    assert [method for method, _, _ in calls] == ["POST", "DELETE", "POST", "DELETE"]
    assert all(body == b'{"canary":"bola-canary"}' for method, _, body in calls if method == "POST")


def test_state_store_receives_atomic_probe_attempt(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        status = 403 if request.headers["authorization"] == "Bearer attacker-token" else 200
        return httpx.Response(status, json={"id": "doc-1"})

    guard, vault = _fixture(tmp_path)
    store = StateStore(tmp_path / "state.db")
    executor = ProbeExecutor(
        guard,
        vault,
        transport=httpx.MockTransport(handler),
        state_store=store,
        now=NOW,
        limits=ExecutorLimits(requests_per_second=1_000),
    )
    result = executor.run(_target(vault))

    assert result.verdict is Verdict.PROTECTED
    assert len(store.list_audit_events()) == 1


def test_response_limit_is_enforced_without_persisting_body(tmp_path: Path) -> None:
    sentinel = b"response-secret-sentinel"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=sentinel, headers={"content-type": "text/plain"})

    executor, vault = _executor(tmp_path, handler, max_response_bytes=4)
    result = executor.run(_target(vault))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.evidence["error_code"] == "invalid_response"
    assert sentinel not in json.dumps(result.evidence).encode()


def test_object_id_must_be_one_safe_path_segment(tmp_path: Path) -> None:
    executor, vault = _executor(
        tmp_path,
        lambda request: httpx.Response(200, json={"id": "doc-1"}),
    )
    result = executor.run(
        ProbeTarget(
            base_url="http://127.0.0.1",
            endpoint_template="/v1/documents/{id}",
            method="GET",
            object_id="doc/../admin",
            owner_identity="owner",
            attacker_identity="attacker",
            owner_credential=_credential(vault, "owner", "owner"),
            attacker_credential=_credential(vault, "attacker", "attacker"),
        )
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.evidence["error_code"] == "invalid_response"


def test_equal_bodies_without_object_ids_do_not_establish_bola(tmp_path: Path) -> None:
    executor, vault = _executor(
        tmp_path,
        lambda request: httpx.Response(200, json={"name": "same-shaped"}),
    )
    result = executor.run(_target(vault))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.evidence["comparison"] == "object_id_mismatch"
    assert result.evidence["object_ref"].startswith("obj_")
    assert "object_id" not in result.evidence


def test_failed_cleanup_overrides_primary_bola_result(tmp_path: Path) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "DELETE":
            return httpx.Response(500)
        return httpx.Response(200, json={"id": "doc-1"})

    executor, vault = _executor(tmp_path, handler, mutation=True)
    result = executor.run(
        _target(vault, mode=ProbeMode.MUTATION),
        mutation=MutationSpec(
            method="POST",
            canary="cleanup-canary",
            cleanup_method="DELETE",
            cleanup_path="/v1/documents/{id}/canary",
            body={"canary": "cleanup-canary"},
            cleanup_body={"canary": "cleanup-canary"},
        ),
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.evidence["error_code"] == "invalid_response"
    assert calls == ["POST", "DELETE"]


def test_mutation_reserves_budget_for_cleanup(tmp_path: Path) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        return httpx.Response(204 if request.method == "DELETE" else 200, json={"id": "doc-1"})

    executor, vault = _executor(tmp_path, handler, mutation=True, max_requests=3)
    result = executor.run(
        _target(vault, mode=ProbeMode.MUTATION),
        mutation=MutationSpec(
            method="POST",
            canary="budget-canary",
            cleanup_method="DELETE",
            cleanup_path="/v1/documents/{id}/canary",
            body={"canary": "budget-canary"},
            cleanup_body={"canary": "budget-canary"},
        ),
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert calls == ["POST", "DELETE"]


def test_unexpected_primary_error_still_attempts_cleanup(tmp_path: Path) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "POST":
            raise ValueError("fixture transport failure")
        return httpx.Response(204)

    executor, vault = _executor(tmp_path, handler, mutation=True)
    result = executor.run(
        _target(vault, mode=ProbeMode.MUTATION),
        mutation=MutationSpec(
            method="POST",
            canary="finally-canary",
            cleanup_method="DELETE",
            cleanup_path="/v1/documents/{id}/canary",
            body={"canary": "finally-canary"},
            cleanup_body={"canary": "finally-canary"},
        ),
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert calls == ["POST", "DELETE"]


def test_redirect_to_another_allowed_origin_does_not_reuse_credentials(tmp_path: Path) -> None:
    scope = {
        "client_name": "redirect fixture",
        "authorization_reference": "REDIRECT-ORIGIN",
        "confirmed": True,
        "starts_at": "2026-08-23T10:00:00Z",
        "expires_at": "2026-08-23T14:00:00Z",
        "allowed_hosts": ["one.example.test", "two.example.test"],
        "allowed_cidrs": [],
        "allowed_paths": ["glob:/v1/**"],
    }
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(yaml.safe_dump(scope), encoding="utf-8")
    loaded_guard = ScopeGuard.from_file(scope_path, now=NOW)

    class CountingGuard(ScopeGuard):
        count = 0

        def require_allowed(self, *args: Any, **kwargs: Any) -> Any:
            self.count += 1
            return super().require_allowed(*args, **kwargs)

    guard = CountingGuard(loaded_guard.config, now=NOW)
    vault = CredentialVault()
    owner = _credential(vault, "owner", "owner-token")
    attacker = _credential(vault, "attacker", "attacker-token")
    target = ProbeTarget(
        base_url="https://one.example.test",
        endpoint_template="/v1/documents/{id}",
        method="GET",
        object_id="doc-1",
        owner_identity="owner",
        attacker_identity="attacker",
        owner_credential=owner,
        attacker_credential=attacker,
    )
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://two.example.test/v1/final"})

    result = ProbeExecutor(
        guard,
        vault,
        transport=httpx.MockTransport(handler),
        now=NOW,
        limits=ExecutorLimits(requests_per_second=1_000),
    ).run(target)

    assert result.verdict is Verdict.INCONCLUSIVE
    assert calls == [
        "https://one.example.test/v1/documents/doc-1",
        "https://one.example.test/v1/documents/doc-1",
    ]
    assert guard.count == 4


def test_https_to_http_redirect_is_blocked_before_second_request(tmp_path: Path) -> None:
    scope = {
        "client_name": "redirect fixture",
        "authorization_reference": "REDIRECT-DOWNGRADE",
        "confirmed": True,
        "starts_at": "2026-08-23T10:00:00Z",
        "expires_at": "2026-08-23T14:00:00Z",
        "allowed_hosts": ["one.example.test"],
        "allowed_cidrs": [],
        "allowed_paths": ["glob:/v1/**"],
    }
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(yaml.safe_dump(scope), encoding="utf-8")
    guard = ScopeGuard.from_file(scope_path, now=NOW)
    vault = CredentialVault()
    owner = _credential(vault, "owner", "owner-token")
    attacker = _credential(vault, "attacker", "attacker-token")
    target = ProbeTarget(
        base_url="https://one.example.test",
        endpoint_template="/v1/documents/{id}",
        method="GET",
        object_id="doc-1",
        owner_identity="owner",
        attacker_identity="attacker",
        owner_credential=owner,
        attacker_credential=attacker,
    )
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://one.example.test/v1/final"})

    result = ProbeExecutor(
        guard,
        vault,
        transport=httpx.MockTransport(handler),
        now=NOW,
        limits=ExecutorLimits(requests_per_second=1_000),
    ).run(target)

    assert result.verdict is Verdict.INCONCLUSIVE
    assert calls == [
        "https://one.example.test/v1/documents/doc-1",
        "https://one.example.test/v1/documents/doc-1",
    ]


def test_async_client_disables_ambient_proxy_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}
    original = httpx.AsyncClient

    class SpyClient(original):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            seen["trust_env"] = kwargs.get("trust_env")
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", SpyClient)
    executor, vault = _executor(
        tmp_path,
        lambda request: httpx.Response(200, json={"id": "doc-1"}),
    )
    executor.run(_target(vault))

    assert seen["trust_env"] is False


def test_deep_response_json_fails_closed_without_recursion_error(tmp_path: Path) -> None:
    deep: Any = {"id": "doc-1"}
    for _ in range(40):
        deep = {"nested": deep}
    executor, vault = _executor(
        tmp_path,
        lambda request: httpx.Response(200, json=deep),
    )

    result = executor.run(_target(vault))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.evidence["comparison"] == "object_id_mismatch"


def test_cancellation_after_dispatch_still_cleans_up_and_stops_attacker(
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "POST":
            raise asyncio.CancelledError()
        return httpx.Response(204)

    executor, vault = _executor(tmp_path, handler, mutation=True)
    result = executor.run(
        _target(vault, mode=ProbeMode.MUTATION),
        mutation=MutationSpec(
            method="POST",
            canary="cancel-canary",
            cleanup_method="DELETE",
            cleanup_path="/v1/documents/{id}/canary",
            body={"canary": "cancel-canary"},
            cleanup_body={"canary": "cancel-canary"},
        ),
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert calls == ["POST", "DELETE"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_seconds", math.nan),
        ("timeout_seconds", math.inf),
        ("max_response_bytes", math.nan),
        ("requests_per_second", math.inf),
        ("max_redirects", True),
        ("max_retries", "2"),
        ("max_requests", 100_001),
        ("max_concurrency", 0),
    ],
)
def test_limits_reject_nonfinite_wrong_type_and_extreme_values(field: str, value: Any) -> None:
    with pytest.raises(ValueError):
        ExecutorLimits(**{field: value})
