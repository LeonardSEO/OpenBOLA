from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import yaml

import openbola.mcp_server as mcp_module
from openbola.mcp_server import MCPService, MCPServiceError, create_mcp_server
from openbola.models import (
    CredentialKind,
    OwnershipConfidence,
    OwnershipEvidence,
    ProbeResult,
    ProbeTarget,
    Verdict,
)
from openbola.state import object_ref_fingerprint


def _write_scope(
    path: Path,
    *,
    allowed_paths: list[str] | None = None,
    **overrides: Any,
) -> Path:
    document: dict[str, Any] = {
        "client_name": "Example",
        "authorization_reference": "PT-LOCAL-001",
        "confirmed": True,
        "starts_at": "2020-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "allowed_hosts": ["api.example.test"],
        "allowed_cidrs": [],
        "allowed_paths": allowed_paths or ["glob:/v1/**"],
    }
    document.update(overrides)
    path.write_text(
        yaml.safe_dump(document),
        encoding="utf-8",
    )
    return path


def _har(path: Path, url: str = "https://api.example.test/v1/documents/42") -> Path:
    path.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": url,
                                "headers": [],
                            },
                            "response": {"status": 200, "headers": [], "content": {}},
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def _ownership_records(path: Path) -> Path:
    path.write_text(
        json.dumps(
            [
                {
                    "url": "https://api.example.test/v1/documents/42",
                    "method": "GET",
                    "identity": "alice",
                    "explicit_ownership": {"42": "alice"},
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_module_does_not_require_fastmcp() -> None:
    # Importing MCPService in the test process succeeds without the optional extra.
    service = MCPService()
    assert service.session.state_store is None


def test_scope_and_state_are_required_before_planning(tmp_path: Path) -> None:
    service = MCPService()

    with pytest.raises(MCPServiceError, match="load_scope"):
        service.plan_tests()

    assert service.load_scope(str(_write_scope(tmp_path / "scope.yaml")))["ok"]
    with pytest.raises(MCPServiceError, match="init_state"):
        service.plan_tests()

    assert service.init_state(str(tmp_path / "state.db"))["ok"]
    assert service.plan_tests() == {"ok": True, "pending_count": 0, "items": []}


def test_engagement_transitions_clear_session_derived_data(tmp_path: Path) -> None:
    service = MCPService()
    scope_a = _write_scope(tmp_path / "scope-a.yaml")
    scope_b = _write_scope(tmp_path / "scope-b.yaml")
    service.load_scope(scope_a)
    service.init_state(tmp_path / "state-a.db")
    service.session.records.append(object())  # type: ignore[arg-type]
    service.session.identity_hints["hint"] = "alice"
    service.session.object_ids[("/v1/items/{id}", "GET", "obj_" + "a" * 64)] = "42"
    service.session.outcomes.append(object())  # type: ignore[arg-type]
    service.session.last_base_url = "https://api.example.test"
    service.executor = lambda *_args, **_kwargs: []

    assert service.load_scope("relative-scope.yaml")["ok"] is False
    assert service.session.state_store is None
    assert service.session.scope_guard is None

    service.load_scope(scope_a)
    service.init_state(tmp_path / "state-a.db")
    service.session.records.append(object())  # type: ignore[arg-type]
    service.executor = lambda *_args, **_kwargs: []
    assert service.init_state("relative-state.db")["ok"] is False
    assert service.session.state_store is None
    assert not service.session.records

    service.load_scope(scope_a)
    service.init_state(tmp_path / "state-a.db")
    service.session.records.append(object())  # type: ignore[arg-type]
    service.executor = lambda *_args, **_kwargs: []
    assert service.load_scope(scope_b)["ok"] is True
    assert service.session.state_store is None
    assert not service.session.records
    assert not service.session.identity_hints
    assert not service.session.object_ids
    assert not service.session.outcomes
    assert service.session.last_base_url is None
    assert service.executor is None

    service.init_state(tmp_path / "state-b.db")
    assert not service.session.records
    assert service.session.credential_vault is not None


def test_invalid_transition_arguments_also_invalidate_ready_session(tmp_path: Path) -> None:
    service = MCPService()
    scope = _write_scope(tmp_path / "scope.yaml")
    assert service.load_scope(scope)["ok"] is True
    assert service.init_state(tmp_path / "state-b.db")["ok"] is True
    service.session.records.append(object())  # type: ignore[arg-type]
    service.executor = lambda *_args, **_kwargs: []

    assert service.load_scope("bad\x00scope.yaml")["ok"] is False
    assert service.session.scope_guard is None
    assert service.session.state_store is None
    assert not service.session.records
    assert service.executor is None

    assert service.load_scope(scope)["ok"] is True
    assert service.init_state(tmp_path / "state-c.db")["ok"] is True
    service.session.records.append(object())  # type: ignore[arg-type]
    service.executor = lambda *_args, **_kwargs: []

    assert service.init_state("bad\x00state.db")["ok"] is False
    assert service.session.state_store is None
    assert not service.session.records
    assert service.executor is None


def test_opaque_pending_object_without_current_capture_mapping_fails_closed(
    tmp_path: Path,
) -> None:
    service = MCPService()
    service.load_scope(_write_scope(tmp_path / "scope.yaml"))
    service.init_state(tmp_path / "state.db")
    service.register_environment_credential("alice", "bearer", "Authorization", "A_TOKEN")
    service.register_environment_credential("bob", "bearer", "Authorization", "B_TOKEN")
    store = service.session.state_store
    assert store is not None
    store.add_ownership_evidence(
        OwnershipEvidence(
            "alice", "/v1/documents/{id}", "GET", "42", OwnershipConfidence.EXPLICIT, "manual"
        )
    )
    with pytest.raises(MCPServiceError, match="concrete mapping"):
        service.run_pending_tests(
            "https://api.example.test/v1/documents", lambda *_args, **_kwargs: []
        )


def test_har_import_rechecks_scope_and_does_not_return_secrets(tmp_path: Path) -> None:
    service = MCPService()
    service.load_scope(str(_write_scope(tmp_path / "scope.yaml")))
    service.init_state(str(tmp_path / "state.db"))

    imported = service.import_har(str(_har(tmp_path / "traffic.har")), "alice")
    assert imported["ok"] is True
    assert service.session.records[0].headers == {}

    denied = service.import_har(
        str(_har(tmp_path / "outside.har", "https://api.example.test/admin/users/42")),
        "alice",
    )
    assert denied["ok"] is False
    assert denied["error"] == "import_denied"


def test_environment_credentials_accept_names_only(tmp_path: Path) -> None:
    service = MCPService()
    service.load_scope(str(_write_scope(tmp_path / "scope.yaml")))
    service.init_state(str(tmp_path / "state.db"))

    registered = service.register_environment_credential(
        "alice", "bearer", "Authorization", "BOLA_ALICE_TOKEN"
    )
    assert registered["reference_registered"] is True
    assert "BOLA_ALICE_TOKEN" not in json.dumps(registered)
    with pytest.raises(MCPServiceError):
        service.register_environment_credential("alice", "bearer", "Authorization", "secret-value")

    identity = service.session.state_store.list_identities()[0]  # type: ignore[union-attr]
    assert str(identity["credential_ref_id"]).startswith("ref_")
    assert "secret-value" not in json.dumps(service.session.state_store.list_identities())  # type: ignore[union-attr]


def test_state_initialization_requires_fresh_real_path(tmp_path: Path) -> None:
    service = MCPService()
    service.load_scope(_write_scope(tmp_path / "scope.yaml"))
    existing = tmp_path / "existing.db"
    existing.write_bytes(b"do-not-reuse")
    denied = service.init_state(existing)
    assert denied["ok"] is False
    assert existing.read_bytes() == b"do-not-reuse"

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    symlink_parent = tmp_path / "symlink-parent"
    symlink_parent.symlink_to(real_parent, target_is_directory=True)
    assert service.init_state(symlink_parent / "new.db")["ok"] is False

    target = tmp_path / "target.db"
    target.write_bytes(b"target")
    symlink_file = tmp_path / "symlink.db"
    symlink_file.symlink_to(target)
    assert service.init_state(symlink_file)["ok"] is False


def test_state_sqlite_error_is_bounded_and_not_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = MCPService()
    service.load_scope(_write_scope(tmp_path / "scope.yaml"))

    def fail_state(_path: object) -> None:
        raise sqlite3.OperationalError("/private/secret/state.db is locked")

    monkeypatch.setattr("openbola.mcp_server.StateStore", fail_state)
    result = service.init_state(tmp_path / "state.db")

    assert result == {
        "ok": False,
        "error": "state_unavailable",
        "message": "state database unavailable",
    }
    assert service.session.state_store is None


def test_endpoint_and_test_plans_omit_object_identifiers(tmp_path: Path) -> None:
    service = MCPService()
    service.load_scope(str(_write_scope(tmp_path / "scope.yaml")))
    service.init_state(str(tmp_path / "state.db"))
    service.import_har(str(_har(tmp_path / "traffic.har")), "alice")

    plan = service.plan_endpoints()
    rendered = json.dumps(plan)
    assert plan["candidate_count"] == 1
    assert "42" not in rendered
    assert service.plan_tests()["pending_count"] == 0


def test_run_requires_injected_executor_and_rechecks_scope(tmp_path: Path) -> None:
    service = MCPService()
    scope = _write_scope(tmp_path / "scope.yaml")
    service.load_scope(str(scope))
    service.init_state(str(tmp_path / "state.db"))
    service.register_environment_credential("alice", "bearer", "Authorization", "A_TOKEN")
    service.register_environment_credential("bob", "bearer", "Authorization", "B_TOKEN")
    store = service.session.state_store
    assert store is not None
    store.add_ownership_evidence(
        OwnershipEvidence(
            "alice", "/v1/documents/{id}", "GET", "42", OwnershipConfidence.EXPLICIT, "manual"
        )
    )
    service.session.object_ids[
        ("/v1/documents/{id}", "GET", object_ref_fingerprint("42"))
    ] = "42"
    service.session.object_origins[
        ("/v1/documents/{id}", "GET", object_ref_fingerprint("42"))
    ] = {"https://api.example.test:443"}
    service.session.origins.add("https://api.example.test:443")
    owner_ref = service.session.credential_vault.environment_reference(
        identity="alice", kind=CredentialKind.BEARER, name="Authorization", variable="A_TOKEN"
    )
    attacker_ref = service.session.credential_vault.environment_reference(
        identity="bob", kind=CredentialKind.BEARER, name="Authorization", variable="B_TOKEN"
    )

    def executor(pending: Any, **kwargs: Any) -> list[ProbeResult]:
        assert kwargs["scope_guard"] is service.session.scope_guard
        combination = pending[0]
        object_value = getattr(combination, "object_ref", "")
        return [
            ProbeResult(
                ProbeTarget(
                    "https://api.example.test",
                    "/v1/documents/{id}",
                    "GET",
                    object_value,
                    "alice",
                    "bob",
                    owner_ref,
                    attacker_ref,
                ),
                Verdict.PROTECTED,
                200,
                403,
            ),
        ]

    result = service.run_pending_tests("https://api.example.test/v1/documents", executor)
    assert result["ok"] is True and result["results"][0]["verdict"] == "protected"

    scope.write_text(
        scope.read_text(encoding="utf-8").replace("api.example.test", "other.test"),
        encoding="utf-8",
    )
    denied = service.run_pending_tests("https://api.example.test/v1/documents", executor)
    assert denied["ok"] is False and denied["error"] == "scope_denied"


def test_default_executor_runs_read_only_with_current_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = MCPService()
    service.load_scope(_write_scope(tmp_path / "scope.yaml"))
    assert service.init_state(tmp_path / "state.db")["ok"] is True
    monkeypatch.setenv("A_TOKEN", "owner-secret")
    monkeypatch.setenv("B_TOKEN", "attacker-secret")
    service.register_environment_credential("alice", "bearer", "Authorization", "A_TOKEN")
    service.register_environment_credential("bob", "bearer", "Authorization", "B_TOKEN")
    store = service.session.state_store
    assert store is not None
    store.add_ownership_evidence(
        OwnershipEvidence(
            "alice", "/v1/documents/{id}", "GET", "42", OwnershipConfidence.EXPLICIT, "manual"
        )
    )
    service.session.object_ids[
        ("/v1/documents/{id}", "GET", object_ref_fingerprint("42"))
    ] = "42"
    service.session.object_origins[
        ("/v1/documents/{id}", "GET", object_ref_fingerprint("42"))
    ] = {"https://api.example.test:443"}
    service.session.origins.add("https://api.example.test:443")
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.headers.get("authorization", ""))
        if request.headers.get("authorization") == "Bearer owner-secret":
            return httpx.Response(200, json={"id": "42"})
        return httpx.Response(403, json={"error": "forbidden"})

    service.transport = httpx.MockTransport(handler)
    result = service.run_pending_tests("https://api.example.test/v1/documents")

    assert result["ok"] is True
    assert result["results"][0]["verdict"] == "protected"
    assert calls == ["Bearer owner-secret", "Bearer attacker-secret"]


def test_public_records_plan_and_run_flow_uses_bound_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = MCPService()
    assert service.load_scope(_write_scope(tmp_path / "scope.yaml"))["ok"] is True
    assert service.init_state(tmp_path / "state.db")["ok"] is True
    monkeypatch.setenv("A_TOKEN", "owner-secret")
    monkeypatch.setenv("B_TOKEN", "attacker-secret")
    service.register_environment_credential("alice", "bearer", "Authorization", "A_TOKEN")
    service.register_environment_credential("bob", "bearer", "Authorization", "B_TOKEN")
    imported = service.import_records(_ownership_records(tmp_path / "ownership.json"))
    assert imported == {"ok": True, "records_imported": 1, "ownership_records": 1}
    planned = service.plan_endpoints()
    assert planned["ownership_persisted"] == 1

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") == "Bearer owner-secret":
            return httpx.Response(200, json={"id": "42"})
        return httpx.Response(403, json={"error": "forbidden"})

    service.transport = httpx.MockTransport(handler)
    result = service.run_pending_tests("https://api.example.test/v1/documents")
    assert result["ok"] is True
    assert result["results"][0]["verdict"] == "protected"


def test_import_records_rejects_oversized_sparse_file(tmp_path: Path) -> None:
    service = MCPService()
    service.load_scope(_write_scope(tmp_path / "scope.yaml"))
    service.init_state(tmp_path / "state.db")
    records_path = tmp_path / "oversized.json"
    with records_path.open("wb") as handle:
        handle.seek(5 * 1024 * 1024)
        handle.write(b"x")

    with pytest.raises(MCPServiceError, match="size limit"):
        service.import_records(records_path)


def test_import_records_rejects_file_growth_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = MCPService()
    service.load_scope(_write_scope(tmp_path / "scope.yaml"))
    service.init_state(tmp_path / "state.db")
    records_path = _ownership_records(tmp_path / "growing.json")
    real_read = mcp_module.os.read
    appended = False

    def growing_read(descriptor: int, size: int) -> bytes:
        nonlocal appended
        data = real_read(descriptor, size)
        if not appended:
            with records_path.open("ab") as handle:
                handle.write(b" ")
            appended = True
        return data

    monkeypatch.setattr(mcp_module.os, "read", growing_read)
    with pytest.raises(MCPServiceError, match="changed while being read"):
        service.import_records(records_path)


def test_import_records_rejects_deep_json(tmp_path: Path) -> None:
    service = MCPService()
    service.load_scope(_write_scope(tmp_path / "scope.yaml"))
    service.init_state(tmp_path / "state.db")
    records_path = tmp_path / "deep.json"
    records_path.write_text("[" * 40 + "0" + "]" * 40, encoding="utf-8")

    with pytest.raises(MCPServiceError, match="JSON"):
        service.import_records(records_path)


def test_mixed_origins_fail_closed_for_same_pending_object(tmp_path: Path) -> None:
    service = MCPService()
    service.load_scope(
        _write_scope(
            tmp_path / "scope.yaml",
            allowed_hosts=["api.example.test", "other.example.test"],
        )
    )
    service.init_state(tmp_path / "state.db")
    service.register_environment_credential("alice", "bearer", "Authorization", "A_TOKEN")
    service.register_environment_credential("bob", "bearer", "Authorization", "B_TOKEN")
    records_path = tmp_path / "mixed.json"
    records_path.write_text(
        json.dumps(
            [
                {
                    "url": "https://api.example.test/v1/documents/42",
                    "method": "GET",
                    "identity": "alice",
                    "explicit_ownership": {"42": "alice"},
                },
                {
                    "url": "https://other.example.test/v1/documents/42",
                    "method": "GET",
                    "identity": "bob",
                    "explicit_ownership": {"42": "alice"},
                },
            ]
        ),
        encoding="utf-8",
    )
    service.import_records(records_path)
    service.plan_endpoints()
    with pytest.raises(MCPServiceError, match="origin"):
        service.run_pending_tests("https://api.example.test/v1/documents", lambda *_args: [])


def test_mcp_execution_is_read_only(tmp_path: Path) -> None:
    service = MCPService()
    service.load_scope(str(_write_scope(tmp_path / "scope.yaml")))
    service.init_state(str(tmp_path / "state.db"))
    with pytest.raises(MCPServiceError, match="read-only"):
        service.run_pending_tests(
            "https://api.example.test/v1/documents",
            lambda *_args, **_kwargs: [],
            mode="mutation",
        )


def test_create_server_imports_fastmcp_lazily(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeServer:
        def __init__(self, name: str) -> None:
            self.name = name

        def tool(self, function: Any) -> Any:
            return function

        def run(self, **_kwargs: Any) -> None:
            return None

    monkeypatch.setitem(__import__("sys").modules, "fastmcp", SimpleNamespace(FastMCP=FakeServer))
    server = create_mcp_server()
    assert server.name == "openbola"
