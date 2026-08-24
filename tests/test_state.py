from __future__ import annotations

import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from openbola.models import (
    AuditEventType,
    CredentialKind,
    CredentialRef,
    Finding,
    OwnershipConfidence,
    OwnershipEvidence,
    ProbeResult,
    ProbeTarget,
    Verdict,
)
from openbola.state import (
    OwnershipConflictError,
    StateStore,
    canonical_finding_text,
    credential_ref_fingerprint,
    object_ref_fingerprint,
    run_label_fingerprint,
)


@pytest.fixture
def store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db")


def _credential(identity: str) -> CredentialRef:
    return CredentialRef(
        identity=identity,
        kind=CredentialKind.BEARER,
        name="Authorization",
        secret_ref=f"keyring:bola/{identity}",
    )


def test_state_database_and_sidecars_are_private(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    store = StateStore(db_path)
    store.add_identity("alice")
    assert db_path.stat().st_mode & 0o777 == 0o600

    sidecar = Path(f"{db_path}-shm")
    if sidecar.exists():
        assert sidecar.stat().st_mode & 0o777 == 0o600


def test_sticky_shared_ancestor_allows_private_owned_database_parent(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o700)
    os.chmod(shared, 0o1777)  # noqa: S103 - models the standard /tmp trust boundary
    private = shared / "engagement"
    private.mkdir(mode=0o700)

    db_path = private / "state.db"
    StateStore(db_path)

    assert db_path.stat().st_mode & 0o777 == 0o600


def test_non_sticky_writable_ancestor_is_rejected(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o700)
    os.chmod(shared, 0o777)  # noqa: S103 - deliberately unsafe regression fixture
    private = shared / "engagement"
    private.mkdir(mode=0o700)

    with pytest.raises(RuntimeError, match="group/world writable"):
        StateStore(private / "state.db")


def test_existing_database_is_hardened_and_symlinks_are_rejected(tmp_path: Path) -> None:
    db_path = tmp_path / "existing.db"
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE marker (value TEXT)")
    connection.commit()
    connection.close()
    os.chmod(db_path, 0o444)

    StateStore(db_path)
    assert db_path.stat().st_mode & 0o777 == 0o600

    target = tmp_path / "target.db"
    target.write_bytes(b"not-a-state-db")
    symlink = tmp_path / "symlink.db"
    symlink.symlink_to(target)
    with pytest.raises(RuntimeError, match="regular file|safe"):
        StateStore(symlink)


def test_database_leaf_replacement_is_detected_before_next_connection(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    store = StateStore(db_path)
    replacement = tmp_path / "replacement.db"
    replacement.write_bytes(b"replacement")
    db_path.unlink()
    db_path.symlink_to(replacement)

    with pytest.raises(RuntimeError, match="path changed|safe|regular"):
        store.list_endpoints()


def _target() -> ProbeTarget:
    return ProbeTarget(
        base_url="https://api.example.test",
        endpoint_template="/documents/{id}",
        method="GET",
        object_id="document-1",
        owner_identity="alice",
        attacker_identity="bob",
        owner_credential=_credential("alice"),
        attacker_credential=_credential("bob"),
    )


def _prepare_v2_ownership_state(store: StateStore, secret: str) -> tuple[int, int]:
    timestamp = "2026-08-24T01:02:03+00:00"
    with store._connection() as connection:
        connection.execute(
            "ALTER TABLE ownership_evidence RENAME COLUMN object_ref TO object_id"
        )
        connection.execute(
            "ALTER TABLE tested_combinations RENAME COLUMN object_ref TO object_id"
        )
        connection.execute("DELETE FROM schema_migrations WHERE version = 3")
        connection.execute("UPDATE schema_version SET version = 2 WHERE singleton = 1")
        endpoint_id = connection.execute(
            "INSERT INTO endpoints(template, method, first_seen_at) VALUES (?, 'GET', ?)",
            (f"/documents/{secret}", timestamp),
        ).lastrowid
        identity_id = connection.execute(
            "INSERT INTO identities(name, metadata_json, first_seen_at) "
            "VALUES ('alice', '{}', ?)",
            (timestamp,),
        ).lastrowid
        assert endpoint_id is not None and identity_id is not None
        connection.execute(
            "INSERT INTO ownership_evidence("
            "identity_id, endpoint_id, object_id, confidence, source, recorded_at"
            ") VALUES (?, ?, ?, 'explicit', 'fixture', ?)",
            (identity_id, endpoint_id, secret, timestamp),
        )
    return int(endpoint_id), int(identity_id)


def test_initialises_schema_and_records_migration(store: StateStore) -> None:
    reopened = StateStore(store.db_path)
    assert reopened.schema_version() == 3

    with reopened._connection() as connection:
        versions = connection.execute("SELECT version FROM schema_migrations").fetchall()
        foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()

    assert [row["version"] for row in versions] == [1, 2, 3]
    assert foreign_keys is not None
    assert foreign_keys[0] == 1


def test_foreign_keys_reject_orphaned_ownership_evidence(store: StateStore) -> None:
    endpoint_id = store.add_endpoint("/documents/{id}", "GET")

    with pytest.raises(sqlite3.IntegrityError):
        store.add_owned_object(
            999,
            endpoint_id,
            "document-1",
            confidence=OwnershipConfidence.EXPLICIT,
            source="fixture",
        )


def test_ownership_persists_and_produces_cross_identity_pending_matrix(store: StateStore) -> None:
    store.add_identity("alice")
    store.add_identity("bob")
    store.add_identity("charlie")
    evidence = OwnershipEvidence(
        identity="alice",
        endpoint_template="/documents/{id}",
        method="GET",
        object_id="document-1",
        confidence=OwnershipConfidence.EXPLICIT,
        source="capture:alice.har",
    )
    store.add_ownership_evidence(evidence)

    pending = store.untested_combinations()

    identities = [(item.owner_identity_id, item.attacker_identity_id) for item in pending]
    assert identities == [(1, 2), (1, 3)]
    assert store.ownership_evidence_for("/documents/{id}", "get", "document-1") == [
        replace(evidence, object_id=object_ref_fingerprint("document-1"))
    ]


def test_heuristic_ownership_never_enters_pending_matrix_but_strong_does(
    store: StateStore,
) -> None:
    store.add_identity("alice")
    store.add_ownership_evidence(
        OwnershipEvidence(
            identity="alice",
            endpoint_template="/documents/{id}",
            method="GET",
            object_id="document-heuristic",
            confidence=OwnershipConfidence.HEURISTIC,
            source="requester_identity",
        )
    )
    store.add_ownership_evidence(
        OwnershipEvidence(
            identity="bob",
            endpoint_template="/documents/{id}",
            method="GET",
            object_id="document-strong",
            confidence=OwnershipConfidence.RESPONSE_MATCH,
            source="response_owner_field:$.owner_id",
        )
    )

    pending = store.untested_combinations()

    assert [(item.owner_identity_id, item.attacker_identity_id) for item in pending] == [(2, 1)]
    assert pending[0].object_ref == object_ref_fingerprint("document-strong")


def test_concurrent_strong_ownership_allows_one_owner_and_rejects_the_other(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.db"
    stores = (StateStore(db_path), StateStore(db_path))
    barrier = threading.Barrier(2)
    evidence = (
        OwnershipEvidence(
            identity="alice",
            endpoint_template="/documents/{id}",
            method="GET",
            object_id="document-1",
            confidence=OwnershipConfidence.EXPLICIT,
            source="explicit_mapping",
        ),
        OwnershipEvidence(
            identity="bob",
            endpoint_template="/documents/{id}",
            method="GET",
            object_id="document-1",
            confidence=OwnershipConfidence.EXPLICIT,
            source="explicit_mapping",
        ),
    )

    def persist(index: int) -> str:
        barrier.wait()
        try:
            stores[index].persist_ownership_evidence(evidence[index])
        except OwnershipConflictError:
            return "conflict"
        return "persisted"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(persist, range(2)))

    assert sorted(results) == ["conflict", "persisted"]
    stored = stores[0].ownership_evidence_for("/documents/{id}", "GET", "document-1")
    assert len(stored) == 1
    assert stored[0].identity in {"alice", "bob"}


def test_retryable_inconclusive_attempt_remains_pending_until_success(store: StateStore) -> None:
    store.add_ownership_evidence(
        OwnershipEvidence(
            identity="alice",
            endpoint_template="/documents/{id}",
            method="GET",
            object_id="document-1",
            confidence=OwnershipConfidence.EXPLICIT,
            source="capture:alice.har",
        )
    )
    store.add_identity("bob")

    store.record_probe_result(
        ProbeResult(
            target=_target(),
            verdict=Verdict.INCONCLUSIVE,
            owner_status=None,
            attacker_status=None,
            evidence={"error_code": "timeout"},
            retryable=True,
        )
    )

    references = {row["name"]: row["credential_ref_id"] for row in store.list_identities()}
    assert references == {
        "alice": credential_ref_fingerprint(_credential("alice")),
        "bob": credential_ref_fingerprint(_credential("bob")),
    }
    assert not store.has_been_tested(1, 1, 2, "document-1")
    assert len(store.untested_combinations()) == 1

    store.record_probe_result(
        ProbeResult(
            target=_target(),
            verdict=Verdict.PROTECTED,
            owner_status=200,
            attacker_status=403,
        )
    )

    assert store.has_been_tested(1, 1, 2, "document-1")
    assert store.untested_combinations() == []


def test_finding_dedupes_canonical_redacted_evidence(store: StateStore) -> None:
    evidence = {
        "object_id": "document-1",
        "attacker_status": 200,
        "comparison": "object_id_match",
    }
    title, description = canonical_finding_text(
        severity="high",
        endpoint_template="/documents/{id}",
        method="GET",
        evidence=evidence,
    )
    finding = Finding(
        endpoint_template="/documents/{id}",
        method="GET",
        severity="high",
        title=title,
        description=description,
        evidence=evidence,
    )

    first_id = store.add_finding(finding)
    duplicate_id = store.add_finding(finding)

    assert duplicate_id == first_id
    findings = store.list_findings()
    assert findings == [
        replace(
            finding,
            evidence={
                "attacker_status": 200,
                "comparison": "object_id_match",
                "object_ref": object_ref_fingerprint("document-1"),
            },
        )
    ]


def test_finding_rejects_custom_title_and_description_without_persisting_them(
    store: StateStore, tmp_path: Path
) -> None:
    sentinel = "alphanumericfindingsecretsentinel"  # noqa: S105 - test sentinel
    finding = Finding(
        endpoint_template="/documents/{id}",
        method="GET",
        severity="high",
        title=sentinel,
        description=sentinel,
        evidence={"object_id": "document-1", "attacker_status": 200},
    )

    with pytest.raises(ValueError):
        store.add_finding(finding)

    assert store.list_findings() == []
    for path in (tmp_path / "state.db", tmp_path / "state.db-wal", tmp_path / "state.db-shm"):
        if path.exists():
            assert sentinel.encode() not in path.read_bytes()


def test_audit_events_are_ordered_and_append_only(store: StateStore) -> None:
    run_id = store.start_run("fixture")
    # Exact pre-enum string values remain runtime-compatible, while arbitrary
    # strings are rejected by the closed event validator.
    second_id = store.add_audit_event(  # type: ignore[arg-type]
        "ownership_imported", {"count": 1}, run_id=run_id
    )

    events = store.list_audit_events()

    assert [event.event_type for event in events] == [
        AuditEventType.RUN_STARTED,
        AuditEventType.OWNERSHIP_IMPORTED,
    ]
    assert [event.id for event in events] == sorted(event.id for event in events)
    assert events[-1].id == second_id
    with store._connection() as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute("DELETE FROM audit_events WHERE id = ?", (second_id,))


def test_audit_event_names_and_run_labels_never_persist_caller_text(
    store: StateStore, tmp_path: Path
) -> None:
    event_name = "sk_live_AuditEventNameSentinel_A1b2C3d4E5f6"  # noqa: S105
    run_label = "sk_live_RunLabelSentinel_Z9y8X7w6V5u4"  # noqa: S105

    with pytest.raises(ValueError, match="approved event name"):
        store.add_audit_event(event_name, {"count": 1})  # type: ignore[arg-type]

    run_id = store.start_run(run_label)
    label_ref = run_label_fingerprint(run_label)
    with store._connection() as connection:
        persisted_label = connection.execute(
            "SELECT label FROM runs WHERE id = ?", (run_id,)
        ).fetchone()[0]

    assert persisted_label == label_ref
    events = store.list_audit_events()
    assert len(events) == 1
    assert events[0].event_type is AuditEventType.RUN_STARTED
    assert events[0].run_id == run_id
    assert events[0].data == {"label": label_ref}
    for path in (tmp_path / "state.db", tmp_path / "state.db-wal", tmp_path / "state.db-shm"):
        if path.exists():
            contents = path.read_bytes()
            assert event_name.encode() not in contents
            assert run_label.encode() not in contents


def test_credential_reference_rejects_raw_values_before_any_database_write(
    store: StateStore, tmp_path: Path
) -> None:
    secret = "credential-value-that-must-not-persist"  # noqa: S105 - test sentinel
    with pytest.raises(ValueError):
        store.add_identity("alice", credential_ref_id=secret)

    invalid_credential = replace(_credential("alice"), secret_ref=secret)
    invalid_target = replace(_target(), owner_credential=invalid_credential)
    with pytest.raises(ValueError):
        store.record_probe_result(
            ProbeResult(
                target=invalid_target,
                verdict=Verdict.PROTECTED,
                owner_status=200,
                attacker_status=403,
            )
        )

    with store._connection() as connection:
        table_counts = {
            "endpoints": connection.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0],
            "identities": connection.execute("SELECT COUNT(*) FROM identities").fetchone()[0],
            "tested_combinations": connection.execute(
                "SELECT COUNT(*) FROM tested_combinations"
            ).fetchone()[0],
            "audit_events": connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0],
        }
    assert table_counts == {
        "endpoints": 0,
        "identities": 0,
        "tested_combinations": 0,
        "audit_events": 0,
    }

    candidates = [tmp_path / "state.db", tmp_path / "state.db-wal", tmp_path / "state.db-shm"]
    for path in candidates:
        if path.exists():
            assert secret.encode() not in path.read_bytes()


@pytest.mark.parametrize(
    "credential_ref_id",
    [
        "env:NOT A_VARIABLE",
        "keyring:Bearer credential-value",
        "vault:eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature",
        "memory:session=credential-value",
    ],
)
def test_credential_reference_rejects_transport_or_value_like_material(
    store: StateStore, credential_ref_id: str
) -> None:
    with pytest.raises(ValueError):
        store.add_identity("alice", credential_ref_id=credential_ref_id)


def test_json_persistence_rejects_unknown_keys_and_authentication_containers(
    store: StateStore, tmp_path: Path
) -> None:
    secret = "custom-authentication-value"  # noqa: S105 - test sentinel

    with pytest.raises(ValueError):
        store.add_audit_event(
            AuditEventType.OWNERSHIP_IMPORTED, {"headers": {"X-Auth": secret}}
        )
    with pytest.raises(ValueError):
        store.add_audit_event(AuditEventType.OWNERSHIP_IMPORTED, {"error": secret})
    with pytest.raises(ValueError):
        store.add_finding(
            Finding(
                endpoint_template="/documents/{id}",
                method="GET",
                severity="high",
                title="Fixture",
                description="Fixture finding",
                evidence={"unrecognised": "value"},
            )
        )

    with store._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0

    for path in (tmp_path / "state.db", tmp_path / "state.db-wal", tmp_path / "state.db-shm"):
        if path.exists():
            assert secret.encode() not in path.read_bytes()


def test_database_never_contains_credential_values(store: StateStore, tmp_path: Path) -> None:
    secret = "env:STATE_SENTINEL"  # noqa: S105 - test sentinel
    credential = replace(_credential("alice"), secret_ref=secret)
    store.add_identity(
        "alice",
        metadata={"subject": "alice"},
        credential=credential,
    )
    store.add_audit_event(AuditEventType.OWNERSHIP_IMPORTED, {"count": 1})
    evidence = {"object_id": "document-1", "attacker_status": 200}
    title, description = canonical_finding_text(
        severity="high",
        endpoint_template="/documents/{id}",
        method="GET",
        evidence=evidence,
    )
    store.add_finding(
        Finding(
            endpoint_template="/documents/{id}",
            method="GET",
            severity="high",
            title=title,
            description=description,
            evidence=evidence,
        )
    )

    assert store.list_identities()[0]["credential_ref_id"] == credential_ref_fingerprint(credential)
    with pytest.raises(ValueError):
        store.add_audit_event(AuditEventType.OWNERSHIP_IMPORTED, {"error_code": secret})
    with pytest.raises(ValueError):
        store.add_audit_event(
            AuditEventType.OWNERSHIP_IMPORTED, {"error_code": "alphanumericsentinel"}
        )
    candidates = [tmp_path / "state.db", tmp_path / "state.db-wal", tmp_path / "state.db-shm"]
    for path in candidates:
        if path.exists():
            assert secret.encode() not in path.read_bytes()


def test_object_identifiers_are_opaque_in_rows_audit_and_findings(
    store: StateStore, tmp_path: Path
) -> None:
    secret = "sk_live_A1b2C3d4E5f6G7h8J9k0"  # noqa: S105 - test sentinel
    object_ref = object_ref_fingerprint(secret)
    alice_id = store.add_identity("alice")
    bob_id = store.add_identity("bob")
    endpoint_id = store.add_endpoint("/documents/{id}", "GET")

    store.add_owned_object(
        alice_id,
        endpoint_id,
        secret,
        confidence=OwnershipConfidence.EXPLICIT,
        source="fixture",
    )
    pending = store.untested_combinations()
    assert len(pending) == 1
    assert pending[0].object_ref == object_ref
    assert pending[0].object_id == object_ref
    assert store.objects_owned_by(alice_id, endpoint_id) == [object_ref]
    assert store.ownership_evidence_for("/documents/{id}", "GET", secret)[0].object_id == (
        object_ref
    )

    store.mark_tested(endpoint_id, alice_id, bob_id, secret, status="protected")
    assert store.has_been_tested(endpoint_id, alice_id, bob_id, secret)
    assert store.has_been_tested(endpoint_id, alice_id, bob_id, object_ref)
    store.add_audit_event(AuditEventType.OWNERSHIP_IMPORTED, {"object_id": secret})

    finding_evidence = {"object_id": secret, "attacker_status": 200}
    title, description = canonical_finding_text(
        severity="high",
        endpoint_template="/documents/{id}",
        method="GET",
        evidence=finding_evidence,
    )
    assert secret not in title
    assert secret not in description
    identity_title, identity_description = canonical_finding_text(
        severity="high",
        endpoint_template="/documents/{id}",
        method="GET",
        evidence={**finding_evidence, "identity": "reportidentitysentinel"},
    )
    assert "reportidentitysentinel" not in identity_title
    assert "reportidentitysentinel" not in identity_description
    assert object_ref in description
    store.add_finding(
        Finding(
            endpoint_template="/documents/{id}",
            method="GET",
            severity="high",
            title=title,
            description=description,
            evidence=finding_evidence,
        )
    )
    persisted_finding = store.list_findings()[0]
    assert persisted_finding.evidence["object_ref"] == object_ref
    assert "object_id" not in persisted_finding.evidence
    assert store.list_audit_events()[-1].data == {"object_ref": object_ref}

    with store._connection() as connection:
        ownership_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(ownership_evidence)")
        }
        attempt_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(tested_combinations)")
        }
        stored_ownership_ref = connection.execute(
            "SELECT object_ref FROM ownership_evidence"
        ).fetchone()[0]
        stored_attempt_ref = connection.execute(
            "SELECT object_ref FROM tested_combinations"
        ).fetchone()[0]
    assert "object_ref" in ownership_columns and "object_id" not in ownership_columns
    assert "object_ref" in attempt_columns and "object_id" not in attempt_columns
    assert stored_ownership_ref == stored_attempt_ref == object_ref

    for path in (tmp_path / "state.db", tmp_path / "state.db-wal", tmp_path / "state.db-shm"):
        if path.exists():
            assert secret.encode() not in path.read_bytes()


@pytest.mark.parametrize(
    "unsafe_segment",
    [
        "424242424242424242424242424242424242424242",
        "%34%32",
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "507f1f77bcf86cd799439011",
        "aB3dE5fG7hI9jK2m",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature",
        "sk_live_A1b2C3d4E5f6G7h8",
    ],
)
def test_state_rejects_concrete_identifier_like_endpoint_segments(
    store: StateStore, tmp_path: Path, unsafe_segment: str
) -> None:
    store.add_endpoint(
        "/v/1/reports/2024/2024-01-31/documents/{id}/events/{id2}", "GET"
    )
    store.add_endpoint("/documents/{id}/labels/route-label", "GET")

    with pytest.raises(ValueError):
        store.add_endpoint(f"/documents/{unsafe_segment}", "GET")

    assert len(store.list_endpoints()) == 2
    for path in (tmp_path / "state.db", tmp_path / "state.db-wal", tmp_path / "state.db-shm"):
        if path.exists():
            assert unsafe_segment.encode() not in path.read_bytes()


@pytest.mark.parametrize("encoding_depth", [1, 4, 5, 8])
def test_state_rejects_deeply_percent_encoded_endpoint_segments_without_persistence(
    store: StateStore, tmp_path: Path, encoding_depth: int
) -> None:
    encoded = "".join(
        f"%{byte:02X}" for byte in b"sk_live_DeepEndpointSentinel_A1b2C3d4E5f6"
    )
    for _ in range(encoding_depth - 1):
        encoded = encoded.replace("%", "%25")

    with pytest.raises(ValueError, match="percent escapes"):
        store.add_endpoint(f"/documents/{encoded}", "GET")

    assert store.list_endpoints() == []
    for path in (tmp_path / "state.db", tmp_path / "state.db-wal", tmp_path / "state.db-shm"):
        if path.exists():
            assert encoded.encode() not in path.read_bytes()


def test_v2_to_v3_migration_scrubs_object_and_endpoint_secret_bytes(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    store = StateStore(db_path)
    secret = "aB3dE5fG7hI9jK2mZ4xC6vB8nM0qR"  # noqa: S105 - test sentinel
    timestamp = "2026-08-24T00:00:00+00:00"

    with store._connection() as connection:
        connection.execute(
            "ALTER TABLE ownership_evidence RENAME COLUMN object_ref TO object_id"
        )
        connection.execute(
            "ALTER TABLE tested_combinations RENAME COLUMN object_ref TO object_id"
        )
        connection.execute("DELETE FROM schema_migrations WHERE version = 3")
        connection.execute("UPDATE schema_version SET version = 2 WHERE singleton = 1")
        endpoint_id = connection.execute(
            "INSERT INTO endpoints(template, method, first_seen_at) VALUES (?, 'GET', ?)",
            (f"/documents/{secret}", timestamp),
        ).lastrowid
        alice_id = connection.execute(
            "INSERT INTO identities(name, metadata_json, first_seen_at) VALUES ('alice', '{}', ?)",
            (timestamp,),
        ).lastrowid
        bob_id = connection.execute(
            "INSERT INTO identities(name, metadata_json, first_seen_at) VALUES ('bob', '{}', ?)",
            (timestamp,),
        ).lastrowid
        assert endpoint_id is not None and alice_id is not None and bob_id is not None
        connection.execute(
            "INSERT INTO ownership_evidence("
            "identity_id, endpoint_id, object_id, confidence, source, recorded_at"
            ") VALUES (?, ?, ?, 'explicit', 'fixture', ?)",
            (alice_id, endpoint_id, secret, timestamp),
        )
        connection.execute(
            "INSERT INTO tested_combinations("
            "endpoint_id, owner_identity_id, attacker_identity_id, object_id, "
            "attempt_status, retryable, attempted_at"
            ") VALUES (?, ?, ?, ?, 'protected', 0, ?)",
            (endpoint_id, alice_id, bob_id, secret, timestamp),
        )
        legacy_evidence = f'{{"object_id":"{secret}","attacker_status":200}}'
        connection.execute(
            "INSERT INTO findings("
            "endpoint_id, severity, title, description, evidence_json, evidence_hash, found_at"
            ") VALUES (?, 'high', ?, ?, ?, 'legacy', ?)",
            (endpoint_id, secret, secret, legacy_evidence, timestamp),
        )
        run_id = connection.execute(
            "INSERT INTO runs(started_at, label, metadata_json) VALUES (?, ?, '{}')",
            (timestamp, secret),
        ).lastrowid
        assert run_id is not None
        connection.execute(
            "INSERT INTO audit_events(event_type, occurred_at, run_id, data_json) "
            "VALUES (?, ?, ?, ?)",
            (
                secret,
                timestamp,
                run_id,
                f'{{"endpoint_id":{endpoint_id},"object_id":"{secret}","label":"{secret}"}}',
            ),
        )

    migrated = StateStore(db_path)
    object_ref = object_ref_fingerprint(secret)

    assert migrated.schema_version() == 3
    assert migrated.list_endpoints()[0]["template"] == "/documents/{id}"
    assert migrated.objects_owned_by(int(alice_id), int(endpoint_id)) == [object_ref]
    assert migrated.list_findings()[0].evidence == {
        "attacker_status": 200,
        "object_ref": object_ref,
    }
    migrated_event = migrated.list_audit_events()[0]
    assert migrated_event.event_type is AuditEventType.LEGACY_EVENT_REDACTED
    assert migrated_event.data == {
        "endpoint_id": int(endpoint_id),
        "label": run_label_fingerprint(secret),
        "object_ref": object_ref,
    }
    with migrated._connection() as connection:
        assert connection.execute("SELECT label FROM runs").fetchone()[0] == (
            run_label_fingerprint(secret)
        )
    for path in (db_path, tmp_path / "state.db-wal", tmp_path / "state.db-shm"):
        if path.exists():
            assert secret.encode() not in path.read_bytes()


def test_v2_to_v3_archives_every_legacy_finding_and_coalesces_current_rows(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.db"
    store = StateStore(db_path)
    secret = "sk_live_LegacyFindingArchiveSentinel_A1b2C3d4E5f6"  # noqa: S105
    timestamp = "2026-08-24T00:00:00+00:00"

    with store._connection() as connection:
        connection.execute(
            "ALTER TABLE ownership_evidence RENAME COLUMN object_ref TO object_id"
        )
        connection.execute(
            "ALTER TABLE tested_combinations RENAME COLUMN object_ref TO object_id"
        )
        connection.execute("DELETE FROM schema_migrations WHERE version = 3")
        connection.execute("UPDATE schema_version SET version = 2 WHERE singleton = 1")
        endpoint_id = connection.execute(
            "INSERT INTO endpoints(template, method, first_seen_at) VALUES (?, 'GET', ?)",
            (f"/documents/{secret}", timestamp),
        ).lastrowid
        assert endpoint_id is not None
        legacy_evidence = f'{{"object_id":"{secret}","attacker_status":200}}'
        for title, evidence_hash in (
            ("legacy-one", "legacy-hash-1"),
            ("legacy-two", "legacy-hash-2"),
        ):
            connection.execute(
                "INSERT INTO findings("
                "endpoint_id, severity, title, description, evidence_json, evidence_hash, found_at"
                ") VALUES (?, 'high', ?, ?, ?, ?, ?)",
                (endpoint_id, title, title, legacy_evidence, evidence_hash, timestamp),
            )

    migrated = StateStore(db_path)
    object_ref = object_ref_fingerprint(secret)
    assert len(migrated.list_findings()) == 1

    with migrated._connection() as connection:
        archive = connection.execute(
            "SELECT legacy_finding_id, legacy_object_ref, canonical_title, evidence_json, "
            "migration_marker FROM legacy_finding_events ORDER BY legacy_finding_id"
        ).fetchall()
        assert len(archive) == 2
        assert [str(row[1]) for row in archive] == [object_ref, object_ref]
        assert all(str(row[4]) == "v3_findings_archive" for row in archive)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE legacy_finding_events SET canonical_title = 'changed' WHERE id = 1"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM legacy_finding_events WHERE id = 1")

        migration_events = connection.execute(
            "SELECT data_json FROM audit_events WHERE event_type = ?",
            (AuditEventType.LEGACY_EVENT_REDACTED.value,),
        ).fetchall()
        assert len(migration_events) == 1
        assert json.loads(str(migration_events[0][0])) == {
            "coalesced_count": 1,
            "migration_marker": "v3_findings_archive",
            "preserved_count": 2,
        }

    for path in (db_path, tmp_path / "state.db-wal", tmp_path / "state.db-shm"):
        if path.exists():
            assert secret.encode() not in path.read_bytes()

    StateStore(db_path)
    with migrated._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM legacy_finding_events").fetchone()[0]
            == 2
        )


def test_v2_to_v3_migration_fails_unchanged_with_active_reader_then_retries(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.db"
    store = StateStore(db_path)
    secret = "sk_live_ActiveReaderMigrationSentinel_A1b2C3d4E5f6"  # noqa: S105
    endpoint_id, identity_id = _prepare_v2_ownership_state(store, secret)

    reader = sqlite3.connect(db_path)
    try:
        reader.execute("PRAGMA journal_mode = WAL")
        reader.execute("BEGIN")
        assert reader.execute("SELECT object_id FROM ownership_evidence").fetchone() == (secret,)

        with pytest.raises((RuntimeError, sqlite3.OperationalError)):
            StateStore(db_path)

        assert reader.execute("SELECT version FROM schema_version").fetchone() == (2,)
        assert reader.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(1,), (2,)]
        assert {
            str(row[1]) for row in reader.execute("PRAGMA table_info(ownership_evidence)")
        } >= {"object_id"}
    finally:
        reader.rollback()
        reader.close()

    untouched = sqlite3.connect(db_path)
    try:
        assert untouched.execute("SELECT version FROM schema_version").fetchone() == (2,)
        assert untouched.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(1,), (2,)]
        assert {
            str(row[1]) for row in untouched.execute("PRAGMA table_info(ownership_evidence)")
        } >= {"object_id"}
        assert untouched.execute("SELECT object_id FROM ownership_evidence").fetchone() == (
            secret,
        )
    finally:
        untouched.close()

    migrated = StateStore(db_path)

    assert migrated.schema_version() == 3
    with migrated._connection() as connection:
        assert [
            int(row[0])
            for row in connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        ] == [1, 2, 3]
    assert migrated.list_endpoints()[0]["template"] == "/documents/{id}"
    assert migrated.objects_owned_by(identity_id, endpoint_id) == [
        object_ref_fingerprint(secret)
    ]
    for path in (db_path, tmp_path / "state.db-wal", tmp_path / "state.db-shm"):
        if path.exists():
            assert secret.encode() not in path.read_bytes()


def test_v2_to_v3_migration_records_v3_only_after_vacuum_and_can_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "state.db"
    store = StateStore(db_path)
    secret = "sk_live_VacuumFailureMigrationSentinel_Q1w2E3r4T5y6"  # noqa: S105
    endpoint_id, identity_id = _prepare_v2_ownership_state(store, secret)

    def fail_vacuum(_connection: sqlite3.Connection) -> None:
        raise sqlite3.OperationalError("injected VACUUM failure")

    with monkeypatch.context() as patch:
        patch.setattr(StateStore, "_vacuum_object_state", staticmethod(fail_vacuum))
        with pytest.raises(sqlite3.OperationalError, match="injected VACUUM failure"):
            StateStore(db_path)

    partially_migrated = sqlite3.connect(db_path)
    try:
        assert partially_migrated.execute(
            "SELECT version FROM schema_version"
        ).fetchone() == (2,)
        assert partially_migrated.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(1,), (2,)]
        assert {
            str(row[1])
            for row in partially_migrated.execute("PRAGMA table_info(ownership_evidence)")
        } >= {"object_ref"}
    finally:
        partially_migrated.close()

    migrated = StateStore(db_path)

    assert migrated.schema_version() == 3
    assert migrated.objects_owned_by(identity_id, endpoint_id) == [
        object_ref_fingerprint(secret)
    ]
    for path in (db_path, tmp_path / "state.db-wal", tmp_path / "state.db-shm"):
        if path.exists():
            assert secret.encode() not in path.read_bytes()


def test_v1_to_v2_migration_removes_literal_reference_bytes(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    store = StateStore(db_path)
    store.add_identity("alice")
    sentinel = "env:V1_MIGRATION_SENTINEL"  # noqa: S105 - test sentinel

    with store._connection() as connection:
        connection.execute(
            "UPDATE identities SET credential_ref_id = ? WHERE name = ?", (sentinel, "alice")
        )
        connection.execute("DELETE FROM schema_migrations WHERE version = 2")
        connection.execute("UPDATE schema_version SET version = 1 WHERE singleton = 1")

    migrated = StateStore(db_path)

    assert migrated.schema_version() == 3
    assert migrated.list_identities()[0]["credential_ref_id"].startswith("ref_")
    for path in (db_path, tmp_path / "state.db-wal", tmp_path / "state.db-shm"):
        if path.exists():
            assert sentinel.encode() not in path.read_bytes()


def test_composite_writes_roll_back_when_audit_insert_fails(store: StateStore) -> None:
    with store._connection() as connection:
        connection.execute(
            "CREATE TRIGGER fail_audit_insert BEFORE INSERT ON audit_events BEGIN "
            "SELECT RAISE(ABORT, 'injected audit failure'); END"
        )

    result = ProbeResult(
        target=_target(),
        verdict=Verdict.PROTECTED,
        owner_status=200,
        attacker_status=403,
    )
    with pytest.raises(sqlite3.IntegrityError):
        store.record_probe_result(result)
    with pytest.raises(sqlite3.IntegrityError):
        store.start_run("will-roll-back")

    with store._connection() as connection:
        table_counts = {
            "endpoints": connection.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0],
            "identities": connection.execute("SELECT COUNT(*) FROM identities").fetchone()[0],
            "runs": connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0],
            "tested_combinations": connection.execute(
                "SELECT COUNT(*) FROM tested_combinations"
            ).fetchone()[0],
            "audit_events": connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0],
        }
    assert table_counts == {
        "endpoints": 0,
        "identities": 0,
        "runs": 0,
        "tested_combinations": 0,
        "audit_events": 0,
    }


def test_concurrent_audit_writers_are_serialized(store: StateStore) -> None:
    with ThreadPoolExecutor(max_workers=4) as executor:
        event_ids = list(
            executor.map(
                lambda index: store.add_audit_event(
                    AuditEventType.OWNERSHIP_IMPORTED, {"count": index}
                ),
                range(12),
            )
        )

    assert sorted(event_ids) == [event.id for event in store.list_audit_events()]
