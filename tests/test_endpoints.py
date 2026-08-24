from __future__ import annotations

from pathlib import Path

import pytest

from openbola.endpoints import (
    CandidateLocation,
    build_test_targets,
    correlate_ownership,
    executable_ownership,
    extract_endpoint_candidates,
    extract_object_ids,
    templatize,
)
from openbola.models import (
    OwnershipConfidence,
    OwnershipEvidence,
)
from openbola.models import (
    OwnershipConflictError as ModelOwnershipConflictError,
)
from openbola.state import (
    OwnershipConflictError as StateOwnershipConflictError,
)
from openbola.state import (
    StateStore,
    object_ref_fingerprint,
)


def _strong_evidence(identity: str) -> OwnershipEvidence:
    return OwnershipEvidence(
        identity=identity,
        endpoint_template="/documents/{id}",
        method="GET",
        object_id="42",
        confidence=OwnershipConfidence.EXPLICIT,
        source=f"fixture:{identity}",
    )


def test_templatize_supported_ids_with_stable_nested_names() -> None:
    uuid = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    mongo_id = "507f1f77bcf86cd799439011"
    opaque_id = "aB3dE5fG7hI9jK2m"

    assert templatize(f"/users/42/orders/{uuid}/events/{mongo_id}/{opaque_id}") == (
        "/users/{id}/orders/{id2}/events/{id3}/{id4}"
    )
    assert extract_object_ids(f"/users/42/orders/{uuid}") == ["42", uuid]


def test_templatize_keeps_versions_slugs_and_dates_and_does_not_mix_query() -> None:
    path = (
        "/v1/users/short-slug/reports/2024-01-31/archive/20240131"
        "/api/2024/v/1?document_id=42"
    )

    assert templatize(path) == (
        "/v1/users/short-slug/reports/2024-01-31/archive/20240131/api/2024/v/1"
    )
    assert extract_object_ids(path) == []


def test_templatize_decodes_an_id_per_segment_without_decoding_path_structure() -> None:
    assert templatize("/documents/%34%32/labels/a%2Fb") == "/documents/{id}/labels/a%2Fb"


def test_templatize_output_is_safe_for_state_persistence(tmp_path: Path) -> None:
    template = templatize(
        "/documents/42/attachments/f47ac10b-58cc-4372-a567-0e02b2c3d479"
    )
    assert template == "/documents/{id}/attachments/{id2}"

    store = StateStore(tmp_path / "state.db")
    store.add_endpoint(template, "GET")
    assert store.list_endpoints()[0]["template"] == template


def test_state_rejects_un_templatized_identifier_like_route(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.db")
    unsafe_template = templatize("/documents/credentialmaterial987654")

    # Endpoint discovery must not silently persist a concrete identifier-shaped
    # segment when the recogniser cannot establish that it is an object ID.
    assert unsafe_template == "/documents/credentialmaterial987654"
    with pytest.raises(ValueError, match="concrete identifier-like segment"):
        store.add_endpoint(unsafe_template, "GET")


def test_ownership_conflict_exception_is_a_shared_contract() -> None:
    assert StateOwnershipConflictError is ModelOwnershipConflictError


def test_extract_candidates_for_path_query_nested_json_and_graphql_variables() -> None:
    entry = {
        "url": "https://api.example.test/projects/12?member_id=34&page=1",
        "method": "POST",
        "body": {
            "document": {"id": "507f1f77bcf86cd799439011"},
            "page": 2,
        },
    }
    candidates = extract_endpoint_candidates(entry)

    candidate_values = [
        (candidate.location, candidate.object_id, candidate.locator) for candidate in candidates
    ]
    assert candidate_values == [
        (CandidateLocation.PATH, "12", "path:id"),
        (CandidateLocation.QUERY, "34", "query:member_id"),
        (CandidateLocation.JSON_BODY, "507f1f77bcf86cd799439011", "$.document.id"),
    ]

    graphql = {
        "url": "https://api.example.test/graphql",
        "method": "POST",
        "body": {
            "query": "query Get($input: Input!) { node { id } }",
            "variables": {"input": {"nodeId": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}},
        },
    }
    graphql_candidates = extract_endpoint_candidates(graphql)

    assert [(candidate.location, candidate.locator) for candidate in graphql_candidates] == [
        (CandidateLocation.GRAPHQL_VARIABLE, "$.variables.input.nodeId")
    ]


def test_sensitive_id_fields_never_become_candidates_or_appear_in_candidate_repr() -> None:
    sentinel = "aB3dE5fG7hI9jK2m"
    candidates = extract_endpoint_candidates(
        {
            "url": f"https://api.example.test/documents/42?api_token_id={sentinel}",
            "method": "POST",
            "body": {
                "apiKeyId": sentinel,
                "session_id": sentinel,
                "document_id": 44,
            },
        }
    )

    assert [candidate.object_id for candidate in candidates] == ["42", "44"]
    assert sentinel not in repr(candidates)


def test_identity_hint_response_match_is_executable_but_requester_only_is_not() -> None:
    entries = [
        {
            "url": "https://api.example.test/documents/42",
            "method": "GET",
            "requester_identity": "mallory",
            "response_body": {"id": 42, "owner_id": "sub-alice"},
        }
    ]

    evidence = correlate_ownership(entries, {"sub-alice": "alice"})

    assert {(item.identity, item.confidence) for item in evidence} == {
        ("alice", OwnershipConfidence.RESPONSE_MATCH),
        ("mallory", OwnershipConfidence.HEURISTIC),
    }
    assert [(item.identity, item.confidence) for item in executable_ownership(evidence)] == [
        ("alice", OwnershipConfidence.RESPONSE_MATCH)
    ]


def test_successful_create_location_and_body_are_observed_ownership() -> None:
    entry = {
        "url": "https://api.example.test/documents",
        "method": "POST",
        "requester_identity": "alice",
        "response_status": 201,
        "response_headers": {"Location": "/documents/42"},
        "response_body": {"id": 42},
    }

    evidence = correlate_ownership([entry], {})

    assert {(item.object_id, item.confidence, item.endpoint_template) for item in evidence} == {
        ("42", OwnershipConfidence.OBSERVED_CREATE, "/documents/{id}"),
        ("42", OwnershipConfidence.OBSERVED_CREATE, "/documents"),
    }
    assert len(executable_ownership(evidence)) == 2


def test_successful_create_ignores_nested_related_ids_unless_location_confirms_them() -> None:
    entry = {
        "url": "https://api.example.test/documents",
        "method": "POST",
        "requester_identity": "alice",
        "response_status": 201,
        "response_headers": {"Location": "/documents/42"},
        "response_body": {"id": 42, "related": {"id": 99}},
    }

    evidence = correlate_ownership([entry], {})

    assert {item.object_id for item in evidence} == {"42"}


def test_conflicting_strong_ownership_is_not_executable() -> None:
    entries = [
        {
            "url": "https://api.example.test/documents/42",
            "method": "GET",
            "explicit_ownership": {"42": "alice"},
        },
        {
            "url": "https://api.example.test/documents/42",
            "method": "GET",
            "explicit_ownership": {"42": "bob"},
        },
    ]

    assert executable_ownership(correlate_ownership(entries, {})) == []


def test_persistence_bridge_only_receives_executable_evidence() -> None:
    class RecordingStore:
        def __init__(self) -> None:
            self.persisted: list[OwnershipEvidence] = []

        def persist_ownership_evidence(self, evidence: OwnershipEvidence) -> int:
            self.persisted.append(evidence)
            return len(self.persisted)

        def ownership_evidence_for(
            self, endpoint_template: str, method: str, object_id: str
        ) -> list[OwnershipEvidence]:
            return [
                evidence
                for evidence in self.persisted
                if (evidence.endpoint_template, evidence.method, evidence.object_id)
                == (endpoint_template, method, object_id)
            ]

    evidence = correlate_ownership(
        [
            {
                "url": "https://api.example.test/documents/42",
                "method": "GET",
                "requester_identity": "mallory",
                "response_body": {"id": 42, "owner_id": "sub-alice"},
            }
        ],
        {"sub-alice": "alice"},
    )
    store = RecordingStore()

    result = build_test_targets(store, evidence)

    assert len(store.persisted) == 1
    assert store.persisted[0].identity == "alice"
    assert result.conflicts == ()


def test_persistence_bridge_rejects_conflict_with_evidence_from_an_earlier_call() -> None:
    class RecordingStore:
        def __init__(self) -> None:
            self.persisted: list[OwnershipEvidence] = []

        def persist_ownership_evidence(self, evidence: OwnershipEvidence) -> int:
            self.persisted.append(evidence)
            return len(self.persisted)

        def ownership_evidence_for(
            self, endpoint_template: str, method: str, object_id: str
        ) -> list[OwnershipEvidence]:
            return [
                evidence
                for evidence in self.persisted
                if (evidence.endpoint_template, evidence.method, evidence.object_id)
                == (endpoint_template, method, object_id)
            ]

    store = RecordingStore()
    alice_evidence = correlate_ownership(
        [
            {
                "url": "https://api.example.test/documents/42",
                "method": "GET",
                "explicit_ownership": {"42": "alice"},
            }
        ],
        {},
    )
    bob_evidence = correlate_ownership(
        [
            {
                "url": "https://api.example.test/documents/42",
                "method": "GET",
                "explicit_ownership": {"42": "bob"},
            }
        ],
        {},
    )

    first = build_test_targets(store, alice_evidence)
    second = build_test_targets(store, bob_evidence)

    assert [item.identity for item in first.persisted] == ["alice"]
    assert store.persisted == list(first.persisted)
    assert len(second.conflicts) == 1
    assert second.conflicts[0].candidate.identity == "bob"
    assert [item.identity for item in second.conflicts[0].existing] == ["alice"]


def test_persistence_bridge_converts_real_state_sequential_conflict(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.db")

    first = build_test_targets(store, [_strong_evidence("alice")])
    second = build_test_targets(store, [_strong_evidence("bob")])

    assert first.persisted == (_strong_evidence("alice"),)
    assert second.persisted == ()
    assert len(second.conflicts) == 1
    assert second.conflicts[0].candidate.identity == "bob"
    assert [item.identity for item in second.conflicts[0].existing] == ["alice"]
    assert store.ownership_evidence_for("/documents/{id}", "GET", "42") == [
        OwnershipEvidence(
            identity="alice",
            endpoint_template="/documents/{id}",
            method="GET",
            object_id=object_ref_fingerprint("42"),
            confidence=OwnershipConfidence.EXPLICIT,
            source="fixture:alice",
        )
    ]


def test_persistence_bridge_converts_transactional_write_race_to_conflict(tmp_path: Path) -> None:
    class InterleavingStore:
        def __init__(self, store: StateStore, intervening: OwnershipEvidence) -> None:
            self.store = store
            self.intervening = intervening
            self.injected = False

        def ownership_evidence_for(
            self, endpoint_template: str, method: str, object_id: str
        ) -> list[OwnershipEvidence]:
            if not self.injected:
                return []
            return self.store.ownership_evidence_for(endpoint_template, method, object_id)

        def persist_ownership_evidence(self, evidence: OwnershipEvidence) -> int:
            if not self.injected:
                self.injected = True
                self.store.persist_ownership_evidence(self.intervening)
            return self.store.persist_ownership_evidence(evidence)

    alice = _strong_evidence("alice")
    store = InterleavingStore(StateStore(tmp_path / "state.db"), alice)

    result = build_test_targets(store, [_strong_evidence("bob")])

    assert result.persisted == ()
    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert conflict.candidate == _strong_evidence("bob")
    assert conflict.existing == (
        OwnershipEvidence(
            identity="alice",
            endpoint_template="/documents/{id}",
            method="GET",
            object_id=object_ref_fingerprint("42"),
            confidence=OwnershipConfidence.EXPLICIT,
            source="fixture:alice",
        ),
    )
