from __future__ import annotations

import json
from pathlib import Path

from openbola.models import Finding
from openbola.reporting import (
    CapabilityProof,
    ReportBundle,
    ReportField,
    ResourceReport,
    canonical_report_document,
)
from openbola.state import StateStore, canonical_finding_text


def test_from_state_adapts_legacy_rows_without_schema_change(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.db")
    evidence = {
        "attacker_status": 200,
        "comparison": "object_id_match",
        "object_ref": "obj_" + "a" * 64,
    }
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
    schema_before = store.schema_version()
    bundle = ReportBundle.from_state(
        store=store,
        outcomes=(),
        scope_target_label="staging",
        authorization_reference="scope-reference",
    )
    document = canonical_report_document(bundle)
    assert document["format"] == "openbola-report-v1"
    assert document["schema_version"] == 1
    assert document["findings"][0]["evidence"]["capabilities"][0]["status"] == "proven"
    assert "scope-reference" not in json.dumps(document)
    assert store.schema_version() == schema_before


def test_document_serializes_typed_resources_in_stable_order() -> None:
    read_proof = CapabilityProof(
        "read",
        "proven",
        "identity_a",
        "identity_b",
        200,
        403,
        "object_id_mismatch",
        "not_applicable",
        "complete",
    )
    resource = ResourceReport(
        provider="generic-http",
        confidence="confirmed",
        dataset="accounts",
        endpoint_template="/accounts/{id}",
        total_discovered=2,
        fields=(ReportField("id", "string"),),
        capabilities=(read_proof,),
    )
    bundle = ReportBundle.from_outcomes(
        findings=(),
        outcomes=(),
        scope_target_label="staging",
        authorization_reference="scope-reference",
        resources=(resource,),
    )
    document = canonical_report_document(bundle)
    assert [row["dataset"] for row in document["resources"]] == ["accounts"]
    repeat = canonical_report_document(bundle)
    assert json.dumps(document, sort_keys=True, separators=(",", ":")) == json.dumps(
        repeat, sort_keys=True, separators=(",", ":")
    )
