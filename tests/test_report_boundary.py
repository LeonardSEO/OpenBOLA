from __future__ import annotations

import dataclasses
import json
import pickle
from pathlib import Path

from openbola.capture import InSessionCapture
from openbola.handles import ValueHandle
from openbola.models import Finding
from openbola.reporting import (
    CapabilityProof,
    FindingEvidence,
    ReportBundle,
    ReportField,
    ResourceReport,
    canonical_report_document,
    generate_csv_report,
    generate_html_report,
    generate_json_report,
    generate_junit_xml,
    generate_markdown_report,
    generate_sarif_report,
    write_reports,
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


def test_cross_phase_sentinels_stop_at_typed_report_boundary(
    tmp_path: Path, captured_session_with_sentinels: InSessionCapture
) -> None:
    """Prove the report boundary cannot resolve or export session material."""

    raw_object_id = "REPORT_RAW_OBJECT_SENTINEL"
    sentinels = (
        raw_object_id,
        "RAW_ID_4eC39HqLyjWDarjtT1zdp7dc",
        "REQUEST_SECRET_SENTINEL",
        "COOKIE_SECRET_SENTINEL",
        "FULL_VALUE_SENTINEL",
    )

    # The capture fixture retains all of these values only behind ValueHandles.
    exchange = captured_session_with_sentinels.exchanges[0]
    assert isinstance(exchange.request_material_handle, ValueHandle)
    assert isinstance(exchange.response_material_handle, ValueHandle)
    assert isinstance(captured_session_with_sentinels.browser_state_handle, ValueHandle)

    state_path = tmp_path / "state.db"
    store = StateStore(state_path)
    evidence = {
        "object_id": raw_object_id,
        "attacker_status": 200,
        "comparison": "object_id_match",
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

    read_proof = CapabilityProof(
        "read",
        "proven",
        "identity_a",
        "identity_b",
        200,
        200,
        "object_id_match",
        "not_applicable",
        "complete",
    )
    resource = ResourceReport(
        provider="generic-http",
        confidence="confirmed",
        dataset="documents",
        endpoint_template="/documents/{id}",
        total_discovered=1,
        fields=(ReportField("id", "string"),),
        capabilities=(read_proof,),
    )
    bundle = ReportBundle.from_state(
        store=store,
        outcomes=(),
        scope_target_label="staging",
        authorization_reference="scope-reference",
        resources=(resource,),
    )

    document = canonical_report_document(bundle)
    artifacts = (
        generate_json_report(bundle),
        generate_markdown_report(bundle),
        generate_csv_report(bundle),
        generate_html_report(bundle),
        generate_junit_xml(bundle),
        generate_sarif_report(bundle),
    )
    paths = write_reports(bundle, output_dir=tmp_path / "reports")
    persisted = [state_path.read_bytes()]
    persisted.extend(path.read_bytes() for path in paths.values())

    # No report representation may retain the source mapping, session registry,
    # or any raw value.  Only the opaque object reference is permitted.
    representations = [
        repr(bundle),
        json.dumps(document, sort_keys=True),
        repr(dataclasses.asdict(bundle)),
        *(item for item in artifacts),
        *(payload.decode("utf-8", errors="replace") for payload in persisted),
    ]
    assert all(
        sentinel not in representation
        for representation in representations
        for sentinel in sentinels
    )
    assert document["findings"][0]["evidence"]["object_ref"].startswith("obj_")
    assert len(document["findings"][0]["evidence"]["object_ref"]) == 68
    assert "scope-reference" not in json.dumps(document)

    # The report bundle is independent of the live session registry; pickling
    # it must not trigger resolution or capture serialization.
    pickled = pickle.dumps(bundle)
    assert all(sentinel.encode() not in pickled for sentinel in sentinels)


def test_legacy_report_explicitly_marks_absent_mutation_facts_as_unavailable() -> None:
    evidence = FindingEvidence.from_legacy_mapping(
        {"attacker_status": 200, "comparison": "object_id_match"},
        method="GET",
        endpoint_template="/documents/{id}",
    )
    read = evidence.capabilities[0]
    assert read.capability == "read"
    assert read.status == "proven"
    # Legacy rows contain no write lifecycle facts; the boundary must not turn
    # a read result into POST/PATCH/PUT/DELETE proof.
    assert read.capability != "post"
    assert read.capability != "patch"
    assert read.capability != "put"
    assert read.capability != "delete"
    assert evidence.coverage == "partial"
