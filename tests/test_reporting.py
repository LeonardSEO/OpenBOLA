from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

import openbola.reporting as reporting
from openbola.models import (
    CredentialKind,
    CredentialRef,
    Finding,
    ProbeResult,
    ProbeTarget,
    Verdict,
)
from openbola.reporting import (
    ReportBundle,
    RunSummary,
    generate_json_report,
    generate_junit_xml,
    generate_markdown_report,
    generate_sarif_report,
    serialize_evidence,
    write_reports,
)
from openbola.state import StateStore, canonical_finding_text, object_ref_fingerprint


def _credential(identity: str) -> CredentialRef:
    return CredentialRef(
        identity=identity,
        kind=CredentialKind.BEARER,
        name="Authorization",
        secret_ref=f"keyring:bola/{identity}",
    )


def _outcome(verdict: Verdict, *, endpoint: str = "/documents/{id}") -> ProbeResult:
    target = ProbeTarget(
        base_url="https://api.example.test",
        endpoint_template=endpoint,
        method="GET",
        object_id="document-1",
        owner_identity="alice",
        attacker_identity="bob",
        owner_credential=_credential("alice"),
        attacker_credential=_credential("bob"),
    )
    status = 200 if verdict == Verdict.BOLA else 403
    return ProbeResult(
        target=target,
        verdict=verdict,
        owner_status=200 if verdict != Verdict.INCONCLUSIVE else None,
        attacker_status=status if verdict != Verdict.INCONCLUSIVE else None,
        evidence={"attacker_status": status, "comparison": "object_id_match"}
        if verdict != Verdict.INCONCLUSIVE
        else {"error_code": "timeout"},
    )


def _finding(*, severity: str = "high", evidence: dict[str, object] | None = None) -> Finding:
    return Finding(
        endpoint_template="/documents/{id}",
        method="GET",
        severity=severity,
        title="Cross-account document access",
        description="The attacker received an object owned by another identity.",
        evidence=evidence
        or {
            "attacker_status": 200,
            "comparison": "object_id_match",
            "object_ref": "obj_" + "a" * 64,
        },
    )


def _bundle(
    *,
    findings: tuple[Finding, ...] = (_finding(),),
    outcomes: tuple[ProbeResult, ...] = (_outcome(Verdict.BOLA),),
) -> ReportBundle:
    return ReportBundle.from_outcomes(
        findings=findings,
        outcomes=outcomes,
        scope_target_label="Example staging API",
        authorization_reference="ENG-1234-approved-scope",
        total_combinations=4,
    )


def test_all_formats_are_parseable_deterministic_and_share_safe_summary() -> None:
    bundle = _bundle(
        outcomes=(
            _outcome(Verdict.BOLA),
            _outcome(Verdict.PROTECTED, endpoint="/accounts/{id}"),
            _outcome(Verdict.INCONCLUSIVE, endpoint="/orders/{id}"),
            _outcome(Verdict.SKIPPED, endpoint="/reports/{id}"),
        )
    )

    report = json.loads(generate_json_report(bundle))
    junit = ET.fromstring(generate_junit_xml(bundle))  # noqa: S314 - own generated XML
    markdown = generate_markdown_report(bundle)
    sarif = json.loads(generate_sarif_report(bundle))

    assert report["summary"] == {
        "bola": 1,
        "coverage": {"completed": 2, "ratio": 0.5, "total_combinations": 4},
        "executed": 4,
        "inconclusive": 1,
        "protected": 1,
        "skipped": 1,
    }
    assert report["authorization"]["reference_fingerprint"].startswith("sha256:")
    assert "ENG-1234-approved-scope" not in generate_json_report(bundle)
    assert junit.attrib == {
        "name": "openbola.bola_idor",
        "tests": "4",
        "failures": "1",
        "errors": "0",
        "skipped": "2",
    }
    assert len(junit.findall("testcase")) == 4
    assert len(junit.findall(".//failure")) == 1
    assert len(junit.findall(".//skipped")) == 2
    assert "Completed coverage | 2/4 (50%)" in markdown
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"] == "api://openbola.invalid/documents/%7Bid%7D"
    assert generate_json_report(bundle) == generate_json_report(bundle)
    assert generate_junit_xml(bundle) == generate_junit_xml(bundle)
    assert generate_markdown_report(bundle) == generate_markdown_report(bundle)
    assert generate_sarif_report(bundle) == generate_sarif_report(bundle)


def test_zero_findings_and_zero_tests_have_distinct_non_misleading_reports() -> None:
    no_outcomes = _bundle(findings=(), outcomes=())
    protected = _bundle(findings=(), outcomes=(_outcome(Verdict.PROTECTED),))

    empty_junit = ET.fromstring(generate_junit_xml(no_outcomes))  # noqa: S314 - own generated XML
    protected_junit = ET.fromstring(generate_junit_xml(protected))  # noqa: S314 - own generated XML

    assert empty_junit.attrib["tests"] == "0"
    assert protected_junit.attrib["tests"] == "1"
    assert "Zero findings does not mean this target was tested." in generate_markdown_report(
        no_outcomes
    )
    assert (
        "No BOLA findings were recorded among the supplied outcomes."
        in generate_markdown_report(protected)
    )
    assert "not evidence that the target contains no vulnerabilities" in generate_markdown_report(
        protected
    )


def test_high_and_critical_bola_outcomes_fail_junit_but_lower_severities_do_not() -> None:
    high = _bundle(findings=(_finding(severity="high"),))
    medium = _bundle(findings=(_finding(severity="medium"),))

    assert ET.fromstring(generate_junit_xml(high)).attrib["failures"] == "1"  # noqa: S314
    assert ET.fromstring(generate_junit_xml(medium)).attrib["failures"] == "0"  # noqa: S314


def test_evidence_redacts_sensitive_containers_and_rejects_unknown_data() -> None:
    secret = "REPORT_SECRET_SENTINEL"  # noqa: S105 - test sentinel
    evidence = {
        "Authorization": f"Bearer {secret}",
        "cookies": {"session": secret},
        "body": secret,
        "attacker_status": 200,
        "comparison": "object_id_match",
    }
    bundle = _bundle(findings=(_finding(evidence=evidence),))
    outputs = (
        generate_json_report(bundle),
        generate_junit_xml(bundle),
        generate_markdown_report(bundle),
        generate_sarif_report(bundle),
    )

    assert serialize_evidence(evidence) == {
        "attacker_status": 200,
        "comparison": "object_id_match",
        "redacted": True,
    }
    assert all(secret not in output for output in outputs)
    assert all('"Authorization"' not in output and '"cookies"' not in output for output in outputs)
    assert all("Bearer " not in output for output in outputs)
    with pytest.raises(ValueError, match="allowlist"):
        serialize_evidence({"unexpected": secret})
    with pytest.raises(ValueError, match="error code"):
        serialize_evidence({"error_code": secret})
    with pytest.raises(ValueError, match="allowlist"):
        serialize_evidence({"metadata": {"token": secret}})
    with pytest.raises(ValueError, match="object reference"):
        serialize_evidence({"object_ref": "document-1"})
    with pytest.raises(ValueError, match="allowlist"):
        serialize_evidence({"object_id": "document-1"})


def test_xml_markdown_and_sarif_escape_injected_display_and_path_values() -> None:
    finding = Finding(
        endpoint_template="/documents/{id}",
        method="GET",
        severity="high",
        title="</failure><script>alert(1)</script>",
        description="Authorization: REPORT_SECRET_SENTINEL\n```\n# injected",
        evidence={"comparison": "object_id_match"},
    )
    bundle = ReportBundle.from_outcomes(
        findings=(finding,),
        outcomes=(_outcome(Verdict.BOLA),),
        scope_target_label="Staging\n# injected",
        authorization_reference="scope-ref",
    )

    xml = generate_junit_xml(bundle)
    markdown = generate_markdown_report(bundle)
    sarif = json.loads(generate_sarif_report(bundle))

    assert ET.fromstring(xml).find(".//failure") is not None  # noqa: S314 - own generated XML
    assert "REPORT_SECRET_SENTINEL" not in xml + markdown + json.dumps(sarif)
    assert "Scope target: Staging \\# injected" in markdown
    assert "### [HIGH]" in markdown
    assert sarif["runs"][0]["results"][0]["message"]["text"].startswith("[redacted]")
    unsafe = Finding(
        endpoint_template="/../etc/passwd",
        method="GET",
        severity="high",
        title="unsafe",
        description="unsafe",
        evidence={},
    )
    with pytest.raises(ValueError, match="safe path"):
        generate_sarif_report(_bundle(findings=(unsafe,)))


def test_junit_removes_xml_1_0_invalid_controls_from_all_untrusted_text() -> None:
    finding = Finding(
        endpoint_template="/documents/{id}",
        method="GET",
        severity="high",
        title="title\x00",
        description="control\x00text\x08",
        evidence={"object_ref": "obj_" + "b" * 64},
    )

    xml = generate_junit_xml(_bundle(findings=(finding,)))

    assert "\x00" not in xml and "\x08" not in xml
    assert ET.fromstring(xml).find(".//failure") is not None  # noqa: S314 - own generated XML


def test_bundle_reads_only_opaque_object_references_from_state(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.db")
    raw_object_id = "REPORT_RAW_OBJECT_SENTINEL"  # noqa: S105 - test sentinel
    evidence = {"object_id": raw_object_id, "attacker_status": 200}
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

    bundle = ReportBundle.from_state(
        store=store,
        outcomes=(_outcome(Verdict.BOLA),),
        scope_target_label="Example staging API",
        authorization_reference="ENG-1234-approved-scope",
    )
    report = json.loads(generate_json_report(bundle))

    object_ref = object_ref_fingerprint(raw_object_id)
    assert report["findings"][0]["evidence"] == {
        "attacker_status": 200,
        "object_ref": object_ref,
    }
    assert raw_object_id not in generate_json_report(bundle)


def test_write_reports_publishes_complete_new_bundle_and_never_follows_symlinks(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    report_dir = tmp_path / "reports"
    paths = write_reports(bundle, output_dir=report_dir)
    secret = "REPORT_SECRET_SENTINEL"  # noqa: S105 - test sentinel

    assert set(paths) == {"json", "junit", "markdown", "sarif"}
    assert all(path.is_file() for path in paths.values())
    assert all(secret.encode() not in path.read_bytes() for path in paths.values())

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "report-link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        write_reports(bundle, output_dir=link / "reports")
    with pytest.raises(ValueError, match="already exists"):
        write_reports(bundle, output_dir=link)


def test_write_reports_rejects_parent_traversal_and_existing_destination(tmp_path: Path) -> None:
    bundle = _bundle()

    with pytest.raises(ValueError, match="traversal"):
        write_reports(bundle, output_dir=tmp_path / "parent" / ".." / "reports")

    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(ValueError, match="already exists"):
        write_reports(bundle, output_dir=existing)


def test_write_failure_cleans_stage_and_never_publishes_partial_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _bundle()
    destination = tmp_path / "reports"
    original_write = reporting._write_staged_file
    writes = 0

    def fail_after_first(directory_fd: int, filename: str, payload: bytes) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("injected artifact write failure")
        original_write(directory_fd, filename, payload)

    monkeypatch.setattr(reporting, "_write_staged_file", fail_after_first)

    with pytest.raises(OSError, match="injected artifact"):
        write_reports(bundle, output_dir=destination)

    assert not destination.exists()
    assert not list(tmp_path.glob(".reports.stage-*"))


def test_native_publish_does_not_replace_destination_created_during_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _bundle()
    destination = tmp_path / "reports"
    original_publish = reporting._publish_directory_no_replace
    destination_inode: int | None = None

    def create_destination_before_publish(parent_fd: int, stage_name: str, final_name: str) -> None:
        nonlocal destination_inode
        os.mkdir(final_name, dir_fd=parent_fd)
        destination_inode = os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False).st_ino
        original_publish(parent_fd, stage_name, final_name)

    monkeypatch.setattr(
        reporting,
        "_publish_directory_no_replace",
        create_destination_before_publish,
    )

    with pytest.raises(ValueError, match="already exists"):
        write_reports(bundle, output_dir=destination)

    assert destination_inode is not None
    assert destination.stat().st_ino == destination_inode
    assert not any(
        (destination / filename).exists() for filename in reporting._ARTIFACT_FILENAMES.values()
    )
    assert not list(tmp_path.glob(".reports.stage-*"))


@pytest.mark.parametrize("failure", ["existing_destination", "unsupported_platform"])
def test_failed_publish_removes_stage_before_syncing_parent_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    bundle = _bundle()
    destination = tmp_path / "reports"
    call_order: list[str] = []
    original_remove = reporting._remove_stage_directory
    original_sync = reporting._sync_parent_directory

    def record_remove(parent_fd: int, stage_name: str) -> None:
        call_order.append("remove")
        original_remove(parent_fd, stage_name)

    def record_sync(parent_fd: int) -> None:
        call_order.append("sync")
        original_sync(parent_fd)

    if failure == "existing_destination":
        original_publish = reporting._publish_directory_no_replace

        def publish_existing(parent_fd: int, stage_name: str, final_name: str) -> None:
            os.mkdir(final_name, dir_fd=parent_fd)
            original_publish(parent_fd, stage_name, final_name)

        monkeypatch.setattr(reporting, "_publish_directory_no_replace", publish_existing)
        expected_error = ValueError
    else:

        def publish_unsupported(parent_fd: int, stage_name: str, final_name: str) -> None:
            raise RuntimeError("native no-replace rename is unavailable")

        monkeypatch.setattr(reporting, "_publish_directory_no_replace", publish_unsupported)
        expected_error = RuntimeError

    monkeypatch.setattr(reporting, "_remove_stage_directory", record_remove)
    monkeypatch.setattr(reporting, "_sync_parent_directory", record_sync)

    with pytest.raises(expected_error):
        write_reports(bundle, output_dir=destination)

    assert call_order == ["remove", "sync"]
    assert not list(tmp_path.glob(".reports.stage-*"))


def test_run_summary_requires_exact_outcome_counts() -> None:
    with pytest.raises(ValueError, match="sum of outcome"):
        RunSummary(
            total_combinations=1,
            executed=1,
            protected=1,
            bola=1,
            inconclusive=0,
            skipped=0,
        )
