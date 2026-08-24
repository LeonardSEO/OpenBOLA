# OpenBOLA P7 Typed Findings and Report Exports Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Each task ends with an independent test and review gate.

**Goal:** Replace generic report evidence with typed, allowlisted report-boundary contracts and publish deterministic, sanitized JSON, Markdown, CSV, HTML, JUnit XML, and SARIF artifacts using the v1 filenames and schema id.

**Architecture:** Keep the existing `models.Finding` and SQLite schema backward-compatible, but convert legacy mappings exactly once at the report boundary into immutable `ReportFinding`, `FindingEvidence`, `CapabilityProof`, and `ResourceReport` values. Render every format from one canonical typed document; the renderer never resolves a `ValueHandle`, reads a session registry, or receives raw request/response material. Extend the existing atomic, no-follow publication path to six artifacts and keep the report API read-only.

**Tech Stack:** Python 3.11+, dataclasses and `typing.Literal`, existing `StateStore`, `Finding`, `ProbeResult`, `ReportBundle`, `html.escape`, `csv`, `xml.etree.ElementTree`, and the standard-library atomic filesystem helpers already present in `openbola.reporting`. No runtime dependency or SQLite migration is needed.

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (§9 Findings and reports, §8 storage/privacy, §13 acceptance criteria 8–10) and `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` (P7).

## Global Constraints

- Every exported value is structural, sanitized, and deterministic; raw IDs, full field values, request/response bodies, headers, cookies, credentials, provider keys, and session handles are never exported.
- `FindingEvidence` and `CapabilityProof` are closed typed contracts. Unknown legacy mapping keys fail closed; missing legacy capability data becomes an explicit `not_tested`/`unknown` state and is never inferred as proof.
- Reports may contain opaque record references and identity fingerprints, but never resolve or serialize a `ValueHandle`; local full values remain an in-process TUI concern for P8.
- Existing `StateStore` rows remain readable without a hidden migration. No new plaintext evidence column, schema version, or compatibility rewrite is introduced by P7.
- Report generation performs no network operation and cannot mutate target state. `write_reports` remains a single atomic, no-replace publication with restrictive permissions and no symlink traversal.
- All six formats derive from the same sorted typed data and contain no timestamps, host-specific target URLs, or nondeterministic identifiers.
- Artifact names are exactly `report.json`, `report.md`, `report.csv`, `report.html`, `junit.xml`, and `report.sarif`; JSON keeps the `openbola-report-v1` schema identifier.
- HTML is self-contained, uses a restrictive CSP, has no remote assets, and escapes every display value before insertion; client-side filtering never interpolates untrusted HTML.
- Preserve the existing `Finding`/`ProbeResult` public behavior, legacy report safety tests, and all P3b/P5/P6 boundary guarantees.

## File Map

- Modify `src/openbola/reporting.py`: define typed report contracts, legacy adapter, canonical document, six renderers, and artifact map while retaining atomic publication helpers.
- Modify `src/openbola/pipeline.py` only where report-path keys or report-bundle resource input must be adapted; do not change probe execution or state persistence.
- Modify `tests/test_reporting.py`: typed contracts, legacy conversion, deterministic renderers, CSV/HTML safety, and publication assertions.
- Modify `tests/test_e2e.py` and `tests/test_cli.py`: expect six v1 artifact names and prove the read-only pipeline still exposes only sanitized report paths.
- Create `tests/test_report_boundary.py`: cross-artifact sentinel proof and no-hidden-migration regression.
- Modify `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` only in the P7 status paragraph after all checks pass.

### Task 1: Add immutable typed report-boundary contracts

**Files:**

- Modify: `src/openbola/reporting.py`
- Test: `tests/test_reporting.py`

**Interfaces:**

- Consumes: existing `Finding`, `ProbeResult`, `ResourceInventory`-derived structural values, and opaque reference strings.
- Produces: `CapabilityProof`, `ReportField`, `ResourceReport`, `FindingEvidence`, `ReportFinding`, and the closed legacy adapter `FindingEvidence.from_legacy_mapping(...)`.

Use these public shapes (field names and literal values are part of the P7 contract):

```python
CapabilityName = Literal["read", "post", "patch", "put", "delete"]
ProofStatus = Literal["proven", "not_proven", "inconclusive", "not_tested"]
CleanupStatus = Literal["verified", "not_applicable", "inconclusive", "not_run"]
CoverageStatus = Literal["complete", "partial", "not_tested"]

@dataclass(frozen=True)
class CapabilityProof:
    capability: CapabilityName
    status: ProofStatus
    owner_identity_ref: str | None
    attacker_identity_ref: str | None
    owner_status: int | None
    attacker_status: int | None
    comparison: str | None
    cleanup: CleanupStatus
    coverage: CoverageStatus

@dataclass(frozen=True)
class ReportField:
    name: str
    type_name: str

@dataclass(frozen=True)
class ResourceReport:
    provider: str
    confidence: str
    dataset: str
    endpoint_template: str
    total_discovered: int
    fields: tuple[ReportField, ...]
    capabilities: tuple[CapabilityProof, ...]

@dataclass(frozen=True)
class FindingEvidence:
    object_ref: str | None
    impacted_identity_refs: tuple[str, ...]
    fields: tuple[ReportField, ...]
    capabilities: tuple[CapabilityProof, ...]
    confidence: str
    reproduction: tuple[str, ...]
    remediation: str
    cleanup: CleanupStatus
    coverage: CoverageStatus

@dataclass(frozen=True)
class ReportFinding:
    endpoint_template: str
    method: str
    severity: str
    title: str
    description: str
    evidence: FindingEvidence
```

The constructors validate uppercase HTTP syntax, safe relative templates, bounded display strings, 100–599 status codes, valid opaque reference syntax, sorted unique fields/capabilities, and the closed literal sets. `repr` and equality contain only these sanitized fields. Identity labels from legacy rows are converted to stable `identity_<sha256>` fingerprints before entering a typed value; the source label is never retained in the report contract.

- [ ] **Step 1: Write failing contract and privacy tests.**

```python
def test_typed_evidence_is_frozen_and_rejects_unknown_capabilities() -> None:
    proof = CapabilityProof("read", "proven", "identity_a", "identity_b", 200, 200,
                            "object_id_match", "not_applicable", "complete")
    evidence = FindingEvidence(None, (), (), (proof,), "high", ("GET /documents/{id}",),
                               "Enforce ownership checks.", "not_applicable", "complete")
    assert evidence.capabilities == (proof,)
    with pytest.raises((AttributeError, TypeError)):
        evidence.confidence = "critical"  # type: ignore[misc]
    with pytest.raises(ValueError, match="capability"):
        CapabilityProof("trace", "proven", None, None, None, None, None,
                        "not_applicable", "not_tested")  # type: ignore[arg-type]

def test_legacy_adapter_allows_known_fields_and_rejects_new_unknown_fields() -> None:
    evidence = FindingEvidence.from_legacy_mapping({
        "attacker_status": 200,
        "comparison": "object_id_match",
        "object_ref": "obj_" + "a" * 64,
    }, method="GET", endpoint_template="/documents/{id}")
    assert evidence.object_ref == "obj_" + "a" * 64
    assert evidence.capabilities[0].status == "proven"
    with pytest.raises(ValueError, match="allowlist"):
        FindingEvidence.from_legacy_mapping({"future_secret": "sentinel"},
                                             method="GET", endpoint_template="/documents/{id}")
```

- [ ] **Step 2: Run focused tests to verify they fail.**

Run: `uv run pytest tests/test_reporting.py -k 'typed or legacy_adapter' -v`

Expected: FAIL because the typed classes and adapter do not yet exist.

- [ ] **Step 3: Implement the closed contracts and adapter.**

Implement immutable dataclasses with explicit `__post_init__` validation. Keep the existing `serialize_evidence` name only as a compatibility shim that accepts a `FindingEvidence` and returns its typed dictionary; do not let a new generic mapping enter renderers. Map current legacy keys (`owner_status`, `attacker_status`, `comparison`, `object_ref`, `status`, `retryable`, `error_code`) to one `CapabilityProof`, drop sensitive containers exactly as the current serializer does, and reject any other key. When evidence lacks capability/cleanup/coverage facts, use `not_tested`, `not_applicable`, and `partial` with an explicit `legacy evidence omitted capability proof` limitation supplied by the bundle; never derive a successful write or delete proof from a read finding.

- [ ] **Step 4: Run focused tests to verify they pass.**

Run: `uv run pytest tests/test_reporting.py -k 'typed or legacy_adapter' -v`

Expected: PASS, including constructor bounds, sorting, opaque identity fingerprints, and no raw sentinel in `repr`.

- [ ] **Step 5: Commit.**

```bash
git add src/openbola/reporting.py tests/test_reporting.py
git commit -m "feat: add typed report boundary contracts"
```

### Task 2: Convert bundles and canonical documents without a database migration

**Files:**

- Modify: `src/openbola/reporting.py`
- Test: `tests/test_reporting.py`
- Test: `tests/test_report_boundary.py`

**Interfaces:**

- Consumes: `StateStore.list_findings()` legacy `Finding` values and optional typed `ResourceReport` values from P4/P6/P8 callers.
- Produces: `ReportBundle(findings: Sequence[ReportFinding], resources: Sequence[ResourceReport])`, `ReportBundle.from_legacy_findings(...)`, `ReportBundle.from_state(...)`, and `canonical_report_document(...)`.

- [ ] **Step 1: Write failing bundle/document tests.**

```python
def test_from_state_adapts_legacy_rows_without_schema_change(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.db")
    evidence = {"attacker_status": 200, "comparison": "object_id_match",
                "object_ref": "obj_" + "a" * 64}
    title, description = canonical_finding_text(
        severity="high", endpoint_template="/documents/{id}", method="GET",
        evidence=evidence,
    )
    store.add_finding(Finding(
        endpoint_template="/documents/{id}", method="GET", severity="high",
        title=title, description=description, evidence=evidence,
    ))
    schema_before = store.schema_version
    bundle = ReportBundle.from_state(
        store=store, outcomes=(), scope_target_label="staging",
        authorization_reference="scope-reference",
    )
    document = canonical_report_document(bundle)
    assert document["format"] == "openbola-report-v1"
    assert document["findings"][0]["evidence"]["capabilities"][0]["status"] == "proven"
    assert "scope-reference" not in json.dumps(document)
    assert store.schema_version == schema_before

def test_document_serializes_typed_resources_in_stable_order() -> None:
    read_proof = CapabilityProof(
        "read", "proven", "identity_a", "identity_b", 200, 403,
        "object_id_mismatch", "not_applicable", "complete",
    )
    resource = ResourceReport(
        provider="generic-http", confidence="confirmed", dataset="accounts",
        endpoint_template="/accounts/{id}", total_discovered=2,
        fields=(ReportField("id", "string"),), capabilities=(read_proof,),
    )
    document = canonical_report_document(
        ReportBundle.from_outcomes(
            findings=(), outcomes=(), scope_target_label="staging",
            authorization_reference="scope-reference", resources=(resource,),
        )
    )
    assert [row["dataset"] for row in document["resources"]] == ["accounts"]
    repeat = canonical_report_document(
        ReportBundle.from_outcomes(
            findings=(), outcomes=(), scope_target_label="staging",
            authorization_reference="scope-reference", resources=(resource,),
        )
    )
    assert json.dumps(document, sort_keys=True, separators=(",", ":")) == \
           json.dumps(repeat, sort_keys=True, separators=(",", ":"))
```

- [ ] **Step 2: Run focused tests to verify they fail.**

Run: `uv run pytest tests/test_reporting.py tests/test_report_boundary.py -k 'bundle or document or schema' -v`

Expected: FAIL because bundles currently contain generic `Finding` values and no resource matrix.

- [ ] **Step 3: Implement typed bundle conversion and canonical document.**

Change `ReportBundle.findings` to `tuple[ReportFinding, ...]` internally while keeping `from_outcomes` source compatibility: it accepts either typed findings or legacy `Finding` values and adapts the latter through the strict adapter. Add `resources=()` as a typed optional input and sort resources by `(provider, dataset, endpoint_template)` and fields/capabilities by their stable keys. Extend the JSON document with `resources`, typed finding evidence, and `schema_version: 1` under the existing `format: "openbola-report-v1"`. Add an explicit limitation whenever a legacy row supplied no capability proof. Do not touch `_MIGRATIONS`, `findings.evidence_json`, or any state write path.

- [ ] **Step 4: Run focused tests to verify they pass.**

Run: `uv run pytest tests/test_reporting.py tests/test_report_boundary.py -k 'bundle or document or schema' -v`

Expected: PASS and the SQLite schema/version is byte-for-byte unchanged.

- [ ] **Step 5: Commit.**

```bash
git add src/openbola/reporting.py tests/test_reporting.py tests/test_report_boundary.py
git commit -m "refactor: adapt legacy findings to typed reports"
```

### Task 3: Render six deterministic v1 formats

**Files:**

- Modify: `src/openbola/reporting.py`
- Modify: `tests/test_reporting.py`

**Interfaces:**

- Consumes: `ReportBundle` and `canonical_report_document(...)` from Task 2.
- Produces: `generate_json_report`, `generate_markdown_report`, `generate_csv_report`, `generate_html_report`, `generate_junit_xml`, `generate_sarif_report`, and `_ARTIFACT_FILENAMES` with the six exact v1 names.

- [ ] **Step 1: Write failing renderer tests.**

```python
def test_csv_has_sanitized_resource_capability_rows() -> None:
    proof = CapabilityProof(
        "read", "proven", "identity_a", "identity_b", 200, 200,
        "object_id_match", "not_applicable", "complete",
    )
    resource = ResourceReport(
        provider="generic-http", confidence="confirmed", dataset="documents",
        endpoint_template="/documents/{id}", total_discovered=1,
        fields=(ReportField("id", "string"),), capabilities=(proof,),
    )
    bundle = ReportBundle.from_outcomes(
        findings=(), outcomes=(), scope_target_label="staging",
        authorization_reference="scope-reference", resources=(resource,),
    )
    csv_text = generate_csv_report(bundle)
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert rows[0]["capability"] == "read"
    assert "REPORT_FULL_VALUE_SENTINEL" not in csv_text
    assert rows[0]["endpoint_template"] == "/documents/{id}"

def test_html_is_self_contained_csp_safe_and_escaped() -> None:
    finding = ReportFinding(
        endpoint_template="/documents/{id}", method="GET", severity="high",
        title="<script>REPORT_XSS</script>",
        description="Attacker received an object.",
        evidence=FindingEvidence(
            object_ref="obj_" + "a" * 64, impacted_identity_refs=(), fields=(),
            capabilities=(), confidence="high", reproduction=("GET /documents/{id}",),
            remediation="Enforce ownership checks.", cleanup="not_applicable",
            coverage="complete",
        ),
    )
    bundle = ReportBundle.from_outcomes(
        findings=(finding,), outcomes=(), scope_target_label="staging",
        authorization_reference="scope-reference",
    )
    html_text = generate_html_report(bundle)
    assert "Content-Security-Policy" in html_text
    assert "src=" not in html_text and "https://" not in html_text
    assert "&lt;script&gt;REPORT_XSS&lt;/script&gt;" in html_text
    assert "REPORT_FULL_VALUE_SENTINEL" not in html_text
```

- [ ] **Step 2: Run focused tests to verify they fail.**

Run: `uv run pytest tests/test_reporting.py -k 'csv or html or filenames' -v`

Expected: FAIL because CSV/HTML renderers and v1 artifact names are absent.

- [ ] **Step 3: Implement all renderers from the canonical typed document.**

Keep JSON canonical (`sort_keys=True`, compact separators, trailing newline). Render Markdown from the typed finding/resource rows and preserve the explicit zero-tests/no-findings disclaimers. Render CSV with this exact header and one row per resource/capability pair: `provider,confidence,dataset,endpoint_template,total_discovered,field_names,field_types,capability,capability_status,owner_identity_ref,attacker_identity_ref,owner_status,attacker_status,cleanup_status,coverage_status`. Use `csv.writer` with `\n` line endings and no raw source URLs. Render HTML with a `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">`, inline CSS, escaped text nodes/attributes, a filter input, and a short inline script that compares `textContent` only; never build HTML from unsanitized strings. Keep SARIF locations synthetic (`api://openbola.invalid/...`) and put typed evidence under allowlisted properties. JUnit continues to map only high/critical BOLA findings to failures and represents skipped/inconclusive outcomes as skipped cases.

- [ ] **Step 4: Run focused tests and determinism checks.**

Run: `uv run pytest tests/test_reporting.py -k 'json or markdown or csv or html or junit or sarif or deterministic' -v`

Expected: PASS; each generator returns identical bytes for equivalent bundles and none of the six outputs contains any sentinel raw value.

- [ ] **Step 5: Commit.**

```bash
git add src/openbola/reporting.py tests/test_reporting.py
git commit -m "feat: add deterministic csv and html report exports"
```

### Task 4: Publish the complete bundle atomically and update callers

**Files:**

- Modify: `src/openbola/reporting.py`
- Modify: `src/openbola/pipeline.py`
- Modify: `tests/test_reporting.py`
- Modify: `tests/test_e2e.py`
- Modify: `tests/test_cli.py`

**Interfaces:**

- Consumes: the six generators from Task 3 and existing `write_reports` callers.
- Produces: `write_reports(...) -> dict[str, Path]` with keys `json`, `markdown`, `csv`, `html`, `junit`, and `sarif`, all pointing to `report.*` files in one newly published directory.

- [ ] **Step 1: Write failing publication and integration tests.**

```python
def test_write_reports_returns_all_v1_artifacts(tmp_path: Path) -> None:
    paths = write_reports(_bundle(), output_dir=tmp_path / "run")
    assert set(paths) == {"json", "markdown", "csv", "html", "junit", "sarif"}
    assert {path.name for path in paths.values()} == {
        "report.json", "report.md", "report.csv", "report.html", "junit.xml", "report.sarif"
    }
    assert all(path.is_file() for path in paths.values())

def test_failed_sixth_write_leaves_no_partial_report_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original_write = reporting._write_staged_file
    calls = 0

    def fail_on_sixth(directory_fd: int, filename: str, payload: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 6:
            raise OSError("injected report write failure")
        original_write(directory_fd, filename, payload)

    monkeypatch.setattr(reporting, "_write_staged_file", fail_on_sixth)
    with pytest.raises(OSError):
        write_reports(_bundle(), output_dir=tmp_path / "run")
    assert not (tmp_path / "run").exists()
    assert not list(tmp_path.glob(".run.stage-*"))
```

- [ ] **Step 2: Run focused tests to verify they fail.**

Run: `uv run pytest tests/test_reporting.py tests/test_e2e.py tests/test_cli.py -k 'report or artifact' -v`

Expected: FAIL because callers and tests still expect the four legacy filenames.

- [ ] **Step 3: Extend atomic publication and update read-only callers.**

Build all six payloads before opening the destination, write each with the existing `O_NOFOLLOW|O_EXCL` and fsync path, then publish once with the existing native no-replace rename. Update `pipeline.py` only for the expanded report-path mapping; do not add a mutation/report network path. Update E2E/CLI assertions to inspect `report.json` and the six returned keys, and retain checks that no URL, raw object ID, token, body, or credential appears in any artifact.

- [ ] **Step 4: Run focused integration tests.**

Run: `uv run pytest tests/test_reporting.py tests/test_e2e.py tests/test_cli.py -v`

Expected: PASS, including symlink, race, partial-write, and zero-outcome behavior.

- [ ] **Step 5: Commit.**

```bash
git add src/openbola/reporting.py src/openbola/pipeline.py tests/test_reporting.py tests/test_e2e.py tests/test_cli.py
git commit -m "feat: publish complete v1 report bundle"
```

### Task 5: Close the typed reporting boundary and roadmap gate

**Files:**

- Create: `tests/test_report_boundary.py`
- Modify: `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md`

**Interfaces:**

- Consumes: P3b session sentinel fixture, P4 inventory handles, P5 sanitized proposal context, P6 sanitized mutation outcomes, `StateStore`, `ReportBundle`, and all six renderers.
- Produces: an acceptance proof that no raw runtime material crosses the report boundary and a roadmap status marker with exact validation evidence.

- [ ] **Step 1: Add the cross-phase sentinel proof.**

Create a fixture containing a raw record ID, full field value, request body, cookie, credential, and `ValueHandle` in the active session. Build one legacy state finding plus one typed resource/capability matrix, generate all six artifacts, and assert every artifact, `repr(bundle)`, canonical document, and `StateStore` sidecar excludes every sentinel. Assert the typed output contains only the opaque `obj_<64 hex>` reference and identity fingerprints, and that the legacy adapter reports `not_tested` for absent POST/PATCH/PUT/DELETE facts. Assert `pickle.dumps(bundle)` and `dataclasses.asdict(bundle)` cannot expose or resolve a session registry; the bundle must contain only immutable report values.

- [ ] **Step 2: Run the focused acceptance suite.**

Run: `uv run pytest tests/test_report_boundary.py tests/test_reporting.py tests/test_e2e.py tests/test_cli.py -v`

Expected: PASS with no raw sentinel in any persisted or exported value and all six formats parseable.

- [ ] **Step 3: Run the mandatory repository checks.**

```bash
uv run ruff check .
uv run mypy src
uv run pytest
```

Fix only P7-caused failures; report unrelated pre-existing failures separately. Do not weaken the allowlist, HTML CSP, atomic publication, or legacy fail-closed behavior.

- [ ] **Step 4: Update the roadmap status.**

Change only the P7 paragraph in `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` to state that typed `FindingEvidence`/`CapabilityProof`, legacy-safe conversion, JSON/Markdown/CSV/HTML/JUnit/SARIF, and the six-artifact boundary are complete. Include the exact focused and repository-wide commands and note that local full field values remain P8 TUI-only. Do not mark P8–P11 complete or alter the P11 external-publication approval gate.

- [ ] **Step 5: Commit the acceptance proof and roadmap marker.**

```bash
git add tests/test_report_boundary.py docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md
git commit -m "test: close P7 typed reporting boundary"
```

## Self-review checklist

- All renderers consume typed values; no renderer accepts a generic evidence mapping or resolves a session handle.
- Legacy SQLite rows remain readable through an explicit adapter, without migration or inferred capability claims.
- Capability states distinguish proven, not proven, inconclusive, and not tested for READ/POST/PATCH/PUT/DELETE; cleanup and coverage are explicit.
- JSON uses `openbola-report-v1`; artifacts use exactly `report.json`, `report.md`, `report.csv`, `report.html`, `junit.xml`, and `report.sarif`.
- HTML is self-contained, CSP-constrained, remote-asset-free, escaped, and deterministic; CSV is RFC-compliant and sanitized.
- Publication remains atomic, no-replace, symlink-safe, and all-or-nothing for six files.
- Every acceptance test scans all formats and persistence representations for raw IDs, full values, credentials, cookies, bodies, and session material.
- P7 makes no network request, target mutation, dependency addition, or hidden state migration.
