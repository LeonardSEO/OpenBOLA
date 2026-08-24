# P7 Task 1 implementation report

## Scope

Added immutable typed report-boundary contracts in `openbola.reporting`:
`CapabilityProof`, `ReportField`, `ResourceReport`, `FindingEvidence`, and
`ReportFinding`.  Constructors enforce closed capability/status literals, safe
HTTP endpoint syntax, bounded redacted display text, opaque object and identity
references, valid HTTP statuses, and sorted unique nested values.

`FindingEvidence.from_legacy_mapping` is a fail-closed adapter for the existing
evidence keys.  Sensitive containers are omitted, unknown keys are rejected,
legacy identity labels are SHA-256 fingerprinted, and missing mutation facts
remain `not_tested`/`not_applicable`/`partial`.  It never turns a legacy read
finding into a write or delete proof.  Existing `serialize_evidence(mapping)`
behavior remains available for pre-P7 callers while typed values can be
serialized by the later report-boundary tasks.

## Validation

- `uv run pytest tests/test_reporting.py -q` — 18 passed
- `uv run ruff check src/openbola/reporting.py tests/test_reporting.py` — passed
- `uv run mypy src/openbola/reporting.py` — passed

No state schema, migration, pipeline, or report publication behavior was
changed in this task.
