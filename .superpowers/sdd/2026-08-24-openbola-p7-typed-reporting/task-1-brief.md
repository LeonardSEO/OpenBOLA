### Task 1: Add immutable typed report-boundary contracts

**Files:**
- Modify: `src/openbola/reporting.py`
- Test: `tests/test_reporting.py`

**Scope:** Implement only the typed report-boundary values and strict legacy evidence adapter described in `docs/superpowers/plans/2026-08-24-openbola-p7-typed-reporting.md` Task 1. Do not change SQLite migrations, state writes, report filenames, pipeline behavior, or HTML/CSV rendering in this task.

**Produces:** `CapabilityProof`, `ReportField`, `ResourceReport`, `FindingEvidence`, `ReportFinding`, and `FindingEvidence.from_legacy_mapping(...)`. Keep all values immutable and structurally sanitized; no session registry or `ValueHandle` resolution is allowed.

**Required proof:** Focused typed/legacy adapter tests cover frozen dataclasses, closed capability/status literals, safe endpoint and status validation, opaque identity fingerprints, accepted legacy keys, rejection of unknown keys/sensitive containers, and absence of raw-ID/full-value sentinels from `repr` and serialized typed evidence.

**Commands:**
```bash
uv run pytest tests/test_reporting.py -k 'typed or legacy_adapter' -v
uv run ruff check src/openbola/reporting.py tests/test_reporting.py
uv run mypy src/openbola/reporting.py
```

**Safety gate:** Existing generic `Finding` remains readable for later Task 2 conversion. Do not introduce a hidden database migration or make a generic mapping accepted by new renderers.
