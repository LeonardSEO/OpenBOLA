# Task 3 report — deterministic v1 report renderers

## Implemented

- Added deterministic CSV and self-contained HTML renderers built from the
  canonical typed report document.
- Updated JSON, Markdown, JUnit, and SARIF renderers to consume immutable typed
  findings/evidence and canonical resource data; SARIF retains synthetic
  locations and allowlisted typed evidence.
- Extended the artifact map and atomic publication payload to the six v1
  artifact names: `report.json`, `report.md`, `report.csv`, `report.html`,
  `junit.xml`, and `report.sarif`.
- Added escaping/CSP/filtering coverage for HTML, CSV capability-row coverage,
  deterministic output checks, and updated the state-boundary assertion for
  typed evidence.

## Validation

- `uv run pytest tests/test_reporting.py -q` — 20 passed.
- `uv run ruff check src/openbola/reporting.py tests/test_reporting.py` — passed.
- `uv run mypy src/openbola/reporting.py` — passed.

The existing end-to-end report test still expects the pre-P7 four-artifact
mapping; its six-artifact assertion belongs to the P7 publication integration
task. No dependencies or network behavior were added.

## Self-review

- HTML has no remote assets, uses the restrictive CSP, escapes all display
  values, and filters via `textContent` rather than HTML interpolation.
- CSV emits the specified header and one row per typed resource/capability
  pair with opaque identity references only.
- Renderers never resolve handles, read a session registry, or receive raw
  request/response material.
