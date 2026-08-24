# Task 4 report — reopen sanitized report runs

## Implemented

- Added `ReportLocator` for numeric run IDs and explicit paths. Numeric lookup
  checks the append-only SQLite run table through a read-only connection and
  resolves only trusted, private run directories; explicit paths cannot leave
  the approved data root or cross symlink/traversal boundaries.
- Added strict bounded run-manifest validation and `write_run_manifest`, which
  atomically publishes only the schema, numeric run ID, artifact filenames, and
  creation timestamp after P7's complete bundle exists.
- Added `load_published_report` for complete-bundle reopening. It requires all
  six P7 artifacts plus the manifest, rejects partial/non-private/symlinked
  copies, validates the `openbola-report-v1` canonical JSON shape, and checks
  Markdown, HTML, CSV, JUnit, and SARIF syntax without returning raw artifact
  text.
- Added bounded duplicate-free JSON parsing, non-finite/depth/size limits, and
  raw `RAW_ID`/`TOKEN`/`BODY` sentinel rejection. The service does not import
  or construct a target executor, session registry, credential vault, or
  network client.

## Validation

- `uv run pytest tests/test_report_command.py tests/test_reporting.py -q` — 32 passed.
- `uv run ruff check src/openbola/reports.py tests/test_report_command.py` — passed.
- `uv run mypy src/openbola/reports.py` — passed.

The existing unrelated documentation, examples, and concurrent P9 service
changes remain unstaged. No CLI integration or runtime dependency was added.
