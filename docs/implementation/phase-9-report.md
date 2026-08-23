# Phase 9 — read-only CLI, pipeline, and local E2E

## Delivered

- Added `bola_checker.pipeline.run_pipeline()` and typed `IdentityInput`/
  `PipelineResult` contracts. The orchestrator loads a provenance-bound
  `ScopeGuard`, imports bounded traffic, extracts credentials into the
  process-local vault, correlates only strong ownership, maps opaque state
  references back to current in-memory IDs, runs `ProbeExecutor`, and writes
  the four-format report bundle atomically.
- Added the `bolacheck scan` Typer command. The command accepts bounded,
  non-symlink records JSON (the preferred executable ownership input) or a
  sanitized HAR (discovery only) and `NAME=ENVIRONMENT_VARIABLE` credential
  references. HAR response bodies are intentionally absent, so HAR-only scans
  report zero executable ownership with an explicit skip reason. It has no
  mutation flag; writes remain available only through the explicit phase-5
  mutation API with its canary/cleanup contract. Records are additionally
  bounded by depth, node, string, header, and body limits before conversion or
  serialization. `--json` emits a bounded machine-safe summary without object
  IDs, request URLs, tokens, or bodies.
- Added `MockTarget`, a deterministic `ThreadingHTTPServer` bound explicitly
  to `127.0.0.1` and an ephemeral port. `/api/documents/{id}` is deliberately
  vulnerable while `/api/secure/{id}` enforces the owner mapping.
- Added local end-to-end tests proving vulnerable and protected verdicts,
  invalid/out-of-scope scope fail-closed behavior, zero-tests reporting, no
  raw token/object-ID material in SQLite sidecars or report artifacts, exact
  origin matching, query candidate skipping, stale-database rejection, and
  atomic report publication. CLI tests cover HAR-only zero-test output,
  records-JSON successful execution, JSON output, and missing-scope denial.

## Verification

```text
uv run pytest tests/test_e2e.py tests/test_cli.py -q
12 passed

uv run ruff check src/bola_checker/pipeline.py src/bola_checker/mock_target.py \
  src/bola_checker/cli.py tests/test_e2e.py tests/test_cli.py
All checks passed!

uv run mypy src/bola_checker/pipeline.py src/bola_checker/mock_target.py \
  src/bola_checker/cli.py
Success: no issues found in 3 source files

uv run bolacheck --help
Commands: scan

uv run pytest -q
246 passed

uv run ruff check .
All checks passed!

uv run mypy src
Success: no issues found in 15 source files
```

The Phase 9-focused suite, full repository suite, Ruff, and mypy all pass in
the final shared-worktree snapshot.
