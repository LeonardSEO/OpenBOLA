# Task 3 report — Hasura variable association and guarded handles

## Implemented

- Added `_record_ids_for_variable`, a recursive, fail-closed extractor that
  accepts direct ID variables and `_eq` values below ID-named fields only.
- Sensitive variable and field names are skipped before any ID-shape check;
  membership, range, pattern, and other non-single-record operators never mint
  handles, and inline GraphQL literals remain unavailable to the extractor.
- Associated only variables referenced by each parsed root with that root's
  `(origin, path, resource)` inventory group, preserving separate IDs for
  multiple roots in one operation.
- Converted deduplicated IDs immediately into process-local `record_id`
  handles; no raw IDs are placed in `ResourceInventory`.
- Added regression tests for per-root association, direct and `_eq` extraction,
  sensitive values/parents, and inline/membership filters.

## Validation

- `uv run pytest tests/test_providers_hasura.py -k 'variable or sensitive or inline or eq' -v` — 9 passed.
- `uv run ruff check src/openbola/providers/hasura.py tests/test_providers_hasura.py` — passed.
- `uv run mypy src/openbola/providers/hasura.py` — passed.
- `uv run pytest tests/test_providers_hasura.py -v` — 17 passed.

## Self-review

- The adapter remains read-only and imports no HTTP client, scope executor, or
  network API.
- Raw variable values are used only during synchronous extraction and are
  immediately converted into opaque process-local handles; provider inventory
  contracts contain handles, not IDs.
- Existing unrelated documentation/example edits in the worktree were left
  untouched.
