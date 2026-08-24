# Task 2 report — Hasura detection, origin gate, and inventory

## Implemented

- Added safe Hasura marker detection to `HasuraAdapter`, using only
  case-insensitive header names (`x-hasura-role` and
  `x-hasura-admin-secret`) and never inspecting or retaining header values.
- Added bounded request-body decoding for the ephemeral `AdapterRecordView`;
  malformed, non-object, non-UTF-8, and redacted GraphQL payloads fail closed.
- Added GraphQL/path-based confidence behavior: parseable GraphQL payloads and
  known `/graphql` or `/v1/graphql` paths infer Hasura, while a parseable
  payload plus a Hasura marker confirms it.
- Added normalized origin isolation (lowercase scheme/hostname, explicit port
  preserved) before inventory grouping. Confirmed evidence from one origin
  cannot authorize inventory from another origin.
- Added deterministic `(origin, path, resource)` grouping with uppercased
  methods and safe field-name unions. Mutation inventories use only parsed
  `returning` fields and never report wrapper fields, aliases, documents, or
  header values.
- Added deterministic detection, origin-isolation, inventory, and
  header-value non-disclosure tests.

## Validation

- `uv run pytest tests/test_providers_hasura.py -v` — 13 passed.
- `uv run pytest tests/test_providers_hasura.py -k 'detect or origin or requires_confirmed or exposes_header' -v` — 5 passed.
- `uv run ruff check src/openbola/providers/hasura.py tests/test_providers_hasura.py` — passed.
- `uv run mypy src` — passed (`22` source files).

## Self-review

- The adapter imports no HTTP client, scope/probe executor, or socket API and
  performs no network operation.
- Only persistent-safe metadata is read through `view.record`; raw request
  bytes are decoded synchronously and are not copied into inventory contracts.
- Origin is derived from `urlsplit(...).hostname`, not `netloc`; malformed URLs
  fail closed. Header checks compare names only.
- Inventory confidence is recomputed per confirmed origin/group, so cross-tenant
  confirmation and field/method merging cannot occur.
- Existing unrelated documentation/example edits in the worktree were left
  untouched.
