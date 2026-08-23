# Phase 4 report: endpoint templating and ownership correlation

## Delivered

- Added `bola_checker.endpoints`, a pure discovery/correlation module with no
  HTTP client or execution capability.
- Path templates recognise integer IDs, UUIDs, Mongo ObjectIds, and
  high-entropy URL-safe opaque IDs. IDs are named deterministically as `{id}`,
  `{id2}`, and so on for nested resources.
- URLs are split before processing: query values are not interpolated into the
  endpoint template, and percent-decoding is done one segment at a time so an
  encoded slash cannot change the path structure.
- Typed `EndpointCandidate` values record IDs discovered in paths, query
  parameters, JSON request bodies, and GraphQL variables. Discovery does not
  execute requests.
- Ownership evidence uses the shared `OwnershipEvidence` and
  `OwnershipConfidence` contracts. Strong evidence is limited to an explicit
  mapping, a `POST 201` response with a Location/body ID, or a response object
  whose owner field maps through `identity_by_hint`.
- Requester identity produces `HEURISTIC` evidence only. The persistence bridge
  filters that evidence and fails closed when strong sources assign the same
  endpoint/method/object tuple to different identities.

## Input contract

`correlate_ownership` accepts `RequestRecord` instances or mapping-style
capture entries. Mapping entries can supply `requester_identity`,
`response_status`, `response_headers`, `response_body`, and an
`explicit_ownership` mapping of object ID to identity (or identity hint).
Response owner hints are resolved through `identity_by_hint`; they are never
treated as a requester fallback.

## Verification

Focused endpoint tests cover false positives (`v1`, slugs, date routes),
nested placeholder names, percent-encoded IDs, query/body/GraphQL candidates,
the confidence gate, successful create evidence, and conflicting ownership.

## Quality fix round 1

- `build_test_targets` now queries `ownership_evidence_for(template, method,
  object_id)` before every write. A strong persisted owner that differs from
  the candidate owner prevents that candidate from being persisted; the
  returned `OwnershipPersistenceResult.conflicts` records both sides.
- Create-response body evidence is restricted to top-level `id` or
  `object_id`. A nested ID is accepted only when it matches the observed
  Location ID, preventing related resources from being claimed as the created
  object.
- Candidate discovery rejects sensitive field families before inspecting or
  storing their values. This includes separator/case variants and `*_id`
  fields for API keys, tokens, secrets, passwords, auth, cookies, sessions,
  credentials, bearer values, and private keys.
- Standalone years from 1900 through 2100 and numeric segments immediately
  following `v` or `version` are retained as route syntax rather than object
  IDs.

### Validation evidence

- `uv run ruff check src/bola_checker/endpoints.py tests/test_endpoints.py`:
  passed.
- `uv run pytest tests/test_endpoints.py`: 11 passed.
- `uv run mypy src`: passed with no issues.

## Integration fix: transactional ownership conflicts

`build_test_targets` still performs its read precheck, but persists through
`StateStore.persist_ownership_evidence`. If the StateStore transaction raises
its typed `OwnershipConflictError` because another import committed first, the
exception is converted into an `OwnershipConflict` inside
`OwnershipPersistenceResult.conflicts`; the import therefore remains
fail-closed and auditably non-crashing.

Focused integration tests cover a real `StateStore` sequential conflict and an
interleaved write that makes the precheck stale before persistence. In both
cases the candidate is absent from `persisted` and the conflicting stored
evidence is available in the result.

## Shared contract and route-shape integration

`OwnershipConflictError` is defined in `bola_checker.models`, the shared
contract layer. `StateStore` remains a compatibility re-export while endpoint
correlation imports the exception from `models`, so the persistence bridge has
no dependency on a concrete storage module and no import cycle.

Endpoint templates are checked at the storage boundary before persistence:
recognised path identifiers are replaced with `{id}`, `{id2}`, and so on, while
identifier-shaped literals that discovery cannot classify are rejected rather
than stored as route syntax. This keeps the route template safe and leaves the
concrete object value transient; SQLite stores only the opaque `object_ref`.

The StateStore planning boundary also filters `untested_combinations()` to
`EXPLICIT`, `OBSERVED_CREATE`, and `RESPONSE_MATCH` ownership. Requester-only
`HEURISTIC` evidence may be retained as provenance, but can never become an
executable cross-identity probe through a direct StateStore caller.

StateStore database initialization uses an explicit private-parent trust
boundary: every parent component is opened without following symlinks, the
final parent is current-user-owned and not group/world writable, and new leaves
are created exclusively with mode `0600`. Existing database/WAL/SHM/journal
files are regular current-user-owned files and are hardened to `0600`; the
database inode is checked before and after SQLite's path-based open because the
Python SQLite API does not accept an already-open file descriptor.

### Validation evidence: integration fix

- `uv run ruff check src/bola_checker/endpoints.py tests/test_endpoints.py`:
  passed.
- `uv run pytest tests/test_state.py tests/test_endpoints.py`: 44 passed.
- `uv run mypy src`: passed with no issues.
- Final repository gate: `uv run pytest -q` — 246 passed; full Ruff and mypy
  passed.
