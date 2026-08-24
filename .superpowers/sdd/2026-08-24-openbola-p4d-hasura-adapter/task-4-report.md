# Task 4 report — Hasura acceptance and protocol proof

## Implemented

- Added mutation inventory acceptance coverage proving `returning { ... }`
  fields are reported, mutation wrapper fields are not, and observed method
  metadata remains `POST`.
- Added explicit coverage for mutations without a `returning` selection and
  for redacted or malformed request payloads; both fail closed without raising
  or inventing inventory.
- Extended the full-fidelity capture fixture with a scoped GraphQL request and
  response.  The test passes the ephemeral `AdapterRecordView` directly to
  `HasuraAdapter`, verifies discovery of `orders` and its fields, confirms an
  opaque record handle, and proves raw values remain absent from the sanitized
  HAR, inventory representation, and serialized view.
- Preserved the existing `ProviderAdapter` type-checking sentinel and the
  adapter's no-network implementation boundary.

## Validation

- `uv run pytest tests/test_providers_hasura.py tests/test_capture.py -k 'mutation or malformed or hasura or adapter_view' -v` — 22 passed.
- `uv run ruff check src/openbola/providers/hasura.py tests/test_providers_hasura.py tests/test_capture.py` — passed.
- `uv run mypy src` — passed.
- `uv run pytest` — 394 passed.

## Self-review

- Only the requested provider and capture tests were changed; unrelated
  documentation and example edits in the worktree were left untouched.
- The capture fixture uses deterministic local Playwright doubles and the
  adapter performs no network operation or request execution.
- Sanitized persistent records retain only redacted GraphQL structure while
  the original request/response bytes are available only during the active
  callback and the view rejects serialization.
