# Phase 5 report: scoped deterministic executor

## Delivered

- Added `bola_checker.executor.ProbeExecutor`, the sole HTTP execution
  boundary. Every initial request and every manually-followed redirect calls
  `ScopeGuard.require_allowed` and sends the returned canonical URL. The
  `httpx` client is configured with `follow_redirects=False` and
  `trust_env=False`. Credential-bearing redirects must remain on the exact
  same scheme, host, and effective port; cross-origin and HTTPS-to-HTTP
  redirects are blocked before a second request.
- Hostname requests with CIDR policy fail closed unless a proven peer-pinning
  transport is available. Direct approved IP targets remain supported.
- Credentials are resolved just before a request and transported as the exact
  bearer, header, or cookie value from the in-memory `CredentialVault`; no
  credential value, response body, or request body enters evidence.
- Read probes are limited to `GET`, `HEAD`, and `OPTIONS`. Mutation probes need
  an explicit `MutationSpec` with a safe canary, a bounded body, an exact
  cleanup request bound to the same canary, and a scope grant for both
  mutation and cleanup methods. The primary request tracks whether it was
  actually dispatched; cleanup is skipped when dispatch definitely did not
  begin, cancellation after dispatch still triggers cleanup, and a failed
  owner cleanup stops the attacker phase. Mutations are never retried.
- Responses are bounded by byte limit, hard wall-clock deadline, redirect,
  request, retry, concurrency, and rate limits. Retries are only made for
  idempotent reads. Mutation requests reserve budget for their cleanup before
  sending the primary request, and cleanup is verified against its explicit
  2xx status contract.
- Comparison uses the owner response as ground truth. A matching object ID in
  both successful responses, tied to the expected object, is `bola`; 401/403/404
  is `protected`; all other outcomes are `inconclusive`. Equal status or body
  shape without object-ID evidence cannot establish a finding. Evidence uses
  only opaque `obj_<sha256>` references, bounded statuses, enum values, and
  closed error codes.
- JSON request/response traversal is bounded by depth and node count, and
  serialization/recursion errors fail closed.
- Successful execution can be passed directly to `StateStore.record_probe_result`
  for the atomic attempt/audit append API.

## Verification

- `uv run pytest tests/test_executor.py`: 28 passed.
- `uv run ruff check src/bola_checker/executor.py tests/test_executor.py`: passed.
- `uv run mypy src/bola_checker/executor.py`: passed.
- Final repository gate: `uv run pytest -q` — 246 passed; full Ruff and mypy
  passed for all 15 source files.

All HTTP tests use `httpx.MockTransport`; no external network or live target is
contacted.
