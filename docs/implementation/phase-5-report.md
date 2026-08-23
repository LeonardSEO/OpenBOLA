# Phase 5 report: scoped deterministic executor

## Delivered

- Added `bola_checker.executor.ProbeExecutor`, the sole HTTP execution
  boundary. Every initial request and every manually-followed redirect calls
  `ScopeGuard.require_allowed` and sends the returned canonical URL. The
  `httpx` client is configured with `follow_redirects=False`.
- Hostname requests with CIDR policy fail closed unless a proven peer-pinning
  transport is available. Direct approved IP targets remain supported.
- Credentials are resolved just before a request and transported as the exact
  bearer, header, or cookie value from the in-memory `CredentialVault`; no
  credential value, response body, or request body enters evidence.
- Read probes are limited to `GET`, `HEAD`, and `OPTIONS`. Mutation probes need
  an explicit `MutationSpec` with a safe canary, a bounded body, an exact
  cleanup request, and a scope grant for both mutation and cleanup methods.
  Mutations are never retried and cleanup is attempted immediately.
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
- Successful execution can be passed directly to `StateStore.record_probe_result`
  for the atomic attempt/audit append API.

## Verification

- `uv run pytest tests/test_executor.py`: 23 passed.
- `uv run ruff check src/bola_checker/executor.py tests/test_executor.py`: passed.
- `uv run mypy src/bola_checker/executor.py`: passed.
- Full `uv run mypy src` is currently blocked by a pre-existing/in-progress
  type error in `state.py:746`; no shared state file was changed by this phase.

All HTTP tests use `httpx.MockTransport`; no external network or live target is
contacted.
