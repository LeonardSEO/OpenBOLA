# Task 3 implementation report

## Result

Implemented explicit, scope-guarded BYOK clients in `src/openbola/ai_clients.py`.

- Added `AIProviderClient`, `OpenAICompatibleClient`, `AzureOpenAIClient`, and
  `client_for_config` with exact provider-kind matching.
- Every provider POST is checked against the separately supplied provider
  `ScopeGuard` before the secret is resolved or transport is called.
- Redirects are never followed. A `Location` target is checked separately by
  the provider guard and then a generic `ProviderRedirectError` is raised.
- API keys are resolved only immediately after authorization and are used only
  for the Authorization header; request payloads contain only the bounded,
  allowlisted sanitized context and strict `ProposedPlan` JSON schema.
- Provider URLs, timeout, headers, request size, response size, response shape,
  and transport failures are bounded and surfaced through generic typed errors
  without response bodies, URLs, credentials, or resolved values.
- Added deterministic `httpx.MockTransport` coverage for successful requests,
  denied scope, missing credentials, unsafe headers, Azure URL construction,
  timeout bounds, malformed/oversize/error responses, redirect checks, factory
  selection, mismatched configurations, and unsafe context rejection.

## Verification

```text
uv run ruff check src/openbola/ai_clients.py tests/test_ai_clients.py
All checks passed!

uv run mypy src/openbola/ai_clients.py
Success: no issues found in 1 source file

uv run pytest tests/test_ai_clients.py tests/test_ai.py -q
82 passed
```

## Review hardening

The client boundary was hardened after review:

- provider guards must be real, provenance-backed `ScopeGuard` instances;
  decisions must be HTTPS `ScopeDecision` values and non-empty approved peer
  sets are rejected unless a pinned transport is available;
- static headers use an explicit allowlist and reject authority, host,
  hop-by-hop, proxy-forwarded, and framing headers;
- response envelopes use duplicate-key/non-finite rejection and streaming
  response-size caps before buffering;
- non-ASCII, whitespace, and control-character provider secrets are rejected;
- provider base URLs are HTTPS origins without a path; OpenAI-compatible calls
  use the conventional `/v1/chat/completions` path.

Additional verification:

```text
uv run ruff check src/openbola/ai.py src/openbola/ai_clients.py tests/test_ai.py tests/test_ai_clients.py
All checks passed!

uv run mypy src/openbola/ai.py src/openbola/ai_clients.py
Success: no issues found in 2 source files

uv run pytest tests/test_ai_clients.py tests/test_ai.py -q
92 passed
```

## Commit

The implementation and review hardening are committed in the current task
commits, with the hardening follow-up recorded after the base
`d4f0d7f feat: add scope-guarded BYOK AI clients` commit.

Final review hardening is in `48d8821 fix: reject routing headers and deep
provider JSON`; it blocks forwarding/routing and method-override headers,
requires ASCII header names and values, and converts deeply nested JSON
recursion failures (including nested proposal content) into the same typed
response error. The final parser containment fix is `3572e92`. Final focused
proof:

```text
uv run pytest tests/test_ai_clients.py tests/test_ai.py -q
97 passed
```
