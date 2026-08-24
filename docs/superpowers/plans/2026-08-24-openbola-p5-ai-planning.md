# OpenBOLA P5: BYOK AI Planning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the legacy optional LiteLLM planning boundary with a typed, BYOK-only AI planner that sends only sanitized handles and structural context, uses explicit OpenAI-compatible and Azure OpenAI clients behind a separately confirmed provider `ScopeGuard`, and returns proposals that the deterministic target validator binds to observed inventory and scope.

**Architecture:** `AIProviderConfig` and `ProposedTest` are immutable public contracts. A planning-context builder converts typed observed candidates into a bounded JSON-safe payload containing opaque endpoint, identity, record, and field handles plus relative endpoint templates; it never resolves a handle. `OpenAICompatibleClient` and `AzureOpenAIClient` are small `httpx` clients with injected transports for tests; before every provider request they require a decision from the provider scope guard loaded from a separate confirmed scope file, never follow redirects, and resolve the API key only for the Authorization header. A deterministic validator intersects every returned handle, method, field, endpoint template, and target-origin path with the current observed candidates and target scope before any later executor can consume the plan.

**Tech Stack:** Python 3.11+, `dataclasses`, `typing.Literal`, `json`, `urllib.parse`, existing `pydantic` strict parsing helpers, existing `httpx` dependency, `ScopeGuard`, `SessionValueRegistry`, and pytest/httpx mock transports. No new runtime dependency is needed for P5.

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (§5 AI provider and typed plan, §7 planning flow, §8 privacy) and `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` (P5 and the separate-provider-scope ruling).

## Global Constraints

- The model sees sanitized schemas, statuses, provider hints, and opaque handles only; it never receives resolved credentials, cookies, raw record identifiers, full response values, request bodies, or target URLs containing record values.
- Every provider network operation must call a `ScopeGuard` built from a separate confirmed provider scope file before sending; `AIProviderConfig` is configuration, not network authority.
- Redirects are not followed implicitly. A response `Location` target is scope-checked without exposing it in an exception or log, then the client stops with a typed redirect error.
- AI may propose a typed plan only. No AI client imports or calls `ProbeExecutor`, `ScopeGuard` for the target as a bypass, Playwright, a target HTTP client, or an MCP mutation tool.
- `ProposedTest` values are accepted only when every handle, method, field handle, endpoint template, and target-origin path is present in current observed inventory and confirmed target scope. Writes still require the later P6 mutation grant.
- Provider API keys are represented by `SecretHandle` and resolved through the process-local `SessionValueRegistry` only while constructing one provider request. Keys, cookies, header values, raw IDs, and full values never enter prompts, reports, exceptions, persistent state, or test output.
- Provider URLs are absolute HTTPS origins without fragments or embedded credentials. `safe_headers` is an allowlist of static, non-sensitive headers; Authorization, Cookie, token, secret, and API-key header names are rejected.
- Payloads and responses are bounded; JSON is strict (duplicate keys, non-finite constants, unknown proposal fields, trailing text, and oversized data fail closed). Provider errors do not echo response bodies or URLs.
- Preserve the existing sanitized `RequestRecord` and P3b `AdapterRecordView` boundary. P5 consumes typed candidate data derived from discovery; it never resolves adapter bodies or session handles.
- Use the existing `httpx` dependency and fake transports in tests. Do not add a dependency or weaken a safety boundary in this plan.
- Before declaring P5 complete, run `uv run ruff check .`, `uv run mypy src`, and `uv run pytest`.

## File Structure

- `src/openbola/ai.py` — public AI contracts, bounded context builder, strict proposal parser/validator, and the compatibility migration adapter for the old `TestPlan`/`TestSuggestion` surface.
- `src/openbola/ai_clients.py` — explicit scoped OpenAI-compatible and Azure OpenAI HTTP clients, provider request/response envelopes, redirect handling, and client factory.
- `tests/test_ai.py` — contract, context privacy, strict parser, validator, and legacy migration tests.
- `tests/test_ai_clients.py` — deterministic fake-transport tests proving provider-scope enforcement, headers, payload privacy, Azure URL construction, response limits, and redirect fail-closed behavior.
- `tests/test_scope.py` — add a small provider-scope fixture helper only if the existing helper cannot express the provider origin/path; do not change `ScopeGuard` semantics.
- `pyproject.toml` — remove the obsolete LiteLLM optional extra only after the compatibility tests pass; retain the existing `httpx` dependency and do not introduce a replacement runtime dependency.

## Public Contracts and Invariants

The implementer must add these exact immutable contracts in `src/openbola/ai.py` before wiring clients:

```python
@dataclass(frozen=True)
class AIProviderConfig:
    kind: Literal["openai_compatible", "azure_openai"]
    base_url: str
    model: str
    api_key: SecretHandle
    azure_deployment: str | None = None
    api_version: str | None = None
    safe_headers: Mapping[str, str] = field(default_factory=dict)

@dataclass(frozen=True)
class PlanningCandidate:
    endpoint_handle: str
    owner_identity_handle: str
    attacker_identity_handle: str
    record_handle: str
    endpoint_template: str
    method: str
    field_handles: tuple[str, ...]

@dataclass(frozen=True)
class ProposedTest:
    endpoint_handle: str
    owner_identity_handle: str
    attacker_identity_handle: str
    record_handle: str
    method: str
    field_handles: tuple[str, ...]
    rationale: str

@dataclass(frozen=True)
class ProposedPlan:
    tests: tuple[ProposedTest, ...]
```

`AIProviderConfig.__post_init__` validates the literal kind, absolute HTTPS base URL, model/deployment/version requirements, safe header names/values, and bounded lengths without revealing values. `PlanningCandidate.__post_init__` normalizes an uppercase method and accepts only safe relative endpoint templates, non-empty opaque handles, and unique field handles. `ProposedTest` applies the same bounds and has no URL, body, header, credential, object-value, or executable callback field. `ProposedPlan` is bounded to ten tests and cannot be serialized with resolved session values because it contains handles only.

`build_sanitized_context(candidates: Sequence[PlanningCandidate]) -> dict[str, object]` returns exactly:

```json
{
  "schema": "openbola-ai-context-v1",
  "candidates": [
    {
      "endpoint_handle": "opaque",
      "owner_identity_handle": "opaque",
      "attacker_identity_handle": "opaque",
      "record_handle": "opaque",
      "endpoint_template": "/v1/documents/{id}",
      "method": "GET",
      "field_handles": ["opaque"]
    }
  ]
}
```

The function sorts candidates by their opaque handles, deduplicates exact candidates, omits all input keys not listed above, enforces item/byte limits, and never calls `resolve_value` or `resolve_secret`. The target origin and provider configuration are used by the local validator/client but are not included in this context.

`validate_proposed_plan(plan, context, target_scope_guard, target_origin) -> ProposedPlan` indexes the original `PlanningCandidate` objects (not only the JSON context), rejects unknown or duplicate candidate tuples, requires exact handle ownership/attacker/record matches, requires fields to be a subset of the candidate field handles, and calls `target_scope_guard.require_allowed(target_origin + endpoint_template, method)` for every proposal. A proposal cannot become executable through this function; it remains a typed value for P6/P8 to review.

### Task 1: Define typed contracts and privacy-safe planning context

**Files:**
- Modify: `src/openbola/ai.py`
- Modify: `tests/test_ai.py`

**Interfaces:**
- Consumes: `SecretHandle` and `SessionValueRegistry` from `openbola.handles`, `ScopeGuard` only as a type used by later validation, and discovery-derived candidate data supplied by P8/Pipeline.
- Produces: `AIProviderConfig`, `PlanningCandidate`, `ProposedTest`, `ProposedPlan`, `build_sanitized_context`, and constants `MAX_PROPOSED_TESTS`, `MAX_CONTEXT_BYTES`.

- [ ] **Step 1: Write failing contract and privacy tests**

Add tests with a sentinel raw ID, full response value, cookie, and API key. Assert that all four sentinels are absent from `build_sanitized_context` and its compact JSON, that an unknown input key is omitted, that candidates are sorted/deduplicated, and that invalid schemes, query/fragment endpoint templates, duplicate field handles, empty handles, invalid methods, and overlong rationale fail with `ValueError`. Assert `dataclasses.is_dataclass` and `frozen=True` behavior for the four contracts.

```python
def test_context_contains_handles_but_never_values() -> None:
    raw_id = "raw-record-id-sentinel"
    full_value = "full-response-value-sentinel"
    candidate = PlanningCandidate(
        endpoint_handle="ep-opaque",
        owner_identity_handle="owner-opaque",
        attacker_identity_handle="attacker-opaque",
        record_handle="record-opaque",
        endpoint_template="/v1/documents/{id}",
        method="GET",
        field_handles=("field-opaque",),
    )
    context = build_sanitized_context((candidate,))
    rendered = json.dumps(context, sort_keys=True)
    assert "ep-opaque" in rendered
    assert raw_id not in rendered and full_value not in rendered
    assert "cookie" not in rendered.casefold()
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `uv run pytest tests/test_ai.py -k 'contract or context' -v`

Expected: FAIL because the spec-shaped contracts and `build_sanitized_context` are not yet defined.

- [ ] **Step 3: Implement the contracts and context allowlist**

Keep the old `TestPlan`/`TestSuggestion` definitions temporarily in place for the migration task, but make all new contracts dataclasses with explicit bounds. Validate endpoint templates with the existing path-safety rules; use opaque handles as uninterpreted strings and never infer or derive a handle from an object value. Build the exact schema shown above, sort by `(endpoint_handle, owner_identity_handle, attacker_identity_handle, record_handle, method)`, and reject a serialized context over 16 KiB. Do not log invalid values in validation errors.

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `uv run pytest tests/test_ai.py -k 'contract or context' -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/openbola/ai.py tests/test_ai.py
git commit -m "feat: add typed AI planning contracts"
```

### Task 2: Parse and validate typed proposals against inventory and target scope

**Files:**
- Modify: `src/openbola/ai.py`
- Modify: `tests/test_ai.py`

**Interfaces:**
- Consumes: `ProposedPlan`, `ProposedTest`, `PlanningCandidate`, `build_sanitized_context`, and `ScopeGuard`.
- Produces: `parse_proposed_plan(raw: str) -> ProposedPlan` and `validate_proposed_plan(plan: ProposedPlan, candidates: Sequence[PlanningCandidate], target_scope_guard: ScopeGuard, target_origin: str) -> ProposedPlan`.

- [ ] **Step 1: Write failing strict-parser and binding tests**

Cover one valid JSON object, one exact `json` fence, duplicate keys, trailing text, unknown fields, arrays instead of objects, oversized output, more than ten tests, empty/oversized rationale, unknown handles, mismatched owner/attacker/record tuples, fields not present in the candidate, methods not observed, and a target-scope denial. Include a fake `ScopeGuard` subclass or real fixture guard whose `require_allowed` call count proves validation checks every proposal.

```python
def test_validator_requires_exact_candidate_and_current_scope(candidate, target_guard) -> None:
    plan = ProposedPlan((ProposedTest(
        endpoint_handle=candidate.endpoint_handle,
        owner_identity_handle=candidate.owner_identity_handle,
        attacker_identity_handle=candidate.attacker_identity_handle,
        record_handle=candidate.record_handle,
        method="GET",
        field_handles=candidate.field_handles,
        rationale="Prioritize the observed record boundary.",
    ),))
    assert validate_proposed_plan(
        plan, (candidate,), target_guard, "https://api.example.test"
    ) == plan
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `uv run pytest tests/test_ai.py -k 'proposed or validator or binding' -v`

Expected: FAIL because the strict parser and typed validator do not yet exist.

- [ ] **Step 3: Implement strict parsing and validation**

Parse only an object with a `tests` list. Reject duplicate keys with `object_pairs_hook`, non-finite JSON constants, trailing bytes, unknown keys, and oversized UTF-8 payloads. Normalize methods to uppercase before constructing `ProposedTest`. In `validate_proposed_plan`, index exact candidate tuples and compare all six binding values; reject unknown endpoint/identity/record/field handles even when the endpoint template happens to match. Require `target_scope_guard.require_allowed` with the supplied origin and each candidate path/method. Do not include the URL, handle contents, or parser input in errors.

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `uv run pytest tests/test_ai.py -k 'proposed or validator or binding' -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/openbola/ai.py tests/test_ai.py
git commit -m "feat: validate typed AI proposals against scope"
```

### Task 3: Add explicitly scoped OpenAI-compatible and Azure OpenAI clients

**Files:**
- Create: `src/openbola/ai_clients.py`
- Create: `tests/test_ai_clients.py`

**Interfaces:**
- Consumes: `AIProviderConfig`, `ProposedPlan`, `build_sanitized_context`, `parse_proposed_plan`, `SessionValueRegistry`, and a separately constructed provider `ScopeGuard`.
- Produces:

```python
class AIProviderClient(Protocol):
    def propose_tests(self, context: Mapping[str, object]) -> ProposedPlan: ...

class OpenAICompatibleClient:
    def __init__(self, config: AIProviderConfig, *, secrets: SessionValueRegistry,
                 provider_scope_guard: ScopeGuard, transport: httpx.BaseTransport | None = None,
                 timeout: float = 30.0) -> None: ...
    def propose_tests(self, context: Mapping[str, object]) -> ProposedPlan: ...

class AzureOpenAIClient(OpenAICompatibleClient):
    def propose_tests(self, context: Mapping[str, object]) -> ProposedPlan: ...

def client_for_config(config: AIProviderConfig, *, secrets: SessionValueRegistry,
                     provider_scope_guard: ScopeGuard,
                     transport: httpx.BaseTransport | None = None) -> AIProviderClient: ...
```

- [ ] **Step 1: Write deterministic fake-transport tests**

Use `httpx.MockTransport` or a custom `httpx.BaseTransport`; never connect to the Internet. Build a confirmed provider scope file that allows only `https://llm.example.test/v1/chat/completions` for `POST`, then assert:

```python
def test_openai_compatible_client_checks_provider_scope_and_never_sends_raw_values(...) -> None:
    seen: list[httpx.Request] = []
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"tests": []}'}}]})
    client = OpenAICompatibleClient(config, secrets=registry,
        provider_scope_guard=provider_guard, transport=httpx.MockTransport(handler))
    assert client.propose_tests(sanitized_context).tests == ()
    payload = json.loads(seen[0].content)
    rendered = json.dumps(payload)
    assert raw_id not in rendered and full_value not in rendered and api_key not in rendered
    assert seen[0].headers["authorization"] == f"Bearer {api_key}"
```

Also test a denied provider path/host (transport handler must not run), missing secret, unsafe `safe_headers`, Azure deployment/version URL construction, provider timeout validation, response size/JSON errors, and a 302 with a `Location` header. For the redirect test, use a guard spy to assert the target is checked and assert the client does not issue a second transport request.

- [ ] **Step 2: Run client tests to verify they fail**

Run: `uv run pytest tests/test_ai_clients.py -v`

Expected: FAIL during import because `openbola.ai_clients` and its clients do not exist.

- [ ] **Step 3: Implement the common scoped HTTP boundary**

Use one `httpx.Client(follow_redirects=False, transport=transport, timeout=timeout)` per proposal call or a safely closed context. Normalize the provider base URL at construction; construct the OpenAI-compatible `/chat/completions` URL and Azure `/openai/deployments/{deployment}/chat/completions?api-version=...` URL without embedding secrets. Before `client.post`, call `provider_scope_guard.require_allowed(url, "POST")`; never send if it raises. Resolve `config.api_key` through `secrets.resolve_secret` only after the decision and use it only for the Authorization header. Add static safe headers after validating their names and values. Send the system prompt plus `build_sanitized_context` and the strict `ProposedPlan` JSON schema; do not send configuration, scope-file contents, target origin, or resolved handles.

On any 3xx response, inspect `Location` without retaining its value, call `provider_scope_guard.require_allowed(location, "POST")` for the redirect target, and raise a generic `ProviderRedirectError` without following. On non-2xx, malformed JSON, missing choices/content, or response overflow, raise a generic typed provider error with no body/URL/credential material. Parse the returned text with `parse_proposed_plan`; the client still returns proposals only.

- [ ] **Step 4: Implement the factory and run client tests**

`client_for_config` returns the exact class for `openai_compatible` or `azure_openai` and rejects a mismatched config. Run: `uv run pytest tests/test_ai_clients.py -v`.

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/openbola/ai_clients.py tests/test_ai_clients.py
git commit -m "feat: add scope-guarded BYOK AI clients"
```

### Task 4: Migrate the legacy planner without preserving an unsafe network path

**Files:**
- Modify: `src/openbola/ai.py`
- Modify: `tests/test_ai.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: existing `TestPlan`/`TestSuggestion` values, `PlanningCandidate`, strict proposal validation, and `AIProviderClient`.
- Produces: `migrate_legacy_plan(plan: TestPlan, candidates: Sequence[PlanningCandidate]) -> ProposedPlan` and a deprecated `LiteLLMAdapter` compatibility symbol that cannot send network traffic or accept an API-key string.

- [ ] **Step 1: Write migration and negative compatibility tests**

Assert that a legacy suggestion maps only when exactly one `PlanningCandidate` matches its endpoint template, method, location, and field handle mapping supplied by the caller; ambiguous or absent identity/record mappings fail closed. Assert the old adapter no longer accepts `api_key: str`, does not import `litellm`, does not start a subprocess, and cannot return an executable request. Verify imports of `TestPlan`, `TestSuggestion`, and `LiteLLMAdapter` remain available only as deprecated non-network compatibility symbols until callers migrate.

- [ ] **Step 2: Run migration tests to verify they fail**

Run: `uv run pytest tests/test_ai.py -k 'legacy or migration' -v`

Expected: FAIL because the migration function and safe compatibility behavior are not implemented.

- [ ] **Step 3: Implement explicit migration and remove the direct LiteLLM path**

Map only structural legacy fields. The migration function must receive a caller-provided candidate mapping for owner, attacker, record, endpoint, and field handles; it must never invent or resolve a record identifier. Keep legacy model parsing bounded and mark the symbol with `DeprecationWarning`; make the old `LiteLLMAdapter.propose_tests` raise a generic migration error instructing callers to construct `AIProviderConfig` and a scoped client. Remove `litellm` from `pyproject.toml` optional dependencies only after all tests prove no import or call remains. Do not replace it with another unscoped library.

- [ ] **Step 4: Run migration tests and the existing AI tests**

Run: `uv run pytest tests/test_ai.py -v`.

Expected: PASS, including the existing strict privacy regressions updated to use `ProposedPlan` and the new fake provider boundary.

- [ ] **Step 5: Commit**

```bash
git add src/openbola/ai.py tests/test_ai.py pyproject.toml uv.lock
git commit -m "refactor: migrate legacy AI planner to typed BYOK flow"
```

### Task 5: Prove the end-to-end P5 boundary and document integration for P6/P8

**Files:**
- Modify: `tests/test_ai.py`
- Modify: `tests/test_ai_clients.py`
- Create: `tests/test_ai_boundary.py`
- Modify: `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md`

**Interfaces:**
- Consumes: the completed contracts, context builder, scoped clients, migration adapter, P3b session fixtures, and real `ScopeGuard` fixtures.
- Produces: a deterministic acceptance proof and the roadmap status update marking P5 complete only after all checks pass. P6/P8 consume `ProposedPlan` as suggestions and remain responsible for mutation grants, target execution, and UI review.

- [ ] **Step 1: Add the boundary acceptance test**

Create a fixture that stores an API key and raw session sentinel in an `InMemorySessionValueRegistry`, builds `PlanningCandidate` values from sanitized discovery metadata, constructs a provider guard from a separate confirmed scope file, and serves a strict fake provider response. Assert the captured provider request contains only the context schema, opaque handles, safe relative templates, and the typed schema; assert it contains none of the API key, cookie, raw object ID, full response value, raw GraphQL/PostgREST body, target scope contents, or `AdapterRecordView` material. Assert the returned plan is rejected when one handle, method, field, path, or scope decision is changed. Assert `registry.close()` prevents any later attempted resolution.

- [ ] **Step 2: Run the focused boundary suite**

Run: `uv run pytest tests/test_ai.py tests/test_ai_clients.py tests/test_ai_boundary.py -v`.

Expected: PASS with no real network connections.

- [ ] **Step 3: Run formatting, type, and full regression checks**

Run:

```bash
uv run ruff check .
uv run mypy src
uv run pytest
```

Expected: all three commands exit 0. Investigate and fix failures caused by P5; report unrelated pre-existing failures separately rather than weakening tests or safety checks.

- [ ] **Step 4: Update the roadmap status**

Change only the P5 status marker in `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` to record the merge date and acceptance commands. Keep the P5 separate-provider-scope ruling and the P11 external-approval gate intact.

- [ ] **Step 5: Commit the acceptance proof and roadmap marker**

```bash
git add tests/test_ai.py tests/test_ai_clients.py tests/test_ai_boundary.py docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md
git commit -m "test: close P5 BYOK AI planning boundary"
```

## Self-Review Checklist

- Spec §5's exact `AIProviderConfig` and `ProposedTest` fields are implemented in Task 1.
- Acceptance criterion 5 is covered by Tasks 3 and 5: fake provider payloads contain handles and sanitized context, while credentials, cookies, raw IDs, and full values are absent.
- The separate confirmed provider scope requirement is explicit in the client constructor, every request path, and denial/redirect tests.
- No task allows AI output to call a target request; target scope validation and later mutation grants remain deterministic boundaries.
- Existing P3b raw material is never consumed by the AI context builder and no P5 file adds serialization, reporting, logging, or MCP access to it.
- The legacy LiteLLM path is migrated without retaining a hidden unscoped network route.
- All named functions, classes, files, commands, and commit scopes are defined above; there are no placeholder TODOs or deferred implementation steps.

