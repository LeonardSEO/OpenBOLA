# Phase 6 report — optional typed AI planner

## Delivered

The ai module adds an optional planning-only AI boundary. Its Pydantic
TestPlan and TestSuggestion contracts are bounded to ten concise suggestions
and contain only an endpoint path template, HTTP method, identifier
location/hint, and response-diff field hint. They contain no URL, headers,
body, identity, credential, object value, or request-execution fields.

Before a provider is called, sanitize_context allowlists endpoint templates,
per-template allowed methods, and structural candidate locations. It removes
all other data, rejects scheme-relative URLs and ambiguous dot, duplicate
slash, percent-encoded, backslash, control-character, query, and fragment
paths. Candidate locators are never trusted from input: the module derives a
canonical location from the validated identifier field name and typed location.
Object values are omitted, and item and byte limits apply. Provider output is
strict JSON only (or one exact JSON fence): duplicate keys, trailing text,
unknown fields, invalid constants, and oversized output are rejected.
Suggestions must match an endpoint, allowed method, location, identifier field,
and response-diff field already present in the sanitized context.

The module has no HTTP client. A returned plan is only a typed proposal; a
future deterministic executor must still obtain ScopeGuard approval and, for
writes, a separately granted mutation policy before it can send a request.

## Providers

- LiteLLMAdapter imports LiteLLM only at call time, requests a strict JSON
  Schema response with temperature zero, and accepts only finite, positive,
  bounded provider timeouts.
- CodexCLIAdapter is intentionally fail-closed and does not start a subprocess.
  A general Codex agent can have filesystem tools and network capabilities that
  this module cannot technically prohibit; a read-only filesystem sandbox is
  not network isolation. The adapter raises CodexCLIAdapterDisabledError until
  a provider with a technically enforced no-tools/no-network boundary exists.

## Validation

The phase-six tests mock both provider boundaries and cover schema bounds,
strict parsing failures, duplicate keys, output limits, secret redaction,
ambiguous-path rejection, canonical candidate-locator derivation, response-diff
binding, hallucinated endpoint rejection, LiteLLM lazy import/schema
configuration, disabled Codex execution, and timeout validation.
