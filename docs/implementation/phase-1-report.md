# Phase 1: capture and HAR import

## Delivered

- `CaptureConfig` validates absolute HTTP(S) URLs without embedded credentials,
  relative `.har` output paths below an existing non-symlink capture root,
  identities, interactive mode, and a positive HAR size ceiling.
- `capture_har` lazy-loads Playwright, closes context and browser reliably, and
  never asks Playwright to persist a raw HAR. A sanitized in-memory event
  collector records request metadata and response metadata without response
  bodies. Every browser HTTP(S) request passes the confirmed `ScopeGuard`
  route before it can continue; redirects are checked as new requests. An
  interactive login explicitly requires `headless: false` and opens a local
  blank page for the authorized operator to navigate.
- Sanitized output is serialized to a mode-`0600` temporary file below a root
  directory descriptor and atomically renamed into place. Parent components
  are opened without following symlinks or created relative to an already
  trusted directory descriptor.
- `parse_har_records` reads at most the configured byte limit, validates the
  HAR envelope and each required request/response field, then converts entries
  to shared `RequestRecord` values containing only the bounded structural
  redaction contract described below.

## Evidence

Focused automated tests cover configuration validation, malformed and oversized
HAR rejection, request/response conversion, secret-safe `RequestRecord` repr,
the lazy missing-Playwright failure path, route enforcement, collector output,
HAR 1.2 completeness, and secure output writing. The Playwright-facing tests
use local fakes and perform no browser, target, redirect, or network operation.

## Boundary retained

This phase records or imports operator-authorized traffic; it does not decide
scope, execute probes, evaluate targets, or log credentials. WebSocket and SSE
traffic are outside HAR coverage.

## Fix round 1 evidence

Raw Playwright HAR recording is removed. An in-memory event collector redacts
sensitive headers, query parameters, and JSON fields before retaining them and
never retains response bodies. Capture writes only that sanitized HAR within an
explicit non-symlink `capture_root`; output must be a relative `.har` path,
and created parents are checked for symlinks. Import accepts regular files only
and applies the same redaction. Tests cover cleanup after context, collector,
and cancellation failures before any output write.

Validation run: `uv run ruff check src/bola_checker/capture.py
tests/test_capture.py` passed; `uv run pytest tests/test_capture.py` passed
with 7 tests; `uv run mypy src/bola_checker/capture.py` passed.

## Fix round 2 evidence

`capture_har` now requires a `ScopeGuard` and installs a context route before
any operator navigation. Every HTTP(S) request, including redirect hops, calls
`require_allowed` and continues only with its canonical URL; unsafe schemes are
aborted. The writer emits minimally valid HAR 1.2 envelopes with creator,
timing, cache, complete request, and complete response fields. URL sanitizing
now strips userinfo/fragments, treats both ampersand and semicolon query
separators conservatively, and redacts OAuth/signature/credential/X-Amz fields
as well as URL-bearing redirect/referrer headers.

## Fix round 3 correction

The earlier statement that scope routing simply continued canonical URLs was
incomplete. Scope denial now explicitly calls Playwright `abort("blockedbyclient")`
and is surfaced only after context/browser cleanup. CIDR decisions cannot be
DNS-pinned safely through Playwright; capture therefore fails closed unless the
canonical hostname is itself an approved direct IP. Link and Refresh URL values
are sanitized too. HAR response content and all standard timing keys are now
present in output.

## Fix round 4 evidence

The default collector now includes the request `Content-Type` as HAR
`postData.mimeType`; absent headers use `text/plain` for textual input and
`application/octet-stream` for byte input. Tests exercise the default
collector's sanitized request body, response metadata, both MIME fallbacks,
Link/Refresh sanitization, and every required field in a complete emitted HAR
1.2 entry.

Output writing no longer validates and later reopens a writable full path. It
anchors at a non-followed root directory descriptor, opens or safely creates
each parent relative to the previously opened descriptor, writes and `fsync`s
an exclusive mode-`0600` temporary file, atomically replaces descriptor-relative
names, and `fsync`s the parent. Tests prove an existing symlink parent is
rejected, a parent swapped to a symlink after opening cannot redirect output,
and a replace failure removes the temporary file while preserving existing
output.

Validation run: `uv run ruff check src/bola_checker/capture.py
tests/test_capture.py` passed; `uv run mypy src/bola_checker/capture.py` passed;
`uv run pytest -q tests/test_capture.py` passed with 17 tests.

## Fix round 5: fail-closed persistent structure

Capture no longer relies on a credential-name denylist. The HAR persistence
boundary rebuilds every collector entry from an explicit schema, so an injected
collector extension, response body, cookie array, or other unrecognized field
cannot bypass the sanitizer. Header names remain as structure, but only a
validated and parameter-free `Content-Type` media type and bounded sanitized
`Location`/`Content-Location` URL can retain values. Every other header value,
including custom `X-Auth` and `X-Session` values, is `[REDACTED]`. `Link`,
`Refresh`, cookies, response bodies, and arbitrary response content are not
retained. URL-bearing allowlisted headers accept only HTTP(S), origin-relative,
or protocol-relative URLs without userinfo; fragments are removed and every
query value is redacted.

Request URLs retain the HTTP(S) scheme, host, port, path, and query field names
needed for endpoint discovery, while every query value and the fragment are
removed. JSON media types, including `application/*+json`, retain only bounded
object field names and list/object shape; strings, numbers, booleans, and null
are all replaced with `[REDACTED]`. Non-JSON, malformed, over-limit, textual,
and byte bodies become a single `[REDACTED]` value. The bounds are 10,000 HAR
entries, 256 headers per direction, 16,384 URL characters, 256 query fields,
a 1 MiB input body, JSON depth 32, 4,096 JSON nodes, and 256 characters per
JSON/query field name. The configured HAR byte ceiling is also enforced before
the secure descriptor-relative writer creates a temporary file.

This boundary is deliberately structural redaction, not entropy scanning or a
claim to detect arbitrary secrets. URL path segments, HTTP methods, header
names, normalized media types, sanitized allowlisted URL paths, query names,
and JSON field names are retained as structural labels; an operator must not
put credentials in those positions. The regression suite
uses custom sentinel values in `X-Auth`, `X-Session`, neutral query parameters,
JSON `auth`/`session`/neutral fields, URL-bearing headers, collector extensions,
and response content, then asserts that none occur anywhere in the emitted HAR
bytes. It also covers common JSON MIME normalization, complete HAR 1.2 fields,
and fail-closed body depth/node/byte and output-size limits. ScopeGuard routing
and the anchored dirfd writer behavior remain covered by their existing tests.
The Playwright context is created with Service Workers blocked before a page
can exist, so context routing remains the sole browser HTTP(S) request path;
the in-memory collector enforces the 10,000-entry ceiling while collecting as
well as at serialization time. The extraction consumer ignores the canonical
`[REDACTED]` transport placeholder instead of registering it as a replayable
credential. Chromium is launched with `--no-proxy-server`, preventing an
inherited system proxy from becoming an unchecked network peer outside the
logical URL authorized by `ScopeGuard`; capture tests assert the complete
browser launch contract.

Validation run: targeted Ruff and mypy checks passed; `uv run pytest -q
tests/test_capture.py tests/test_extract.py` passed with 37 tests. Repository-wide
`uv run ruff check .` and `uv run mypy src` passed; `uv run pytest` passed all
244 tests in the final shared-worktree gate.
