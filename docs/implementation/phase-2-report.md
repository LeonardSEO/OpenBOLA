# Phase 2 implementation report

## Outcome

Phase 2 implements deterministic, request-only credential extraction.  It
corrects the historical HAR example: response headers and response bodies can
produce redacted body-secret warnings, but can never produce a credential that
the executor could replay.

## Boundary and API

`CredentialVault` is in-memory and has no JSON export.  `store()` returns a
`CredentialRef` with a process-local HMAC-SHA-256 reference; `resolve()` is
the only route that returns the original value.  The HMAC uses one random key
per process, is never persisted, and permits only within-process correlation.
`environment_reference()` creates an `env:NAME` reference whose value is read
only when it is resolved.  Resolution validates the reference type/name for
vault entries and raises a generic error without exposing a value.

`extract_requests(records, vault)` recognises these request transports:

- `Authorization: Bearer <token>` becomes `CredentialKind.BEARER`; repeated
  bearer prefixes are removed before storage, so a later request builder must
  add at most one prefix.
- Non-bearer `Authorization` and the recognised API-key headers become
  `CredentialKind.HEADER` with the supplied header name.
- `Cookie` is parsed into named `CredentialKind.COOKIE` entries.

The extractor returns credential references, unverified JWT identity hints,
body-secret warnings, and header/body-free `RequestRecord` copies.  JWT
payload parsing is deliberately signature-unverified and must never establish
ownership or authorise a probe.  Body scanning returns only a field name and
process-local HMAC fingerprint; no body value is retained.

## Validation

Focused tests cover bearer/header/cookie handling, repeated bearer prefix
normalisation, response-credential exclusion, malformed JWTs, environment
references, generic errors, and representation/JSON leakage boundaries.

- `uv run ruff check .` passed.
- `uv run pytest -q tests/test_credentials.py tests/test_extract.py` passed:
  9 tests.
- `uv run mypy src/bola_checker/credentials.py src/bola_checker/extract.py`
  passed.

## Fix round 2: conservative query-name redaction

Persistent URL handling is now fail-closed: only absolute `http` or `https`
URLs with a hostname, a valid port, and no userinfo are retained. Relative,
malformed, invalid-port, and userinfo-bearing URLs become `[INVALID_URL]`.
Query names are percent-decoded, case-normalised, stripped of separators and
an optional leading `x`, then conservatively redacted when they contain a
credential-shaped part such as `token`, `secret`, `auth`, `apiKey`,
`accessKey`, `session`, `cookie`, `bearer`, `credential`, `code`, or `key`.
This includes `X-API-Key`, `X-Auth-Token`, `X-Access-Token`,
`X-Session-Token`, and case/underscore/percent-encoded variants.

Fix-round validation:

- `uv run ruff check src/bola_checker/credentials.py src/bola_checker/extract.py tests/test_credentials.py tests/test_extract.py` passed.
- `uv run pytest -q tests/test_credentials.py tests/test_extract.py` passed:
  16 tests.
- `uv run mypy src/bola_checker/credentials.py src/bola_checker/extract.py`
  passed.

## Fix round 1: persistent URL and serialisation hardening

Persistent request copies now strip URL userinfo and redact values for
credential-shaped query keys, while retaining the path, key name, and
non-sensitive query parameters. This applies before the record reaches any
result repr or dataclass/JSON serialisation. Environment references are now
instance-bound: `resolve()` accepts only references registered by
`environment_reference()` or `register_env_ref()` on that vault. Arbitrary
constructed `env:` references fail with the same generic resolution error.
Fragments are discarded too, and malformed URLs produce the fixed
`[INVALID_URL]` placeholder instead of preserving untrusted text.

`CredentialVault` and its internal secret wrapper explicitly reject pickle
through reduction and state hooks. The vault uses an `RLock` around stores,
environment registration, resolution, and diagnostic entry counts.

Fix-round validation:

- `uv run ruff check src/bola_checker/credentials.py src/bola_checker/extract.py tests/test_credentials.py tests/test_extract.py` passed.
- `uv run pytest -q tests/test_credentials.py tests/test_extract.py` passed:
  12 tests, including URL/repr/JSON sentinels, unregistered environment refs,
  pickle rejection, and concurrent store/resolve coverage.
- `uv run mypy src/bola_checker/credentials.py src/bola_checker/extract.py`
  passed.

## Fix round 3: strict persistent URL validation

Before a persistent URL is emitted, phase 2 rejects all control or whitespace
characters, backslashes, and malformed percent escapes. It accepts only a
canonical absolute `http`/`https` URL with no userinfo, a parsed valid port,
and a hostname that is either a valid IP address or a lowercase IDNA hostname
with valid non-empty labels (apart from an optional trailing root dot). Invalid
input is always replaced by `[INVALID_URL]`; safe URLs retain path and
non-sensitive query data in canonical scheme/host form.

Fix-round validation:

- `uv run ruff check src/bola_checker/credentials.py src/bola_checker/extract.py tests/test_credentials.py tests/test_extract.py` passed.
- `uv run pytest -q tests/test_credentials.py tests/test_extract.py` passed:
  22 tests.
- `uv run mypy src/bola_checker/credentials.py src/bola_checker/extract.py`
  passed.
