# Phase 7 — Local MCP interface

`src/bola_checker/mcp_server.py` adds a small service layer and an optional
FastMCP adapter.  The module imports no MCP dependency at import time; the
`fastmcp` package is loaded only by `create_mcp_server()`.  The adapter runs
stdio only and exposes bounded tools for loading a scope, opening state,
registering environment credential references, importing sanitized HAR data,
planning endpoints/tests, running pending tests through an injected phase-5
executor, and writing deterministic reports.

Safety properties:

- planning, import, execution, and reporting require both a provenance-checked
  `ScopeGuard` and a `StateStore` in the same local session;
- HAR import rechecks every record against the loaded scope;
- `import_records` provides a bounded explicit-ownership JSON route for
  executable read evidence. Its file is opened as a regular no-follow file,
  checked with `fstat`, read at most 5 MiB, and rejected if it grows or changes
  during the read. JSON depth, node, and string limits are enforced before
  allowlisted record validation; malformed, recursive, duplicate-key, and
  non-standard JSON fail as bounded service errors;
- each execution rechecks the base URL against the active scope; the MCP
  surface is read-only and rejects mutation mode. Reversible mutations remain
  available only through the separately controlled phase-5 API;
- the executor is a dependency injection boundary.  MCP callers cannot select
  a Python import path or construct an HTTP client. If no test executor is
  injected, the service lazily creates the deterministic phase-5
  `ProbeExecutor` from the current scope, in-memory vault, and fresh state;
  the instance is never retained across an engagement reset;
- credentials are accepted only as validated environment variable names and
  are resolved later by the in-memory `CredentialVault`; SQLite receives only
  opaque reference fingerprints;
- tool results omit object identifiers, request headers, cookies, bodies, and
  credential material; endpoint planning returns structural metadata only;
- changing scope or state clears all session-derived records, object mappings,
  identity hints, outcomes, credentials, base URL, and injected executor;
  this reset happens before validating a new path, so failed transition
  attempts cannot retain a previous engagement;
- state initialization accepts only a new database path below a real,
  non-symlink parent directory; existing databases and SQLite sidecars are
  rejected to prevent arbitrary historical state reuse;
- opaque object references loaded from SQLite must have a current in-memory
  mapping from the same sanitized capture before they are passed to an
  executor; a reopened database otherwise fails closed;
- FastMCP remains optional and tests use a small fake server, never a network
  transport.

Validation evidence for this phase: `uv run pytest tests/test_mcp_server.py`
passed 19 tests. `uv run ruff check
src/bola_checker/mcp_server.py tests/test_mcp_server.py` and `uv run mypy src`
passed. The final integrated repository gate passed 244 tests with full Ruff
and mypy green.
