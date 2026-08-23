# BOLACheck

Authorization-first, deterministic BOLA/IDOR validation for HTTP APIs.

BOLACheck is an open-source defensive testing library for teams that have
written permission to assess an API. It correlates traffic from multiple
identities, records only evidence-backed ownership, and compares an owner's
request with an attacker's request for the same object. The target-probe
network boundary belongs to the deterministic executor; separately scoped
browser capture can collect structural traffic. The optional AI layer can
suggest a typed plan, but cannot send a target request or widen policy.

> **Alpha:** this repository is under active development. Test only systems you
> own or systems covered by explicit, written authorization. The command-line
> orchestrator is read-only by default and the local vulnerable/protected mock
> target is included for development and CI proof.

## Why BOLACheck?

Many authorization tests stop at “the endpoint returned 200”. BOLACheck keeps
the decision auditable:

- ownership is persisted only when the captured evidence is explicit or an
  unambiguous create/response correlation;
- every request, including every redirect hop, must receive a fresh
  `ScopeDecision`;
- read probes are the default, while writes require a separate method/path
  grant and a reversible canary plus cleanup request;
- replay credentials supplied through environment references stay in an
  in-memory vault and are excluded from SQLite, reports, and MCP responses;
  HAR output follows the structural redaction boundary documented below and
  is not a general-purpose secret detector;
- each attempted owner/object/attacker combination is recorded in append-only
  state and reports distinguish untested, inconclusive, protected, and BOLA
  outcomes.

## Current status

The implementation currently includes these phase modules:

| Area | Module | Current contract |
| --- | --- | --- |
| Authorization | `scope.py` | Confirmed, time-bounded host/CIDR/path policy; explicit mutation grants |
| Capture/import | `capture.py` | Scope-checked browser capture adapter and bounded, sanitized HAR import |
| Credentials | `credentials.py`, `extract.py` | In-memory credential vault and secret-safe request extraction |
| Audit state | `state.py` | SQLite migrations, opaque credential/object references, append-only audit records |
| Endpoint evidence | `endpoints.py` | Candidate discovery and strong ownership correlation |
| Deterministic probes | `executor.py` | Bounded HTTP probes, manual redirects, response comparison, reversible mutation boundary |
| Optional planning | `ai.py` | Bounded JSON plan suggestions; no target-network client or execution authority |
| Local MCP adapter | `mcp_server.py` | Optional stdio adapter around a testable service; FastMCP is lazy-loaded |
| Reports | `reporting.py` | Deterministic JSON, JUnit XML, Markdown, and SARIF output |
| CLI/pipeline | `cli.py`, `pipeline.py` | Scope-enforced read-only orchestration with machine-safe JSON mode |
| Local demo | `mock_target.py` | Ephemeral `127.0.0.1` vulnerable and protected endpoints |

The installed `bolacheck` entry point exposes the `scan` command. Credentials
are supplied only by environment-variable references; a traffic HAR is
sanitized on import and cannot provide a replay token or response-body
ownership evidence by itself. Use a bounded, sanitized records JSON file (via
`--identity NAME=records.json` or `IdentityInput.records_path`) when response
bodies are required for correlation.

## Safety boundary

Read [AUTHORIZATION.md](AUTHORIZATION.md) before creating a scope file. The
non-negotiable rules are:

1. A real scope file must be confirmed, time-bounded, and allow-list the target.
2. The reviewed scope file is bound to the guard; changing, replacing, or
   symlinking it after load fails closed.
3. Redirects are never followed implicitly. Every target is checked again.
4. `GET`, `HEAD`, and `OPTIONS` are the safe default. `POST`, `PUT`, `PATCH`,
   and `DELETE` need an explicit mutation grant; a write probe additionally
   needs an operator-supplied canary and cleanup request.
5. Do not use the tool for unsolicited scanning, credential attacks,
   persistence, data extraction, destructive actions, denial of service, or
   bypassing access controls outside the written scope.

See [SECURITY.md](SECURITY.md) for disclosure guidance and [LICENSE](LICENSE)
for the Apache-2.0 terms.

## Install for development

Python 3.11 or newer and `uv` are required for the development workflow. From
a checkout:

```bash
uv sync --extra dev
uv run ruff check .
uv run mypy src
uv run pytest
```

Optional capabilities are deliberately separate:

```bash
uv sync --extra ai       # LiteLLM adapter
uv sync --extra mcp      # FastMCP stdio adapter
uv sync --extra capture  # Playwright capture adapter
```

`uv sync --extra all` installs all optional capabilities. A browser binary is
still an operator-managed Playwright installation; capture is not a license to
navigate an unapproved target.

## Working with a scope

Start from [examples/scope.example.yaml](examples/scope.example.yaml), replace
the example client/reference/timestamps and targets, and set `confirmed: true`
only after written authorization has been verified. Keep real contract details
out of source control when they are sensitive. The loader rejects ambiguous YAML,
unknown fields, invalid URL/path encodings, expired windows, and unapproved
methods.

The scope example intentionally contains a placeholder authorization and an
example time window. It is documentation, not a ready-to-run authorization.

## Capturing or importing traffic

`capture.py` accepts an actual `ScopeGuard` and retains sanitized request and
response structure. The retained contract keeps URL paths and field/header
names for endpoint discovery, but redacts every query value, every JSON scalar,
and every non-allowlisted header value; raw bodies and response bodies are not
retained. `Content-Type` is reduced to a validated media type, while `Location`
and `Content-Location` retain only a bounded URL structure with redacted query
values. This is structural redaction, not arbitrary secret detection: credentials
must not be placed in retained URL path segments or structural names. For a
browser capture, install the capture extra and use an operator-controlled login
session; the target URL is checked by the scope guard before any navigation is
allowed.

For existing traffic, use a HAR with at least a `log.entries` array and import
it only after confirming that every entry belongs to the same written scope.
The capture/import layer is not a proxy and does not record raw response bodies
or cookies for later replay.

## Ownership, probes, and findings

Endpoint discovery (`endpoints.py`) recognizes path, query, JSON, and GraphQL
identifier candidates. A candidate is not a test target by itself: executable
ownership requires explicit evidence or a strong observed create/response match.
The state layer stores opaque references and an audit trail so later reports do
not need the original credential or identifier values.

`ProbeExecutor` is the only module permitted to send deterministic target
probes. It uses bounded timeouts, response sizes, redirects, retries, rate, and
concurrency.
The normal read comparison reports one of `protected`, `bola`, `inconclusive`,
or `skipped`. Mutation mode is a separate opt-in path and never retries the
mutation automatically.

`reporting.py` renders deterministic JSON, JUnit XML, Markdown, and SARIF. A
report with zero findings is not proof that a target was safe: untested and
inconclusive combinations remain visible in the summary and limitations.

## Read-only CLI

Create a confirmed scope file first, then provide one sanitized structural
records JSON file per identity when automatic ownership evidence is intended.
A sanitized HAR is accepted for discovery, but HAR response bodies are removed
by design and therefore commonly produce zero executable tests. Provide an
environment variable reference for each credential; the command never accepts
a token value and does not enable mutation probes. Before running, load
`BOLA_ALICE_TOKEN` and `BOLA_BOB_TOKEN` into the environment from your approved
secret manager; the exact command depends on that secret manager:

```bash
mkdir -p ./state
uv run bolacheck scan \
  --scope ./scope.yaml \
  --base-url https://staging.example.test \
  --identity alice=./alice.json \
  --identity bob=./bob.json \
  --credential alice=BOLA_ALICE_TOKEN \
  --credential bob=BOLA_BOB_TOKEN \
  --db ./state/engagement.db \
  --report-dir ./reports/engagement
```

Use `--json` for one machine-readable summary line. The summary includes
skipped-candidate counts and reasons; unsupported query/body/GraphQL or
multi-identifier routes are never sent to the path-only executor. Every request and
redirect is still checked by `ScopeGuard`; an out-of-scope target or invalid
scope exits non-zero before network traffic is sent. Start each scan with a
new state database path and report directory; historical findings are never
mixed into a fresh run. A report directory is published atomically and must
not already exist.

For a local, external-network-free proof against both a deliberately
vulnerable and a protected endpoint, run:

```bash
uv run pytest tests/test_e2e.py -q
```

The mock binds only to `127.0.0.1` on an ephemeral port. It is a fixture, not
an authorization bypass or a substitute for an approved target.

## Optional AI and MCP

The AI adapter receives a bounded, redacted structural context and must return
strict JSON matching the `TestPlan`/`TestSuggestion` models. Suggestions are
validated against the observed context and are not executable requests. The
Codex CLI adapter is intentionally disabled because a general agent cannot meet
this boundary. The optional LiteLLM adapter may contact the model provider
configured by the operator, but it cannot contact the assessed target or
execute a proposed request.

`mcp_server.py` exposes the service through an optional local stdio FastMCP
adapter. Its tool arguments accept paths, identities, and environment-variable
names, never secret values. The service requires a successfully loaded scope
and initialized state before planning or running work. FastMCP is imported only
when `create_mcp_server()` is called.

## Architecture

```text
confirmed scope
      |
capture / sanitized HAR import
      |
secret-safe extraction + in-memory credential vault
      |
SQLite append-only audit state
      |
evidence-based endpoint ownership
      |                         optional typed AI suggestions
      +----------------------<-----------------------------+
      |
deterministic, scope-enforced probes
      |
JSON / JUnit / Markdown / SARIF reports
```

The phase responsibilities and contracts are described in
[docs/architecture.md](docs/architecture.md). Implementation evidence and
known follow-up work live under [docs/implementation](docs/implementation/).

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull
request. Security-sensitive reports must follow [SECURITY.md](SECURITY.md), not
the public issue tracker.

## Disclaimer

BOLACheck is a testing aid, not a guarantee of authorization correctness or
the absence of vulnerabilities. You are responsible for obtaining permission,
choosing a safe test environment, protecting captured material, and reviewing
every mutation grant before execution.
