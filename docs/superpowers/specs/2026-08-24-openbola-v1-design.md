# OpenBOLA v1 Product Design

**Status:** Approved in product-design dialogue on 2026-08-24  
**Product name:** OpenBOLA  
**Repository target:** `LeonardSEO/openbola`  
**Primary command:** `openbola`  
**Product language:** English

## 1. Product definition

OpenBOLA is an open-source, local-first terminal application for proving Broken
Object Level Authorization (BOLA/IDOR) in authorized web and API assessments.
It starts with a URL, guides an operator through scope and identity setup,
automates authenticated Playwright sessions, inventories exposed resources,
uses an optional AI provider to prioritize typed tests, and lets only a
deterministic policy-enforced executor send target requests.

The v1 experience must feel like an installed program rather than a collection
of Python utilities:

- `openbola` opens a full-screen interactive terminal application.
- Standalone Windows and macOS builds require no system Python.
- First-run setup installs the pinned browser and initializes the OS credential
  vault.
- Findings show resources, records, fields, affected identities, proven read
  and write capabilities, reproduction steps, and cleanup status.
- Headless subcommands remain available for CI and advanced users.

## 2. Goals and non-goals

### Goals

1. Install and start on Windows x64, macOS arm64, and macOS x64 without a
   separately installed Python runtime.
2. Make the default interaction an accessible Textual TUI launched by
   `openbola`.
3. Begin every assessment with URL and authorization confirmation, then capture
   two or more identities through automated Playwright login recipes.
4. Perform a read-only discovery phase before any write-capable test.
5. Display full response data only in the active local TUI while persisting
   secret-safe, opaque audit evidence.
6. Identify generic API resources and add confirmed or inferred provider
   context for Supabase/PostgREST, Firebase, and Hasura.
7. Test every discovered record authorized by an explicit all-record mutation
   grant, with immediate verification, restore, and restore verification.
8. Provide BYOK AI support for OpenAI-compatible endpoints and Azure OpenAI
   without exposing credentials or raw record identifiers to the model.
9. Produce attractive, self-contained HTML findings in addition to JSON,
   Markdown, CSV, JUnit, and SARIF.
10. Relaunch publicly under the OpenBOLA name with a professional visual README
    and deterministic terminal demo.

### Non-goals

- No native desktop GUI or local report server in v1.
- No system-wide proxy, credential stuffing, unsolicited scanning, persistence,
  or denial-of-service behavior.
- No plaintext raw HAR, token, cookie, password, record identifier, original
  mutation value, or full response persistence.
- No arbitrary database-protocol scanning. A database/provider claim requires
  observed HTTP or GraphQL protocol evidence.
- No AI-generated target request is executed directly.
- No modification outside a confirmed scope and a separate mutation grant.
- No primary DELETE against pre-existing records. DELETE is permitted only for
  OpenBOLA-created canary records.
- No automatic update installation, telemetry, Linux standalone build, or OS
  code signing in v1.

## 3. Application architecture

The existing authorization-first engine remains the core. A new Textual shell
orchestrates it but does not own network access.

```text
openbola CLI / Textual TUI
        |
        +-- configuration + OS credential vault
        +-- assessment session + in-memory value registry
        +-- Playwright identity capture
        +-- generic and provider-specific discovery
        +-- sanitized AI context -> typed suggested plan
        |
        v
ScopeGuard -> deterministic ProbeExecutor -> append-only safe state
        |
        +-- in-session full-data findings
        +-- sanitized HTML/JSON/CSV/Markdown/JUnit/SARIF
```

Subsystem boundaries:

- **Application shell:** home, setup, assessment, capture, discovery, grant
  review, verification, findings, export, and recovery screens.
- **Session services:** configuration, platform paths, opaque handles,
  in-memory full-value registry, progress events, cancellation, and crash
  recovery.
- **Capture:** login recipes, isolated Playwright contexts, sanitized persistent
  traffic, and memory-only replay material.
- **Discovery:** generic route/resource inventory plus provider adapters that
  produce normalized resource and capability contracts without sending
  requests themselves.
- **Planning:** deterministic candidate generation plus optional sanitized AI
  prioritization. AI output is validated against observed handles and scope.
- **Verification:** all target traffic, redirect handling, limits, mutation
  canaries, restore, and append-only outcomes.
- **Reporting:** in-session rich view and deterministic secret-safe exports.
- **Distribution:** PyInstaller builds, installers, setup/doctor/update, release
  manifests, checksums, and attestations.

## 4. Public command surface

```text
openbola                         # open the TUI
openbola scan [existing flags]   # headless assessment
openbola setup                   # browser + vault + local self-test
openbola doctor                  # platform and recovery diagnostics
openbola report RUN              # reopen sanitized persistent results
openbola mcp                     # local read-only stdio MCP adapter
openbola update                  # check, verify, confirm, replace
openbola --version
```

There is no `bolacheck` compatibility alias. The package, import root, console
script, report schema IDs, SARIF tool name, documentation, and repository are
renamed to `openbola`. Existing git history is preserved; rewriting historical
authors is outside this design.

## 5. Core contracts

### Opaque handles and session values

```python
@dataclass(frozen=True)
class SecretHandle:
    id: str
    purpose: str

@dataclass(frozen=True)
class ValueHandle:
    id: str
    kind: Literal["record_id", "field_value", "body", "session_state"]

class SessionValueRegistry(Protocol):
    def resolve_secret(self, handle: SecretHandle) -> str: ...
    def resolve_value(self, handle: ValueHandle) -> object: ...
```

Handles use random, non-semantic identifiers. Persistent state, reports, and AI
context may contain handles or one-way fingerprints, never resolved values.
Only the active process resolves a handle immediately before a policy-approved
operation.

### Login recipes

```python
@dataclass(frozen=True)
class LoginRecipe:
    name: str
    start_url: str
    username_selector: str
    password_selector: str
    submit_selector: str
    success_url_pattern: str
    username_secret: SecretHandle
    password_secret: SecretHandle
    extra_secret_fields: tuple[LoginSecretField, ...] = ()
```

Recipes persist selectors, URL patterns, and secret handles. Secret values live
in macOS Keychain or Windows Credential Manager. CAPTCHA and WebAuthn pause the
recipe for operator completion; ordinary username/password and optional TOTP
fields may be automated when their values are stored in the OS vault.

### Resource and provider inventory

```python
class ProviderConfidence(StrEnum):
    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class ResourceInventory:
    provider: str
    provider_confidence: ProviderConfidence
    resource_name: str
    endpoint_template: str
    fields: tuple[FieldInventory, ...]
    record_handles: tuple[ValueHandle, ...]
    observed_methods: frozenset[str]

class ProviderAdapter(Protocol):
    name: str
    def detect(self, records: Sequence[RequestRecord]) -> ProviderDetection: ...
    def inventory(self, records: Sequence[RequestRecord]) -> tuple[ResourceInventory, ...]: ...
```

Adapters consume already captured evidence and produce normalized contracts.
They do not own an HTTP client. Supabase/PostgREST, Firebase, and Hasura are the
required v1 adapters; generic HTTP/OpenAPI/GraphQL discovery is always present.

### AI provider and typed plan

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
class ProposedTest:
    endpoint_handle: str
    owner_identity_handle: str
    attacker_identity_handle: str
    record_handle: str
    method: str
    field_handles: tuple[str, ...]
    rationale: str
```

DeepSeek, OpenRouter, OrcaRouter, Kimi-compatible services, and other compatible
providers use the `openai_compatible` contract with a custom base URL and model.
Azure OpenAI has a distinct deployment/api-version configuration. Provider
keys remain in the OS vault. The model sees sanitized schemas, statuses,
provider hints, and handles; it never sees resolved credentials, record IDs, or
full response values. A validator intersects every proposed handle, method,
field, and path with observed inventory and the confirmed scope.

## 6. Scope and all-record mutation grants

The scope YAML remains fail-closed and rejects unknown keys. Mutation grants
gain explicit field, record, and budget constraints:

```yaml
mutation_grants:
  - methods: [POST, PUT, PATCH, DELETE]
    path_patterns:
      - "glob:/api/users/*"
    allowed_fields: ["username", "email"]
    record_scope: "all_discovered"
    max_records: 10000
    max_requests: 100000
    allow_canary_create_delete: true
```

The corresponding immutable contract is:

```python
class MutationRecordScope(StrEnum):
    EXPLICIT = "explicit"
    ALL_DISCOVERED = "all_discovered"

@dataclass(frozen=True)
class MutationGrant:
    methods: frozenset[str]
    path_rules: tuple[PathRule, ...]
    allowed_fields: frozenset[str]
    record_scope: MutationRecordScope
    max_records: int
    max_requests: int
    allow_canary_create_delete: bool
```

The TUI must show the discovered record count and calculated request budget
before confirmation. It may automatically verify every discovered record only
when the grant is `all_discovered`, the concrete method/path/field matches, and
both limits cover the calculated work. There is no silent sample or truncation.
The existing global executor hard limit of 100,000 requests remains.

For each existing record, OpenBOLA may test GET/HEAD/OPTIONS and reversible
PATCH/PUT fields allowed by the grant. It snapshots the original field value,
sends the canary change, verifies it through the unauthorized identity,
restores the original, and verifies restoration before advancing. POST/DELETE
may test lifecycle authorization only on a canary record created during the
same test. The first unverified cleanup stops all further writes.

## 7. Assessment flow

1. **Home:** choose New Assessment, Resume Sanitized Run, Recovery, Setup,
   Doctor, or Update.
2. **Target:** enter URL; normalize origin; create or select a time-bounded
   authorization scope; confirm authorization reference.
3. **Identity setup:** create at least two identities; choose or record a login
   recipe; store values in the OS vault.
4. **Automated capture:** run one isolated Playwright context per identity;
   enforce scope on navigation and every captured/replayed request; keep full
   session material in memory and persist only sanitized traffic.
5. **Read-only discovery:** detect specs, routes, GraphQL, providers, resources,
   records, fields, ownership, and read-access differences.
6. **AI planning:** optionally send a previewed sanitized context to the chosen
   BYOK provider; validate returned typed suggestions.
7. **Grant review:** show methods, paths, fields, record count, request count,
   duration estimate, and cleanup policy; bind confirmation to the immutable
   scope file.
8. **Verification:** execute every authorized target, stream progress, support
   safe cancellation, and append outcomes.
9. **Findings:** browse resource matrix and finding detail with full in-memory
   values, request/response comparisons, reproduce action, and cleanup state.
10. **Export:** write only sanitized deterministic artifacts. Full values are
    destroyed when the process exits.

## 8. Storage, privacy, and crash recovery

Platform data roots:

- macOS: `~/Library/Application Support/OpenBOLA/`
- Windows: `%LOCALAPPDATA%\OpenBOLA\`

Persistent sanitized data includes configuration without secrets, login
recipes with handles, scope files, opaque SQLite audit state, reports, update
metadata, and diagnostics. Full responses, replay bodies, raw IDs, session
cookies, and original field values stay in memory.

A mutation is the sole persistence exception. Before sending it, OpenBOLA
writes an AES-GCM encrypted recovery journal containing only the minimum exact
request and original value needed for restore. The encryption key is held by
the OS vault. After verified restoration, the journal is atomically replaced
with an empty state and removed. OpenBOLA makes no secure-erasure claim for
SSD/filesystem remnants. If a journal exists on startup, all new assessments
are blocked until recovery succeeds or the operator records a manual escalation.
Recovery never bypasses an expired or changed scope.

## 9. Findings and reports

The local TUI resource matrix contains:

- provider and confidence;
- dataset/resource and endpoint;
- total discovered records;
- field names and types;
- owner/attacker identity matrix;
- proven READ, POST, PATCH, PUT, and DELETE capabilities;
- cleanup and coverage state.

Finding detail includes severity, confidence, impacted identities, full local
field values, owner/attacker status and body comparison, exact in-session
reproduce action, remediation, and restore verification. Existing generic
`Mapping[str, Any]` report evidence is replaced at the report boundary by
typed, allowlisted `FindingEvidence` and `CapabilityProof` contracts.

Exports:

- `report.html`: self-contained, CSP-compatible, no remote assets, filterable
  tables and finding detail;
- `report.csv`: sanitized resource/capability matrix;
- `report.json`: `openbola-report-v1` typed document;
- `report.md`: human-readable assessment;
- `junit.xml`: CI failure mapping;
- `report.sarif`: GitHub code-scanning integration.

Exports contain sanitized examples and reproduction templates using opaque
variables such as `${bob.credential}` and `${alice.record_id}`. They never
claim an opaque handle can be replayed after the session. Later reproduction
requires a fresh discovery run.

## 10. TUI and visual design

The approved visual language uses:

- warm cream `#F7F4ED` backgrounds for README/report assets;
- ink `#1B2230`, navy `#1D436E`, muted `#697386`, and terminal panel
  `#0A0E13`;
- subtle technical grids, editorial serif display headings, restrained badges,
  black terminal panels, and soft shadows;
- separate compositions for the GitHub README banner, actual terminal UI, and
  findings presentation; no copied website navigation or sales-page layout.

The TUI must work at 80x24, provide clear keyboard focus, support reduced color,
avoid color-only status, and expose loading, empty, denied, error, recovery,
cancelled, and success states. The English copy must describe proof precisely
and avoid claims that zero findings means safety.

## 11. Distribution and updates

Required GitHub Release artifacts:

- `openbola-VERSION-windows-x64.zip`
- `openbola-VERSION-macos-arm64.tar.gz`
- `openbola-VERSION-macos-x64.tar.gz`
- `SHA256SUMS`

PyInstaller builds natively on each platform and includes the Python runtime,
Textual, OpenBOLA, Playwright's Python package, and required libraries. Chromium
is not embedded; `openbola setup` downloads the exact Playwright-pinned build.

`install.sh` installs to `~/.local/bin` and asks before editing shell PATH.
`install.ps1` installs to `%LOCALAPPDATA%\OpenBOLA\bin` and asks before changing
the user PATH. Builds are intentionally not Apple-notarized or Authenticode-
signed in v1, so documentation must disclose Gatekeeper/SmartScreen warnings.
Checksums and GitHub artifact attestations are mandatory.

The application checks at most once every 24 hours for a GitHub Release,
displays version and provenance, and updates only after explicit confirmation.
`openbola update` performs the same process on demand. There is no telemetry.

## 12. GitHub launch

After the pending personal-account repository transfer is accepted, rename the
repository to `LeonardSEO/openbola`, update local remotes, topics, security
reporting URL, and release metadata. Do not publish, transfer, rename, release,
or rewrite history without the relevant explicit external-action approval at
execution time.

The README is English and includes the approved SVG hero, status/platform/
license badges, one-line installs, deterministic TUI demo, sanitized finding
example, provider support, architecture/safety boundary, quickstart, headless
CI use, roadmap, contribution guide, and private disclosure link. A matching
social-preview image uses the same style without copying the reference site's
layout or assets.

## 13. Acceptance criteria

OpenBOLA v1 is complete only when:

1. A clean Windows x64, macOS arm64, and macOS x64 user can install and launch
   `openbola` without system Python.
2. `openbola setup` installs the pinned browser and passes its local self-test.
3. The bundled local demo completes automated two-identity login, read-only
   discovery, confirmed BOLA read, authorized PATCH, restore, and verified
   cleanup without external target access.
4. Supabase/PostgREST, Firebase, Hasura, and generic adapters pass deterministic
   fixture contracts.
5. The AI test proves provider payloads contain handles and sanitized context
   but no credentials, cookies, raw IDs, or full field values.
6. All discovered records inside an all-record grant are tested or the run
   fails explicitly before mutation; no silent sampling occurs.
7. A simulated crash after mutation blocks startup, recovery restores the
   original value, and the encrypted journal is removed.
8. Full values are visible during the active TUI session and absent from every
   persisted artifact afterward.
9. HTML, CSV, JSON, Markdown, JUnit, and SARIF outputs are deterministic,
   escaped, atomic, secret-safe, and honest about coverage.
10. All renamed legacy tests plus new TUI, capture, adapter, mutation, installer,
    report, and platform tests pass with Ruff and strict mypy.

