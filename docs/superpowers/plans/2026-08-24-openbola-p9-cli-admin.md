# OpenBOLA P9: CLI Administration and Safe Maintenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the distributable OpenBOLA administration surface—`setup`, `doctor`, `report RUN`, `update`, `mcp`, and `--version`—with typed services, deterministic output, explicit update confirmation, and no secret or target-network escape from the existing safety boundaries.

**Architecture:** Keep Typer handlers thin and put all side effects behind small, dependency-injected services. Setup owns the pinned Playwright browser and OS-vault self-test; doctor aggregates local diagnostics and the P6 recovery gate; report reopens already-persisted sanitized artifacts without rerunning a target; update talks only to the allowlisted GitHub release endpoints and replaces the executable only after checksum verification and an explicit confirmation; the MCP command starts the existing renamed server in read-only mode.

**Tech Stack:** Python 3.11+, Typer/Rich, existing `httpx`, Playwright's optional Python package, `hashlib`/`tempfile`/`os`/`pathlib`, P6 `RecoveryGate`/vault protocol, P7 typed reporting, and the existing `MCPService`/FastMCP optional extra. No new runtime dependency or lockfile change is required by P9.

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (§1, §3, §4, §8, §11, §13 acceptance criterion 2) and `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` (P9).

## Global Constraints

- The existing `ScopeGuard`/`ProbeExecutor` remain the only target-network boundary; setup, doctor, report, update, and MCP administration never send a request to an assessment target.
- `openbola setup` is an explicit operator action. It may download the exact Playwright-pinned browser and initialize the approved OS credential vault, but it never accepts, prints, persists, or forwards a credential value.
- `openbola doctor` is diagnostic and read-only with respect to targets and recovery material. It reports bounded status codes, not exception text, paths containing user data, or secret values.
- `openbola report RUN` only reads an existing sanitized report/run manifest and never reconstructs raw request/response material or reruns probes. A missing, stale, malformed, or non-sanitized artifact fails closed.
- `openbola update` checks at most once per 24 hours unless `--force-check` is explicitly supplied, accepts only `https://api.github.com/repos/LeonardSEO/openbola/...` and `https://github.com/LeonardSEO/openbola/...` URLs, validates every redirect target, verifies `SHA256SUMS` before replacing anything, and requires `--yes` (or an interactive confirmation) for replacement. There is no automatic update or telemetry.
- Update replacement is atomic, keeps the current executable until the new file is verified, preserves executable mode, and never executes downloaded bytes during the command. A failed check/download/verification leaves the installed file untouched.
- The local MCP command uses the renamed server name `openbola`; its exposed execution mode is read-only and mutation probes are not registered or accepted. FastMCP remains optional and is imported lazily.
- Every JSON mode emits a bounded allowlist with stable error codes. Rich output may include friendly local labels but never credentials, cookies, raw object IDs, response bodies, release tokens, or full filesystem paths.
- Preserve `openbola scan` flags and the P8 default TUI/no-argument behavior. Do not modify the P11 repository, release, rename, topics, or external-publication gate.
- Add tests before implementation for success, denied, malformed, offline, symlink/path, checksum, redirect, recovery-blocked, and secret-sentinel cases. Before declaring P9 complete run `uv run ruff check .`, `uv run mypy src`, and `uv run pytest`.

## File Structure and Contracts

- `src/openbola/cli.py` — Typer command registration, `--version`, thin adapters for typed service results, exit-code mapping, and existing `scan` compatibility.
- `src/openbola/setup.py` — bounded Playwright install/self-test and P6 OS-vault initialization protocol; no target client.
- `src/openbola/doctor.py` — local diagnostic checks and safe serialization of `DiagnosticReport`.
- `src/openbola/updates.py` — GitHub release metadata client, platform artifact selection, checksum verification, cache policy, and atomic executable replacement.
- `src/openbola/reports.py` — read-only run/report locator and safe artifact loading for `report RUN`; it consumes P7 reporting contracts and does not render raw state.
- `src/openbola/mcp_server.py` — add an explicit read-only server factory/registration path while retaining the existing service API and optional FastMCP import.
- `src/openbola/state.py` and `src/openbola/pipeline.py` — write/read a bounded run manifest containing only the numeric run id, relative report artifact names, schema id, and creation timestamp; no raw IDs, URLs, credentials, or body values.
- `tests/test_cli.py` — command dispatch, version, exit codes, JSON safety, and scan regression tests.
- `tests/test_setup.py` — fake Playwright runner/vault and local self-test outcomes.
- `tests/test_doctor.py` — platform/path/browser/vault/recovery diagnostics and secret-free output.
- `tests/test_updates.py` — release parsing, allowlisted redirects, cache, checksum, atomic replacement, and refusal paths using an injected transport/filesystem.
- `tests/test_report_command.py` — run lookup, sanitized artifact reopen, malformed/stale rejection, and no-network/no-secret proof.
- `tests/test_mcp_server.py` — read-only tool registration and refusal of mutation/non-read modes.

The services use these concrete contracts:

```python
@dataclass(frozen=True)
class CommandResult:
    ok: bool
    code: str
    details: Mapping[str, str | int | bool]

@dataclass(frozen=True)
class SetupResult:
    browser: Literal["installed", "already_ready", "unavailable"]
    vault: Literal["ready", "unavailable"]
    self_test: Literal["passed", "failed"]

@dataclass(frozen=True)
class Diagnostic:
    name: str
    status: Literal["ok", "warning", "blocked"]
    code: str

@dataclass(frozen=True)
class DiagnosticReport:
    diagnostics: tuple[Diagnostic, ...]
    recovery_state: Literal["clear", "required", "escalated", "blocked"]

@dataclass(frozen=True)
class ReleaseArtifact:
    version: str
    platform: Literal["windows-x64", "macos-arm64", "macos-x64"]
    download_url: str
    sha256: str
    size: int

@dataclass(frozen=True)
class UpdateResult:
    status: Literal["current", "available", "updated", "denied", "unavailable"]
    current_version: str
    candidate_version: str | None = None
    reason_code: str | None = None
```

## Task 1: Add typed command registration, version output, and shared safe errors

**Files:**

- Modify: `src/openbola/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**

- Consumes: existing `app`, `scan`, `PipelineError`, P8's no-argument TUI launcher, and `openbola.__version__`.
- Produces: stable `openbola --version`, subcommand registration hooks, and a single bounded JSON/Rich error mapper used by Tasks 2–6.

- [ ] **Step 1: Write failing dispatch/version tests.**

  Add tests using `CliRunner` that assert `--version` prints only the package version; `setup`, `doctor`, `report`, `update`, and `mcp` appear in help; invalid command arguments produce a stable non-secret error code; existing `scan --json` output and exit code remain unchanged; and a monkeypatched P8 launcher is called for an empty invocation. Include a secret sentinel in an injected service exception and assert it never appears in either output mode.

- [ ] **Step 2: Run focused tests to verify they fail.**

  `uv run pytest tests/test_cli.py -k 'version or dispatch or help or error' -v`

- [ ] **Step 3: Implement the thin command boundary.**

  Register the command groups without importing optional Playwright/FastMCP modules at CLI import time. Add `--version` through Typer's callback/version support, preserve the existing scan options, and route service exceptions to exit code `2` with `setup_unavailable`, `diagnostics_blocked`, `report_denied`, `update_denied`, or `mcp_unavailable`. JSON mode must serialize only `CommandResult.details`; Rich mode must use generic messages. Keep all path/argument validation in the owning service.

- [ ] **Step 4: Run focused tests to verify they pass.**

  `uv run pytest tests/test_cli.py -k 'version or dispatch or help or error' -v`

- [ ] **Step 5: Commit.**

  `git add src/openbola/cli.py tests/test_cli.py && git commit -m "feat: register OpenBOLA administration commands"`

## Task 2: Implement setup with Playwright browser install and vault self-test

**Files:**

- Create: `src/openbola/setup.py`
- Modify: `src/openbola/cli.py`
- Test: `tests/test_setup.py`, `tests/test_cli.py`

**Interfaces:**

- Consumes: `data_root()`, P6's `RecoveryKeyStore`/vault adapter, the installed Playwright package, and an injected bounded subprocess/callable for tests.
- Produces: `run_setup(*, force_browser: bool = False, installer: BrowserInstaller | None = None, vault: RecoveryKeyStore | None = None) -> SetupResult` and `openbola setup [--json] [--force-browser]`.

- [ ] **Step 1: Write failing setup tests.**

  Use fakes to prove: a ready browser is reported without a second install; an explicit force installs exactly the pinned browser; a missing Playwright extra returns `browser_unavailable`; the vault key can be created/read through the OS-vault protocol but is never returned; `about:blank` self-test performs no network request; installer/vault failure leaves a generic failure code and no partial marker; and browser/vault output never contains `PLAYWRIGHT_SECRET`, a key, or a user home path. Test the command's JSON and Rich modes.

- [ ] **Step 2: Run focused tests to verify they fail.**

  `uv run pytest tests/test_setup.py -v`

- [ ] **Step 3: Implement the setup service.**

  Resolve the platform data root without creating it until after validation, create only private directories, and call Playwright through an argument-vector callable (`python -m playwright install chromium`) with bounded captured output and no shell. Read the browser version from the installed Playwright package/lockfile rather than allowing a user-supplied version. Initialize the P6 vault via its typed key provider and run a local browser launch/open/close self-test against `about:blank`; do not resolve or print any credential. Write a small version/status marker atomically only after all checks pass, with restrictive permissions. Convert dependency, subprocess, and OS errors to the typed result codes.

- [ ] **Step 4: Run focused tests and the existing capture import test.**

  `uv run pytest tests/test_setup.py tests/test_capture.py -k 'playwright or setup or lazy' -v`

- [ ] **Step 5: Commit.**

  `git add src/openbola/setup.py src/openbola/cli.py tests/test_setup.py tests/test_cli.py && git commit -m "feat: add explicit browser and vault setup"`

## Task 3: Implement local doctor and recovery diagnostics

**Files:**

- Create: `src/openbola/doctor.py`
- Modify: `src/openbola/cli.py`
- Test: `tests/test_doctor.py`, `tests/test_cli.py`

**Interfaces:**

- Consumes: `data_root()`, package metadata/version, P6 `RecoveryGate`, setup status marker, `StateStore` safety checks, and injected platform/browser/vault probes.
- Produces: `run_doctor(*, db_path: Path | None = None, json_output: bool = False) -> DiagnosticReport` and `openbola doctor [--db PATH] [--json]`.

- [ ] **Step 1: Write failing diagnostics tests.**

  Cover supported macOS/Windows platform values, missing `LOCALAPPDATA`, private and symlink-free data root, package/version presence, Playwright import and browser readiness, vault readiness, state DB schema/readability, and every P6 recovery state (`clear`, `required`, `escalated`, `blocked`). Assert the report is deterministic, bounded, and contains no raw home paths, journal bytes, exception details, secrets, or object IDs. A blocked recovery state must produce a nonzero command exit while still allowing read-only diagnostics.

- [ ] **Step 2: Run focused tests to verify they fail.**

  `uv run pytest tests/test_doctor.py -v`

- [ ] **Step 3: Implement diagnostics and serialization.**

  Make each check return one of the explicit `Diagnostic` codes and never raise caller-visible exceptions. Use `RecoveryGate.status()` without attempting recovery or escalation. Check the data-root directory/file mode and symlink status using the same trust rules as `StateStore`; report only `data_root_ready`, not its absolute path. Sort diagnostics by name, expose only allowlisted fields in JSON, and map any `blocked` diagnostic to exit code `2`.

- [ ] **Step 4: Run focused tests and state/path regressions.**

  `uv run pytest tests/test_doctor.py tests/test_paths.py tests/test_state.py -k 'doctor or path or schema or recovery' -v`

- [ ] **Step 5: Commit.**

  `git add src/openbola/doctor.py src/openbola/cli.py tests/test_doctor.py tests/test_cli.py && git commit -m "feat: add safe local doctor diagnostics"`

## Task 4: Reopen sanitized report runs without rerunning targets

**Files:**

- Create: `src/openbola/reports.py`
- Modify: `src/openbola/reporting.py`, `src/openbola/state.py`, `src/openbola/pipeline.py`, `src/openbola/cli.py` only where the existing run metadata cannot locate a published report.
- Test: `tests/test_report_command.py`, `tests/test_cli.py`

**Interfaces:**

- Consumes: P7 `openbola-report-v1` artifacts, the append-only `StateStore`, and a numeric run id or an explicit report-directory path.
- Produces: `ReportLocator.resolve(run_ref: str, *, db_path: Path, data_root: Path) -> Path`, `load_published_report(path: Path) -> Mapping[str, object]`, and `openbola report RUN [--json] [--format FORMAT]`.

- [ ] **Step 1: Write failing report-command tests.**

  Generate a safe report bundle in a temporary run directory and assert that `report 7` (using a run manifest) and `report PATH` reopen it without constructing a `ProbeExecutor`, contacting a target, or altering SQLite. Test all P7 formats (`json`, `html`, `junit`, `markdown`, `csv`, `sarif`) through an explicit `--format` allowlist. Reject missing run ids, path traversal, symlinked manifests/artifacts, wrong schema id, malformed JSON/XML/HTML, partial bundles, and artifacts containing `RAW_ID`, `TOKEN`, or `BODY` sentinels. Assert Rich output uses only sanitized report fields.

- [ ] **Step 2: Run focused tests to verify they fail.**

  `uv run pytest tests/test_report_command.py -v`

- [ ] **Step 3: Implement the read-only locator and manifest.**

  Store only a bounded numeric run id, relative artifact names, schema id, and creation timestamp in a private atomic manifest after `write_reports` succeeds; if an older run lacks a manifest, return `run_not_found` rather than guessing. Resolve numeric runs beneath the trusted data root and path runs beneath the caller-approved report root, reject absolute paths, `..`, symlinks, unexpected files, and non-private parents. Validate `openbola-report-v1` and pass report content through P7's safe parser/renderer; never load HAR, session registry, credential vault, or executor state. `--json` returns summary counts and artifact metadata only.

- [ ] **Step 4: Run focused tests and reporting regressions.**

  `uv run pytest tests/test_report_command.py tests/test_reporting.py tests/test_e2e.py -k 'report or artifact or schema' -v`

- [ ] **Step 5: Commit.**

  `git add src/openbola/reports.py src/openbola/reporting.py src/openbola/state.py src/openbola/pipeline.py src/openbola/cli.py tests/test_report_command.py tests/test_cli.py && git commit -m "feat: reopen sanitized OpenBOLA report runs"`

## Task 5: Add verified, explicitly confirmed GitHub release updates

**Files:**

- Create: `src/openbola/updates.py`
- Modify: `src/openbola/cli.py`
- Test: `tests/test_updates.py`, `tests/test_cli.py`

**Interfaces:**

- Consumes: `__version__`, `data_root()`, the current executable path, injected `httpx` transport/filesystem/confirmation functions, and P10's release asset names/`SHA256SUMS` contract.
- Produces: `check_for_update(force_check: bool = False) -> UpdateResult`, `apply_update(*, confirm: bool = False) -> UpdateResult`, and `openbola update [--json] [--check] [--yes] [--force-check]`.

- [ ] **Step 1: Write failing update tests.**

  Use a fake transport and temporary executable to prove current-version/no-op, newer-version available, 24-hour cache suppression and `--force-check`, unsupported platform, malformed release JSON/duplicate keys, non-GitHub URLs, every redirect variant, oversized download, missing/mismatched `SHA256SUMS`, digest mismatch, permission failure, declined confirmation, and successful atomic replacement. Assert the old executable remains byte-for-byte unchanged on every failure and that output contains no release response body, local secret, or token.

- [ ] **Step 2: Run focused tests to verify they fail.**

  `uv run pytest tests/test_updates.py -v`

- [ ] **Step 3: Implement the release client and replacement transaction.**

  Fetch only the latest-release JSON from the fixed GitHub API origin with a strict byte cap, timeout, user agent, and redirects disabled; validate exact JSON keys, tag semver, and asset names. Select the native P10 artifact (`windows-x64`, `macos-arm64`, or `macos-x64`), fetch `SHA256SUMS` from the same release, parse exactly one matching line, then stream the artifact through a bounded temporary file while hashing. Require the digest and expected size to match before asking for confirmation. With `--yes` or an affirmative TTY prompt, fsync the new executable, preserve mode, atomically replace it, fsync the parent, and write a sanitized cache record. Never run the downloaded file, send credentials, follow a redirect, or silently retry a replacement.

- [ ] **Step 4: Run focused tests and CLI safety checks.**

  `uv run pytest tests/test_updates.py tests/test_cli.py -k 'update or checksum or redirect' -v`

- [ ] **Step 5: Commit.**

  `git add src/openbola/updates.py src/openbola/cli.py tests/test_updates.py tests/test_cli.py && git commit -m "feat: add checksum-verified explicit updates"`

## Task 6: Expose the renamed local read-only MCP command

**Files:**

- Modify: `src/openbola/mcp_server.py`, `src/openbola/cli.py`
- Test: `tests/test_mcp_server.py`, `tests/test_cli.py`

**Interfaces:**

- Consumes: existing `MCPService`, `create_mcp_server`, optional FastMCP import, and P1's server name `openbola`.
- Produces: `create_mcp_server(..., read_only: bool = False)` and `openbola mcp [--json]` that starts the local stdio server only after the optional dependency is present.

- [ ] **Step 1: Write failing MCP command tests.**

  Inject a fake FastMCP and assert the read-only server name is exactly `openbola`, registered tools exclude mutation/write modes, `run_pending_tests` accepts only `mode="read"`, and no default executor can be constructed by the command. Assert import failure returns `mcp_unavailable` without a traceback and that registration/output never contains credential values, raw object IDs, or body sentinels. Preserve all existing service-level tests and the normal factory's compatibility.

- [ ] **Step 2: Run focused tests to verify they fail.**

  `uv run pytest tests/test_mcp_server.py tests/test_cli.py -k 'mcp or read_only' -v`

- [ ] **Step 3: Implement the explicit read-only registration path.**

  Add a `read_only` factory parameter or a separate `create_read_only_mcp_server` that registers the existing scope/import/planning/report tools and the read-only pending-test handler, but does not register mutation/recovery/update tools or accept a caller-supplied executor. Keep FastMCP lazy, call `.run(transport="stdio")` only from the CLI command, and translate import/transport exceptions to bounded local error codes. The service's existing repeated scope check and origin binding remain authoritative.

- [ ] **Step 4: Run focused tests and optional-extra import checks.**

  `uv run pytest tests/test_mcp_server.py tests/test_cli.py -k 'mcp or read_only' -v`

- [ ] **Step 5: Commit.**

  `git add src/openbola/mcp_server.py src/openbola/cli.py tests/test_mcp_server.py tests/test_cli.py && git commit -m "feat: expose local read-only MCP command"`

## Task 7: P9 acceptance boundary, documentation, and roadmap marker

**Files:**

- Create or extend: `tests/test_p9_boundary.py`
- Modify: `README.md` and `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` only after implementation/review passes

**Interfaces:**

- Consumes: all P9 command services, P6 recovery state, P7 report artifacts, P8 no-argument TUI launcher, and P10 asset naming.
- Produces: one deterministic local acceptance proof and a roadmap status marker with exact validation evidence.

- [ ] **Step 1: Add the boundary proof.**

  In a temporary private data root, run setup with fakes, doctor with a clear and a blocked recovery gate, create a sanitized report run and reopen it by numeric id, exercise update against a fake GitHub release with one declined and one confirmed replacement, and inspect the read-only MCP tool list. Assert no target HTTP transport is touched, every command output is free of sentinels (`TOKEN`, `COOKIE`, `RAW_ID`, `BODY`, vault key), update refusal leaves the old executable unchanged, and a blocked recovery state prevents assessment entry without preventing diagnostics/report reads.

- [ ] **Step 2: Run the complete P9-focused suite.**

  `uv run pytest tests/test_cli.py tests/test_setup.py tests/test_doctor.py tests/test_report_command.py tests/test_updates.py tests/test_mcp_server.py tests/test_p9_boundary.py -v`

- [ ] **Step 3: Run the mandatory repository checks.**

  ```bash
  uv run ruff check .
  uv run mypy src
  uv run pytest
  ```

  Fix only failures caused by P9. Keep any pre-existing failures explicit in the handoff and do not weaken scope, recovery, checksum, or read-only MCP tests.

- [ ] **Step 4: Update user-facing command documentation.**

  Add concise English examples for `openbola setup`, `doctor`, `report RUN`, `update --check`, `update --yes`, `mcp`, and `--version` to the existing README/quickstart. Document that setup downloads the pinned browser, update requires explicit confirmation and checksums, report is read-only, MCP is local/read-only, and P9 does not claim Windows artifact execution from this macOS checkout.

- [ ] **Step 5: Mark P9 complete and commit the acceptance proof.**

  Update only the P9 status paragraph in `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` with the merge date and exact focused/full validation commands. Preserve unrelated working-tree edits and the P11 external-publication approval gate.

  `git add tests/test_p9_boundary.py README.md docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md && git commit -m "test: close P9 CLI administration boundary"`

## Self-review checklist

- `openbola --version` and all new subcommands are discoverable without importing optional dependencies or changing `scan` behavior.
- Setup installs only the pinned Playwright browser, initializes the approved vault, runs a local `about:blank` self-test, and writes a marker only after success.
- Doctor diagnoses platform, path, browser, vault, state, and recovery conditions with stable non-secret codes and never attempts recovery or target traffic.
- Report reopens only a complete `openbola-report-v1` artifact through a trusted run manifest; it cannot trigger a probe or expose raw session values.
- Update uses fixed GitHub origins, strict redirects/size/JSON/semver checks, exact `SHA256SUMS`, atomic replacement, and explicit confirmation; all failure paths preserve the old executable.
- MCP's CLI path is local stdio and read-only; mutation execution is not registered, and existing repeated scope/origin checks remain intact.
- No new runtime dependency or lockfile change is hidden in P9, and P11 publication/repository actions remain approval-gated.
- The final handoff distinguishes local static/CLI proof from the platform artifact proof owned by P10.
