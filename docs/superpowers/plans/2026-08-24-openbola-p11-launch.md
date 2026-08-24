# OpenBOLA v1 visual design and GitHub launch materials Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a polished, deterministic, safety-accurate OpenBOLA launch surface locally—README, visual assets, demo transcript, and a reviewable GitHub launch checklist—without publishing, renaming, transferring, releasing, or changing repository metadata until the user grants each external action separately.

**Architecture:** Keep launch content as static, repository-owned artifacts. SVG files are the canonical visual sources; a local renderer may produce a PNG social-preview derivative without contacting a remote service. The README consumes only checked-in assets and the public contracts delivered by P7–P10 (typed reports, TUI, CLI, installers, and release artifacts), while a separate checklist records external GitHub mutations as approval-gated operations rather than silently performing them.

**Tech Stack:** Markdown, self-contained SVG, Python 3.11 standard library for deterministic checks, the existing OpenBOLA CLI/TUI, local mock-target fixtures, and Playwright only when already installed by the capture/all development extra for local screenshot rendering.

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (sections 10–13)

## Global Constraints

- Use the visual language exactly: warm cream `#F7F4ED`, ink `#1B2230`, navy `#1D436E`, muted `#697386`, terminal panel `#0A0E13`; use subtle grids, serif display headings, restrained badges, and soft shadows.
- README copy is English, describes proof precisely, and never claims that zero findings means safety; it must repeat the authorization, scope, redirect, credential, mutation, AI, and no-telemetry boundaries.
- All examples, screenshots, transcripts, and URLs are synthetic or local; never include credentials, cookies, raw IDs, customer data, private scope details, or raw request/response bodies.
- Canonical launch assets contain no remote fonts, images, scripts, CSS imports, tracking pixels, or copied third-party layout/assets. They must render offline.
- The deterministic demo is local-only and must exercise the existing mock target/TUI contracts; it must not send traffic to an external target or alter a real repository.
- Do not run `gh repo rename`, `gh repo edit`, `gh api`, release creation, transfer, topic/security-setting mutation, remote rewrites, force-pushes, or any other external publication action in this plan. Each is documented as a separate approval-gated operation with a dry-run and postcondition.
- Preserve unrelated worktree edits, especially the user-owned `README.md`, examples, implementation reports, design spec, and `src/openbola/scope.py`; the implementation task must reconcile them deliberately rather than overwrite them blindly.
- Keep the P11 status “local materials complete; external launch pending” until explicit approval and live verification of each external action.
- Run `uv run ruff check .`, `uv run mypy src`, and `uv run pytest` before claiming the local plan is complete; document that native Windows/macOS artifact acceptance remains P10/CI evidence, not macOS-only proof.

## File map

- Create `docs/assets/openbola-hero.svg`: accessible, offline README hero artwork with the approved palette and OpenBOLA wordmark/tagline.
- Create `docs/assets/openbola-social-preview.svg`: 1280×640 derivative composition for repository/social preview use; no copied reference-site structure.
- Create `scripts/check_launch_assets.py`: deterministic standard-library validator for SVG dimensions, palette, forbidden external references, accessible labels, and social-preview bounds.
- Create `scripts/render_launch_assets.py`: optional local-only renderer that converts the canonical social-preview SVG to `docs/assets/openbola-social-preview.png` using an already-installed Playwright browser; fail closed if Playwright is unavailable and never download a browser or contact a URL.
- Create `examples/demo/openbola-demo.cast`: checked-in asciinema-v2-style deterministic transcript containing only synthetic local fixture output and sanitized opaque handles.
- Create `scripts/check_demo_transcript.py`: validator that rejects timestamps/terminal output containing credentials, cookies, raw IDs, absolute home paths, external hosts, or nondeterministic values.
- Modify `README.md`: replace the alpha-era launch surface with the English hero, badges, install paths, demo, sanitized finding example, provider support, architecture/safety explanation, quickstart, headless CI, roadmap, contributing/disclosure links, and honest limitations while retaining all applicable safety guidance.
- Create `docs/launch/github-launch-checklist.md`: local dry-run and approval checklist for rename, remote update, topics, security URL, release metadata, social preview upload, and post-action verification.
- Create `tests/test_launch_assets.py` and `tests/test_demo_transcript.py`: offline regression tests for the assets, README contract, and transcript redaction.

### Task 1: Build and validate canonical offline visual assets

**Files:**
- Create: `docs/assets/openbola-hero.svg`
- Create: `docs/assets/openbola-social-preview.svg`
- Create: `scripts/check_launch_assets.py`
- Create: `scripts/render_launch_assets.py`
- Test: `tests/test_launch_assets.py`

**Interfaces:**
- `scripts/check_launch_assets.py` exposes `validate_asset(path: Path, *, kind: Literal["hero", "social"]) -> None` and a CLI accepting explicit paths; it raises a constant, non-sensitive `ValueError` on failure and exits non-zero.
- `scripts/render_launch_assets.py` exposes `render_social_preview(source: Path, destination: Path) -> None`; it accepts only repository-relative paths under `docs/assets`, launches a local browser with no network permissions, and atomically writes the PNG or fails without leaving a partial file.
- Later README work consumes the exact relative paths `docs/assets/openbola-hero.svg` and `docs/assets/openbola-social-preview.svg`.

- [ ] **Step 1: Write failing asset-contract tests.**

  Add tests that parse the SVG XML and assert: hero `viewBox="0 0 1600 520"`, social preview `viewBox="0 0 1280 640"`; both contain an accessible `<title>` and `<desc>`; both include every approved palette color; neither contains `http://`, `https://`, `@import`, `<script`, external `href`, base64 image data, or a copied navigation pattern; and the validator rejects a malformed SVG, an external reference, a missing palette color, and a social asset with the wrong dimensions.

- [ ] **Step 2: Run tests to verify they fail.**

  Run: `uv run pytest tests/test_launch_assets.py -v`

  Expected: FAIL because the canonical assets and validator do not yet exist.

- [ ] **Step 3: Create the SVG compositions and validator.**

  Draw a cream background, an understated technical grid, a navy/ink OpenBOLA lockup, a restrained status badge, and a terminal-panel motif. Keep all text as SVG text with explicit fallback families; include an accessible title/description; use no external image or font. The social composition must reuse the palette and information hierarchy without copying a reference site. The validator must parse XML (not regex-only), enforce bounded file size, reject external references/scripts/embedded payloads, and emit only constant error messages. Keep the renderer optional: it may use `playwright.async_api` if importable, but it must set offline/no-network context, render a `file://` local SVG, write through a temporary sibling, `fsync`, and atomically replace the destination.

- [ ] **Step 4: Run focused checks.**

  Run:

  ```bash
  uv run pytest tests/test_launch_assets.py -v
  uv run python scripts/check_launch_assets.py docs/assets/openbola-hero.svg --kind hero
  uv run python scripts/check_launch_assets.py docs/assets/openbola-social-preview.svg --kind social
  ```

  Expected: all tests pass; the validator prints a short success line containing only the asset kind/path basename.

- [ ] **Step 5: Commit.**

  ```bash
  git add docs/assets/openbola-hero.svg docs/assets/openbola-social-preview.svg \
    scripts/check_launch_assets.py scripts/render_launch_assets.py tests/test_launch_assets.py
  git commit -m "docs: add offline OpenBOLA launch artwork"
  ```

### Task 2: Add a deterministic, sanitized local TUI demo transcript

**Files:**
- Create: `examples/demo/openbola-demo.cast`
- Create: `scripts/check_demo_transcript.py`
- Test: `tests/test_demo_transcript.py`
- Read-only integration inputs: `src/openbola/mock_target.py`, the P8 TUI session/demo service, and P9 local CLI command contracts.

**Interfaces:**
- `scripts/check_demo_transcript.py` exposes `validate_transcript(path: Path) -> None` and validates an asciinema-v2-style JSON-lines transcript without executing commands or opening a network connection.
- The transcript records the exact deterministic local demo entry point delivered by P8/P9 (the implementer must use the command name and flags those plans publish; if the command is absent, stop and report the dependency rather than inventing a network-backed demo).
- The demo output must show two synthetic identities, read-only discovery, a confirmed local BOLA read, an authorized reversible PATCH, restore, verified cleanup, and a sanitized finding/report summary; it must show opaque handles such as `${alice.record_id}` rather than raw values.

- [ ] **Step 1: Write failing transcript tests.**

  Assert the transcript is valid JSONL with a deterministic header, bounded event count and output length, monotonic fixed delays, no ANSI control sequences outside the approved terminal rendering, no timestamps/random IDs/home-directory paths, no `http(s)` authority other than the loopback mock, and required labels for discovery, mutation grant, restore verification, and report output. Add negative fixtures containing a bearer token, cookie, UUID-like raw ID, and an external host; each must be rejected with a constant error.

- [ ] **Step 2: Run tests to verify they fail.**

  Run: `uv run pytest tests/test_demo_transcript.py -v`

  Expected: FAIL until the transcript and validator exist.

- [ ] **Step 3: Produce the transcript from the local fixture only.**

  Run the P8/P9 deterministic demo against `openbola.mock_target` on loopback, capture only the rendered terminal events, replace every runtime-specific port/run ID/handle with stable placeholders, and commit the resulting transcript. Do not capture environment variables, request bodies, cookies, credentials, absolute paths, or raw object IDs. Keep the command reproducible from a clean checkout and make the transcript's final lines state that a zero-finding result is not proof of safety.

- [ ] **Step 4: Implement the offline validator and verify it.**

  Parse each line, allow only the documented event keys, normalize the expected placeholder set, and reject unknown fields, overlong output, forbidden secret/path/host patterns, and non-deterministic values. Run:

  ```bash
  uv run pytest tests/test_demo_transcript.py -v
  uv run python scripts/check_demo_transcript.py examples/demo/openbola-demo.cast
  ```

- [ ] **Step 5: Commit.**

  ```bash
  git add examples/demo/openbola-demo.cast scripts/check_demo_transcript.py tests/test_demo_transcript.py
  git commit -m "docs: add deterministic local TUI demo transcript"
  ```

### Task 3: Rewrite the English README around the local launch experience

**Files:**
- Modify: `README.md`
- Test: `tests/test_launch_assets.py` (README assertions)

**Interfaces:**
- README links to the exact local assets and existing `AUTHORIZATION.md`, `SECURITY.md`, `CONTRIBUTING.md`, `docs/architecture.md`, `examples/scope.example.yaml`, and the demo transcript.
- README documents the public P7 report names (`report.html`, `report.csv`, `report.json`, `report.md`, `junit.xml`, `report.sarif`), the P8 no-argument TUI, the P9 `setup`, `doctor`, `report`, `update`, and local `mcp` commands, and the P10 artifact names/installers once those contracts land.
- README must not expose private repository URLs or claim that repository rename/topics/security settings are already complete while the external gate is pending.

- [ ] **Step 1: Add README contract tests.**

  Assert the README begins with the OpenBOLA hero image, includes status/platform/license badges whose URLs are stable and non-secret, contains one-line development and packaged-install examples, links the deterministic demo, names all six report formats, names generic/Hasura/Supabase/PostgREST/Firebase support, states the no-network-AI and write-grant boundaries, includes headless CI guidance, links contribution and private disclosure guidance, and contains the phrases “zero findings” and “not proof of safety” in the same limitations section. Reject raw credentials, cookies, UUID-like example values, `localhost` URLs that are not the documented mock demo, and stale `bola_checker`/LiteLLM launch instructions.

- [ ] **Step 2: Run the README tests to verify they fail.**

  Run: `uv run pytest tests/test_launch_assets.py -k readme -v`

- [ ] **Step 3: Replace the launch surface while preserving safety content.**

  Use the hero, concise value proposition, restrained badges, and a “proof, not permission” framing. Include:

  1. install snippets for `uv`, packaged platform artifacts, and `openbola setup` (without claiming native platform proof from this Mac);
  2. the deterministic terminal demo embed/link and a sanitized finding excerpt using opaque variables;
  3. provider support and architecture flow from scoped capture through typed reports;
  4. quickstart for a confirmed local scope, headless CI invocation, and local MCP usage;
  5. safety boundaries for ScopeGuard, redirects, credential vaults, mutation grants/recovery, AI planning, append-only audit, and no telemetry;
  6. report artifact table, roadmap links, contribution/security links, and explicit release/platform limitations.

  Remove stale optional-AI/LiteLLM wording, old `OpenBOLA scan` casing, and any implication that the GitHub rename or release has already happened. Keep all sample scope values synthetic and `confirmed: false`.

- [ ] **Step 4: Verify docs and links locally.**

  Run:

  ```bash
  uv run pytest tests/test_launch_assets.py -k readme -v
  uv run python scripts/check_launch_assets.py docs/assets/openbola-hero.svg --kind hero
  uv run python scripts/check_demo_transcript.py examples/demo/openbola-demo.cast
  git diff --check
  ```

  Expected: all checks pass with no external HTTP requests.

- [ ] **Step 5: Commit.**

  ```bash
  git add README.md tests/test_launch_assets.py
  git commit -m "docs: publish OpenBOLA v1 launch README"
  ```

### Task 4: Record the approval-gated GitHub launch checklist and close local validation

**Files:**
- Create: `docs/launch/github-launch-checklist.md`
- Modify: `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` (P11 status only, after local tasks pass)
- Test: `tests/test_launch_assets.py` (checklist safety assertions)

**Interfaces:**
- The checklist is a local runbook, not an executable workflow. It names each external mutation, required explicit user approval, precondition, dry-run command, exact postcondition, rollback/abort condition, and evidence to record without storing tokens.
- The external target is the post-transfer repository `LeonardSEO/openbola`; until the transfer is accepted and the user approves the operation, no command in this plan may mutate repository metadata.
- The roadmap marker records “P11 local launch materials complete; external GitHub launch pending approval” and preserves the P11 gate text.

- [ ] **Step 1: Write checklist tests.**

  Assert the checklist contains separate approval gates for repository rename/transfer, local remote update, topics, security reporting URL, release metadata/artifact upload, and social-preview upload; each gate has a read-only preflight and a read-only verification command. Assert it explicitly forbids force-push/history rewrite and secrets in logs, and that the document does not contain a live token or an unconditional mutating command.

- [ ] **Step 2: Write the local-only checklist.**

  Include these gates in order: verify personal-account transfer acceptance and current owner; inspect current remotes and default branch; request approval for rename and run `gh repo rename` only after approval; update/verify the local `origin` URL; request separate approval for topics and apply/verify the approved list; request separate approval for the private vulnerability-reporting URL and verify `SECURITY.md`; request separate approval for release creation and attach only locally checksummed P10 artifacts; request separate approval to upload the social preview; then capture immutable URLs, commit SHA, artifact checksums, and GitHub settings evidence. Every mutating line is shown as a commented example or a command preceded by an explicit “STOP—obtain approval” gate, never as an automatic script.

- [ ] **Step 3: Run local safety checks and update the roadmap marker.**

  Run:

  ```bash
  uv run pytest tests/test_launch_assets.py tests/test_demo_transcript.py -v
  uv run ruff check .
  uv run mypy src
  uv run pytest
  git diff --check
  ```

  Update only the P11 status line in the roadmap; do not mark the external launch complete. Record that native Windows x64/macOS arm64/x64 clean-machine acceptance and actual GitHub metadata remain unverified until their respective external/CI evidence exists.

- [ ] **Step 4: Commit the local checklist and roadmap marker.**

  ```bash
  git add docs/launch/github-launch-checklist.md \
    docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md \
    tests/test_launch_assets.py
  git commit -m "docs: gate OpenBOLA GitHub launch actions"
  ```

## Self-review checklist

- Spec §10 is covered by Tasks 1 and 3 (palette, accessibility, separate README/social/TUI compositions, and honest status copy).
- Spec §12 is covered by Tasks 3 and 4 (English README contents, local assets, and explicit approval gates for rename/topics/security/release/social preview).
- Spec §13 criterion 3 is represented by Task 2's local mock/TUI transcript; it is evidence of a deterministic local demo, not proof of external-target safety.
- Spec §13 criteria 1, 2, and 10 remain dependent on P8–P10 implementation and native CI/machines; the plan does not claim them from this macOS checkout.
- Placeholder scan: no step says “TBD”, “TODO”, “implement later”, or “add appropriate validation”; all commands, paths, interfaces, and expected results are concrete.
- External-action scan: no task permits a publish, release, transfer, rename, topic/security mutation, remote rewrite, or force-push without a fresh, explicit approval.

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-24-openbola-p11-launch.md`. Execute it only after P8–P10 publish their concrete TUI, command, and artifact contracts. Use `superpowers:subagent-driven-development` for the four tasks with independent review between tasks. The external GitHub checklist is intentionally a later, separately approved operation; this plan itself performs no external action.
