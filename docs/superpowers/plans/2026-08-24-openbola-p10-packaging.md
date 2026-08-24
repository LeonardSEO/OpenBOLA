# OpenBOLA P10 Distribution Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce reproducible, checksum-verifiable OpenBOLA v1 bundles for Windows x64, macOS arm64, and macOS x64, with local installers and a guarded GitHub Actions release workflow, while proving only the native macOS build locally and leaving Windows proof to Windows CI.

**Architecture:** PyInstaller builds a one-file terminal executable from an explicit per-target spec and includes the OpenBOLA package, Textual, Playwright's Python package, and required optional modules; Chromium remains external and is installed by `openbola setup`. A stdlib artifact assembler creates deterministic archives and per-bundle executable manifests, then emits the required `SHA256SUMS`. The shell and PowerShell installers consume an extracted local bundle, verify its executable manifest, install atomically into the platform-specific user bin directory, and ask before editing PATH. GitHub Actions builds natively on each target, attests build artifacts, and places release publication behind a protected environment; no tag, release, or external upload is performed during local implementation.

**Tech Stack:** Python 3.11+, PyInstaller 6.15.0 as a CI/build-only pin, existing `openbola.cli:app` and `openbola.__version__`, Python `zipfile`/`tarfile`/`hashlib`/`pathlib`/`tomllib`, POSIX `sh`, PowerShell 7-compatible syntax, and GitHub Actions with pinned action SHAs. No runtime network client, credential, or browser binary is added for packaging.

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (§11 Distribution and updates, §12 GitHub launch approval boundary, §13 acceptance criteria 1–2) and `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` (P10 and the out-of-session verification note).

## Global Constraints

- Required release artifacts are exactly `openbola-VERSION-windows-x64.zip`, `openbola-VERSION-macos-arm64.tar.gz`, `openbola-VERSION-macos-x64.tar.gz`, and `SHA256SUMS`; archive names contain the normalized project version, not an arbitrary branch name.
- PyInstaller builds run natively on Windows x64, macOS arm64, and macOS x64. Do not cross-compile a Windows executable from this macOS workstation or claim a Windows artifact was verified locally.
- Bundles include the Python runtime, Textual, OpenBOLA, Playwright's Python package, and required libraries. Chromium is never embedded; `openbola setup` remains responsible for downloading the exact Playwright-pinned browser.
- `install.sh` installs to `~/.local/bin`; `install.ps1` installs to `%LOCALAPPDATA%\\OpenBOLA\\bin`. Both verify the extracted executable against an adjacent manifest, replace files atomically, and ask before editing a user PATH. Neither script uses `sudo`, writes outside its target directory, follows a redirect, or downloads code.
- Build output is restricted to the allowlisted executable, installer for that platform, `openbola.sha256`, `LICENSE`, and `README.md`. Build/cache directories, `.env` files, credentials, cookies, raw target values, and Chromium are rejected before archiving.
- `SHA256SUMS` is sorted by filename, uses two-space GNU checksum formatting, and is generated only after all three archives exist. A mismatch or missing entry fails the release job.
- GitHub artifact attestations are mandatory. Release publication is protected by an explicit `release` environment and is never triggered by a local build, a normal `main` push, or this plan's commit.
- No package-manager runtime dependency is added. PyInstaller is available only through the exact CI/build invocation (`uv run --with pyinstaller==6.15.0`); if the implementation discovers a compatibility issue, stop and record the reason before changing the pin.
- Every task preserves the authorization-first boundaries: packaging does not execute target requests, resolve credentials, serialize session values, or weaken `ScopeGuard`, mutation grants, recovery, or report redaction.
- Before declaring P10 complete, run `uv run ruff check .`, `uv run mypy src`, `uv run pytest`, and the native macOS packaging smoke test. Windows x64 and both clean-machine install claims remain open until their CI/real-machine runs are observed.

## File Structure

- `packaging/pyinstaller/openbola-windows-x64.spec` — Windows x64 PyInstaller analysis and executable metadata.
- `packaging/pyinstaller/openbola-macos-arm64.spec` — native macOS arm64 PyInstaller analysis and executable metadata.
- `packaging/pyinstaller/openbola-macos-x64.spec` — native macOS x64 PyInstaller analysis and executable metadata.
- `packaging/build_artifacts.py` — bounded, deterministic archive creation, per-bundle executable manifests, version/target validation, and `SHA256SUMS` generation. It must be usable as `python packaging/build_artifacts.py ...` without importing the installed application.
- `packaging/install.sh` — local macOS installer with checksum verification, atomic copy, and explicit PATH prompt.
- `packaging/install.ps1` — local Windows installer with checksum verification, atomic copy, and explicit PATH prompt.
- `.github/workflows/release.yml` — native build matrix, artifact checks, attestations, and protected release publication; no automatic release occurs on `main`.
- `tests/test_packaging.py` — spec, archive, manifest, checksum, version, and native smoke-contract tests.
- `tests/test_installers.py` — shell/PowerShell static safety checks and temporary-directory installer tests.
- `tests/test_release_workflow.py` — release workflow trigger, matrix, permission, version-gate, and protected-environment checks.
- `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` — mark P10 complete only after the focused and global checks pass; preserve the out-of-session caveat.

## Public Contracts and Invariants

The implementation must expose these build-helper interfaces from `packaging/build_artifacts.py`; they are testable pure functions and must not import `openbola` or make network calls:

```python
TARGETS = ("windows-x64", "macos-arm64", "macos-x64")

@dataclass(frozen=True)
class TargetArtifact:
    target: Literal["windows-x64", "macos-arm64", "macos-x64"]
    version: str
    archive: Path
    executable_digest: str
    archive_digest: str

def read_project_version(pyproject: Path) -> str: ...
def archive_target(
    *,
    target: str,
    version: str,
    executable: Path,
    output_dir: Path,
    license_file: Path,
    readme_file: Path,
    installer_file: Path,
) -> TargetArtifact: ...
def write_sha256sums(artifacts: Sequence[TargetArtifact], output: Path) -> None: ...
```

`read_project_version` accepts only a PEP 440-compatible release string from `[project].version` and rejects path-like, whitespace-containing, or tag-mismatched values without echoing file contents. `archive_target` accepts exactly one target, verifies that the executable and metadata are regular files inside the supplied build/output roots, rejects symlink escapes and unexpected archive members, writes `openbola.sha256` for the executable, and uses stable member order, normalized timestamps, and normalized modes. Windows archives contain `openbola.exe`, `install.ps1`, `openbola.sha256`, `LICENSE`, and `README.md`; macOS archives contain `openbola`, `install.sh`, `openbola.sha256`, `LICENSE`, and `README.md`. `write_sha256sums` requires one artifact for every target, sorts by archive filename, writes `<sha256>  <filename>` lines with a final newline, and refuses duplicates or missing targets.

Each installer has a non-network command contract:

```text
install.sh [--bin-dir DIR] [--yes] [--no-path]
install.ps1 [-BinDir DIR] [-Yes] [-NoPath]
```

The default replaces an existing executable only after an interactive confirmation. `--yes`/`-Yes` confirms replacement for CI; `--no-path`/`-NoPath` explicitly declines any PATH edit. A missing/invalid `openbola.sha256`, a digest mismatch, a non-regular executable, an unsupported OS/architecture, or a failed atomic rename exits non-zero before touching the destination. PATH changes are offered only after a successful install and are never made without an affirmative answer.

### Task 1: Add explicit native PyInstaller specifications

**Files:**
- Create: `packaging/pyinstaller/openbola-windows-x64.spec`
- Create: `packaging/pyinstaller/openbola-macos-arm64.spec`
- Create: `packaging/pyinstaller/openbola-macos-x64.spec`
- Create: `tests/test_packaging.py`

**Interfaces:**
- Consumes: the final P8/P9 `openbola.cli:app`, `openbola.__version__`, and the installed `openbola[all]` module graph.
- Produces: three independent specs that all emit a console executable named `openbola` (with `.exe` on Windows) and reject a build on the wrong native architecture.

- [ ] **Step 1: Write failing spec-contract tests**

Add tests that read each spec as text and assert the target tuple, `console=True`, `name="openbola"`, `openbola.cli:app` as the entry point, collection of `openbola` and `playwright` submodules/data, no Chromium path or browser binary, and an explicit architecture guard. Assert the three expected output names are unique and that no spec references a developer home directory, environment secret, cookie, or target URL.

```python
@pytest.mark.parametrize(
    ("target", "spec_name", "executable"),
    [
        ("windows-x64", "openbola-windows-x64.spec", "openbola.exe"),
        ("macos-arm64", "openbola-macos-arm64.spec", "openbola"),
        ("macos-x64", "openbola-macos-x64.spec", "openbola"),
    ],
)
def test_spec_declares_native_target_and_safe_entrypoint(
    target: str, spec_name: str, executable: str
) -> None:
    source = (ROOT / "packaging" / "pyinstaller" / spec_name).read_text()
    assert f'TARGET = "{target}"' in source
    assert 'name="openbola"' in source
    assert "console=True" in source
    assert "openbola.cli:app" in source
    assert "playwright" in source
    assert "chromium" not in source.casefold()
    assert executable in source
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `uv run pytest tests/test_packaging.py -k 'spec or native_target' -v`

Expected: FAIL because the three spec files do not exist.

- [ ] **Step 3: Implement the three specs**

Use a shared, duplicated allowlist in each spec so a spec can be run by PyInstaller without importing a project-only helper. Collect the package's hidden imports and data needed by Textual and Playwright's Python package, set `console=True`, set `strip=False`, and use one-file output. The entry script must be the installed `openbola.cli:app` module, not a developer wrapper. Add a build-time architecture assertion: Windows requires `win32`/`AMD64`, macOS arm64 requires `darwin`/`arm64`, and macOS x64 requires `darwin`/`x86_64`; fail before analysis when the host does not match. Do not add Chromium, browser caches, `.env` files, or arbitrary filesystem globs to `datas`/`binaries`.

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `uv run pytest tests/test_packaging.py -k 'spec or native_target' -v`

Expected: PASS for all three specs. On this macOS host only the spec matching `platform.machine()` may proceed to a real PyInstaller invocation; the two other specs are contract-tested but not claimed built locally.

- [ ] **Step 5: Commit**

```bash
git add packaging/pyinstaller tests/test_packaging.py
git commit -m "build: add native OpenBOLA PyInstaller specs"
```

### Task 2: Implement deterministic archives, manifests, and SHA256SUMS

**Files:**
- Create: `packaging/build_artifacts.py`
- Modify: `tests/test_packaging.py`

**Interfaces:**
- Consumes: a native PyInstaller `dist` executable, `LICENSE`, `README.md`, and the platform installer script.
- Produces: `TargetArtifact`, `archive_target`, `write_sha256sums`, and a CLI with `archive` and `checksums` subcommands that are deterministic and offline.

- [ ] **Step 1: Write failing artifact-helper tests**

Cover project-version parsing, all three required archive names, regular-file and symlink-escape rejection, missing metadata, unexpected member rejection, executable manifest creation, deterministic archive bytes across two output directories, duplicate/missing target rejection in `SHA256SUMS`, sorted two-space checksum lines, and refusal of a version that does not match the requested `v` tag. Include sentinels in a fake `.env`, cookie file, raw object ID, and Chromium directory and assert none enters an archive.

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `uv run pytest tests/test_packaging.py -k 'archive or checksum or manifest or version' -v`

Expected: FAIL because `packaging/build_artifacts.py` and its public functions do not yet exist.

- [ ] **Step 3: Implement the offline artifact assembler**

Use only `pathlib`, `hashlib`, `zipfile`, `tarfile`, `tomllib`, and `re`. Normalize archive member names to POSIX separators, sort them, set a fixed timestamp and mode, and write bytes atomically through a sibling temporary file followed by `os.replace`. Use `zipfile.ZIP_DEFLATED` with a fixed compression level and normalized metadata for Windows; use a gzip tar stream with normalized metadata for macOS. Create `openbola.sha256` from the executable digest before archiving. Restrict all source paths to explicit roots, resolve symlinks before comparison, and reject any member not in the target allowlist. Add `--project-root`, `--target`, `--version`, `--executable`, `--output-dir`, and `--tag` arguments so CI cannot accidentally package a different checkout version. Never import `openbola`, read credentials, or contact GitHub.

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `uv run pytest tests/test_packaging.py -k 'archive or checksum or manifest or version' -v`

Expected: PASS, including byte-for-byte repeatability and all rejection cases.

- [ ] **Step 5: Commit**

```bash
git add packaging/build_artifacts.py tests/test_packaging.py
git commit -m "build: create deterministic OpenBOLA release artifacts"
```

### Task 3: Add checksum-verifying, prompt-safe installers

**Files:**
- Create: `packaging/install.sh`
- Create: `packaging/install.ps1`
- Create: `tests/test_installers.py`
- Modify: `tests/test_packaging.py`

**Interfaces:**
- Consumes: an extracted bundle containing the platform executable, installer, `openbola.sha256`, `LICENSE`, and `README.md`.
- Produces: local installation to `~/.local/bin` or `%LOCALAPPDATA%\\OpenBOLA\\bin`, with explicit replacement and PATH prompts and no network path.

- [ ] **Step 1: Write failing installer tests**

Run the shell installer against a temporary bundle with a fake executable and valid manifest using `--bin-dir <tmp>/bin --yes --no-path`; assert an atomic installed file and no profile modification. Repeat with a changed executable, missing manifest, mismatched digest, destination symlink, and a path containing spaces; each must fail closed without replacing the previous file. Parse the PowerShell script to assert it uses `Get-FileHash -Algorithm SHA256`, `Move-Item`/equivalent atomic replacement, `-NoPath`, and no `Invoke-WebRequest`, `curl`, `irm`, `Start-BitsTransfer`, or plaintext secret names. Assert both scripts prompt before PATH edits and never use `sudo`.

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `uv run pytest tests/test_installers.py -v`

Expected: FAIL because the installer scripts do not exist.

- [ ] **Step 3: Implement `install.sh`**

Use `set -eu`, `SCRIPT_DIR` derived from `BASH_SOURCE`, `mktemp` in the destination directory, `shasum -a 256` (falling back to `sha256sum` only when present), and `mv` after a successful digest check. Resolve the executable and manifest relative to the script, reject a non-macOS host or a non-arm64/x64 host, and refuse to follow a destination symlink. Create `~/.local/bin` with mode `700` only when absent, install the executable with mode `755`, preserve no source metadata, and clean temporary files with a trap. Ask before replacing an existing file; `--yes` confirms only that replacement. After installation, ask separately whether to add the exact bin directory to the detected interactive shell's profile; `--no-path` skips this question and any edit. Print only the installed path, version command result, and generic failure reason.

- [ ] **Step 4: Implement `install.ps1`**

Use strict mode and `Get-FileHash -Algorithm SHA256`, resolve the script directory with `$PSScriptRoot`, require Windows x64, reject reparse-point destinations, create `%LOCALAPPDATA%\\OpenBOLA\\bin` with restrictive user ACL inheritance, and replace through a same-directory temporary file plus `Move-Item`. Ask separately for replacement and PATH edits; `-Yes` confirms replacement and `-NoPath` suppresses PATH changes. Do not invoke PowerShell remoting, package managers, web clients, or the installed executable with credentials. Return a non-zero exit code for all validation or filesystem failures.

- [ ] **Step 5: Run the focused tests to verify they pass**

Run: `uv run pytest tests/test_installers.py tests/test_packaging.py -v`

Expected: PASS for shell behavior and PowerShell static safety checks. Native PowerShell execution is reserved for the Windows CI matrix; this macOS run must not be described as Windows installer proof.

- [ ] **Step 6: Commit**

```bash
git add packaging/install.sh packaging/install.ps1 tests/test_installers.py tests/test_packaging.py
git commit -m "feat: add checksum-verifying OpenBOLA installers"
```

### Task 4: Add the guarded native release workflow

**Files:**
- Create: `.github/workflows/release.yml`
- Create: `tests/test_release_workflow.py`

**Interfaces:**
- Consumes: the three specs, `packaging/build_artifacts.py`, installers, and the project version from `pyproject.toml`.
- Produces: native Windows x64/macOS arm64/macOS x64 build jobs, uploaded archives, `SHA256SUMS`, artifact attestations, and a protected release job that is inert until a reviewed version tag and `release` environment approval exist.

- [ ] **Step 1: Write failing workflow contract tests**

Load the workflow with `yaml.safe_load` and assert it triggers only on `workflow_dispatch` and `v*` tags (never on `main`), uses `windows-2022`, `macos-14`, and `macos-13`, runs `uv sync --extra all --extra dev`, invokes `uv run --with pyinstaller==6.15.0`, runs the artifact assembler, uploads all four required files, grants only the permissions needed for contents/read, attestations/write, and release publication, and sets `environment: release` on the publish job. Assert the workflow checks that `github.ref_name` equals `v` plus `[project].version` before publication and that no step contains a personal token, raw API key, or `curl | sh` installer.

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `uv run pytest tests/test_release_workflow.py -v`

Expected: FAIL because `.github/workflows/release.yml` and the contract tests do not exist.

- [ ] **Step 3: Implement the native build matrix**

Pin every third-party action to a reviewed commit SHA. The matrix maps `windows-2022` to `windows-x64` and the Windows spec, `macos-14` to `macos-arm64`, and `macos-13` to `macos-x64`. Each job checks out the exact commit, installs Python 3.11 through `astral-sh/setup-uv`, runs `uv sync --extra all --extra dev`, invokes the matching spec with `uv run --with pyinstaller==6.15.0 pyinstaller ... --clean`, runs the target executable's `--version` smoke command, and invokes `python packaging/build_artifacts.py archive` with the project version and tag. The job uploads only its archive and a small build log; it must not upload `dist/`, caches, `.env`, or browser directories.

- [ ] **Step 4: Implement checksum, attestation, and protected publication jobs**

The aggregation job downloads the three matrix archives, runs `python packaging/build_artifacts.py checksums`, verifies every line with the platform-native hash tool, and uploads `SHA256SUMS`. Run `actions/attest-build-provenance` for each archive with `id-token: write` and `attestations: write`. A final job with `environment: release`, `contents: write`, and an `if` condition requiring a `v` tag creates or updates a draft GitHub Release only after the environment reviewer approves it, uploads the three archives and `SHA256SUMS`, and verifies the tag/version match again. No local command in this task pushes a tag, calls GitHub's release API, renames a repository, or publishes an artifact.

- [ ] **Step 5: Run workflow contract tests**

Run: `uv run pytest tests/test_release_workflow.py -v`

Expected: PASS. A YAML parser warning or a missing action SHA is a task failure; do not weaken the test to accommodate it.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/release.yml tests/test_release_workflow.py
git commit -m "ci: build and attest native OpenBOLA releases"
```

### Task 5: Prove the native macOS bundle and document platform limits

**Files:**
- Modify: `tests/test_packaging.py`
- Modify: `tests/test_installers.py`
- Modify: `.github/workflows/release.yml`
- Modify: `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md`

**Interfaces:**
- Consumes: the completed specs, artifact helper, installers, and release matrix.
- Produces: a repeatable macOS-native smoke proof and an honest roadmap status that distinguishes local macOS evidence from Windows/clean-machine acceptance.

- [ ] **Step 1: Add the native macOS smoke test**

On Darwin only, select the spec whose declared target matches `platform.machine()` (`arm64` or `x86_64`), build into a temporary directory with `uv run --with pyinstaller==6.15.0 pyinstaller`, run the resulting `openbola --version` and `openbola --help`, archive it, and verify `openbola.sha256` and the corresponding `SHA256SUMS` line. Skip with an explicit reason when PyInstaller is unavailable or the host is not macOS; never substitute a Linux or cross-compiled executable.

- [ ] **Step 2: Add installer smoke coverage for the native bundle**

Extract the native macOS archive into a temporary directory, run `bash install.sh --bin-dir <tmp>/bin --yes --no-path`, assert the installed executable launches and reports its version, then run the checksum verifier against the archive. Keep the destination temporary and remove it after the test. Do not run `openbola setup`, access a real target, or download Chromium in this packaging proof.

- [ ] **Step 3: Run the complete P10 verification set**

Run:

```bash
uv run ruff check .
uv run mypy src
uv run pytest
```

Expected: all commands exit 0, the native macOS smoke test passes on the matching architecture, and no test opens a network connection or includes a secret/raw value in an artifact. If Windows CI is unavailable, record that as an unverified platform proof rather than changing the acceptance test.

- [ ] **Step 4: Update the roadmap marker**

Change only the P10 entry in `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` to record the implementation commit and the checks above. Keep the explicit statement that Windows x64 and clean-machine install/launch require real Windows/CI observation; do not mark acceptance criteria 1–2 globally complete from this macOS session.

- [ ] **Step 5: Commit the acceptance proof**

```bash
git add tests/test_packaging.py tests/test_installers.py .github/workflows/release.yml docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md
git commit -m "test: verify native OpenBOLA packaging boundary"
```

## Self-Review Checklist

- The three required target artifacts, installer destinations, Chromium exclusion, checksum format, and attestation requirement from design §11 each have an implementation task and test.
- The build workflow is native per platform and has no cross-compiled Windows claim; local verification is explicitly limited to the host's macOS architecture.
- Installer scripts are local-only, checksum-first, atomic, non-root, and prompt before PATH edits or replacement; no network or credential path is present.
- Version/tag mismatch, symlink escape, archive traversal, unexpected members, missing checksums, and duplicate checksum targets fail closed.
- The protected release job is configuration only. This plan performs no push, tag, release, repository rename, transfer, or external publication, preserving the P11 approval boundary.
- P6/P7/P8/P9 contracts are consumed through the public CLI/version surface without adding a second request executor or serializing session values.
- Every function, file, target name, command, and commit scope used by the tasks is defined above; no task depends on an unspecified helper or placeholder.
