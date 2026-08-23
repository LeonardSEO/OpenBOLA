# Phase 8 report: deterministic, safe BOLA reporting

## Delivered

- Added `bola_checker.reporting`, a read-only phase module that receives a
  typed `ReportBundle` instead of querying or mutating the state store.
- `RunSummary` derives `executed`, `protected`, `bola`, `inconclusive`, and
  `skipped` directly from supplied `ProbeResult` values. Its coverage numerator
  is only terminal (`protected` or `bola`) outcomes; a zero denominator is
  reported as not measurable rather than `100%`.
- JSON, JUnit XML, Markdown, and SARIF 2.1.0 all derive from the same bundle
  and are byte-deterministic for equivalent input. The formats do not add a
  current timestamp.
- JUnit creates one testcase for every outcome, including protected,
  inconclusive, and skipped attempts. Only BOLA outcomes that correspond to a
  high or critical finding create a JUnit failure. Inconclusive and skipped
  outcomes use JUnit `skipped` nodes.
- Markdown states the scope target label, an irreversible SHA-256 fingerprint
  of the authorization reference, coverage, explicit limitations, and a
  no-vulnerability disclaimer. A report with zero findings and zero outcomes
  says that it does not establish that the target was tested.
- The evidence serializer has a small allowlist. Authentication/header/cookie/
  token/body/credential-like fields are dropped and replaced only by a generic
  redaction indicator; unfamiliar non-sensitive fields fail closed. Credential
  references, request bodies, headers, cookies, and raw authorization values
  are never rendered.
- XML output is built with `ElementTree`, Markdown display fields are escaped
  and code fences adapt to their content, and SARIF uses a synthetic authority
  with a validated, percent-encoded endpoint path. Target URLs are not
  published in SARIF locations.
- `write_reports` generates all content before writing and rejects symlinked
  report-directory components and output files.

## Verification

Focused reporting tests parse JSON, JUnit XML, and SARIF; inspect the Markdown
snapshot shape; distinguish no findings from no tests; exercise output escaping
and secret redaction; and reject unsafe paths and report-directory symlinks.

## Fix round 1: state contracts and bundle publication

- Report evidence now accepts the same closed `ErrorCode` values as persistent
  state and rejects arbitrary identifiers under `error_code`. It accepts an
  object reference only as `obj_<64 lowercase hexadecimal characters>`; raw
  object identifiers are not a report field.
- `ReportBundle.from_state()` reads findings through the narrow,
  credential-safe `StateStore.list_findings()` contract, keeping report
  construction read-only.
- Report publication now stages all four artifacts in a private sibling
  directory and publishes that directory with one rename. The requested final
  directory must not already exist, so a failed artifact write cannot leave a
  partial or mixed-generation bundle behind.
- Every report parent component is created/opened through a directory file
  descriptor with `O_NOFOLLOW`; no pathname `lstat()`/open traversal remains.
  Staged files and both staging/parent directories are synced before and after
  publication, and failures remove the private stage without following entries.
- JUnit rendering removes XML 1.0-invalid control characters from every
  untrusted text value before serialization.

The expanded focused suite covers closed error codes, raw-object rejection,
nested unknown evidence, XML control characters, symlink/parent traversal,
and injected artifact-write failure without a published output directory.

### Validation evidence

```text
uv run pytest tests/test_reporting.py -q
14 passed

uv run pytest
198 passed

uv run ruff check .
All checks passed!
```

`uv run mypy src/bola_checker/reporting.py` and repository-wide
`uv run mypy src` both pass without reporting suppressions.

## Fix round 2: race-free publish

The final staged-directory publication is now an atomic no-replace operation,
not a preflight existence check followed by a replace-capable rename. On macOS
it calls `renameatx_np` with `RENAME_EXCL`; on Linux it calls `renameat2` (or
the architecture-known libc syscall) with `RENAME_NOREPLACE`. Both calls use
the already-open parent directory file descriptor for source and destination.
`EEXIST` and `ENOTEMPTY` fail closed, preserving a concurrently-created report
directory. Platforms without a native no-replace primitive fail closed rather
than falling back to `rename`.

The race regression creates an empty destination immediately before the native
publish call and verifies its inode remains unchanged, no BOLACheck artifacts
appear there, and the failed staging directory is removed. A normal directory
rename could replace that empty destination, so this specifically proves the
no-replace primitive is being enforced.

## Fix round 3: durable failed-stage cleanup

Every failed publish path now removes its private stage and then fsyncs the
already-open parent directory before closing it. This also makes stage removal
durable after `EEXIST`/`ENOTEMPTY` and unsupported-native-platform failures.
If cleanup or its fsync fails while another publish error is already in flight,
the primary fail-closed error is retained and annotated with the secondary
failure; absent a primary error, the durability error is raised and chained to
the cleanup error where both occurred. Focused regressions assert the exact
remove-then-parent-sync order for both failure classes.
