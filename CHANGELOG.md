# Changelog

All notable changes to BOLACheck will be recorded here. The project is in alpha
and has not published a stable release yet.

## Unreleased

### Added

- Authorization-first scope validation with host, CIDR, path, time-window, and
  explicit mutation-grant checks.
- Scope-checked, secret-safe HAR capture/import and deterministic request
  extraction with an in-memory credential vault.
- SQLite audit state with opaque credential/object references and append-only
  records.
- Evidence-based endpoint discovery and ownership correlation.
- Deterministic bounded HTTP probe contracts, including explicit redirect and
  reversible mutation boundaries.
- Optional typed AI planning and a local stdio MCP service adapter with a
  scope-bound, read-only deterministic executor.
- Deterministic JSON, JUnit XML, Markdown, and SARIF report renderers.
- Read-only CLI and pipeline orchestration with exact-origin ownership
  evidence, bounded records import, and machine-safe JSON output.
- An ephemeral `127.0.0.1` vulnerable/protected mock target and full local
  end-to-end proof.
- Immutable, sanitized migration history for legacy findings and private
  SQLite state files.
