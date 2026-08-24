# Task 4 implementation report

Implemented the P3b scope/lifecycle and ephemeral discovery bridge. Provider
interfaces now accept `AdapterRecordView` only; the existing Supabase, Firebase,
and generic discovery adapters consume the sanitized `view.record` while the
ephemeral request/response bodies remain callback-only. Body-derived IDs are
minted as opaque `record_id` handles synchronously during discovery and never
copied into the persistent record; this is the intentional ephemeral bridge
needed by the later Hasura adapter. Added scope-denial, registry-close,
capture-to-discovery, and raw-result-escape regressions. `AdapterRecordView`
defaults both ephemeral body fields to `None` for metadata-only adapters.

Validation:

- `uv run pytest tests/test_discovery.py tests/test_providers_supabase.py tests/test_providers_firebase.py -q` — 50 passed
- `uv run pytest tests/test_capture.py -q` — 62 passed
- Ruff on capture/discovery/providers/tests — passed
- strict mypy on capture/discovery/providers — passed
- `git diff --check` — passed

Unrelated pre-existing user edits in README, CHANGELOG, examples, and phase
documentation were preserved and not staged.
