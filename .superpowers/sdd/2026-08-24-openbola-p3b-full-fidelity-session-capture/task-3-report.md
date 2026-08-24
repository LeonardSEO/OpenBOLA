# Task 3 implementation report

## Scope

Implemented the P3b full-fidelity collector and one scoped browser run in
`src/openbola/capture.py`, with the dual-collector and boundary regressions in
`tests/test_capture.py`.

## Changes

- Added bounded `_FullFidelityEventCollector` for request material, response
  body tasks, browser state, pairing, duplicate/missing-event detection, and
  opaque `SessionValueStore` handles.
- Added individual body, browser-state, exchange-count, and cumulative raw
  material limits with raw-free `CaptureError` messages.
- Added `_run_scoped_capture()` shared by `capture_har()` and
  `capture_session()`, routing before collectors/page creation and preserving
  browser/context/page cleanup.
- Added `capture_session()` that writes only the existing sanitized HAR and
  returns `InSessionCapture` handles for full material.
- Added an event multiplexer so simple test doubles and Playwright contexts both
  receive sanitized and full collectors for one browser run.
- Hardened duplicate-response detection when the first response body task has
  not completed yet.
- Updated `InSessionCapture.with_adapter_records()` to pass ephemeral
  `AdapterRecordView` values containing the sanitized `RequestRecord` and raw
  bodies only during the callback; strict inventory allowlisting still rejects
  raw views/results.

## Validation

```text
uv run ruff check src/openbola/capture.py tests/test_capture.py  # passed
uv run mypy src/openbola/capture.py                              # passed
uv run pytest tests/test_capture.py -k "adapter_bridge" -q      # 1 passed
uv run pytest tests/test_capture.py -q                           # passed in the prior implementation run; focused adapter rerun passed
```

## Commits

- `73d8e77 feat: capture full session material in memory`
- `f6b1c44 fix: reject duplicate full capture responses`
- `4288ea3 fix: close full registry on capture setup failure`
- `5d97a11 fix: expose ephemeral adapter record views` includes the adapter-view contract fix.
