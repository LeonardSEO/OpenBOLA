## Summary

<!-- What changed, and which contract or safety boundary does it affect? -->

## Validation

- [ ] `uv run ruff check .`
- [ ] `uv run mypy src`
- [ ] `uv run pytest`
- [ ] Other checks (describe below)

## Safety review

- [ ] No live credentials, customer data, private scope references, or raw
      request/response bodies are included.
- [ ] Scope, redirect, credential, mutation, and report boundaries remain
      fail-closed (or the change explains the reviewed contract).
- [ ] Any network or mutation behavior is covered by local, authorized tests.

## Notes and limitations

<!-- Mention unrun checks, follow-up work, migration concerns, or residual risk. -->
