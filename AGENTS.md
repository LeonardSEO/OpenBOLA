# AGENTS.md

## Project

BOLACheck is an open-source, authorization-first BOLA/IDOR testing tool. It
captures or imports traffic from two or more identities, establishes object
ownership from explicit evidence, and compares authorized versus unauthorized
access without allowing an AI model to send network traffic.

## Non-negotiable safety boundaries

- Every network operation must pass `ScopeGuard` using a confirmed scope file.
- Redirects are never followed implicitly; every redirect target is checked.
- Read probes are the default. Write probes require a separate, explicit
  mutation grant that names methods and path patterns.
- Credentials are never logged, reported, committed, or persisted in plaintext.
- AI may propose a typed plan but may not execute requests or bypass policy.
- Tested combinations and findings form an append-only audit trail.
- Never weaken these boundaries without asking the user first.

## Engineering conventions

- Python 3.11+, `src/` layout, typed public APIs.
- Tests live in `tests/` and use pytest.
- Prefer standard library and small explicit abstractions.
- Keep phase modules independent and integrate through `models.py`.
- Run `uv run ruff check .`, `uv run mypy src`, and `uv run pytest` before
  claiming completion.

