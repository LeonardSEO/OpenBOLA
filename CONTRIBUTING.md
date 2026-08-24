# Contributing to OpenBOLA

Thank you for helping make authorization testing safer and more reviewable.
OpenBOLA is an alpha project: small, evidence-backed changes are easier to
review than broad rewrites.

## Before you start

- Read [AUTHORIZATION.md](AUTHORIZATION.md) and [SECURITY.md](SECURITY.md).
- Never include live credentials, customer data, private scope references, or
  captured request/response bodies in an issue, pull request, fixture, or
  commit.
- Use only local fixtures or systems for which you have explicit written
  authorization. Do not add a test that sends traffic to a third-party target.
- Preserve the fail-closed boundaries in `AGENTS.md`; changes that weaken them
  need an explicit design discussion before implementation.

## Development setup

```bash
uv sync --extra dev
uv run ruff check .
uv run mypy src
uv run pytest
```

Run focused tests while iterating, then run the full commands above before
opening a pull request. If a check cannot run locally, explain why and state
the remaining risk in the pull request.

## Pull requests

Please keep a pull request focused and describe:

- the safety or user-facing contract that changed;
- the files and tests that exercise it;
- whether the change can perform network I/O, mutate a target, or handle
  credential-related data;
- checks run and any known limitations.

Security-sensitive changes should include negative tests for scope denial,
redirect handling, secret retention, and mutation authorization where relevant.
Do not “fix” a failing security test by weakening the assertion or removing the
test.

## Commit and review guidance

Use clear, imperative commit messages and avoid mixing formatting-only changes
with behavior changes. Reviewers should be able to follow an input from the
confirmed scope through state, execution, and report output. New public data
fields require an explicit allowlist decision so they cannot accidentally carry
secrets into persistent state or reports.

## Documentation and examples

Examples must be local, synthetic, and visibly non-authorizing. Keep
`confirmed: false` in example scopes unless a test creates a temporary scope
itself. Never add real hostnames, contract numbers, tokens, cookies, or customer
identifiers.

## Security reports

Do not open a public issue for a vulnerability or suspected secret disclosure.
Follow [SECURITY.md](SECURITY.md) and remove sensitive material from local
fixtures after reporting it.
