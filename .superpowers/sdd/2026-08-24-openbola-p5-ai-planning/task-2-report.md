# Task 2 implementation report

## Result

Implemented strict typed proposal parsing and deterministic binding validation in
`src/openbola/ai.py`.

- `parse_proposed_plan` accepts exactly one bounded JSON object (or one exact
  `json` fence), rejects duplicate keys, non-finite constants, trailing text,
  unknown fields, invalid shapes, oversized output, and invalid typed fields.
- `validate_proposed_plan` rejects unobserved or duplicate candidate bindings,
  mismatched identity/record/method/field handles, ambiguous candidate matches,
  and invalid target origins. It re-checks the target `ScopeGuard` for every
  proposal path and returns only the original non-executable `ProposedPlan`.
- Validation and parser errors are generic and do not echo provider output,
  URLs, handle values, or other sensitive material.
- Added focused tests for strict parsing, bounds, binding failures, target
  scope checks, and per-proposal scope call counts.

## Verification

```text
uv run ruff check src/openbola/ai.py tests/test_ai.py
All checks passed!

uv run mypy src/openbola/ai.py
Success: no issues found in 1 source file

uv run pytest tests/test_ai.py -k 'proposed or validator or binding' -q
18 passed, 33 deselected
```

## Commit

The implementation is committed as `feat: validate typed AI proposals against scope`.

## Review fix

The target-origin boundary now requires an absolute HTTPS origin with no
userinfo, query, fragment, non-root path, malformed host/port, or port zero.
The regression suite also proves the normalized origin produces the exact
guarded target path.

Additional verification after the fix:

```text
uv run ruff check src/openbola/ai.py tests/test_ai.py
All checks passed!

uv run mypy src/openbola/ai.py
Success: no issues found in 1 source file

uv run pytest tests/test_ai.py -k 'proposed or validator or binding' -q
28 passed, 33 deselected
```
