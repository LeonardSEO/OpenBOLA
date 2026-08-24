# Task 1 report — Hasura parser contracts

## Implemented

- Added `src/openbola/providers/hasura.py` with immutable `_RootSelection` and
  `_ParsedOperation` contracts.
- Added a bounded standard-library lexer that drops quoted and numeric literal
  contents, skips comments, and rejects malformed source without exposing source
  substrings in errors.
- Added operation parsing for `query` and `mutation`, aliases, balanced root
  arguments, direct selected fields, mutation `returning` fields, and safe root
  resource normalization.
- Added parser contract tests in `tests/test_providers_hasura.py`, including
  comment/string variable lookalike and introspection-only rejection cases.

## Validation

- `uv run pytest tests/test_providers_hasura.py -k 'parse' -v` — 3 passed.
- `uv run pytest tests/test_providers_hasura.py` — 3 passed.
- `uv run ruff check src/openbola/providers/hasura.py tests/test_providers_hasura.py` — passed.
- `uv run mypy src/openbola/providers/hasura.py` — passed.

## Self-review

- The parser retains only identifier names, variable names, punctuation, and
  placeholder token kinds; it does not retain literal values or source text.
- Parser failure paths return `None` and do not interpolate document content into
  exceptions.
- The change is stdlib-only and does not add network, provider registration, or
  capture persistence behavior; those belong to later P4d tasks.
- Existing unrelated working-tree documentation/example edits were preserved.

## Review fix

- Hardened delimiter handling with a full nested delimiter stack so mismatched
  parentheses, brackets, and braces fail closed.
- Rejected empty/trailing argument values and numeric tokens with identifier
  suffixes, with explicit regression tests for the reviewer examples.
- Revalidated parser tests (5 passed), Ruff, and strict mypy.

## Review fix 2

- Added parenthesized argument/directive grammar validation for required
  name/variable-colon-value pairs, malformed values, and dangling commas.
- Preserved nested GraphQL object/list values while rejecting mismatched delimiters
  and malformed numeric tokens.
- Added a selection-depth budget so deeply nested documents fail closed instead of
  reaching Python recursion limits.
- Revalidated parser tests (7 passed), Ruff, and strict mypy.

## Review fix 3

- Extended the argument validator for GraphQL variable-definition type lists,
  non-null markers, defaults, and insignificant trailing commas while continuing
  to reject malformed double commas and missing values.
- Added regression coverage for typed/defaulted variable definitions and trailing
  commas.
- Revalidated parser tests (8 passed), Ruff, and strict mypy.
