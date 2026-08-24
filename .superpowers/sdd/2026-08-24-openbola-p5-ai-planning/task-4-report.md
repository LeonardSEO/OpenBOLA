# P5 Task 4 implementation report

Migrated the legacy AI planning boundary to typed `AIProviderConfig`,
`PlanningCandidate`, and `ProposedPlan`/`ProposedTest` validation while
retaining a deprecation-compatible `LiteLLMAdapter` shim. The shim delegates
only to the typed context/proposal contracts and cannot execute target traffic.

Validation:

- `uv run pytest tests/test_ai.py -q` — 66 passed (legacy deprecation warnings only)
- Ruff on AI source/tests — passed
- strict mypy on `src/openbola/ai.py` — passed
- `git diff --check` — passed
