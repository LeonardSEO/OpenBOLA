# Architecture

```text
scope policy -> capture/import -> secret-safe extraction -> ownership evidence
     -> persistent audit state -> deterministic probes -> reports
                                      ^
                                      |
                            optional typed AI plan
```

The network boundary is owned exclusively by the deterministic executor. The
AI planner receives only redacted structured context and returns a validated
plan. It has no HTTP client and no authority to widen scope.

## Phase ownership

| Phase | Module | Responsibility |
|---|---|---|
| 0 | `scope.py` | Authorization, host/CIDR/path/time/mutation policy |
| 1 | `capture.py` | Playwright capture configuration and HAR import |
| 2 | `extract.py`, `credentials.py` | Secret-safe request and identity extraction |
| 3 | `state.py` | SQLite audit state without credential material |
| 4 | `endpoints.py` | Templating and evidence-based ownership |
| 5 | `executor.py` | Scoped deterministic probes and response comparison |
| 6 | `ai.py` | Optional typed plan generation |
| 7 | `mcp_server.py` | Local stdio tools |
| 8 | `reporting.py` | JSON, JUnit, Markdown, and SARIF |
| 9 | `cli.py`, `pipeline.py`, `mock_target.py` | User flow and E2E proof |

