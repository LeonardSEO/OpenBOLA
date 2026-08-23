# BOLACheck

Authorization-first automated BOLA/IDOR testing for HTTP APIs.

> **Alpha:** the implementation is under active development. Only test systems
> you own or have explicit written permission to assess.

BOLACheck learns endpoint shapes and object ownership from captured traffic
from multiple identities, then performs deterministic cross-identity probes.
The optional AI layer can propose typed test plans, but it never executes HTTP
requests and cannot bypass scope policy.

## Safety model

- Confirmed, time-bounded scope is mandatory.
- Every initial and redirected URL is checked against host, CIDR, and path rules.
- Read-only probes are the default.
- Mutation probes require explicit method and path grants.
- Credentials stay in memory and are never written to reports or SQLite.
- Every attempted combination is auditable.

## Development

```bash
uv sync --extra dev --extra all
uv run ruff check .
uv run mypy src
uv run pytest
```

See [AUTHORIZATION.md](AUTHORIZATION.md) and [the architecture](docs/architecture.md).

