# Phase 0: scope guard

## Status

Implemented the fail-closed authorization boundary in
`src/bola_checker/scope.py`. `ScopeConfig` is immutable after parsing,
`ScopeGuard` authorizes one URL/method at a time, and `ScopeError` reports
policy failures without echoing request URLs, query strings, or userinfo.

## Decisions

- The YAML document has a closed schema. It requires a non-empty client name
  and authorization reference, the exact boolean `confirmed: true`, UTC
  `starts_at` and `expires_at`, at least one host or CIDR allow-list, and at
  least one explicit path rule. Unknown fields, malformed YAML, ambiguous
  values, and inactive scopes fail closed.
- Host rules allow exact hostnames and leftmost `*.` wildcards only. A wildcard
  never matches its bare suffix. Literal IP targets require `allowed_cidrs`.
  When CIDRs are configured for a hostname, a caller must inject a resolver;
  every returned IP must belong to an allowed network. The guard itself never
  performs DNS resolution.
- URL checks accept only absolute HTTP(S) URLs without userinfo. Paths are
  matched independently from query strings. Rules are explicitly prefixed with
  `glob:` or `regex:`; regexes are anchored and restricted to a small
  path-only subset.
- GET, HEAD, and OPTIONS are the default read methods. POST, PUT, PATCH, and
  DELETE require a matching mutation grant that names both the exact uppercase
  method and allowed path pattern. Redirects are not followed; each redirect
  target must be passed to `ScopeGuard.require_allowed` as a new check.

## Files

- `src/bola_checker/scope.py`: typed scope parser, policy types, and request guard.
- `tests/test_scope.py`: missing-file, confirmation, authorization reference,
  expiry, wildcard, CIDR/resolver, path, method/grant, and userinfo coverage.
- `examples/scope.example.yaml`: documented, intentionally unconfirmed template.

## Validation

Run from the repository root:

```text
uv run ruff check src/bola_checker/scope.py tests/test_scope.py
uv run pytest tests/test_scope.py
```

Results:

```text
All checks passed!
10 passed in 0.04s
```

Additional focused type checking also passed:

```text
uv run mypy src/bola_checker/scope.py
Success: no issues found in 1 source file
```

`uv run mypy src` was also attempted, but currently reports three unrelated
`no-any-return` errors in the concurrently added `src/bola_checker/endpoints.py`.
No phase-0 file was implicated or changed to suppress those errors.

## Concerns

The phase-0 guard intentionally has no HTTP client and does not perform DNS.
Future executors must call it before every request and again before each
redirect hop, supplying a resolver whenever a CIDR policy is configured.

## Fix round 1

- Request URLs now produce an immutable `ScopeDecision`, rather than a
  permission-only result. It contains the canonical URL, normalized hostname,
  method, and resolved IP set. An executor must send exactly the canonical URL;
  if `connect_ips` is non-empty, it must pin the connection to one of those
  addresses and verify the actual connected peer is in that set. Redirects
  always require a new decision.
- Before path matching, the guard rejects raw and recursively percent-decoded
  dot segments, encoded slash or backslash values, literal backslashes,
  controls, malformed percent escapes, and repeated separators. URLs with a
  fragment are also rejected. This prevents routing normalization from turning
  an authorized path into a different endpoint.
- `ScopeGuard` independently reconstructs and validates every public
  `ScopeConfig` invariant on construction, including confirmation,
  authorization reference, UTC validity window, allow-list presence, rule
  types, and mutation grants. `require_in_scope` goes through that same guard.
- The YAML reader is a `SafeLoader` subclass which additionally rejects
  duplicate mapping keys, merge keys, anchors, and aliases. This prevents YAML
  syntax from silently changing the policy that was reviewed.
- Glob compilation is segment-safe: `*` and `?` cannot cross `/`; `**` is the
  only recursive wildcard. Regex rules remain explicitly anchored.

Validation for this fix round:

```text
uv run ruff check src/bola_checker/scope.py tests/test_scope.py
All checks passed!

uv run mypy src/bola_checker/scope.py
Success: no issues found in 1 source file

uv run pytest tests/test_scope.py
29 passed in 0.07s
```

## Fix round 2

- `ScopeConfig` now has private, `init=False` provenance fields. Only
  `load_scope` sets its module-private validation marker, absolute source path,
  regular-file metadata, and SHA-256 digest after the full parse and policy
  validation succeed. `ScopeGuard` validates normal policy invariants first,
  then requires that provenance and rechecks that the file is still a
  non-symlink regular file with the same metadata and bytes. A manually
  constructed, otherwise-valid `ScopeConfig` is therefore rejected.
- Request hostname validation now happens before exact or wildcard matching.
  It rejects percent signs, controls, backslashes, leading dots, empty labels,
  repeated labels/separators, and invalid hostname characters. Exactly one DNS
  root dot is normalized away; multiple trailing dots are rejected. Literal IP
  hosts are parsed directly with `ipaddress`.

Validation for this fix round:

```text
uv run ruff check src/bola_checker/scope.py tests/test_scope.py
All checks passed!

uv run mypy src/bola_checker/scope.py
Success: no issues found in 1 source file

uv run pytest tests/test_scope.py
35 passed in 0.09s
```

## Fix round 3

- Provenance is now revalidated at the start of every `ScopeGuard.require_allowed`
  call, not only while constructing the guard. A scopefile modified, replaced,
  or swapped for a symlink after guard creation fails before URL, host, or
  method authorization proceeds.
- IPv4 literals must have the canonical `ipaddress` form. The guard rejects
  legacy spellings that some socket stacks can reinterpret, including leading
  zero/octal components, hexadecimal values, single-integer forms, and
  shortened dotted forms. Literal IPs still require the existing CIDR policy.
- Policy `allowed_hosts` now uses the same strict validator as request hosts:
  one trailing DNS root dot is normalized, while multiple trailing dots, empty
  labels, and other malformed names are rejected.

Validation for this fix round:

```text
uv run ruff check src/bola_checker/scope.py tests/test_scope.py
All checks passed!

uv run mypy src/bola_checker/scope.py
Success: no issues found in 1 source file

uv run pytest tests/test_scope.py
46 passed in 0.10s
```
