# Implementation ledger

- Ruling: the approved plan is corrected before implementation where its own
  safety claims conflict with code snippets. Cost if wrong: small divergence
  from the supplied snippets, in exchange for fail-closed behavior.
- Ruling: credentials are represented by references and held in an in-memory
  vault; SQLite stores no credential values. Cost if wrong: users must reload
  credentials when starting a new process.
- Ruling: requester identity alone is heuristic ownership and cannot authorize
  a probe. Cost if wrong: fewer automatically generated targets, lower false
  positive and unintended-access risk.
- Ruling: mutation probes require explicit method and path grants; read probes
  remain the default. Cost if wrong: additional setup for write-authorization
  testing, lower chance of altering customer data unexpectedly.
- Ruling: redirects are handled manually and each hop is scope-checked. Cost if
  wrong: some legitimate redirect-heavy APIs need additional allow-list rules.

