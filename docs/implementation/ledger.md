# Implementation ledger

- Ruling: the approved plan is corrected before implementation where its own
  safety claims conflict with code snippets. Cost if wrong: small divergence
  from the supplied snippets, in exchange for fail-closed behavior.
- Ruling: credentials are represented by references and held in an in-memory
  vault; SQLite stores no credential values. Cost if wrong: users must reload
  credentials when starting a new process.
- Ruling: concrete object identifiers are process-local inputs; SQLite,
  findings, and audit events retain only deterministic `obj_<sha256>` values
  named `object_ref`. Persisted endpoints contain route syntax and `{id}`
  placeholders only. Cost if wrong: a reopened store cannot reconstruct a raw
  object ID and the executor must receive it again from an authorized capture.
- Ruling: requester identity alone is heuristic ownership and cannot authorize
  a probe. The StateStore pending-work query enforces this independently of
  endpoint correlation. Cost if wrong: fewer automatically generated targets,
  lower false positive and unintended-access risk.
- Ruling: mutation probes require explicit method and path grants; read probes
  remain the default. Cost if wrong: additional setup for write-authorization
  testing, lower chance of altering customer data unexpectedly.
- Ruling: redirects are handled manually and each hop is scope-checked. Cost if
  wrong: some legitimate redirect-heavy APIs need additional allow-list rules.
