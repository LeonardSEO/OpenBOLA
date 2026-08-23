# Authorized use only

BOLACheck is intended only for systems you own or are explicitly authorized
to test. A run must start from a scope document containing:

- the client or system owner;
- a non-empty authorization reference;
- `confirmed: true`;
- allowed hosts and/or CIDR ranges;
- allowed path patterns;
- a time window;
- optional mutation grants.

The default policy permits non-mutating probes only. `POST`, `PUT`, `PATCH`,
and `DELETE` require an additional mutation grant that explicitly lists both
the HTTP methods and path patterns. The executor must fail closed if policy
is missing, expired, ambiguous, or does not match a redirect target.

Do not use BOLACheck for unsolicited scanning, credential attacks, persistence,
data extraction, destructive actions, denial of service, or bypassing access
controls outside a signed test scope.

