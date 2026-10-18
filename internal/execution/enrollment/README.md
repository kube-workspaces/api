# CSR-bound bootstrap enrollment ledger

This is an internal enrollment service and storage contract. No HTTP enrollment
route, controller token staging or guest key persistence is enabled yet.

`Service.Mint` is a trusted provisioning operation, not an end-user permission.
It checks current workspace identity/policy and creates a random 256-bit bootstrap
token with an explicit lifetime of at most 15 minutes. Only the token's SHA-256
hash and exact workspace namespace/name/UID/provisioning generation/revocation
epoch are stored. The raw token must be staged per clone through a trusted path
and never logged; existing locally consumed desktop tokens are not interchangeable.

`Service.Enroll` accepts that token and an exact CSR. It checks current identity,
bootstrap expiry and CSR proof of possession, issues a candidate via the dedicated
management CA, and atomically commits the first CSR hash and certificate result.
Another CSR/key is denied. Concurrent callers for the same CSR receive the exact
same persisted certificate, including through separate PostgreSQL-backed API
replicas; they do not receive separately issued candidate identities.

Retries still require the original unexpired token, current workspace identity
and an unexpired issued certificate. A bootstrap retry is not a renewal flow.
The service rechecks current identity and the trusted clock after commit before
returning, so reset/expiry during issuance withholds the result. Subsequent mTLS
authorization independently fences stale identities; a certificate signature is
not authorization to an old generation. Guest private keys never enter the ledger.

`storage.NewPostgresEnrollment` applies shared embedded migrations and never falls
back to process memory. The separate bounded memory implementation is for tests
and explicitly process-local control state; it is not replica-safe/durable
issuance. Ledger cleanup/retention is a remaining integration responsibility;
capacity exhaustion denies rather than evicting credentials.

Before exposing enrollment, integrate controller-owned per-clone provisioning,
an authenticated/pinned bootstrap transport, management CA custody, bounded
request/deadline/rate controls and machine-protected guest keys. Current-identity
callbacks must perform fresh authoritative lookups and fail closed on outages.
Renewal must authenticate the enrolled machine rather than reusing bootstrap
authority. Execution grant/recording admission remains separate from enrollment.

```sh
go test -race ./internal/execution/enrollment ./internal/execution/storage
KW_EXECUTION_TEST_DATABASE_URL='postgres://test:test@127.0.0.1:15432/test?sslmode=disable' \
  go test -race ./internal/execution/storage -run TestPostgresEnrollmentIntegration
```

The integration check uses a disposable database and two independent connection
pools to exercise identical-CSR retries, competing CSR groups, expiry and full
unsigned-64-bit revocation epochs. It does not use deployment credentials.
