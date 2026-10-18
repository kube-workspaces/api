# CSR-bound bootstrap enrollment ledger

This is an internal enrollment service, production identity resolver, protected
bootstrap importer and storage contract. No HTTP enrollment route, startup CA/
import worker, guest token delivery or guest key persistence is enabled yet.

## Current identity and protected controller bootstrap

`KubernetesResolver` uses uncached dynamic Kubernetes reads with a five-second
deadline, a fresh enabled execution policy, exact Workspace UID, and an exact
controller-owned running VirtualMachine. The VM UID is the management generation:
reset/recreation changes it and ordinary VMI reboot preserves it. Pending
reset/stop/reboot/deletion, changed snapshot resource versions, unknown ownership,
and inconsistent Windows profile provisioning deny. No resourceVersion or
metadata.generation is used as a durable identity. Epoch zero is the explicit
initial contract; nonzero epochs deny until a controller-owned epoch source exists.
`resolver.Authorize` is the production `CurrentIdentity` callback, separate from
end-user execution permission and authenticated guest capability checks.

`BootstrapImporter` reads only an explicitly configured protected control-plane
namespace, never the workspace namespace or a caller-selected Secret name. It
derives the Secret name from current Workspace/VM UIDs and validates immutable
Opaque type, version/identity labels, scope annotations, strict bounded JSON,
token binding and expiry. The controller's opt-in provisioning uses the same
`management-bootstrap-v1.json` fixture. Only then does `Service.Register` import
the token hash into the ledger with a fresh identity check. Legacy desktop tokens
and tenant namespace Secrets are not management authority.

`Register` is idempotent for the same identity/token/expiry and preserves redeemed
CSR/certificate state. It refuses rebinding or expiry extension. Timestamps are
canonicalized to PostgreSQL microsecond precision so restart imports cannot
mistake timestamp rounding for a conflicting token. It is an internal trusted
provisioning operation, not a public token-registration endpoint.

## Issuance and redemption

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
capacity exhaustion denies rather than evicting credentials. Committed token
rows must be retained at least through bootstrap expiry so re-import cannot
reopen a previously consumed credential.

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
