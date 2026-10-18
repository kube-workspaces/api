# Opt-in management issuer runtime

This runtime loads the dedicated management CA, opens the shared bootstrap
issuance ledger and runs trusted protected-namespace imports. It is wired into
API startup, but **does not expose a public enrollment route or enable guest
execution**. Protected guest key/token delivery and an authenticated bootstrap
transport remain required.

## Configuration

| Environment variable | Contract |
|---|---|
| `KW_MANAGEMENT_ISSUER_ENABLED` | Explicit boolean opt-in; defaults false. |
| `KW_MANAGEMENT_CA_CERT_FILE` | Absolute clean path to issuer-first CA PEM chain (at most 8 certificates / 128 KiB). |
| `KW_MANAGEMENT_CA_KEY_FILE` | Absolute clean path to one unencrypted PKCS#8 Ed25519 or P-256 CA key (at most 16 KiB), mounted from a protected Secret. |
| `KW_MANAGEMENT_TRUST_ROOTS_FILE` | Absolute clean path to explicit management CA trust bundle; no system/web-root fallback. May point to the issuer certificate file for a self-signed root. |
| `KW_MANAGEMENT_BOOTSTRAP_NAMESPACE` | Protected namespace matching controller provisioning; never a workspace namespace. |
| `KW_MANAGEMENT_CERT_TTL` | One minute through one hour; defaults to `10m`. |

Credential locations/settings without explicit enablement are rejected. Disabled
startup does not read credential files, open a ledger or launch an issuer worker.
Kubernetes projected Secret symlinks to regular files are supported. Private keys
are never generated automatically or accepted inline through environment values.
Config/runtime/authority formatting redacts private material and locations.

The present issuer requires execution storage mode `external` or `bundled`, a
durable PostgreSQL enrollment ledger and ready recording storage. It never falls
back to the process-local ledger. Recording persistence and issuance replay
defense are distinct: until a replica-safe alternative ledger exists, ephemeral
recording deployments cannot enable this issuer. Forgetting redeemed tokens on
restart would permit another CSR to enroll.

Explicitly enabled startup rejects missing/malformed keys, wrong key/certificate
pairs, wrong CA purpose/trust, insufficient remaining CA lifetime, disabled or
unavailable authentication, unavailable recording storage or ledger initialization
failure. The enabled execution policy is checked during readiness and every
scope-bound import/issuance; disabling it fences operations without requiring an
API restart. Normal disabled deployments retain their ordinary API behavior.

## Key custody and trust rotation

The signing key remains inside the API issuer process and its protected Secret
mount. The issuer certificate/chain and trust bundle contain public material only.
Both server-auth and client-auth chain purposes are checked at startup/current
time and at the end of the configured leaf lifetime, including intermediate/root
expiry. Returned certificates are checked against current trust, requested CSR
public key and exact current guest identity before handoff.

Rotation is an operator-coordinated Secret/root update and process restart; this
runtime does not silently reload keys or auto-generate replacements. Overlap old
and new trust/issuer chains when existing credentials must remain usable. An old
persisted certificate outside current trust is denied, never replaced by another
identity through the same bootstrap token. HSM-backed signer integration and
renewal remain separate work.

## Background import and readiness

The informer lists/watches only the configured namespace with the management-v1
bootstrap label. Its transform retains only selected identity metadata; raw
`data`, `stringData`, unrelated annotations and token bodies are not cached.
Deduplicated workspace keys trigger a fresh `BootstrapImporter` read and current
Workspace/VM/policy checks. Temporary failures retry at most five times and then
wait for a metadata event or the one-minute resync. Denied/expired material is not
renewed or repeatedly treated as an infrastructure error.

Initial cache synchronization has a 30-second bound; failure stops the configured
worker/API instead of advertising readiness. The runtime reports ready only after
initial sync and while authentication, policy, CA trust/lifetime, recording and
ledger prerequisites pass. Readiness does not promise every token was imported or
that a guest is capable of execution. The existing authenticated
`GET /v1/executions/status` adds `issuer_ready` for this distinction.

`Runtime.Enroll` is an internal transport boundary: it re-imports current protected
material on demand, resolves expected scope independently, and calls CSR-bound
issuance. It rejects a token used through another workspace/incarnation before
the token can be spent. Results contain only the public leaf/issuer chain/trust
bundle and are withheld if prerequisites disappear during issuance. No HTTP
handler, user-session bypass or plaintext/diagnostic enrollment path is added.

Shutdown cancels the worker, stops informer/queue goroutines and closes its owned
ledger once. Recording storage and Kubernetes/auth clients remain caller-owned.

## Verification

```sh
go test -race ./internal/execution/management
KW_EXECUTION_TEST_DATABASE_URL='postgres://test:test@127.0.0.1:15432/test?sslmode=disable' \
  go test -race ./internal/execution/management -run TestRuntimePostgresIntegration
```

Tests cover opt-in/mode rejection, credential parsing/pairing/expiry/trust,
metadata-only cache transformation, initial sync failure, issuance and wrong-scope
denial, loss of auth/policy/recording/ledger/current identity, orderly shutdown,
and two independently opened issuers sharing exact-CSR retries in PostgreSQL.
