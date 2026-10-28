# Durable exact-action phase issuer boundary

`PhaseIssuer` composes the signed `updates.PhasePermit` contract with durable
attempt/worker fencing and independently acknowledged protected intent recording.
It is **not constructed by the server**. There is no phase route, management
listener, permissive authority source, automatic upgrade or QGA fallback.

## Mandatory dependencies

- A durable `UpgradePhaseLedger` (PostgreSQL only; no RAM fallback).
- The admitted attempt store and a separately provisioned Ed25519 signing key.
- `PhaseAuthoritySource`: current administrator/workspace access and elevated
  policy, enrollment/VM/epoch/boot, approved verified manifests/predecessor,
  reboot consent/deadline, and exact journal lineage from an independently
  trusted head. It must not approve a guest's self-reported checkpoint hash.
- `PhaseIntentRecorder`: a single-owner protected encrypted recording writer
  that returns an exact recording/chunk-index/plaintext-digest receipt **only
  after durable acknowledgment**. Missing/finalized/lost recordings deny.

The live authority source and recording-writer recovery/reattachment adapters
are not supplied here. Mocks in tests are not production authorization or proof
of a deployed recording pipeline. No trust key or release is created by this
library.

## Recording and issuance order

1. `RecordIntent` strictly decodes the exact active journal checkpoint against
   independently trusted plan/checkpoint digests. Current authority verifies
   its legitimate lineage, not merely structurally valid action fields.
2. Commit those exact bytes through the independent protected recorder. Only
   after its ACK can the ledger persist the receipt and checkpoint. Failure
   may leave orphan recording evidence, never permission to dispatch.
3. The PostgreSQL transaction locks the attempt and linked execution. It checks
   actor/workspace/VM/epoch/manifests/inventory/reboot consent, current owner and
   fence, lease/deadline, cancellation, checkpoint floor and a healthy durable
   SYSTEM-upgrade recording. The first intent pins the complete plan digest.
4. `Issue` loads the exact recorded action; callers cannot choose an action,
   manifest, peer or nonce in the signing call. The required live source repeats
   current authorization and obtains boot ID, guest challenge and certificate
   digest from the authenticated management exchange, not HTTP fields.
5. A second locked transaction rechecks the attempt/recording and exact intent,
   then irreversibly claims the action/challenge. Both the action and guest
   challenge are unique; identical retries conflict. The permit hash/peer/time
   remain in the ledger as evidence. Only a successful commit acknowledgment
   allows a signature to be computed or returned.

The permit expires within 15 seconds and no later than the worker lease or
journal deadline. Database checks sample `clock_timestamp()` **after** row locks,
not transaction-start `now()` or only the caller's pre-lock time. A lock wait
cannot extend an expired lease. Slow commits are checked again before signing.

A lost COMMIT ACK or response never causes a second signature for that action,
even after reopening the ledger. Recovery must reconcile the guest journal and
recording; it must not manufacture a new action/nonce to retry an installer.
Cancellation currently denies all new phase issuance, including cleanup. Any
future narrowly authorized compensation path needs its own explicit contract.

An API signature is not proof that policy remained current after commit: the
guest's durable challenge consumption and live checks are still mandatory at
the effect boundary. This ledger does not execute an installer, rewrite a root,
qualify a driver or establish enrolled-guest health/reboot acceptance.

## Automated tests

Ordinary unit tests cover missing trust/durability/recording dependencies,
recording and authority outages, binding/schema denial, protected receipt
substitution, key-copy isolation, signature verification, slow callbacks/commits,
and uncertain-commit replay denial.

With **disposable** PostgreSQL only:

```sh
KW_EXECUTION_TEST_DATABASE_URL='postgres://…' go test -race -count=3 ./internal/execution/storage -run '^TestPostgresUpgradePhasesIntegration$'
KW_EXECUTION_TEST_DATABASE_URL='postgres://…' go test -race -count=3 ./internal/execution/upgrades -run '^TestPostgresPhaseIssuerIntegration$'
```

These exercise independent connections/reopen, concurrent claims and actual
signed responses, lost-ACK behavior, global challenge reuse denial, changed
owner/fence/boot/action/plan, cancellation, lease/deadline expiry, stale caller
time, checkpoint regression, recording terminal state and plan/receipt pinning.
Authority and protected-recorder adapters remain test doubles; database atomicity
and Ed25519 execution are real, not deployed-guest or encrypted-recorder proof.
