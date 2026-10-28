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
are not supplied here. `KubernetesPhaseGate` supplies the credential/policy/
controller-incarnation part, not a complete `PhaseAuthoritySource` (below).
The admission `Service` supplies a concrete recorder for
its existing live session (below), not permission to resume a writer after
restart. Test authority mocks are not production authorization. No trust key or
release is created by this library.

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

## Concrete active-writer recorder

`Service.RecordPhaseIntent` implements `PhaseIntentRecorder` using only the
attempt's **existing** live admission session. It requires a ready durable store,
the exact current attempt/lease/identity bindings and healthy matching SYSTEM
upgrade execution metadata. It checks those bindings before and after append.
A cancellation or fence change during PUT leaves evidence but returns no receipt
for admitting a phase. The phase ledger still performs its own atomic checks.
`CheckPhaseRecording` is mandatory before the issuer claims a phase and again
before signing: prior intent evidence and healthy metadata alone cannot bypass a
missing/finalized/poisoned live writer. Writer loss after claim leaves it spent
without returning a signature. `Session.CheckRecording` reads the same locked
terminal/poisoned state without writing or reopening anything.
The issuer rejects an already known intent before appending again, including a
row whose earlier commit acknowledgment was lost. Concurrent first submissions
still rely on the ledger's unique transaction; orphan evidence is never authority.

`execution.Session.AppendChunkReceipt` allocates the recording index under the
same lock as append/finalization, hashes an owned copy of the exact plaintext and
returns its recording/index/digest receipt only after the encrypted recorder ACK.
The generic receipt is not a durability or authorization claim; this adapter
independently requires durable storage. Errors, including uncertain S3 ACKs,
poison the session's append path: neither another receipt call nor the ordinary
append path can retry/overwrite that chunk index. Finalization reports
`recording_lost`, not success or ordinary cancellation.

A sibling/restarted service without the original session fails closed. It never
calls `RecordingStore.Begin`, resets indices, rewrites the pending marker or
reconstructs a hash chain from guessed state. There is no distributed recorder
recovery/lease protocol here; that remains a production prerequisite. The
concrete adapter is not connected to a phase route, transport or enabled issuer.

## Live credential and controller-incarnation gate

`KubernetesPhaseGate.Check(ctx, admittedAttempt, trustedJournal, credential)`
performs the concrete Kubernetes/account part of current authority. It returns
only the expected management guest identity, **not permission to sign/install**.
It deliberately does not implement `PhaseAuthoritySource`, and the server does
not construct it for an enabled upgrade path. Inputs must come from trusted
attempt/journal coordination, not an HTTP body or guest self-reported hash.

- Requires a fresh signed credential bound to the admitted actor UID and its
  current authentication method/revision. It calls the existing execution
  authorizer for namespace/workspace execution and elevation, then independently
  requires current administrator authority. A delegated SYSTEM/editor/manage
  grant, stale token role, caller-built `UserInfo`, anonymous/auth-disabled mode
  or durable actor UID alone cannot authorize this check.
- Re-reads account state and honors the existing explicit `AuthConfig.adminEmails`
  override only while it is current. Disabled/deleted/replaced accounts, revoked
  method/password revisions and temporary-password restrictions deny. This adds
  no MFA/recent-auth claim or alternative authentication mechanism.
- Requires current strict default-off upgrade, VM execution and elevation policy.
  It bypasses the ordinary auth/policy caches using fresh auth providers and the
  existing uncached strict policy readers. Cached predecessor signing keys are
  not reused across checks; key rotation may conservatively require fresh sign-in.
- Uses the existing management enrollment resolver for current Workspace/VM UID,
  controller ownership, running state, provisioning markers and acknowledged
  revocation epoch. Stop/reset/delete/reboot/detach and pending revocation deny.
  Scope is the currently qualified `windows11-amd64-v1` profile, not arbitrary
  Linux/generic guests or a newly enabled profile. No QGA/VMI/launcher transport
  is acquired by this gate.
- Rejects mixed AuthConfig/PlatformConfig/User/Workspace UID/resource-version
  snapshots. Credential and policy checks bracket identity resolution; resource
  lookups share a five-second deadline. Missing/unversioned state and outages
  return no identity rather than a last-good result.
- Rechecks admitted plan/actor/VM/epoch/manifest/inventory/reboot bindings, active
  journal action/sequence, stored owner/fence, cancellation and lease/journal/
  credential deadlines, including after cluster reads. These are snapshot checks,
  not a replacement for the ledger's locked authoritative attempt checks.

The credential is call-local: the gate never stores it on an attempt, logs it,
mints worker tokens or substitutes an actor lookup for credential verification.
Recovery must obtain current authority, not reconstruct credentials from metadata.

Still required for a complete production source: publisher/allowlist and payload
approval, exact journal lineage from an independent trusted head, the actual
authenticated guest boot/challenge/API-certificate exchange and live recording
ownership/recovery. Controller identity alone does not prove possession of an
enrolled guest key or a successful mTLS handshake. Nor can these reads guarantee
policy remained unchanged after return: guest-side current authority is mandatory
at the effect boundary. There is no new route, listener, QGA fallback or rollout.

## Automated tests

Ordinary unit tests cover missing trust/durability/recording dependencies,
recording and authority outages, binding/schema denial, protected receipt
substitution, key-copy isolation, signature verification, slow callbacks/commits,
and uncertain-commit replay denial.

`TestKubernetesPhaseGate*` runs in the ordinary race-enabled suite. It exercises
the real credential/provenance validators and Kubernetes resolvers with a fake
dynamic client: administrator/delegation/UID checks, immediate policy/account/
credential/epoch/lifecycle revocation, version changes during reads, lookup
outages, missing metadata and deadlines reached during reads. A test-only issuer
composition proves current revocation prevents claim/signature despite an already
recorded intent. Artifacts, lineage, recording and guest exchange in that
composition remain doubles; these are not live-cluster or enrolled-guest proofs.

With **disposable** PostgreSQL only:

```sh
KW_EXECUTION_TEST_DATABASE_URL='postgres://…' go test -race -count=3 ./internal/execution/storage -run '^TestPostgresUpgradePhasesIntegration$'
KW_EXECUTION_TEST_DATABASE_URL='postgres://…' go test -race -count=3 ./internal/execution/upgrades -run '^TestPostgresPhaseIssuerIntegration$'
KW_EXECUTION_TEST_DATABASE_URL='postgres://…' KW_EXECUTION_TEST_S3_ENDPOINT='http://…' KW_EXECUTION_TEST_S3_ACCESS_KEY='…' KW_EXECUTION_TEST_S3_SECRET_KEY='…' go test -race -count=3 ./internal/execution/upgrades -run '^TestPhaseRecorderPersistentIntegration$'
```

These exercise independent connections/reopen, concurrent claims and actual
signed responses, lost-ACK behavior, global challenge reuse denial, changed
owner/fence/boot/action/plan, cancellation, lease/deadline expiry, stale caller
time, checkpoint regression, recording terminal state and plan/receipt pinning.
In the PostgreSQL-only issuer suite, authority and recorder adapters remain test
doubles; database atomicity and Ed25519 execution are real, not deployed-guest or
encrypted-recorder proof.

The separate `TestPhaseRecorderPersistentIntegration` uses **real** admission,
PostgreSQL, encrypted S3 recording, exact receipts, ledger and signer; only the
live authority/guest exchange remains a double. It independently observes the
encrypted object before signing, then verifies/decrypts the finalized recording
through a newly opened store. Fault tests deny a real PUT or replace only its
successful upstream ACK with an error, prove no receipt/intent/signature and no
retry/overwrite, and check truthful `recording_lost` finalization. Missing writer
after restart, finalized/terminal metadata, altered identity, lease expiry and
cancellation/fence changes during PUT deny. These are disposable storage tests,
not deployed transport/guest acceptance or distributed writer recovery.
Additional cases retain an already recorded intent and healthy metadata while
removing/poisoning the live writer; neither can obtain a signature.
