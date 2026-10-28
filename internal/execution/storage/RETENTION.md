# Persistent command/script recording retention

Recording expiry is destructive and **disabled by default**. Duration defaults
alone never enable deletion. To opt in for persistent external/bundled storage,
an operator must configure both:

```text
KW_EXECUTION_RETENTION_ENABLED=true
KW_EXECUTION_RETENTION_RECORDINGS=<explicit positive Go duration>
```

Select the duration under the operator's approved evidence/custody policy. This
document does not approve the proposed 720h default as a permanent policy. The
configured metadata duration must still cover the recording duration, but **no
metadata/audit deletion is implemented**. Ephemeral mode rejects this opt-in.
This API-level switch is not a dedicated Helm values field yet; coordinate any
operator-controlled deployment overlay/chart adoption separately. Existing chart
duration settings do not enable the worker.

## Scope and safety

- Only admitted **command/script** executions with a committed terminal state,
  end time older than the cutoff, and matching original-actor `finished` audit
  qualify. Unknown stays unknown; expiry never reports guest success or reruns
  anything. Age is measured from the original execution end, not recovery time.
- Active/admitted/running work and sealed-but-unreconciled terminal evidence are
  never reaped. Shells, upgrades, orphan cleanup, incomplete/unaudited outcomes,
  PostgreSQL metadata/audit deletion and backup deletion are outside this slice.
- A transaction locks/rechecks the execution and commits a permanent recording
  expiry fence plus `recording.expiry_started` audit **before** any S3 deletion.
  Protected API replay observes that shared fence on every request, even if
  object deletion fails. Authorized expired playback returns 404 with
  `recording expired by retention`; it is not mislabelled as corrupt recording or
  guest/transport loss. Unauthorized callers still receive authorization denials.
- Cleanup removes at most 128 current objects per recording per pass, beneath
  exactly `executions/<recording-id>/`. It checks identifiers/prefixes and preserves
  similarly named neighboring recordings. A durable marker allows restart/retry
  and competing replicas without duplicate audit or a new guest invocation.
- Only after deletion finishes does another transaction commit completion and
  `recording.expired` audit. Database/audit/S3 failures leave cleanup pending and
  replay fenced. A lost acknowledgement is not authority to bypass that fence.
- Existing execution outcomes, all audit events and unique execution/recording
  reservations remain. Expiry does not let old IDs be re-admitted. **A committed
  plan is irreversible:** disabling the worker or increasing the duration stops
  new plans but cannot reopen partially deleted recordings. Re-enabling resumes
  unfinished plans even under a longer duration.

In-flight requests may already hold verified bytes before expiry; no retention
system can revoke content already delivered. A request racing deletion may fail
closed while reading. Retention is not secure erasure of process memory, backups,
external copies or storage-device remnants.

## Storage prerequisites and rollout

1. Upgrade **every API replica** to a binary that understands migration 000007 and
   the shared replay fence **before** enabling retention. The migration only adds
   tracking state; upgrading alone does not delete data. Do not roll back to a
   fence-unaware reader after any expiry plan commits.
2. Use a dedicated **unversioned** recording bucket. Cleanup checks bucket
   versioning before and after deletion and refuses enabled/suspended versioning
   instead of silently leaving old sensitive object versions behind. Object locks,
   versioned retention and backup policy need a separate operator-owned design;
   the worker never changes bucket policy.
3. Grant the API narrowly scoped bucket versioning-read, prefix list/read/write
   and object delete permissions. Missing permissions/storage failures do not
   claim cleanup completed. Failed attempts may already have committed logical
   expiry; fix storage/permissions without removing markers or reopening evidence.
4. Select an explicit duration and opt in through the deployment configuration.
   The worker starts with an immediate bounded pass, then every minute, with a
   10-second budget and at most 16 executions per pass. It keyset-paginates over
   failures/pending work so one record cannot starve later candidates. Shutdown
   cancels/joins the worker before closing storage.
5. Verify protected playback before expiry, explicit expiry afterward, retained
   metadata and both system audit events. Inspect pending markers and counts-only
   `executions.retention` failure logs. Recording admission/storage readiness is
   not a claim that retention cleanup or deployed acceptance has passed.

Do not retire an encryption key until all evidence, pending recovery, excluded
operation types and backup/rollback requirements that need it have been reviewed.

## Opt-in test proof

`TestExecutionRetentionIntegration` requires the existing disposable PostgreSQL/S3
test variables and PostgreSQL **CREATE DATABASE** permission. It creates/drops
only its own uniquely named test database and uses its own object bucket, so its
destructive sweep cannot select another test campaign's evidence. Never point
these variables at operational storage or discover credentials from a deployment.

The production HTTP/admission path, real PostgreSQL/S3, audit-failure triggers,
delete-denial proxy, reconstructed coordinator and competing pools are exercised.
Account/policy/guest execution are fixtures: this is not a deployed pod/process
restart or installed-guest acceptance claim. `TestS3Integration/recording-retention`
also checks bounded deletion, exact prefixes and versioned-bucket refusal.
