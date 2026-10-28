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
configured metadata duration must still cover the recording duration. Recording
expiry alone does **not** delete metadata/audit; that requires the separate opt-in
below. Ephemeral mode rejects both retention switches.
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
  PostgreSQL metadata/audit deletion and backup deletion are outside the
  recording-expiry worker. Optional metadata handling is described below.
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
- Recording expiry retains execution outcomes, all audit events and unique
  execution/recording reservations. Expiry does not let old IDs be re-admitted. **A committed
  plan is irreversible:** disabling the worker or increasing the duration stops
  new plans but cannot reopen partially deleted recordings. Re-enabling resumes
  unfinished plans even under a longer duration.

In-flight requests may already hold verified bytes before expiry; no retention
system can revoke content already delivered. A request racing deletion may fail
closed while reading. Retention is not secure erasure of process memory, backups,
external copies or storage-device remnants.

## Optional metadata/audit retention

This is independently **off by default** and requires recording expiry to be
enabled, together with both of these settings:

```text
KW_EXECUTION_METADATA_RETENTION_ENABLED=true
KW_EXECUTION_RETENTION_METADATA=<explicit positive Go duration, at least recording duration>
```

The metadata worker only selects admitted terminal commands/scripts whose original
recording cleanup **completed**. The execution end time, cleanup completion time
and **every audit event** must be older than the metadata cutoff. A recent replay,
denial, recovery or cleanup audit renews protection for that whole execution; an
old end date alone never permits deleting recent audit evidence. Existing upgrade
attempt/phase/journal references are excluded, even for misclassified legacy
command/script rows. Active, unaudited, shell/upgrade and unfinished recording
cleanup/recovery evidence remain protected. Historical orphan audit rows are not
swept by this worker.

Migration 000008 adds a minimal `execution_identities` ledger and backfills existing
ID pairs without deleting any history. Database triggers reserve IDs for all
writers, including older SQL clients, and serialize audit inserts with purging.
An audit arriving first is visible to the purge's eligibility recheck; one arriving
after deletion fails instead of creating an orphaned event.

Under locked identity/execution rows, one transaction rechecks eligibility,
deletes original execution/audit/recording-expiry rows and writes the system
deletion receipt in `execution_identities`. Failure to write the receipt rolls
back all deletion. Competing purgers and a retry after a lost COMMIT acknowledgement
cannot duplicate or rewrite the receipt. Authorized history/playback of a purged
ID returns not found; the old guest operation is never resubmitted.

**Minimal reservations are retained for the database's lifetime:** execution ID,
recording ID, purge/cutoff/recording-cleanup timestamps, number of audit events
deleted and the constant `system:execution-retention` actor. No original actor,
workspace scope, invocation, result or audit payload is copied there. This receipt
is the audit of `metadata.expired`, not a new orphaned execution-audit row.
The IDs remain correlatable with evidence held elsewhere; this is not complete
anonymization. Plan capacity for this growing minimal ledger. Deleting its entries
would discard replay/ID-reuse protection and is not part of automatic retention.

The metadata worker has the same 16-execution/10-second pass bounds, minute
interval and cancel/join behavior as recording expiry. Failure logs distinguish
`scope=metadata` from `scope=recordings`. Both require deliberate operator policy;
no duration default alone enables either worker.

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

`TestExecutionRetentionIntegration` and the metadata-migration subtest of
`TestPostgresIntegration` require the existing disposable PostgreSQL/S3 test
variables (PostgreSQL alone for the migration proof) and PostgreSQL **CREATE DATABASE**
permission. They create/drop
only its own uniquely named test database and uses its own object bucket, so its
destructive sweep cannot select another test campaign's evidence. Never point
these variables at operational storage or discover credentials from a deployment.

The production HTTP/admission path, real PostgreSQL/S3, audit-failure triggers,
delete-denial proxy, reconstructed coordinator and competing pools are exercised.
Metadata cases explicitly age fixture timestamps; they do not wait out real
retention periods. Tests cover recent/concurrent audit protection, pending cleanup
and upgrade-reference exclusions, atomic receipt rollback, committed deletion with
lost COMMIT acknowledgement (only on explicitly plaintext disposable PostgreSQL),
competing workers, HTTP not-found outcomes, lifetime reservations and legacy SQL
re-admission/orphan-audit denials. A version-7-to-current migration proof checks
backfill, unchanged active create semantics and preservation of historical orphan
evidence while rejecting new orphan events.
Account/policy/guest execution are fixtures: this is not a deployed pod/process
restart or installed-guest acceptance claim. `TestS3Integration/recording-retention`
also checks bounded deletion, exact prefixes and versioned-bucket refusal.
