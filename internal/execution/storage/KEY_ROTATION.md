# Persistent recording key rotation

External and bundled storage accept either the original base64-encoded 32-byte
recording key or a versioned JSON keyring in the same Secret-mounted file named
by `KW_EXECUTION_RECORDING_KEY_FILE`:

```json
{
  "version": 1,
  "active": "<base64-encoded 32-byte active key>",
  "previous": ["<base64-encoded 32-byte read-only key>"]
}
```

The placeholders are not valid keys. Generate keys using an approved secure
source and keep every value in the operator's Secret/key-custody system, never
Git, command-line arguments, ordinary logs or screenshots. The existing Helm
Secret reference/mount can carry this file unchanged; no new environment setting,
chart release or inline Helm value is required by this format extension.

The keyring has exactly one active key and at most eight distinct read-only keys.
`previous` can be omitted or empty. Its entries may also stage a **future** writer
key for the overlap described below. Key IDs are derived fingerprints, not
operator-supplied aliases. Duplicate fields/keys, unknown fields/versions, malformed
keys, trailing JSON and files over 16 KiB are rejected without echoing file content.
Ephemeral storage does not use persistent read-only keys.

## Coordinated rolling rotation: A to B

1. **Upgrade every API replica to a keyring-capable binary first**, retaining the
   existing single-key file A. Older binaries do not parse JSON keyrings.
   Coordinate normal API/guest availability and execution-history compatibility
   separately; this procedure does not authorize a deployment restart.
2. Generate and securely retain B. Update the mounted file to `active=A`,
   `previous=[B]` (plus any older still-needed keys), then roll **every** replica.
   Verify that all readers/recovery workers have that configuration before B can
   become a writer key. Keys are read at process startup, not hot-reloaded.
3. Update to `active=B`, `previous=[A]` (plus older needed keys) and roll replicas.
   During the overlap A writers read B and B writers read A. Already-open writers
   remain pinned to their original active key and may finish under A. Verify a
   new B recording, protected playback of A/B recordings and terminal recovery.
4. If rollback is necessary, roll to `active=A`, `previous=[B]` while retaining all
   older needed keys. Do not roll back to a binary without keyring support or
   remove B after it has written recordings. This is a key-policy rollback, not
   an instruction to rerun interrupted commands.
5. Retire A only after confirming that no retained recording, pending terminal
   recovery, in-flight old writer, backup/restore requirement or rollback window
   still needs it. Retention deletion/enforcement is separate and currently not
   implemented: a configured retention duration is not proof of deletion.

Keep the keyring within its bound; plan custody/retention before accumulating more
rotations. Never silently discard an old key to make a deployment start.

## Security and evidence limits

- Each writer uses only its active key for AES-GCM chunks, authenticated manifests
  and encrypted terminal recovery intent. Read-only keys never select a new
  writer's key. Existing v1/v2 recording formats and key IDs remain unchanged;
  rotation does not re-encrypt or rewrite old objects.
- A manifest's untrusted key ID selects only a locally configured key. The selected
  key must authenticate that exact manifest, recording ID and complete chunk chain.
  Unknown IDs, substituted known IDs, missing retired keys or corrupt content fail
  closed; there is no trial-key, unauthenticated, external-key-fetch or plaintext
  fallback. Terminal intent remains subject to full verification/admission matching.
- Missing an old key prevents replay/recovery of that evidence; it does **not**
  fabricate a terminal outcome, rerun a guest command or globally disable unrelated
  new active-key admissions. Restore the correct retained key through custody.
- Key rotation is not deletion, retroactive revocation of a disclosed key, guest
  management PKI rotation or a storage/guest security assessment. A disclosed key
  requires incident response and consideration of backups and prior evidence.

Opt-in disposable-store tests run in the existing `TestS3Integration` key-rotation
subtest and `TestExecutionPostgresOutageIntegration/during-result-key-rotation`.
They cover legacy/v2 replay, old/new writers, key retirement/substitution denials,
and HTTP replay plus terminal reconciliation after actual PostgreSQL connection
loss under a new active key. Account/policy/guest execution are fixtures; this is
not deployed rollover or installed-guest acceptance.
