# Agent update contracts — offline verification foundation

`updates.Verify` and workspace-agent's `kw_management::updates::verify` verify
the same publisher-signed manifest contract. These libraries implement no
download, installation, grant issuance, listener, availability endpoint or live
upgrade capability. A valid signature is artifact authenticity, not permission
to execute an updater. Production publisher-key custody and management/job/
recording integration remain separate prerequisites.

## Trust and byte framing

Callers supply an independently configured publisher public-key ring (1–16
Ed25519 public keys), key ID, expected manifest SHA-256 and detached signature.
The manifest cannot supply trust roots, expected digest or a download URL.

- Key ID: first 16 bytes of SHA-256(public key), lowercase hex (32 characters).
- Manifest digest: SHA-256 of the **exact raw JSON bytes**, lowercase hex.
- Signature: Ed25519 over ASCII `kw-agent-update-manifest/v1`, one NUL byte,
  then those raw manifest bytes. Do not reserialize before verifying. Whitespace
  changes require a different signature and independently approved digest.
- Signature/public-key byte inputs are raw 64/32-byte values. The shared fixture
  metadata encodes them as canonical, unpadded base64url for test transport.

The signed test fixtures are pinned to LF by `.gitattributes` in both repos;
Windows checkout must not rewrite their bytes. Runtime verification never
normalizes line endings or whitespace to make a changed signature pass.

Use a dedicated publisher key, independent of API grant and management CA keys.
Rotation is an explicit operator keyring update; retiring a key denies manifests
signed by it. There is no key fetch, algorithm negotiation, unsigned mode,
trust-on-first-use or implicit operating-system trust fallback.

## JSON schema and bounds

`testdata/manifest-v1.json` shows the complete wire schema, including optional IDD
metadata. Required objects/fields must be present and non-null; `driver` may be
omitted or null. `rollback_predecessors` must be an array (empty is allowed),
never omitted/null. Field names are exact and case-sensitive. Both implementations
reject unknown/duplicate fields, including escaped duplicate aliases, invalid
UTF-8, trailing JSON and noninteger numeric fields.

- Manifest: at most 64 KiB; version exactly 1; OS `windows`, architecture `amd64`.
- Target IDs and artifact filenames: 1–128 ASCII lowercase letters/digits plus
  `.`, `_`, `-`, beginning with a letter/digit. Filenames are basenames, reject
  trailing dots and Windows reserved device stems (`con`, `nul`, `com1`, …).
  Paths, drive prefixes, alternate streams and URLs are not accepted.
- Artifact sizes: 1 byte–2 GiB, hashes exactly 64 lowercase hex characters.
  MSI/updater/IDD package suffixes are `.msi`, `.exe`, `.zip` respectively.
- Agent versions and compatibility bounds: canonical numeric `major.minor.patch`,
  no prefix/prerelease/leading zero; major/minor ≤255, patch ≤65535 (MSI bounds).
  Minimum installed version must not exceed maximum. Driver version uses four
  canonical numeric uint16 components.
- MSI ProductCode: canonical lowercase nonzero GUID without braces. UpgradeCode
  is fixed to the agent's stable `f72bb43e-dba8-4dbb-a963-b201e6c0d885`, distinct
  from ProductCode. The eventual installer must check actual registration too.
- Updater protocol is 1. Management/desktop compatibility ranges are positive,
  ordered and bounded to 64. These are declarations, not observed capabilities.
- Optional IDD requires package identity/hash, signing-certificate SHA-256 and
  1–8 exact, case-insensitively unique ASCII hardware IDs (≤128 bytes, letters,
  digits, `_`, `.`, `&`, `-`, `\`, with a `\`). No wildcard device selection.
- At most 16 rollback predecessors: unique target IDs **and** manifest digests,
  no self-target. Reboot policy: `never` or `may-require`; actual reboot still
  requires separate administrator consent and installed-device evidence.

The verifier does not prove Windows package signatures, archive contents, IDD
qualification, guest version compatibility, target allowlisting/revocation or
rollback safety. Those checks belong to the eventual availability/admission and
independent updater implementation. Publisher-signed metadata alone never makes
an arbitrary driver safe to install.

## Payload verification

A verified manifest retains its own immutable artifact identities. Go metadata
access returns a deep copy; Rust returns a shared immutable reference.
`VerifyArtifact`/`verify_artifact` selects an exact signed filename and streams
at most its signed size **plus one byte** into SHA-256. It rejects missing,
oversized, truncated, corrupt and unknown payloads, including I/O errors after
the expected bytes. It does not buffer an entire MSI or open paths/URLs.

## Test vectors

The manifest and signature JSON are byte-identical to
`workspace-agent/kw-management/tests/testdata/manifest-v1*.json`. Tests on both
sides verify publisher signature/digest and the streams `msi-v1`, `helper-v1`,
`idd-v1`. These are synthetic bytes, **not installers or a release**. The fixture
key is deterministically derived from the public test seed `[0x55; 32]`; it must
never be deployed as publisher trust.

Regression tests re-sign malformed schemas with that synthetic key so validation
is exercised independently from signature failure. They cover substitution,
domain confusion, duplicate/unknown/case-confused fields, Windows path/device
names, numeric bounds, rollback ambiguity, payload loss/flood and mutable-copy
isolation. Go additionally supplies a signed-parser fuzz target.

## Authenticated machine inventory

`VerifyInventory` and Rust `kw_management::updates::inventory::verify`
authenticate `management.inventory.v1`. The exact payload bytes are signed
under ASCII `kw-management-inventory/v1` plus one NUL with a pinned agent
identity keyring, then bound to the independently minted 256-bit nonce and a
60-second freshness window with no future skew. The verified payload SHA-256 is
the inventory digest later pinned as `expected_installed_inventory_sha256`.

The schema (`testdata/inventory-v1.json`) carries namespace/name, workspace and
VM UIDs, revocation epoch, OS/architecture, inventory timestamp/nonce, agent
version and build digest, supported management/updater protocol ranges,
registered MSI ProductCode/UpgradeCode/version/install-directory entries
(exactly one agent UpgradeCode registration, at most eight), the optional IDD
package/INF/device/driver-version identity, pending-reboot state and the
optional updater journal/active-attempt observation. Every string field is
ASCII-bounded and both verifiers require a byte-identical canonical re-encode,
so Go and Rust accept exactly the same byte set; an absent driver or attempt
section must appear as explicit JSON null.

Inventory is signed evidence, never upgrade authority: availability comparison,
start-time re-read and admission remain separate. The fixture bytes are
byte-identical to workspace-agent's `tests/testdata/inventory-v1*.json` and are
signed by the synthetic test seed `[0x5A; 32]`, never a deployed identity.
