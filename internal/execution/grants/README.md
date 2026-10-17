# Management-v1 grant foundation

This package is an API-side issuer and reference verifier. It is **not yet wired
to a guest listener or a public execution-start route**. Enrollment, certificate
issuance, mTLS peer validation, guest-side implementation, live policy/epoch
updates and runner integration remain separate prerequisites.

## Envelope

The token is a compact JWS with unpadded base64url segments:

```text
base64url(header JSON).base64url(claims JSON).base64url(Ed25519 signature)
```

The signature covers the exact first two encoded segments and separator.
Header values are `alg: EdDSA`, `typ: kw-management-grant+jwt`, and `kid` equal
to the first 16 bytes of SHA-256 of the Ed25519 public key, lowercase hex.
Verification keys are explicitly pinned; there is no URL/key discovery,
symmetric verification, unsigned mode or desktop-ticket compatibility.

Claims have `version: 1`, issuer `kube-workspaces-api/management/v1`, audience
`kube-workspaces/management/v1`, random 256-bit `jti`, integer Unix `iat`/`exp`,
and a `binding` object. Lifetime is at most 60 seconds. Expiration is exclusive;
future-issued tokens are rejected without a clock-skew allowance.

The binding carries immutable actor UID; namespace, workspace name/UID and
provisioning generation; execution/recording IDs; command/script/shell operation;
OS identity and independent elevation flag; policy version and revocation epoch;
fresh 256-bit guest challenge; SHA-256 of the mTLS API peer certificate DER; and
SHA-256 of the exact framed operation request. These digests are lowercase hex.
An ordinary grant cannot target `root`, UID `0` or `SYSTEM`. The guest must also
resolve actual OS identity and enforce privilege boundaries; string validation
does not replace OS token/account validation.

## Issuance and consumption

Only the API holds the dedicated management private key. Guests receive public
keys, including overlapping keys during rotation. Removing a key rejects its
grants immediately on the next verification with the updated key ring.
Management keys must not reuse session HMAC secrets or desktop grants.

Issuance follows current user/policy evaluation, guest capability validation and
successful mandatory recording admission. This package intentionally performs
none of those upstream decisions and grants no authority by itself.

The verifier compares the *complete* signed binding with independently obtained
expected values before consuming a grant. Workspace identity/generation and
revocation epoch come from guest enrollment and authenticated current state;
the peer fingerprint comes from validated mTLS; the guest generates its challenge
for each connection; request bytes come from the actual framed operation. Copying
the token's claims into expected values would defeat the binding.

Consumption is single-use and atomic, with a bounded replay cache. At capacity,
unexpired entries are retained and new grants are denied. A connection must keep
its verifier for the lifetime of its challenge; disconnect/restart generates a
new challenge. Recreating an empty cache with an old challenge is prohibited.
Distributed job idempotency/leases remain necessary in addition to this
connection-local replay defense. Long-running process/shell authorization needs
fresh grants and live revocation fencing; a consumed start grant is not an
unlimited session lease.

## Checks

```sh
go test -race ./internal/execution/grants
go test ./internal/execution/grants -run '^$' -fuzz FuzzConsume -fuzztime 5s
```
