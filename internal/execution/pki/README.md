# Management PKI and mutual-TLS contract

This package supplies a dedicated certificate issuer and Go TLS reference
configuration. It is not a public enrollment route, a guest listener or authority
to execute processes. The Rust guest still needs its TLS integration.

## Issuance and identity

An operator provisions a dedicated management CA certificate and private signer;
the package never auto-generates a production root or uses session/display keys.
The issuer must receive enrollment authorization from a one-use server-side
credential reservation and a fresh workspace incarnation lookup. Existing
desktop enrollment tokens consumed locally are not accepted as such authority.
Guest private keys remain on the guest; issuance receives a signed CSR only.

CSRs prove possession of an Ed25519 or P-256 key and must not request a subject,
SAN or extensions. Issuance rejects requested identities rather than trusting or
silently copying them. The server selects the identity from current provisioning
state. A CA key cannot also be issued as a guest/API leaf key.

Guest leaves have a single URI SAN:

```text
spiffe://kubeworkspaces.io/management/v1/workspaces/{namespace}/{name}/{uid}/{generation}/{revocation_epoch}
```

They have server-auth purpose only and the fixed DNS SAN
`management.workspace.internal`. That verification name is not a dial address;
the API still discovers/dials the workspace endpoint independently. Go's normal
CA, DNS, expiry and signature verification remains enabled, followed by exact URI
identity matching. The URI scheme is an identity convention, not a dependency on
a SPIFFE control plane or proof of SPIFFE deployment.

API leaves have client-auth purpose only and one URI SAN:

```text
spiffe://kubeworkspaces.io/management/v1/apis/{replica_id}
```

Identity components are bounded ASCII identifiers (letters/digits/dot/underscore/
hyphen), never URI-escaped paths, queries or fragments. Epochs are canonical
unsigned decimal. The lifetime is explicitly selected between one minute and one
hour, with at most 30 seconds of issuance backdating and no extension beyond the
issuer expiry. Provisioning and policy revocation remain necessary even while a
certificate is cryptographically valid.

## Transport verification

Both reference configurations require TLS 1.3 and ALPN `kw-management/1`, an
explicit management CA bundle and purpose-correct local credentials. System/web
trust roots, anonymous clients, desktop protocol fallback and TLS resumption are
not used. A missing current-authorization callback is a configuration error.
Root rotation can explicitly overlap old/new CAs; removing a root denies its
certificates on the next full handshake.

Each successful handshake additionally invokes current authorization: the API
must resolve the guest UID/generation/epoch and the guest must validate the API
replica's current authority. Lookups must use bounded deadlines and fail on
outage. A fixed `allow` callback is appropriate only in synthetic tests; chain
validation alone does not fence reset, deleted or revoked identities.

`APIClientFingerprint` and `VerifiedAPIFingerprint` derive the same SHA-256 of the
API certificate DER. This is the value bound into management grants. The guest
must derive it from its successfully verified TLS peer, not an operation field.

Handshake authentication does not authorize a process or an unlimited session.
The transport integration must preserve a fresh challenge/replay verifier per
connection, bound frames and deadlines, recheck grants/epochs during execution,
and close/fence sessions at certificate expiry or revocation. Mandatory recording
admission remains a separate gate.

## Remaining enrollment integration

One-use credential provisioning/redemption must be shared across API replicas,
bound to current workspace UID/generation, expiry and the guest CSR public key.
Persist an issued result for same-CSR retry without issuing a second identity;
reject another CSR, reset or deleted workspace. Implement rotation/renewal and
guest machine-protected key storage before exposing enrollment or a listener.
Keep CA/private keys in Secret/HSM references and only public roots/verification
keys in image trust material. No image-wide or desktop bootstrap credential is a
management issuance bypass.

```sh
go test -race ./internal/execution/pki
```

Tests perform real mutual-TLS exchanges and cover identity substitution, reset,
epoch revocation, authorization outage, wrong CA/purpose, anonymous clients,
expiry, TLS downgrade, ALPN mismatch, CSR proof/SAN injection and root rotation.
