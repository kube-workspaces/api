# Kube Workspaces API

![License](https://img.shields.io/github/license/kube-workspaces/api)
![Go Version](https://img.shields.io/github/go-mod/go-version/kube-workspaces/api)
![Release](https://img.shields.io/github/v/release/kube-workspaces/api)
![CI](https://img.shields.io/github/actions/workflow/status/kube-workspaces/api/ci.yml?label=ci)
![Docker Image](https://img.shields.io/github/actions/workflow/status/kube-workspaces/api/docker.yml?label=docker)

REST API service for managing Kubernetes workspaces, built with the [Goa](https://goa.design) framework.

## Overview

The API provides:
- **Workspaces** - CRUD, start/stop/reset/reboot, logs, events, pod details
- **Volumes** - PVC management (create, list, delete)
- **Images** - List available workspace images with proxy configuration
- **SshKeys** - CRUD of user SSH public keys (used to seed VM guest access)
- **Namespaces** - List available Kubernetes namespaces (supports `_all` for cross-namespace listing)
- **Proxy** - Reverse proxy to workspace web UIs with WebSocket support
- **Console/exec bridges** - WebSocket bridges to workspace terminals, VM serial
  consoles, VM noVNC displays, and web SSH sessions (single-session with take-over)
- **Admin** - Raw CRD browsing endpoints
- **Health** - Health check endpoint
- **OpenAPI** - Auto-generated OpenAPI 3.0 spec (JSON and YAML)

## Workspace volume mount modes

Each `volume_mounts` entry accepts `readonly: true` or `readonly: false`.
When omitted, container PVCs and VM data disks are writable; VM CD-ROMs default
to read-only. This mount setting is separate from the PVC access mode
(`ReadWriteOnce`, `ReadWriteMany`, or `ReadOnlyMany`).

Home/profile volumes used by an application's permission-fix init container must
be writable: running `chown` as root cannot modify a read-only mount. Inherited
init-container mounts follow the main container's mount modes, including edits.
Auxiliary mounts such as `/dev/shm` are retained when editing PVC attachments.

The corrected default applies to new requests. Existing Workspaces that already
store `readOnly: true` retain that setting until explicitly changed; it is not
safe to assume every existing read-only mount was accidental.

## VM access

For `spec.type: vm` workspaces the API bridges WebSockets to KubeVirt
subresources (and guest sshd), using a session registry so each bridge is
single-session with an idle TTL and take-over consent:

- `GET /v1/workspaces/{name}/console` — serial console (`.../virtualmachineinstances/{name}/console`)
- `GET /v1/workspaces/{name}/vnc` — noVNC display (`.../virtualmachineinstances/{name}/vnc`)
- `GET /v1/workspaces/{name}/ssh` — web SSH into the guest (dials the workspace
  Service; the browser supplies the private key transiently)
- `GET/POST .../console/status`, `.../console/takeover`, `.../ssh/status`,
  `.../ssh/takeover` — session status + take-over
- `POST /v1/workspaces/{name}/reboot` — delete the VMI (persistent root disk preserved)

## Authentication configuration availability

Unauthenticated mode requires an existing `AuthConfig` named `default` with
`spec.enabled: false`. A missing or unreadable AuthConfig, a missing/non-boolean
`spec.enabled`, or an enabled configuration whose session signing key cannot be
loaded does **not** disable authentication. Protected requests and `/auth/me`
return `503` with error `auth_unavailable` when configuration resolution fails.

Configuration results, including failures, are cached for 30 seconds. After a
failed refresh, stale configuration is not used to authorize requests. The last
good signing-key state is retained internally so normal key-rotation continuity
is preserved when configuration access recovers. Health, public version/schema
and authentication routes remain reachable; authentication handlers validate
their own prerequisites.

Authenticated requests require a current, enabled User CR. Its current role and
namespace access replace stale token authorization data; configured admin emails
remain an explicit override but cannot bypass a missing/disabled account. OIDC
users must be pre-provisioned or successfully auto-provisioned before sign-in.
New login credentials include the User UID, preventing them from adopting a
replacement account with the same email. Legacy credentials remain accepted by
existing routes but cannot authorize agent-backed machine execution.

### Scoped VM execution authorization foundation

`User.spec.executionGrants` holds administrator-managed, additive grants with an
exact `namespace`, optional exact `workspaces`, `permissions`, and optional
RFC3339 `expiresAt`. Grants do not create namespace membership. Supported names:

- `workspace.exec` and `workspace.shell` — ordinary command/script and shell access.
- `workspace.exec.elevated` — separately required for root/SYSTEM targets.
- `workspace.execution.manage` — manage others' executions.
- `workspace.execution.recordings.read` — separate sensitive recording access.

Authenticated administrators can update grants through `PUT /admin/users/{name}`
using `executionGrants`; send `[]` to revoke all grants. Unknown fields, wildcards,
unknown permissions and malformed expiry values are rejected. Auth-disabled mode
cannot write execution grants. Ordinary editor/viewer roles imply no grants.

Execution admission/renewal must use a user-bound credential and fresh current
User data. `PlatformConfig.spec.vmExecution.enabled` and `allowElevated` are
separate opt-in policy gates, read fresh by the execution policy provider. These
checks are applied alongside the explicitly enabled QGA backend, mandatory full
recording in the selected storage mode and guest-side signed-grant enforcement.

Synchronous commands/scripts revalidate the original signed session/device
credential, current account, exact exec/elevation grants and platform policy again
after protected input admission, immediately before entering the guest transport.
Revocation, expired authority, unavailable checks or a pre-dispatch disconnect
prevent dispatch and retain a protected terminal result when admission completed.
This is not immediate cancellation of an already dispatched command: the bounded
pilot still runs under its guest deadline, and no command is automatically rerun.

### Bounded Linux and Windows scripts

`POST /v1/executions/start` supports root/SYSTEM scripts on a matching guest runner:

```json
{
  "namespace": "team-a",
  "workspace_name": "linux-vm",
  "deadline_seconds": 20,
  "script": {
    "body": "#!/bin/sh\nprintf 'hello\\n'\n",
    "name": "maintenance.sh",
    "cwd": "/tmp"
  }
}
```

Scripts are mutually exclusive with `executable`/`args`. Supply cwd at only one
level (top-level or script), and use a basename hint containing only ASCII
alphanumeric/`.`/`_`/`-`, excluding `.` and `..`. The UTF-8 body limit is 64 KiB.
First lines must be exactly `#!/bin/sh`, `#!/bin/bash`, `#!/usr/bin/bash` or
`#!/usr/bin/python3`, without arguments, BOM or CRLF. For Windows, use exactly
`#!powershell` (LF or CRLF), followed by PowerShell code, and an optional `run.ps1`
hint. The Windows policy maps this marker to the fixed installed Windows
PowerShell executable with `-NoLogo -NoProfile -NonInteractive -ExecutionPolicy
Bypass -File` and a SYSTEM-only staged `.ps1`. No `pwsh`, PATH lookup, interpreter
arguments or ordinary-user-to-SYSTEM fallback. Interactive stdin/PTY remain
unsupported.

Clients can discover support with
`GET /v1/executions/capabilities?namespace=team-a&workspace_name=linux-vm`.
This requires the same current user-bound identity, scoped execution/elevation,
enabled policy, ready recording store and eligible running target as start.
The result binds namespace/name/Workspace UID and reports `os_identity`,
`script_supported`, `script_request_version`, `interpreter_policy`,
`max_script_bytes` and an unavailable `reason`. Compatible runners advertise
version 2, `linux-shebang-v1` (root) or `windows-powershell-v1` (SYSTEM), and 65536 bytes. Old/incompatible runners report
unsupported; policy/auth/storage/target failures return the corresponding HTTP
error. Discovery creates no execution, recording or grant. Clients must treat it
as a hint: every script submission independently repeats preflight and guest
grant verification.

Before admission the API validates the script and its encoded envelope budget,
then invokes only the fixed installed runner's `management-exec --capabilities`
probe through the current owned launcher's authenticated QGA path. Old/missing
or incompatible runners fail before script admission, staging or grant issuance.
The probe reports protocol support, not privilege/cgroup/storage readiness.

The encoded-envelope limit is independently 96 KiB. Preflight reserves the full
16 KiB grant-token bound, so heavily escaped JSON bodies can be rejected below
the raw-body limit. No executable script is staged by the API: the signed v2
request carries the script, and the guest verifies it before creating a private
temporary file. Windows staging adds the policy-defined UTF-8 BOM so Windows
PowerShell 5.1 can read non-ASCII source; protected recording retains the original
submitted text. The complete script/name/interpreter policy and cwd are committed
to protected recording before dispatch; metadata identifies `operation=script`
without exposing its body. Deadline, 16 KiB combined output, process-tree cleanup,
recording-loss and transport-unknown behavior match bounded commands. Requests
are never automatically rerun.

#### Installed script proof (explicit opt-in)

With a disposable agent-equipped VM, matching installed runner, enabled QGA /
elevation policy and a kubeconfig allowed to reach its owned launcher:

```sh
KW_EXECUTION_SCRIPT_LIVE_NAMESPACE=execution-proof \
KW_EXECUTION_SCRIPT_LIVE_WORKSPACE=linux-vm \
go test -v -run '^TestScriptExecutionLive$' .
```

The same command works for a Windows proof VM by selecting its workspace name.
These variables are separate from the command-only live harness; ordinary tests
skip this proof. It stages a fresh management verification key, so use a
disposable VM, not a production workspace. Authentication/account fixtures and
encrypted ephemeral recording are local; live target/policy resolution, QGA,
guest signatures, script staging and process execution are real. It does not
establish deployed browser authentication or persistent PostgreSQL/S3 recording.

The harness checks scoped discovery without admission, root/SYSTEM identity,
cwd and distinct streams/nonzero exit, explicit UTF-8 output, root-exit/deadline/
output-limit descendant termination, and complete protected input/result binding.
Each PID check is a new recorded read-only script; no script is automatically
retried. After every script (including PID checks), a separately recorded command
inspects the fixed management `scripts` directory and requires only its lock file
to remain. This command uses no script staging and neither repairs nor deletes
leftovers. Run the campaign without competing executions on that disposable VM.
The whole campaign is pinned to the initially resolved guest/launcher/
revocation epoch. Target changes or a failed/unknown/lost-recording result stop it.
Windows Unicode source uses the policy's BOM; its UTF-8 output case explicitly
sets the process output encoding, rather than assuming a default host code page.

### Execution storage configuration

The startup configuration loader recognizes `KW_EXECUTION_STORAGE_MODE` values
`disabled` (the default), `ephemeral`, `external`, and `bundled`. Ephemeral mode
needs no database, object store or persistent key; it configures a bounded
temporary directory and history that may be lost on restart. External/bundled
modes use PostgreSQL metadata/state plus S3-compatible recording storage and a
stable recording key. Persistent configuration errors never select ephemeral.

Persistent modes require `KW_EXECUTION_RECORDING_KEY_FILE`, containing base64 text
for a random 32-byte key, or the versioned active/read-only keyring described in
[recording key rotation](internal/execution/storage/KEY_ROTATION.md). New recordings
always use the active key; retained keys support protected replay and terminal
recovery without rewriting old evidence. External mode uses a Secret-backed
`KW_EXECUTION_DATABASE_URL` with `sslmode=verify-full`; bundled mode constructs a
URL from separate `KW_EXECUTION_PG_HOST`, `_PORT`, `_DATABASE`, `_USER`, `_PASSWORD`
values without string-interpolating credentials. S3 endpoint/bucket/region and
credential settings use `KW_EXECUTION_S3_*`. Private S3 CAs can be supplied with
`KW_EXECUTION_S3_CA_FILE`; HTTPS certificate verification is never disabled.

The bundled test profile explicitly opts into internal PostgreSQL/TCP and S3/HTTP
through `KW_EXECUTION_ALLOW_INSECURE_STORAGE_TRANSPORT=true`; external mode also
requires this opt-in for plaintext transport. Retention defaults are 720h for
recordings and 8760h for metadata, independently configurable with
`KW_EXECUTION_RETENTION_RECORDINGS` and `KW_EXECUTION_RETENTION_METADATA` (metadata
must cover recording retention). Credentials and recording keys are redacted from
ordinary configuration formatting/errors.
These retention values are currently configuration contracts; automatic retention
deletion is not implemented. Do not retire a key on the assumption that its old
recordings or pending recovery evidence have already expired or been deleted.

Store initialization, migrations, encrypted recording admission and replay are
wired into startup and execution. Unready storage denies admission; persistent
mode never silently falls back to ephemeral storage.
Deployment profiles and Secret setup are documented in
[VM execution storage](https://github.com/kube-workspaces/deploy/blob/main/docs/vm-execution-storage.md).

Browser WebSocket handshakes and state-changing requests require an exact origin
from comma-separated `ALLOWED_ORIGINS`; CORS headers alone are not authorization.
Cookie-authenticated mutations/handshakes without an Origin are rejected. Native
bearer clients may omit Origin. Set this list to the frontend's actual origin
(including scheme and non-default port); host/forwarded headers and wildcard or
suffix matches cannot expand the allowlist. Safe reads retain normal CORS behavior.

Container exec always targets its Workspace's conventional pod; scratch pod
resolution is supplied internally by the server. Client `pod` query parameters
cannot redirect exec into another pod, and an existing Workspace must be read
successfully before the route opens any console/exec stream.

## Native app authentication (RFC 8252)

Desktop clients cannot read the `HttpOnly` `kw-session` cookie, so the API also
supports the loopback + PKCE flow from RFC 8252 ("OAuth 2.0 for Native Apps").
The client never talks to the IdP, so the flow works with whichever
authentication the administrator configured.

1. The client starts a loopback listener on an ephemeral port and opens the
   **system browser** at:

   ```
   GET /auth/login?native_redirect=http://127.0.0.1:<port>/cb
                  &code_challenge=<BASE64URL(SHA256(verifier))>
                  &code_challenge_method=S256
                  &state=<opaque client nonce>
   ```

   `native_redirect` must be `http`, on the loopback **literal** `127.0.0.1` or
   `[::1]` (not `localhost`, per RFC 8252 §8.3), with no query or fragment and
   no userinfo. Anything else is a `400`. Only `S256` is accepted.

   `state` is optional but recommended: it is the client's own nonce, echoed
   verbatim in step 3 so the client can perform the RFC 6749 §10.12 check. It
   must be at most 256 unreserved characters (`A-Z a-z 0-9 - . _ ~`). The
   server's internal OIDC CSRF state is never echoed — the client has not seen
   it and could not check it.

2. The API runs its normal OIDC flow. The native parameters ride through the
   round trip inside the HMAC-signed `kw-auth-state` cookie.

3. `/auth/callback` mints the session token exactly as for a browser login but,
   instead of setting the cookie, redirects to
   `native_redirect?code=<code>&state=<client state>`. The code is single-use,
   expires after 60s and is bound to the PKCE challenge. Failures before this
   point (IdP error, email not allowed) are reported to the same listener as
   `?error=...&error_description=...&state=...` so the client fails fast.

4. The client exchanges it:

   ```
   POST /auth/native/token
   {"code": "...", "code_verifier": "..."}

   200 {"token": "...", "expires_at": 1234567890, "email": "...", "role": "..."}
   ```

   Failures return `400` with `{"error": "...", "message": "..."}` where `error`
   is `invalid_code`, `invalid_verifier` or `invalid_request`.

5. The token is then used as `Authorization: Bearer <token>`, which `/auth/me`
   and `/auth/change-password` accept in addition to the session cookie.

`GET /auth/config` advertises support as `"nativeAuth": {"enabled": true,
"methods": ["loopback-pkce"]}`.

Omitting the native parameters leaves the browser flow completely unchanged.

Codes are held in memory on the replica that issued them, so with multiple
replicas the exchange must reach that replica; a failed exchange simply
restarts the login.

## Design

The API is defined using Goa DSL in `design/design.go`. Running `goa gen` generates:
- HTTP server and client code
- OpenAPI 2.0 and 3.0 specifications
- Type definitions and encoders/decoders

Additional endpoints (logs, events, pod, proxy, admin) are implemented directly in `cmd/kube_workspaces/http.go`, along with the WebSocket bridges (exec/console/vnc/ssh) and their session registry.

## Development

```bash
# Regenerate code from design
go run goa.design/goa/v3/cmd/goa gen github.com/kube-workspaces/api/design

# Sync the embedded OpenAPI copy served at /openapi3.{json,yaml}
# (go:embed cannot reference ../gen, so this is a manual copy)
cp gen/http/openapi3.json gen/http/openapi3.yaml cmd/kube_workspaces/

# Build
go build -o bin/kube-workspaces-api ./cmd/kube_workspaces/

# Run locally (uses current kubeconfig)
go run ./cmd/kube_workspaces/ --http-port=8090
```

## Docker

```bash
docker build -t kube-workspaces-api:latest -f Dockerfile .
```

Requires Go 1.26+ (for k8s.io/client-go@v0.36.2 compatibility).

## Workspace Proxy

The API includes a built-in reverse proxy at `/proxy/{namespace}/{name}/{path...}`:

- Full WebSocket passthrough
- Location header rewriting for redirects
- Referer-based catch for escaped absolute-path requests
- No-op ServiceWorker at `/sw.js`
- Per-image proxy configuration (see `internal/proxy/proxy.go`)

## Image Defaults

When creating workspaces, the API auto-injects default settings for known images:
- `codercom/code-server:latest` - Adds `--bind-addr 0.0.0.0:8080 --auth none` args

## Key Files

| File | Description |
|------|-------------|
| `design/design.go` | Goa API design DSL |
| `cmd/kube_workspaces/http.go` | HTTP server setup, proxy, admin, WebSocket bridge routes |
| `cmd/kube_workspaces/main.go` | Entry point, client initialization |
| `internal/k8s/client.go` | CoreClient for pods, logs, events |
| `internal/k8s/workspace.go` | Workspace CR dynamic client |
| `internal/k8s/sshkey.go` | SshKey CR client |
| `internal/k8s/image.go` | Image CR client (workspace types, defaults) |
| `internal/auth/oidc.go` | OIDC login/callback, `/auth/me`, `/auth/config` |
| `internal/auth/native.go` | RFC 8252 native-app flow (loopback redirect validation, PKCE, code store) |
| `internal/exec/session.go` | Session registry (single-session, TTL, take-over) |
| `internal/exec/vmconsole.go` | VM serial console WebSocket bridge |
| `internal/exec/vmvnc.go` | VM noVNC display WebSocket bridge |
| `internal/exec/ssh.go` | Web SSH console WebSocket bridge |
| `internal/proxy/proxy.go` | Reverse proxy handler |
| `workspaces.go` | Workspace service implementation |
| `volumes.go` | Volume service implementation |
| `images.go` | Images service (static registry) |
| `sshkeys.go` | SshKeys service |

## Configuration

The API uses the current kubeconfig or in-cluster service account for Kubernetes access.

| Env Var | Description | Default |
|---------|-------------|---------|
| `KUBECONFIG` | Path to kubeconfig file | `~/.kube/config` |
| `HTTP_HOST` | Listen address | `localhost:8080` |

## Related Repositories

| Repository | Description |
|------------|-------------|
| [kube-workspaces/controller](https://github.com/kube-workspaces/controller) | Kubernetes controller (CRD reconciliation) |
| [kube-workspaces/proxy](https://github.com/kube-workspaces/proxy) | Workspace reverse proxy |
| [kube-workspaces/frontend](https://github.com/kube-workspaces/frontend) | Next.js web UI |
| [kube-workspaces/deploy](https://github.com/kube-workspaces/deploy) | Deployment manifests and documentation |

## License

Apache License 2.0
## Execution history and protected playback

The execution management API requires a current User-UID-bound credential even
when ordinary API authentication is disabled. Legacy sessions must sign in again.
Current User grants and namespace membership are reloaded by authentication on
each HTTP request; token role claims do not grant management authority.

| Route | Permission / behavior |
|---|---|
| `GET /v1/executions/status` | Authenticated user-bound identity; policy/storage status and opt-in `issuer_ready`, not a guest-execution capability promise. |
| `GET /v1/executions?namespace=team&workspace_name=vm` | Exact workspace scope and `workspace.execution.manage`; optional actor/since/limit filters only narrow that scope. |
| `GET /v1/executions/{id}` | `workspace.execution.manage` on the recorded scope; inaccessible IDs return 404. |
| `GET /v1/executions/{id}/recording` | Independent `workspace.execution.recordings.read`; verify the authenticated manifest and full chunk chain, then audit access before returning recording metadata. |
| `GET /v1/executions/{id}/recording/chunks/{index}` | Fresh recording-read authorization and integrity verification; returns base64 plaintext data in JSON. |

Recording responses use `Cache-Control: no-store`; management payloads are excluded
from debug body logging. Recording chunks are capped at 1 MiB. Manifests are
HMAC-SHA-256 authenticated with domain separation in addition to AES-256-GCM chunk
encryption and the ciphertext hash chain. Unsigned manifests fail verification.
Replay currently verifies the entire recording on each request; it is intended
as a correctness-first protected playback surface, not a streaming optimization.

Configured persistent storage initialization failures stop API startup; disabled
storage leaves the ordinary API running and management admission unavailable.
Every admission reserves both execution and recording IDs atomically before
opening its sink. Recording-write failures latch, cannot be finalized as success,
and preserve available evidence on abort. Bounded command/script start is available
only through the separately enabled QGA pilot; it is not an mTLS fallback.
Session finalization commits terminal metadata and its actor-bound `finished`
audit atomically (also `recording.lost` on recording failure). PostgreSQL audit
failure rolls back the terminal state rather than leaving unaudited success;
ephemeral mode performs the same operation under one lock.

Finalized sessions now preserve an encrypted **terminal intent** alongside the
protected recording: the original admission (execution/recording IDs, actor,
workspace UID/scope, identity, grant version and storage mode) plus intended outcome and
timing. A version-2 authenticated manifest binds this ciphertext to the recording
chain; AES-256-GCM uses a domain-separated derived key and recording/key-ID AAD.
Intent is bounded to 16 KiB before encryption and charged to ephemeral recording
capacity. Input/output chunk counts and public replay responses are unchanged.

Reading terminal intent verifies the entire recording first, then decrypts and
validates it. It is **not committed metadata or an active-work ownership grant**.
Persistent modes run a bounded metadata-only reconciliation sweep at startup and
every 30 seconds (32 candidates per pass, 10-second pass budget, keyset pagination).
Only a fully finalized, verified intent for the unchanged admission can repair a
nonterminal synchronous command/script. The immutable verified snapshot and
row-lock/CAS completion fence serialize the original completer and other replicas;
no lease expiry, guest redispatch or output-text inference is involved.

Recovery atomically commits the intended outcome, the original actor's `finished`
audit (and `recording.lost` if applicable), and a `completion.recovered` system audit.
Already-committed matching outcomes are no-ops, including after an uncertain commit
response. If recovery wins before the original completer, its matching fully
audited completion is accepted without another audit or a spurious conflict.
Conflicting terminal outcomes are never overwritten. Unknown stays
unknown. Failed recovery/audit leaves metadata unchanged for a later pass. Missing,
legacy, incomplete or corrupt recordings do not authorize repair; active owners
without finalized terminal intent are left alone. This is not general async-job,
shell or upgrade owner/lease recovery. Ephemeral mode starts no recovery worker.

**Storage-format compatibility:** this API reads both v1 and v2. Older API binaries
reject v2 recordings, so persistent-storage rollout/rollback must account for all
replicas' reader versions; never drop authentication or silently downgrade to make
an older reader accept new recordings. Existing v1 recordings are not rewritten.

The optional management issuer now supports protected mounted CA credentials,
shared-ledger initialization and a metadata-only protected-bootstrap import
worker. Its configuration, trust rotation and readiness contract are documented
in [`internal/execution/management/README.md`](internal/execution/management/README.md).
It remains disabled by default and exposes no public enrollment/start route.

Disposable PostgreSQL/S3 integration checks are opt-in:

```sh
KW_EXECUTION_TEST_DATABASE_URL='postgres://test:test@127.0.0.1:15432/test?sslmode=disable' \
  go test -race ./internal/execution/storage -run TestPostgresIntegration
KW_EXECUTION_TEST_S3_ENDPOINT='http://127.0.0.1:19000' \
KW_EXECUTION_TEST_S3_ACCESS_KEY='test-access' \
KW_EXECUTION_TEST_S3_SECRET_KEY='test-secret' \
  go test -race ./internal/execution/storage -run TestS3Integration
```

Use isolated disposable services: these tests apply migrations and write test
execution records and recording objects. They never discover cluster credentials.

The HTTP execution/recording integration campaign uses both services together:

```sh
KW_EXECUTION_TEST_DATABASE_URL='postgres://test:test@127.0.0.1:15432/test?sslmode=disable' \
KW_EXECUTION_TEST_S3_ENDPOINT='http://127.0.0.1:19000' \
KW_EXECUTION_TEST_S3_ACCESS_KEY='test-access' \
KW_EXECUTION_TEST_S3_SECRET_KEY='test-secret' \
  go test -race -count=1 -v -run '^TestExecutionPersistentIntegration$' .
```

It exercises real PostgreSQL/S3 admission, encrypted input before dispatch,
command and Linux/Windows script recordings, storage/service reopen, independently
authorized replay, corruption detection, and fail-closed S3 read/write failures
before and after dispatch. It intentionally corrupts its own objects in the
`execution-http-integration` bucket; use **disposable storage only**. Account,
policy and guest transport are fixtures: this is not installed-guest, deployed
restart, PostgreSQL outage or distributed-owner acceptance. No guest is contacted
and no execution is automatically retried. Both persistent selectors share these
storage engines; this campaign selects `external`, not a Helm deployment.

For actual PostgreSQL TCP connection loss (existing sessions and new connections),
use the same disposable-service variables with
`go test -race -count=1 -v -run '^TestExecutionPostgresOutageIntegration$' .`.
This checks pre-admission denial, failure to commit the terminal state,
recovery before result finalization, and terminal-audit failure rolling back the
metadata commit. The persistent/connection-loss campaigns also verify that terminal
intent survives storage reopen and database/audit failure, matches the persisted
admission, hides its identity fields from plaintext object metadata, and cannot be
used after recording corruption. The PostgreSQL tests temporarily install narrowly
execution-scoped
fault-injection triggers; the disposable test database user needs permission to
create those triggers/functions. If PostgreSQL remains
unavailable at finalization, start returns 503 and the protected S3 result survives,
and a newly constructed coordinator repairs metadata from its verified intent after
database/audit recovery, without another guest call. Tests also cover competing
completers, admission substitution, recovery-audit rollback, and repeated recovery
without duplicate audit. **Remaining limitation:** without valid finalized v2
evidence, metadata can still remain `running`; active/incomplete-owner recovery
requires a separate lifecycle contract. Never automatically rerun such an execution.
The campaign requires a PostgreSQL URL and does not stop the database service.

CI runs both campaigns plus the standalone storage-engine checks against
digest-pinned disposable PostgreSQL and RustFS services. Ordinary local tests
still skip these checks unless the service variables are set.

Two additional recovery campaigns use the same disposable-service variables:

```sh
go test -race -count=1 -v -run '^TestExecution(CommitResponseLoss|ProcessLoss)Integration$' .
```

- **COMMIT response loss:** a test-only PostgreSQL wire proxy observes the backend's
  real `COMMIT` CommandComplete, then drops the acknowledgement before the client
  sees it. Both original completion and recovered completion must return uncertainty,
  while an independent connection proves committed metadata/audit. Repeated recovery
  must not duplicate the audit or guest dispatch. This protocol-inspection test
  requires an explicitly disposable plaintext PostgreSQL URL (`sslmode=disable`);
  it does not change deployment TLS configuration.
- **Process loss:** the test starts a private helper test process using the real
  authenticated HTTP/recording path and disposable PostgreSQL/S3. A test seam pauses
  immediately after sealing the recording but before metadata completion. The parent
  hard-kills only that child, then reconstructs the coordinator in another address
  space and checks recovered state/audit plus an unchanged one-dispatch ledger.
  The shared recording-key file stays in the private temporary test directory.

Guest execution, accounts and policy remain fixtures. These are local database-wire
and coordinator-process proofs, not installed-guest, production-binary or live
deployment restart/partition acceptance. CI runs all four campaigns; the subprocess
helper skips ordinary test invocation and is enabled only by its parent test.
