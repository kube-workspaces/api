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
foundations do not yet expose guest process execution: authenticated transport,
full recording in the selected storage mode and runner lifecycle are additional
mandatory admission requirements.

### Execution storage configuration

The startup configuration loader recognizes `KW_EXECUTION_STORAGE_MODE` values
`disabled` (the default), `ephemeral`, `external`, and `bundled`. Ephemeral mode
needs no database, object store or persistent key; it configures a bounded
temporary directory and history that may be lost on restart. External/bundled
modes use PostgreSQL metadata/state plus S3-compatible recording storage and a
stable recording key. Persistent configuration errors never select ephemeral.

Persistent modes require `KW_EXECUTION_RECORDING_KEY_FILE`, containing base64 text
for a random 32-byte key. External mode uses a Secret-backed
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

This is configuration validation, not implemented database migrations, recording
writes or storage readiness. Execution must remain unavailable until those
stores, recording admission and authenticated guest enforcement are integrated.
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
