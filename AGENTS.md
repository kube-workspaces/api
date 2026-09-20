# AGENTS.md

## Repository: kube-workspaces/api

REST API service for the kube-workspaces platform. Built with Goa v3.

## Structure

| Directory | Purpose |
|-----------|---------|
| `cmd/kube_workspaces/` | Main entrypoint + HTTP handlers |
| `design/design.go` | Goa DSL design (source of truth for API routes) |
| `gen/` | Generated Goa code (types, endpoints, HTTP transport, OpenAPI) |
| `internal/auth/` | Auth middleware (OIDC, local auth, session cookies, Bearer tokens, RFC 8252 native-app flow) |
| `internal/exec/` | WebSocket bridges: exec, VM serial console, VM noVNC display, web SSH + session registry, and the shared-display WS route (`shareddisplay.go`, `/v1/workspaces/{name}/display/ws`) that runs a broker generation per workspace (capture lease + one upstream dial, plus the interactive seat when free) shared by all participants |
| `internal/display/` | Display ownership: Lease-backed `Store`/`Guard` for the interactive seat and the **VNC-console capture lease** (`ClaimCapture`, own coordination object — `Acquire` takes seat+capture, `AcquireCapture` takes the console alone for observer-only coexistence with a Tier 1 seat holder), a **separate control-role lease** (`ClaimControl`/`RenewControl`/`RevokeControl`/`ReleaseControl`) and `Fence.DispatchInput` gating input writes at the fencing bound, plus the in-memory `Sessions` registry (one controller + view-only observers, `SetControlLocked` while a Tier 1 session owns the seat) backing the Goa `display` service |
| `internal/rfb/` | Shared-display broker groundwork: bounded post-handshake client-message framing and mutation classification; not wired into the VNC route yet |
| `internal/broker/` | Shared-display RFB broker: one capture upstream, up to eight participants, immutable snapshot fan-out with slow-reader isolation. `ServeParticipant` serves observers read-only and forwards a controller's guest-mutating messages upstream **only through an `InputGate`** (the display control `Fence`), with upstream writes serialized against capture. ZRLE output (`zrle.go`) when negotiated — solid/packed-palette/plain-RLE/raw tiles, smallest per tile, one connection-scoped zlib stream; Raw fallback. Wired publicly via exec's shared-display route (`internal/exec/shareddisplay.go`). |
| `internal/k8s/` | Kubernetes client utilities |
| `internal/platform/` | PlatformConfig reading |
| `internal/proxy/` | Legacy proxy support |

## Commands

```
go build -o bin/kube-workspaces-api ./cmd/kube_workspaces/    # build
go run ./cmd/kube_workspaces/ --http-port=8090                # run locally
go run goa.design/goa/v3/cmd/goa gen github.com/kube-workspaces/api/design  # regenerate Goa code
```

## Key Notes

- Go version: 1.26 (see `go.mod`)
- Goa code generation: After editing `design/design.go`, run the goa gen command above. Hand-written implementations go in root `.go` files and `cmd/kube_workspaces/http.go`, NOT in `gen/`.
- All API fetch calls from the frontend must include `credentials: "include"` (httpOnly cookies).
- Admin endpoints check `auth.IsAdmin(r.Context())` which returns true when auth is disabled.
- Auth is opt-in. When `AuthConfig.spec.enabled` is false, auth middleware is a no-op.
- Uses unstructured/dynamic K8s client for CRD access (no import from controller).
- Maintenance mode: returns 503 for non-admin users on non-exempt paths when enabled.
- VM access WebSocket bridges live in `internal/exec/` (`vmconsole.go` serial
  console, `vmvnc.go` noVNC display, `ssh.go` web SSH). All are single-session
  via `session.go`'s registry with an idle TTL and take-over consent; `PUT`
  workspace updates and `shared_memory`/`volume_mounts` are rejected for `vm`.
- Shared display sessions (`display.go` service, routes
  `/v1/workspaces/{name}/display*`): Goa-designed membership/control API backed
  by `internal/display.Sessions`. The stream route
  `/v1/workspaces/{name}/display/ws` (`internal/exec/shareddisplay.go`) serves
  one controller + view-only observers against a single broker generation per
  workspace; the controller's RFB input only reaches the VM through the display
  control `Fence` (control lease + local role gate). The legacy single-session
  `/v1/workspaces/{name}/vnc` bridge is unchanged and competes for the VM's VNC
  console through the same claims. Handwritten `display.go` mirrors the
  exec/vnc console gate (editor/admin + namespace access) with Goa
  `unauthorized`/`forbidden`/`not_found`/`capacity`(429)/`conflict`(409) errors.
- Lease model: three coordination leases per workspace. The **interactive
  seat** (`kw-display-*`, tier `vnc`/`tier1`) is the cross-tier controller
  mutex; the **capture lease** (`kw-display-capture-*`) coordinates the single
  KubeVirt VNC console connection — every console dialer holds it (`Acquire`
  takes seat+capture; a shared-display generation whose seat is tier1-held
  takes the capture alone via `AcquireCapture` and serves observer-only until
  its watcher claims the freed seat with `EnsureSeat`); the **control lease**
  (`kw-display-control-*`) gates participant input. Losing any held claim
  stops the guard and ends the broker generation.
- Replica owner routing: every claim (`claimLease`, used by the seat
  `Acquire`, `ClaimCapture` and `ClaimControl`) records this pod's identity
  (hostname) in the `kubeworkspaces.io/display-owner` lease annotation. A
  replica that loses the race gets a typed `display.OwnershipError` (unwraps
  to `ErrBusy`). The consumer is `exec.OwnerHop`: the request is forwarded to
  the owner pod (resolved via the pods API, one hop marked by
  `X-KW-Display-Hop`, loop-guarded) with the client's credentials intact, so
  the owner re-authorizes it; an unresolvable owner degrades to the 409/owner
  body. The Goa display REST routes forward through
  `exec.DisplayOwnerMiddleware`, keeping the in-memory membership registry
  coherent across pods. See `Store.SeatOwner`/`Store.CaptureOwner`/
  `Store.ControlOwner`.
- Pilot gate: the shared display ships opt-in (plan E) —
  `KW_DISPLAY_SHARED=on` enables it (`SharedDisplayEnabledFromEnv`). Off by
  default: capability/status advertise `enabled: false`, join/control answer
  400, and the stream route answers 404 (`exec.Options.SharedDisplayDisabled`).
- Stream/participant binding: the WS route accepts `?participant=<id>` to attach
  a stream to a participant registered via `POST .../display/join` (so a client
  learns its `participant_id` and drives `control/acquire|release|transfer` with
  it). A bound participant's membership survives a disconnect (reconnect keeps
  the id, REST `leave` removes it); a fresh-join (`no participant`) stream still
  removes its member on disconnect. Role and attachment state are validated
  before the upgrade. `Sessions.Lookup` refreshes the idle deadline. The route
  also accepts `&force=1` (a takeover reconnect after the peer's REST
  `control/acquire(force=true)`): revokes and claims the control lease rather
  than failing busy until the old fence releases.
- SshKey CRUD is implemented in `sshkeys.go` (`/v1/sshkeys*`) backed by
  `internal/k8s/sshkey.go`; keys live in the user's personal namespace.
- Native (desktop) auth: `internal/auth/native.go` implements the RFC 8252
  loopback + PKCE flow — `/auth/login` takes `native_redirect`/`code_challenge`,
  `/auth/callback` returns a single-use code to the loopback listener instead of
  setting a cookie, and `POST /auth/native/token` exchanges it for the session
  token in the response body. `validateLoopbackRedirect` is security-critical:
  loosening it turns `/auth/login` into a token-leaking open redirect. The
  `/auth/*` routes are hand-written in `cmd/kube_workspaces/http.go` and are not
  part of the Goa design, so no regeneration is needed when adding one.

## Docker Image

Published to: `ghcr.io/kube-workspaces/api`

## CI

- `.github/workflows/ci.yml` — build + vet
- `.github/workflows/docker.yml` — build & push Docker image
