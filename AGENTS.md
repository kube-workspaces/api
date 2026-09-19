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
| `internal/exec/` | WebSocket bridges: exec, VM serial console, VM noVNC display, web SSH + session registry |
| `internal/display/` | Display ownership: Lease-backed `Store`/`Guard` for the legacy capture seat, a **separate control-role lease** (`ClaimControl`/`RenewControl`/`RevokeControl`/`ReleaseControl`, own coordination object) and `Fence.DispatchInput` gating input writes at the fencing bound, plus the in-memory `Sessions` registry (one controller + view-only observers) backing the Goa `display` service |
| `internal/rfb/` | Shared-display broker groundwork: bounded post-handshake client-message framing and mutation classification; not wired into the VNC route yet |
| `internal/broker/` | Read-only multi-viewer RFB feasibility prototype, independent observer sessions and bounded capture; not routed publicly. See its README for native/noVNC integration checks. |
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
  by `internal/display.Sessions`. It is NOT yet wired to a viewer WebSocket or
  the RFB broker, so participant membership/control is exercised by the API
  only; there is no live multi-session media path. Handwritten `display.go`
  mirrors the exec/vnc console gate (editor/admin + namespace access) with Goa
  `unauthorized`/`forbidden`/`not_found`/`capacity`(429)/`conflict`(409) errors.
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
