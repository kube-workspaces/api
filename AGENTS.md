# AGENTS.md

## Repository: kube-workspaces/api

REST API service for the kube-workspaces platform. Built with Goa v3.

## Structure

| Directory | Purpose |
|-----------|---------|
| `cmd/kube_workspaces/` | Main entrypoint + HTTP handlers |
| `design/design.go` | Goa DSL design (source of truth for API routes) |
| `gen/` | Generated Goa code (types, endpoints, HTTP transport, OpenAPI) |
| `internal/auth/` | Auth middleware (OIDC, session cookies, Bearer tokens) |
| `internal/exec/` | Workspace exec (WebSocket terminal) |
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

## Docker Image

Published to: `kubeworkspaces/api`

## CI

- `.github/workflows/ci.yml` — build + vet
- `.github/workflows/docker.yml` — build & push Docker image
