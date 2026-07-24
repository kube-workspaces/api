# kube-workspaces API

REST API service for managing Kubernetes workspaces, built with the [Goa](https://goa.design) framework.

## Overview

The API provides:
- **Workspaces** - CRUD, start/stop, logs, events, pod details
- **Volumes** - PVC management (create, list, delete)
- **Images** - List available workspace images with proxy configuration
- **Namespaces** - List available Kubernetes namespaces (supports `_all` for cross-namespace listing)
- **Proxy** - Reverse proxy to workspace web UIs with WebSocket support
- **Admin** - Raw CRD browsing endpoints
- **Health** - Health check endpoint
- **OpenAPI** - Auto-generated OpenAPI 3.0 spec (JSON and YAML)

## Design

The API is defined using Goa DSL in `design/design.go`. Running `goa gen` generates:
- HTTP server and client code
- OpenAPI 2.0 and 3.0 specifications
- Type definitions and encoders/decoders

Additional endpoints (logs, events, pod, proxy, admin) are implemented directly in `cmd/kube_workspaces/http.go`.

## Development

```bash
# Regenerate code from design
go run goa.design/goa/v3/cmd/goa gen github.com/flaccid/kube-workspaces/api/design

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
| `cmd/kube_workspaces/http.go` | HTTP server setup, proxy, admin endpoints |
| `cmd/kube_workspaces/main.go` | Entry point, client initialization |
| `internal/k8s/client.go` | CoreClient for pods, logs, events |
| `internal/k8s/workspace.go` | Workspace CR dynamic client |
| `internal/proxy/proxy.go` | Reverse proxy handler |
| `workspaces.go` | Workspace service implementation |
| `volumes.go` | Volume service implementation |
| `images.go` | Images service (static registry) |

## Configuration

The API uses the current kubeconfig or in-cluster service account for Kubernetes access.

| Env Var | Description | Default |
|---------|-------------|---------|
| `KUBECONFIG` | Path to kubeconfig file | `~/.kube/config` |
| `HTTP_HOST` | Listen address | `localhost:8080` |

## License

Apache License 2.0
