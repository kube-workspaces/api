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
