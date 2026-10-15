package exec

import (
	"context"
	"net/http"
	"strings"

	"github.com/kube-workspaces/api/internal/agent"
)

// AgentOwnerMiddleware routes lifecycle calls only to a cryptographically
// authenticated issuer. Forward resolves pod identity through Kubernetes,
// preserves credentials for reauthorization, and bounds forwarding to one hop.
func AgentOwnerMiddleware(instance string, keys func(context.Context) ([][]byte, error), hop *OwnerHop, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if r.Method == http.MethodPost && len(parts) == 5 && parts[0] == "v1" && parts[1] == "workspaces" && parts[3] == "agent" && (parts[4] == "renew" || parts[4] == "release") {
			if signingKeys, err := keys(r.Context()); err == nil {
				if owner := agent.SessionOwner(r.Header.Get("X-KW-Agent-Session"), signingKeys); owner != "" && owner != instance {
					hop.Forward(w, r, owner)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
