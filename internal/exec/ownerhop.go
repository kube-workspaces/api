package exec

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/kube-workspaces/api/internal/display"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// hopHeader marks a request that already traveled one internal hop, so a
// stale lease read on two pods at once can never ping-pong a client between
// them: the second pod answers the 409 instead of forwarding again.
const hopHeader = "X-KW-Display-Hop"

// apiPort is the API's own container port for pod-to-pod traffic. It is the
// port the deployment exposes and probes, not a user setting.
const apiPort = "8080"

// OwnerHop forwards a shared-display request to the replica that owns the
// workspace's display generation, so any API pod can answer while exactly one
// pod dials the VM's VNC console. The owner identity never comes from the
// caller: it is read from the lease annotation the owning replica wrote, and
// resolved to a pod IP through the Kubernetes API. The forwarded request
// keeps the client's credentials, so the owning pod re-authorizes it like any
// direct request.
type OwnerHop struct {
	clientset kubernetes.Interface
	namespace string
	transport http.RoundTripper
}

// NewOwnerHop returns an OwnerHop resolving owner pod names against the API's
// own namespace (from the service account, defaulting to the deployment's
// namespace when running off-cluster).
func NewOwnerHop(clientset kubernetes.Interface) *OwnerHop {
	return &OwnerHop{clientset: clientset, namespace: ownNamespace(), transport: http.DefaultTransport}
}

func ownNamespace() string {
	if b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(b)); ns != "" {
			return ns
		}
	}
	return "kube-workspaces-system"
}

// hopped reports whether r already traveled one internal hop.
func hopped(r *http.Request) bool { return r.Header.Get(hopHeader) != "" }

// resolve maps an owning replica's identity (hostname == pod name) to a
// routable host:port.
func (h *OwnerHop) resolve(ctx context.Context, owner string) (string, error) {
	if h.clientset == nil {
		return "", errors.New("no Kubernetes client")
	}
	pod, err := h.clientset.CoreV1().Pods(h.namespace).Get(ctx, owner, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if pod.Status.PodIP == "" {
		return "", errors.New("owner pod has no IP yet")
	}
	return net.JoinHostPort(pod.Status.PodIP, apiPort), nil
}

// Forward proxies r to the owning replica. When the request already made a
// hop, or the owner cannot be resolved, it answers the 409/owner body itself:
// the client's next attempt re-reads a fresher lease and either succeeds or
// learns the new owner.
func (h *OwnerHop) Forward(w http.ResponseWriter, r *http.Request, owner string) {
	if hopped(r) {
		writeOwnerConflict(w, owner)
		return
	}
	host, err := h.resolve(r.Context(), owner)
	if err != nil {
		writeOwnerConflict(w, owner)
		return
	}
	r.Header.Set(hopHeader, "1")
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = host
		},
		Transport: h.transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeOwnerConflict(w, owner)
		},
	}
	proxy.ServeHTTP(w, r)
}

// writeOwnerConflict answers the B.4 cross-replica contract: a 409 naming the
// owning replica, before any second console could be dialed.
func writeOwnerConflict(w http.ResponseWriter, owner string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "interactive display is owned by another replica",
		"owner": owner,
	})
}

// DisplayOwnerMiddleware forwards Goa display membership/control requests
// (everything under /v1/workspaces/{name}/display except the /display/ws
// stream, which forwards itself) to the replica owning the workspace's
// display, whenever an owner is known. The membership registry is in-memory
// per replica, so a join on one pod and a stream attach on another would
// otherwise diverge into 404s; routing every call to the owner keeps the one
// registry coherent. With no owner known yet, any replica may answer — the
// stream attach that follows creates the generation on the same pod.
func DisplayOwnerMiddleware(store *display.Store, instance string, hop *OwnerHop, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hopped(r) {
			if owner := displayRequestOwner(r, store, instance); owner != "" {
				hop.Forward(w, r, owner)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// displayRequestOwner extracts the workspace from a display REST path and
// returns the owning replica, or "" when the request is not a display REST
// call or no other replica owns the display.
func displayRequestOwner(r *http.Request, store *display.Store, instance string) string {
	name, ok := displayRESTName(r.URL.Path)
	if !ok {
		return ""
	}
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = "workspaces"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	// The seat is checked first (a full generation holds both), then the
	// capture (an observer-only generation holds only it).
	if owner, err := store.SeatOwner(ctx, ns, name); err == nil && owner != "" && owner != instance {
		return owner
	}
	if owner, err := store.CaptureOwner(ctx, ns, name); err == nil && owner != "" && owner != instance {
		return owner
	}
	return ""
}

// displayRESTName returns the workspace name from a display REST path:
// /v1/workspaces/{name}/display[/status|join|sessions|control]. The /display/ws
// stream route is excluded — it routes itself through the broker attach.
func displayRESTName(path string) (string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 4 || parts[0] != "v1" || parts[1] != "workspaces" || parts[3] != "display" {
		return "", false
	}
	if len(parts) > 4 && parts[4] == "ws" {
		return "", false
	}
	return parts[2], true
}
