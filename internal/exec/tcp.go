package exec

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// tcpDialTimeout bounds the launcher-pod TCP dial. The bridge upgrade happens
// after the dial so a dead guest answers 503 instead of a hung WebSocket.
const tcpDialTimeout = 10 * time.Second

// tcpSessions guards one raw-TCP bridge per (namespace, name, port): the
// Tier 1 fallback and ad-hoc port forwards are single-session like the rest
// of the console family, with the same status/takeover consent pattern.
var tcpSessions = newSessionRegistry()

func tcpKey(namespace, name string, port int) string {
	return namespace + "/" + name + ":" + strconv.Itoa(port)
}

// TCPOptions configures the generic TCP bridge.
type TCPOptions struct {
	// Clientset resolves the workspace Service endpoints to the launcher pod
	// IP where masquerade forwards guest ports.
	Clientset kubernetes.Interface
}

// TCPHandler upgrades to WebSocket and bridges raw binary frames to
// guest TCP port ?port=N on the workspace's VM. VM workspaces only.
//
// The target is the launcher pod IP (from the workspace Service Endpoints)
// dialled at the requested port — the same masquerade path the SSH bridge
// uses, minus the SSH protocol: every client binary frame is written to TCP
// and every TCP byte is returned as a binary frame. Text frames are rejected.
// Requires editor/admin (enforced by the route's requireEditorAccess).
func TCPHandler(opts *TCPOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		namespace := r.URL.Query().Get("namespace")
		if namespace == "" {
			namespace = "workspaces"
		}
		name := r.PathValue("name")
		if name == "" {
			http.Error(w, "workspace name is required", http.StatusBadRequest)
			return
		}
		port, err := ParseTCPPort(r.URL.Query().Get("port"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		key := tcpKey(namespace, name, port)
		handle := &sessionHandle{cancel: cancel}
		if _, acquired := tcpSessions.acquire(key, handle); !acquired {
			http.Error(w, "tcp session is in use for this workspace and port", http.StatusConflict)
			return
		}
		defer tcpSessions.release(key, handle)

		upstream, err := tcpDialTarget(ctx, opts.Clientset, namespace, name, port)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		dialer := net.Dialer{Timeout: tcpDialTimeout}
		upConn, err := dialer.DialContext(ctx, "tcp", upstream)
		if err != nil {
			http.Error(w, fmt.Sprintf("cannot reach guest port %d: %v", port, err), http.StatusServiceUnavailable)
			return
		}
		defer upConn.Close()

		clientConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer clientConn.Close()

		handle.setClose(func() {
			_ = clientConn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "taken over by another user"),
				time.Now().Add(time.Second))
			clientConn.Close()
			upConn.Close()
		})
		if !tcpSessions.stillCurrent(key, handle) {
			return
		}
		go func() {
			<-ctx.Done()
			clientConn.Close()
			upConn.Close()
		}()

		var wg sync.WaitGroup

		// client → guest: binary frames only; text frames are a protocol error.
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			for {
				msgType, msg, err := clientConn.ReadMessage()
				if err != nil {
					return
				}
				if msgType != websocket.BinaryMessage {
					_ = clientConn.WriteMessage(websocket.CloseMessage,
						websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "binary frames only"))
					return
				}
				handle.touch()
				if _, err := upConn.Write(msg); err != nil {
					return
				}
			}
		}()

		// guest → client: stream bytes as binary frames.
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			buf := make([]byte, 32<<10)
			for {
				n, err := upConn.Read(buf)
				if n > 0 {
					if werr := clientConn.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					if err != io.EOF {
						_ = clientConn.WriteControl(websocket.CloseMessage,
							websocket.FormatCloseMessage(websocket.CloseAbnormalClosure, "upstream closed"),
							time.Now().Add(time.Second))
					}
					return
				}
			}
		}()

		// Keepalive pings so idle forwards survive intermediaries.
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := clientConn.WriteMessage(websocket.PingMessage, nil); err != nil {
						return
					}
				}
			}
		}()

		wg.Wait()
	}
}

// ParseTCPPort validates the ?port= query: 1-65535, no names, no ranges. The
// editor/admin gate on the route is the authorization; this is the syntax.
func ParseTCPPort(raw string) (int, error) {
	if raw == "" {
		return 0, fmt.Errorf("query parameter port is required")
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port must be a TCP port number 1-65535")
	}
	return port, nil
}

// tcpDialTarget resolves the launcher pod IP for the workspace and dials the
// requested guest port there. The Endpoints address is the virt-launcher pod
// IP where masquerade DNATs guest ports (the same path sshDialTarget uses);
// the port itself is the caller's ?port=, not the Service port.
func tcpDialTarget(ctx context.Context, clientset kubernetes.Interface, namespace, name string, port int) (string, error) {
	if clientset == nil {
		return "", fmt.Errorf("kubernetes client not available")
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	eps, err := clientset.CoreV1().Endpoints(namespace).Get(cctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("cannot reach VM network: %v", err)
	}
	for _, subset := range eps.Subsets {
		if len(subset.Addresses) == 0 {
			continue
		}
		return net.JoinHostPort(subset.Addresses[0].IP, strconv.Itoa(port)), nil
	}
	return "", fmt.Errorf("workspace has no network endpoint (is the VM running?)")
}

// TCPInUse reports whether a TCP bridge holds (namespace, name, port).
func TCPInUse(namespace, name string, port int) bool {
	return tcpSessions.held(tcpKey(namespace, name, port))
}

// TakeOverTCP force-ends the TCP bridge for (namespace, name, port), if any.
func TakeOverTCP(namespace, name string, port int) bool {
	return tcpSessions.forceRelease(tcpKey(namespace, name, port))
}
