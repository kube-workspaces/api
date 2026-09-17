package exec

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kube-workspaces/api/internal/display"
	"k8s.io/client-go/rest"
)

// throughputLogger streams bandwidth metrics when debug logging is enabled.
type throughputLogger struct {
	mu         sync.Mutex
	start      time.Time
	bytesSent  int64
	lastLog    time.Time
	intervalMs int // e.g., 5000 ms = 5 second log interval
	debugMode  bool
}

func newThroughputLogger(intervalMs int) *throughputLogger {
	return &throughputLogger{
		start:      time.Now(),
		lastLog:    time.Now(),
		intervalMs: intervalMs,
		debugMode:  os.Getenv("AQC_DEBUG_THROUGHPUT") == "1",
	}
}

func (l *throughputLogger) recordBytesSent(n int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bytesSent += n
	now := time.Now()
	if now.Sub(l.lastLog) > time.Duration(l.intervalMs)*time.Millisecond {
		l.logStats(now)
		l.lastLog = now
	}
}

func (l *throughputLogger) logStats(now time.Time) {
	if !l.debugMode {
		return
	}
	duration := now.Sub(l.start).Seconds()
	avgBps := float64(l.bytesSent) / duration
	avgKbps := avgBps / 1024.0

	fmt.Fprintf(os.Stderr, "[AQC-THROUGHPUT] %s: bytes=%d duration=%.1fs avg=%.2f KB/s\n",
		time.Now().Format(time.RFC3339), l.bytesSent, duration, avgKbps)

	l.bytesSent = 0
}

var throughputLoggerInstance *throughputLogger

// vncUpgrader negotiates the RFB WebSocket with the browser client. noVNC and
// virtctl-style clients advertise one of these subprotocols; the upgrader must
// echo a match or the browser abandons the handshake.
var vncUpgrader = websocket.Upgrader{
	Subprotocols: []string{"binary", "base64", "plain.kubevirt.io"},
	CheckOrigin: func(r *http.Request) bool {
		return true // Origin checking is handled by CORS middleware
	},
}

// VMVNCHandler returns an HTTP handler that upgrades the client connection to
// a WebSocket and bridges it to the KubeVirt VMI VNC subresource. The VMI name
// equals the workspace name. The socket carries the raw RFB (VNC) byte stream;
// the client side is expected to run a noVNC RFB client on top. KubeVirt's VNC
// console is single-session: while another session is active the dial fails
// with "Active VNC connection. Request denied."
func VMVNCHandler(opts *Options) http.HandlerFunc {
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

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		if opts.Display == nil {
			http.Error(w, "display ownership unavailable", http.StatusServiceUnavailable)
			return
		}
		guard, err := display.Acquire(ctx, opts.Display, namespace, name)
		if err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, display.ErrBusy) { status = http.StatusConflict }
			http.Error(w, "interactive display unavailable", status)
			return
		}
		defer guard.Close()

		logger := newThroughputLogger(5000) // Log every 5 seconds if debug enabled

		handle := &sessionHandle{cancel: cancel}
		if _, ok := vncSessions.acquire(consoleKey(namespace, name), handle); !ok {
			http.Error(w, "VNC display is in use for this workspace", http.StatusConflict)
			return
		}
		defer vncSessions.release(consoleKey(namespace, name), handle)

		// Build the VMI VNC subresource URL on the API server:
		// /apis/subresources.kubevirt.io/v1/namespaces/{ns}/virtualmachineinstances/{name}/vnc
		vncURL, err := vmVNCURL(opts.RESTConfig, namespace, name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		tlsCfg, err := rest.TLSConfigFor(opts.RESTConfig)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to build TLS config: %v", err), http.StatusInternalServerError)
			return
		}
		dialer := websocket.Dialer{
			Subprotocols:    []string{"plain.kubevirt.io"},
			TLSClientConfig: tlsCfg,
			Proxy:           http.ProxyFromEnvironment,
		}

		// Propagate the API server's own identity (service account bearer token).
		headers := http.Header{}
		if tok := consoleToken(opts.RESTConfig); tok != "" {
			headers.Set("Authorization", "Bearer "+tok)
		}

		vmConn, resp, err := dialer.DialContext(ctx, vncURL, headers)
		if err != nil {
			status := http.StatusBadGateway
			if resp != nil {
				status = resp.StatusCode
			}
			http.Error(w, fmt.Sprintf("failed to connect to VM display (is the VM running, is another VNC session active?): %v", err), status)
			return
		}
		defer vmConn.Close()

		// Upgrade the client connection to WebSocket.
		clientConn, err := vncUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return // Upgrade already wrote the error response
		}
		defer clientConn.Close()

		handle.setClose(func() {
			clientConn.Close()
			vmConn.Close()
		})
		if !vncSessions.stillCurrent(consoleKey(namespace, name), handle) || ctx.Err() != nil {
			return
		}

		// Force-close both sockets when the session is cancelled (TTL expiry or
		// API shutdown) so blocked ReadMessage pumps unwind and the slot frees.
		go func() {
			select { case <-ctx.Done(): case <-guard.Done(): cancel() }
			vmConn.Close()
			clientConn.Close()
		}()

		var wg sync.WaitGroup

		// client → VM: forward the raw RFB input stream
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			for {
				msgType, msg, err := clientConn.ReadMessage()
				if err != nil {
					return
				}
				handle.touch()
				deadline, valid := guard.Deadline()
				if !valid { return }
				_ = vmConn.SetWriteDeadline(deadline)
				if err := vmConn.WriteMessage(msgType, msg); err != nil {
					return
				}
			}
		}()

		// VM → client: forward the raw RFB output stream
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			for {
				msgType, msg, err := vmConn.ReadMessage()
				if len(msg) > 0 && logger.debugMode {
					logger.recordBytesSent(int64(len(msg)))
				}
				if err != nil {
					return
				}
				if err := clientConn.WriteMessage(msgType, msg); err != nil {
					return
				}
			}
		}()

		// Keepalive pings so idle VNC sessions aren't dropped by intermediaries
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
					if err := clientConn.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)); err != nil {
						return
					}
				}
			}
		}()

		wg.Wait()
		clientConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "vnc session closed"))
	}
}

// vmVNCURL builds the WebSocket URL for the KubeVirt VMI VNC subresource on the
// API server, using the scheme matching rest.Config.Host.
func vmVNCURL(cfg *rest.Config, namespace, name string) (string, error) {
	host := strings.TrimSuffix(cfg.Host, "/")
	switch {
	case strings.HasPrefix(host, "https://"):
		host = "wss://" + strings.TrimPrefix(host, "https://")
	case strings.HasPrefix(host, "http://"):
		host = "ws://" + strings.TrimPrefix(host, "http://")
	default:
		host = "wss://" + host
	}
	raw := host + "/apis/subresources.kubevirt.io/v1/namespaces/" +
		url.PathEscape(namespace) + "/virtualmachineinstances/" + url.PathEscape(name) + "/vnc"
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid vnc URL: %w", err)
	}
	return u.String(), nil
}
