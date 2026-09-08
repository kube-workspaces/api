package exec

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"k8s.io/client-go/rest"
)

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

		vmConn, resp, err := dialer.Dial(vncURL, headers)
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
		clientConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return // Upgrade already wrote the error response
		}
		defer clientConn.Close()

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

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
					if err := clientConn.WriteMessage(websocket.PingMessage, nil); err != nil {
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
