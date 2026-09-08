package exec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"k8s.io/client-go/rest"
)

// VMConsoleHandler creates an HTTP handler that upgrades the client connection
// to a WebSocket and bridges it to the KubeVirt VMI serial console subresource.
// The VMI name equals the workspace name. The console is a raw serial stream:
// no shell is spawned — the guest image must run a getty on the console for a
// login prompt to appear.
func VMConsoleHandler(opts *Options) http.HandlerFunc {
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

		// Reserve this workspace's serial-console slot before dialing. KubeVirt
		// serial consoles are single-session and last-wins — a blind dial would
		// silently sever an existing session. A second bridge is therefore only
		// accepted once the UI has explicitly taken the console over
		// (POST /v1/workspaces/{name}/console/takeover).
		handle := &sessionHandle{cancel: cancel}
		var acquired bool
		_, acquired = serialSessions.acquire(consoleKey(namespace, name), handle)
		if !acquired {
			http.Error(w, "serial console is in use for this workspace", http.StatusConflict)
			return
		}
		defer serialSessions.release(consoleKey(namespace, name), handle)

		// Build the VMI console subresource URL on the API server:
		// /apis/subresources.kubevirt.io/v1/namespaces/{ns}/virtualmachineinstances/{name}/console
		consoleURL, err := vmConsoleURL(opts.RESTConfig, namespace, name)
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

		vmConn, resp, err := dialer.Dial(consoleURL, headers)
		if err != nil {
			status := http.StatusBadGateway
			if resp != nil {
				status = resp.StatusCode
			}
			http.Error(w, fmt.Sprintf("failed to connect to VM console (is the VM running?): %v", err), status)
			return
		}
		defer vmConn.Close()

		// Upgrade the client connection to WebSocket.
		clientConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return // Upgrade already wrote the error response
		}
		defer clientConn.Close()

		// When a take-over evicts this session, send a clean close with an
		// explicit reason so the browser treats it as intentional rather than
		// starting an auto-reconnect war against the new owner.
		handle.close = func() {
			_ = clientConn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "taken over by another user"),
				time.Now().Add(time.Second))
			clientConn.Close()
			vmConn.Close()
		}

		// If a take-over superseded us while dialing/upgrading, abandon this
		// half-built bridge so it doesn't straddle the slot the new owner holds.
		if !serialSessions.stillCurrent(consoleKey(namespace, name), handle) {
			clientConn.Close()
			vmConn.Close()
			return
		}

		var wg sync.WaitGroup

		// client → VM: forward raw input; swallow terminal resize control messages
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			for {
				msgType, msg, err := clientConn.ReadMessage()
				if err != nil {
					return
				}
				if msgType == websocket.TextMessage {
					var resize resizeMessage
					if json.Unmarshal(msg, &resize) == nil && resize.Type == "resize" {
						continue // serial consoles have no resize channel
					}
				}
				handle.touch()
				if err := vmConn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
					return
				}
			}
		}()

		// VM → client: forward the serial stream
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			for {
				_, msg, err := vmConn.ReadMessage()
				if err != nil {
					return
				}
				if err := clientConn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
					return
				}
			}
		}()

		// Keepalive pings so idle consoles aren't dropped by intermediaries
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
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "console closed"))
	}
}

// vmConsoleURL builds the WebSocket URL for the KubeVirt VMI console
// subresource on the API server, using the scheme matching rest.Config.Host.
func vmConsoleURL(cfg *rest.Config, namespace, name string) (string, error) {
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
		url.PathEscape(namespace) + "/virtualmachineinstances/" + url.PathEscape(name) + "/console"
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid console URL: %w", err)
	}
	return u.String(), nil
}

// consoleToken returns the API server's own bearer token for the KubeVirt
// console subresource. client-go's InClusterConfig sets both BearerToken (read
// once at startup) and BearerTokenFile (the projected token kubelet refreshes
// in place). Prefer the freshly-read file so an expired startup token in the
// long-running API pod doesn't 401 the console dial; fall back to the static
// token when no file is configured (e.g. out-of-cluster configs).
func consoleToken(cfg *rest.Config) string {
	if cfg == nil {
		return ""
	}
	if cfg.BearerTokenFile != "" {
		if tok, err := os.ReadFile(cfg.BearerTokenFile); err == nil {
			if tok = []byte(strings.TrimSpace(string(tok))); len(tok) > 0 {
				return string(tok)
			}
		}
	}
	return strings.TrimSpace(cfg.BearerToken)
}
