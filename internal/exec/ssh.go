package exec

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// sshAuthMessage is the first client message on an SSH bridge session, carrying
// the guest username and the user's SSH private key (PEM). The private key is
// never persisted: it is held only for the lifetime of the bridge and used to
// authenticate to the guest's sshd.
type sshAuthMessage struct {
	Type       string `json:"type"`
	User       string `json:"user"`
	PrivateKey string `json:"privateKey"`
}

// sshHandshakeTimeout bounds how long the bridge waits for the client's auth
// message after the WebSocket upgrade, so a silently-idle client cannot wedge
// the single-session slot.
const sshHandshakeTimeout = 10 * time.Second

// sshDialTimeout bounds the connection to the guest sshd.
const sshDialTimeout = 10 * time.Second

// SSHOptions configures the SSH bridge handler.
type SSHOptions struct {
	// Clientset is used to resolve the workspace Service endpoints (the
	// launcher pod IP:port that masquerade forwards to the guest sshd).
	Clientset kubernetes.Interface
}

// SSHHandler creates an HTTP handler that upgrades to WebSocket and bridges to
// the guest's sshd over the workspace's masqueraded port. The client authentic
// with the private key matching one of the public keys the controller seeded
// into the guest's cloud-init (SshKey CRs).
//
// The target is the workspace Service's endpoints address:port — the
// virt-launcher pod IP where KubeVirt's masquerade DNATs to the guest — which
// bypasses the Service ClusterIP (VM Services do not DNAT correctly under the
// launcher's iptables; the pod IP path works cross-node). Guest sshd host keys
// are self-generated and rotate per image rebuild, so no host key verification
// is possible; the session is carried over the authenticated WS + TLS to the
// API instead.
func SSHHandler(opts *SSHOptions) http.HandlerFunc {
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

		// Reserve this workspace's SSH slot; a second bridge is refused until
		// the UI has explicitly taken it over (POST /v1/workspaces/{name}/ssh/takeover).
		handle := &sessionHandle{cancel: cancel}
		if _, acquired := sshSessions.acquire(consoleKey(namespace, name), handle); !acquired {
			http.Error(w, "ssh session is in use for this workspace", http.StatusConflict)
			return
		}
		defer sshSessions.release(consoleKey(namespace, name), handle)

		upstream, err := sshDialTarget(ctx, opts.Clientset, namespace, name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		clientConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return // Upgrade already wrote the error response
		}
		defer clientConn.Close()

		// The client's first message must carry the SSH credentials.
		clientConn.SetReadDeadline(time.Now().Add(sshHandshakeTimeout))
		_, raw, err := clientConn.ReadMessage()
		if err != nil {
			return
		}
		auth := sshAuthMessage{}
		if err := json.Unmarshal(raw, &auth); err != nil || auth.Type != "ssh" {
			clientConn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "expected SSH auth message"))
			return
		}
		if auth.User == "" {
			clientConn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "username is required"))
			return
		}
		signer, err := ssh.ParsePrivateKey([]byte(auth.PrivateKey))
		if err != nil {
			clientConn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "invalid private key"))
			return
		}
		clientConn.SetReadDeadline(time.Time{})

		sshConfig := &ssh.ClientConfig{
			User:            auth.User,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // see handler doc
			Timeout:         sshDialTimeout,
		}

		// Dial the guest sshd through the launcher pod's masquerade port.
		sshClient, err := ssh.Dial("tcp", upstream, sshConfig)
		if err != nil {
			clientConn.WriteMessage(websocket.TextMessage,
				[]byte(fmt.Sprintf("\r\nSSH connection failed: %v\r\n", err)))
			return
		}
		defer sshClient.Close()

		session, err := sshClient.NewSession()
		if err != nil {
			clientConn.WriteMessage(websocket.TextMessage,
				[]byte(fmt.Sprintf("\r\nSSH session failed: %v\r\n", err)))
			return
		}
		defer session.Close()

		cols := uint16(80)
		rows := uint16(24)
		if c := r.URL.Query().Get("cols"); c != "" {
			var v uint16
			fmt.Sscanf(c, "%d", &v)
			if v > 0 {
				cols = v
			}
		}
		if ro := r.URL.Query().Get("rows"); ro != "" {
			var v uint16
			fmt.Sscanf(ro, "%d", &v)
			if v > 0 {
				rows = v
			}
		}

		var closeOnce sync.Once
		forceClose := func() {
			closeOnce.Do(func() {
				session.Close()
				sshClient.Close()
				clientConn.Close()
			})
		}

		// Let the registry break the session cleanly on take-over/TTL expiry.
		handle.close = func() {
			_ = clientConn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "taken over by another user"),
				time.Now().Add(time.Second))
			forceClose()
		}
		if !sshSessions.stillCurrent(consoleKey(namespace, name), handle) {
			forceClose()
			return
		}
		go func() {
			<-ctx.Done()
			forceClose()
		}()

		stdin, err := session.StdinPipe()
		if err != nil {
			return
		}
		wsOut := &sshWSWriter{conn: clientConn, ctx: ctx}
		session.Stdout = wsOut
		session.Stderr = wsOut

		// All pipes must be wired before the PTY/shell are started.
		if err := session.RequestPty("xterm-256color", int(rows), int(cols), ssh.TerminalModes{
			ssh.ECHO:  1,
			ssh.IXON:  1,
			ssh.IUTF8: 1,
		}); err != nil {
			clientConn.WriteMessage(websocket.TextMessage,
				[]byte(fmt.Sprintf("\r\nFailed to allocate PTY: %v\r\n", err)))
			return
		}
		if err := session.Shell(); err != nil {
			clientConn.WriteMessage(websocket.TextMessage,
				[]byte(fmt.Sprintf("\r\nFailed to start shell: %v\r\n", err)))
			return
		}

		var wg sync.WaitGroup

		// client → guest shell: forward input; resize control messages call
		// WindowChange on the PTY.
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			for {
				msgType, msg, err := clientConn.ReadMessage()
				if err != nil {
					return
				}
				var resize resizeMessage
				if msgType == websocket.TextMessage && json.Unmarshal(msg, &resize) == nil && resize.Type == "resize" {
					if resize.Cols > 0 && resize.Rows > 0 {
						_ = session.WindowChange(int(resize.Rows), int(resize.Cols))
					}
					continue
				}
				handle.touch()
				if _, err := stdin.Write(msg); err != nil {
					return
				}
			}
		}()

		// Wait for the shell to exit; cancelling ctx force-closes everything.
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			_ = session.Wait()
		}()

		// Keepalive pings so an idle session isn't dropped by intermediaries.
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
		forceClose()
		clientConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "ssh session ended"))
	}
}

// sshDialTarget resolves the guest sshd address through the workspace's
// Service endpoints: the launcher pod's IP where the masquerade DNAT exposes
// the guest sshd port.
func sshDialTarget(ctx context.Context, clientset kubernetes.Interface, namespace, name string) (string, error) {
	if clientset == nil {
		return "", fmt.Errorf("kubernetes client not available")
	}
	eps, err := clientset.CoreV1().Endpoints(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("cannot reach VM network: %v", err)
	}
	for _, subset := range eps.Subsets {
		if len(subset.Addresses) == 0 || len(subset.Ports) == 0 {
			continue
		}
		ip := subset.Addresses[0].IP
		port := subset.Ports[0].Port
		return net.JoinHostPort(ip, fmt.Sprintf("%d", port)), nil
	}
	return "", fmt.Errorf("workspace has no ssh endpoint (is the VM running?)")
}

// sshWSWriter streams SSH stdout/stderr to the WebSocket as binary messages.
type sshWSWriter struct {
	conn *websocket.Conn
	ctx  context.Context
	mu   sync.Mutex
}

func (w *sshWSWriter) Write(p []byte) (int, error) {
	select {
	case <-w.ctx.Done():
		return 0, nil
	default:
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// SSHConsoleInUse reports whether an SSH bridge is currently active for the workspace.
func SSHConsoleInUse(namespace, name string) bool {
	return sshSessions.held(consoleKey(namespace, name))
}

// TakeOverSSHConsole force-ends the active SSH bridge for the workspace, if any.
func TakeOverSSHConsole(namespace, name string) bool {
	return sshSessions.forceRelease(consoleKey(namespace, name))
}
