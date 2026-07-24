// Package exec provides a WebSocket-to-Kubernetes-exec bridge for terminal sessions.
package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// shellCandidates is the ordered list of shells to try when detecting an available shell.
var shellCandidates = []string{"/bin/bash", "/bin/sh", "/bin/ash", "/bin/zsh"}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Origin checking is handled by CORS middleware
	},
}

// Options configures the exec handler.
type Options struct {
	// RESTConfig is the Kubernetes REST config for SPDY exec connections.
	RESTConfig *rest.Config
	// Clientset is the Kubernetes clientset for pod exec requests.
	Clientset kubernetes.Interface
}

// resizeMessage is sent by the client to resize the terminal.
type resizeMessage struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// terminalSizeQueue implements remotecommand.TerminalSizeQueue.
type terminalSizeQueue struct {
	ch chan *remotecommand.TerminalSize
}

func (q *terminalSizeQueue) Next() *remotecommand.TerminalSize {
	size, ok := <-q.ch
	if !ok {
		return nil
	}
	return size
}

// detectShell probes the pod to find an available shell.
// It tries each candidate in order by running a quick non-interactive exec.
// Returns the first shell that exits successfully, or "/bin/sh" as last resort.
func detectShell(ctx context.Context, opts *Options, namespace, podName string) string {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	for _, shell := range shellCandidates {
		if probeShell(probeCtx, opts, namespace, podName, shell) {
			return shell
		}
	}
	// If all probes fail (unlikely), default to /bin/sh and let the interactive
	// session show the error to the user
	return "/bin/sh"
}

// probeShell tests if a specific shell binary is available in the pod by running
// it with "-c exit 0". Returns true if the command exits successfully.
func probeShell(ctx context.Context, opts *Options, namespace, podName, shell string) (ok bool) {
	// Recover from panics (e.g. nil REST client from fake clientsets in tests)
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()

	restClient := opts.Clientset.CoreV1().RESTClient()
	if restClient == nil {
		return false
	}

	req := restClient.Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command: []string{shell, "-c", "exit 0"},
			Stdout:  true,
			Stderr:  true,
			TTY:     false,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(opts.RESTConfig, "POST", req.URL())
	if err != nil {
		return false
	}

	var stdout, stderr bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	return err == nil
}

// Handler creates an HTTP handler that upgrades to WebSocket and bridges to pod exec.
// The handler expects path parameters: namespace, name (workspace name).
// Query parameters: shell (optional, auto-detected if not provided), cols, rows.
func Handler(opts *Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		namespace := r.PathValue("namespace")
		name := r.PathValue("name")
		if namespace == "" {
			namespace = r.URL.Query().Get("namespace")
		}
		if namespace == "" {
			namespace = "workspaces"
		}
		if name == "" {
			http.Error(w, "workspace name is required", http.StatusBadRequest)
			return
		}

		shell := r.URL.Query().Get("shell")
		podName := name + "-0"

		// Only run shell detection if no shell was explicitly configured
		// (empty means the Image CR had no defaultShell set)
		if shell == "" {
			shell = detectShell(r.Context(), opts, namespace, podName)
		}

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

		// Upgrade to WebSocket
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			// Upgrade already wrote the error response
			return
		}
		defer conn.Close()

		// Create exec request
		restClient := opts.Clientset.CoreV1().RESTClient()
		if restClient == nil {
			conn.WriteMessage(websocket.TextMessage, []byte("\r\nError: Kubernetes REST client not available\r\n"))
			return
		}

		req := restClient.Post().
			Resource("pods").
			Name(podName).
			Namespace(namespace).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Command: []string{shell},
				Stdin:   true,
				Stdout:  true,
				Stderr:  true,
				TTY:     true,
			}, scheme.ParameterCodec)

		exec, err := remotecommand.NewSPDYExecutor(opts.RESTConfig, "POST", req.URL())
		if err != nil {
			conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\nError creating exec session: %v\r\n", err)))
			return
		}

		// Set up terminal size queue
		sizeQueue := &terminalSizeQueue{
			ch: make(chan *remotecommand.TerminalSize, 1),
		}

		// Send initial size
		sizeQueue.ch <- &remotecommand.TerminalSize{Width: cols, Height: rows}

		// Create pipes for stdin
		stdinReader, stdinWriter := io.Pipe()

		// Context for coordinating goroutines
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		var wg sync.WaitGroup

		// Goroutine: read from WebSocket → write to exec stdin
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer stdinWriter.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				msgType, msg, err := conn.ReadMessage()
				if err != nil {
					cancel()
					return
				}

				if msgType == websocket.TextMessage {
					// Check if it's a control message (resize)
					var resize resizeMessage
					if json.Unmarshal(msg, &resize) == nil && resize.Type == "resize" {
						if resize.Cols > 0 && resize.Rows > 0 {
							select {
							case sizeQueue.ch <- &remotecommand.TerminalSize{
								Width:  resize.Cols,
								Height: resize.Rows,
							}:
							default:
								// Drop if queue is full
							}
						}
						continue
					}
					// Otherwise treat as stdin data
					if _, err := stdinWriter.Write(msg); err != nil {
						cancel()
						return
					}
				} else if msgType == websocket.BinaryMessage {
					// Binary messages are raw stdin data
					if _, err := stdinWriter.Write(msg); err != nil {
						cancel()
						return
					}
				}
			}
		}()

		// wsWriter wraps WebSocket as an io.Writer for stdout/stderr
		wsWriter := &wsWriterImpl{conn: conn, ctx: ctx}

		// Run the exec stream (blocks until done)
		err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdin:             stdinReader,
			Stdout:            wsWriter,
			Stderr:            wsWriter,
			Tty:               true,
			TerminalSizeQueue: sizeQueue,
		})

		cancel()
		close(sizeQueue.ch)

		if err != nil {
			// Abnormal exit: write error message and close with 1001 (Going Away)
			conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\nSession ended: %v\r\n", err)))
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseGoingAway, "session error"))
		} else {
			// Clean shell exit: close with 1000 (Normal Closure)
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "shell exited"))
		}

		// Wait for reader goroutine to finish
		wg.Wait()
	}
}

// wsWriterImpl writes exec output to a WebSocket connection.
type wsWriterImpl struct {
	conn *websocket.Conn
	ctx  context.Context
	mu   sync.Mutex
}

func (w *wsWriterImpl) Write(p []byte) (int, error) {
	select {
	case <-w.ctx.Done():
		return 0, io.EOF
	default:
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	err := w.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
