package exec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

func TestTerminalSizeQueue(t *testing.T) {
	q := &terminalSizeQueue{
		ch: make(chan *remotecommand.TerminalSize, 2),
	}

	// Send a size
	q.ch <- &remotecommand.TerminalSize{Width: 80, Height: 24}
	q.ch <- &remotecommand.TerminalSize{Width: 120, Height: 40}

	// Read them back
	size := q.Next()
	if size == nil {
		t.Fatal("expected non-nil size")
	}
	if size.Width != 80 || size.Height != 24 {
		t.Errorf("expected 80x24, got %dx%d", size.Width, size.Height)
	}

	size = q.Next()
	if size == nil {
		t.Fatal("expected non-nil size")
	}
	if size.Width != 120 || size.Height != 40 {
		t.Errorf("expected 120x40, got %dx%d", size.Width, size.Height)
	}

	// Close the channel
	close(q.ch)
	size = q.Next()
	if size != nil {
		t.Errorf("expected nil after close, got %v", size)
	}
}

func TestResizeMessageParsing(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		isValid bool
		cols    uint16
		rows    uint16
	}{
		{
			name:    "valid resize message",
			input:   `{"type":"resize","cols":120,"rows":40}`,
			isValid: true,
			cols:    120,
			rows:    40,
		},
		{
			name:    "resize with zero cols",
			input:   `{"type":"resize","cols":0,"rows":40}`,
			isValid: true,
			cols:    0,
			rows:    40,
		},
		{
			name:    "not a resize message",
			input:   `{"type":"other","data":"hello"}`,
			isValid: false,
		},
		{
			name:    "invalid json",
			input:   `not json at all`,
			isValid: false,
		},
		{
			name:    "empty object",
			input:   `{}`,
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var msg resizeMessage
			err := json.Unmarshal([]byte(tt.input), &msg)
			isResize := err == nil && msg.Type == "resize"

			if isResize != tt.isValid {
				t.Errorf("expected isResize=%v, got %v", tt.isValid, isResize)
			}
			if tt.isValid {
				if msg.Cols != tt.cols {
					t.Errorf("expected cols=%d, got %d", tt.cols, msg.Cols)
				}
				if msg.Rows != tt.rows {
					t.Errorf("expected rows=%d, got %d", tt.rows, msg.Rows)
				}
			}
		})
	}
}

func TestWsWriterImpl(t *testing.T) {
	// Create a WebSocket server that just reads and discards messages
	var receivedMessages [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade failed: %v", err)
			return
		}
		defer conn.Close()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			receivedMessages = append(receivedMessages, msg)
		}
	}))
	defer server.Close()

	// Connect as a client
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	writer := &wsWriterImpl{conn: conn, ctx: ctx}

	// Test writing data
	data := []byte("hello world")
	n, err := writer.Write(data)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected n=%d, got %d", len(data), n)
	}

	// Test that cancelled context returns EOF
	cancel()
	_, err = writer.Write([]byte("after cancel"))
	if err == nil {
		t.Error("expected error after context cancel")
	}
}

func TestDetectShellCandidatesOrder(t *testing.T) {
	// Verify the shell candidates are in the expected order
	expected := []string{"/bin/bash", "/bin/sh", "/bin/ash", "/bin/zsh"}
	if len(shellCandidates) != len(expected) {
		t.Fatalf("expected %d candidates, got %d", len(expected), len(shellCandidates))
	}
	for i, s := range expected {
		if shellCandidates[i] != s {
			t.Errorf("candidate[%d]: expected %q, got %q", i, s, shellCandidates[i])
		}
	}
}

func TestDetectShellWithUnreachablePod(t *testing.T) {
	// When the pod is unreachable, detectShell should fall back to /bin/sh
	fakeClientset := fake.NewSimpleClientset()
	opts := &Options{
		RESTConfig: &rest.Config{Host: "http://localhost:0"}, // unreachable
		Clientset:  fakeClientset,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	shell := detectShell(ctx, opts, "test-ns", "test-pod-0")
	if shell != "/bin/sh" {
		t.Errorf("expected /bin/sh fallback, got %q", shell)
	}
}

func TestHandlerRejectsEmptyName(t *testing.T) {
	opts := &Options{
		RESTConfig: &rest.Config{Host: "http://localhost:0"},
		Clientset:  fake.NewSimpleClientset(),
	}

	handler := Handler(opts)

	// Request with no name should return 400
	req := httptest.NewRequest("GET", "/v1/workspaces//exec?namespace=test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandlerUsesExplicitShellWithoutDetection(t *testing.T) {
	// This test verifies the handler path: when shell is explicitly set,
	// detection is skipped. We verify this indirectly by ensuring the handler
	// attempts to use the provided shell (which will fail to connect to a
	// non-existent pod, but importantly won't hang on detection).

	fakeClientset := fake.NewSimpleClientset()
	opts := &Options{
		RESTConfig: &rest.Config{Host: "http://localhost:0"},
		Clientset:  fakeClientset,
	}

	handler := Handler(opts)

	// Create a test WebSocket server wrapping our handler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate path value by setting query params
		// The handler reads from PathValue first, then query params
		handler(w, r)
	}))
	defer server.Close()

	// Try connecting with an explicit shell - should not trigger detection
	// (we can't easily assert detection wasn't called without refactoring,
	// but we can verify the handler completes quickly, i.e. doesn't spend
	// 5s on detection timeout)
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?namespace=test&shell=/bin/custom-shell&cols=80&rows=24"

	start := time.Now()
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	elapsed := time.Since(start)

	if err != nil {
		// The connection may fail because there's no real pod, but it should
		// fail fast (< 2s) since detection is skipped
		if elapsed > 2*time.Second {
			t.Errorf("handler took %v with explicit shell; detection may have run", elapsed)
		}
		// If we got an HTTP response (upgrade failed), that's expected
		if resp != nil {
			return
		}
		// WebSocket upgrade failure is also fine for this test
		return
	}
	defer conn.Close()

	// If connection succeeded (unlikely with fake clientset), read any error message
	_, msg, _ := conn.ReadMessage()
	t.Logf("received message: %s", string(msg))

	// Key assertion: the whole thing completed in under 2s
	if elapsed > 2*time.Second {
		t.Errorf("handler took %v; expected < 2s with explicit shell (no detection)", elapsed)
	}
}
