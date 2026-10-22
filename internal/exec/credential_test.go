package exec

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kube-workspaces/api/internal/auth"
)

// revokedStreamServer upgrades a request and holds the connection until the
// credential watchdog ends it.
func revokedStreamServer(t *testing.T, revalidate RevalidateFunc, interval time.Duration) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		defer watchCredential(ctx, conn, cancel, revalidate, interval)()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestWatchCredentialEndsStreamWhenCredentialIsRevoked(t *testing.T) {
	srv := revokedStreamServer(t, func(context.Context) error {
		return auth.ErrCredentialRevoked
	}, 10*time.Millisecond)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err = conn.ReadMessage()
	closeErr, ok := err.(*websocket.CloseError)
	if !ok {
		t.Fatalf("expected a websocket close error, got %v", err)
	}
	if closeErr.Code != closeCodeCredentialRevoked {
		t.Fatalf("expected close code %d, got %d", closeCodeCredentialRevoked, closeErr.Code)
	}
}

func TestWatchCredentialKeepsStreamWhileCredentialIsValid(t *testing.T) {
	srv := revokedStreamServer(t, func(context.Context) error {
		return nil
	}, 10*time.Millisecond)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.WriteMessage(websocket.TextMessage, []byte("echo")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("expected the stream to stay open without a read deadline")
	} else if !isTimeout(err) {
		t.Fatalf("expected a read timeout, got %v", err)
	}
}

func TestWatchCredentialEndsStreamWhenCredentialCannotBeVerified(t *testing.T) {
	srv := revokedStreamServer(t, func(context.Context) error {
		return errors.New("temporarily unavailable")
	}, 10*time.Millisecond)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Repeated verification failures must not leave the stream open on
	// unverified state.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err = conn.ReadMessage()
	closeErr, ok := err.(*websocket.CloseError)
	if !ok {
		t.Fatalf("expected a websocket close error, got %v", err)
	}
	if closeErr.Code != closeCodeCredentialRevoked {
		t.Fatalf("expected close code %d, got %d", closeCodeCredentialRevoked, closeErr.Code)
	}
}

func isTimeout(err error) bool {
	var netErr interface{ Timeout() bool }
	return errors.As(err, &netErr) && netErr.Timeout()
}
