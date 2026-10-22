package exec

import (
	"context"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kube-workspaces/api/internal/auth"
)

// closeCodeCredentialRevoked is the WebSocket close code used when a stream
// ends because the credential that authorised it is no longer usable.
const closeCodeCredentialRevoked = 4001

// RevalidateFunc re-checks the credential that authorised a stream. It returns
// auth.ErrCredentialRevoked once the credential is no longer usable.
type RevalidateFunc func(context.Context) error

// watchCredential revalidates the caller's credential while a stream is open
// and ends the stream when the credential is revoked. Revocation is detected
// from live account state, so a revocation performed on any replica ends the
// stream on every replica.
//
// The returned function stops the watchdog.
func watchCredential(ctx context.Context, conn *websocket.Conn, cancel context.CancelFunc, revalidate RevalidateFunc, interval time.Duration) func() {
	return auth.WatchCredentialRevocation(ctx, revalidate, interval, func(reason string) {
		endStream(conn, cancel, reason)
	})
}

// endStream tells the client why the stream ended and tears it down.
func endStream(conn *websocket.Conn, cancel context.CancelFunc, reason string) {
	if conn != nil {
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(closeCodeCredentialRevoked, reason),
			time.Now().Add(2*time.Second))
	}
	if cancel != nil {
		cancel()
	}
	if conn != nil {
		conn.Close()
	}
}
