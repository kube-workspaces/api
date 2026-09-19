package broker

import (
	"errors"
	"io"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketStream flattens binary WebSocket messages into an RFB byte stream.
// A single goroutine reads and a single goroutine writes; Close may run from
// another goroutine. It does not dial, upgrade or authorize a connection.
type WebSocketStream struct {
	conn   *websocket.Conn
	reader io.Reader
}

func NewWebSocketStream(c *websocket.Conn) *WebSocketStream {
	c.SetReadLimit(int64(MaxPixels*4 + 1<<20))
	return &WebSocketStream{conn: c}
}

func (s *WebSocketStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if s.reader == nil {
			kind, reader, err := s.conn.NextReader()
			if err != nil {
				return 0, err
			}
			if kind != websocket.BinaryMessage {
				return 0, errors.New("RFB broker requires binary WebSocket data")
			}
			s.reader = reader
		}
		n, err := s.reader.Read(p)
		if err == io.EOF {
			s.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (s *WebSocketStream) Write(p []byte) (int, error) {
	if err := s.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
func (s *WebSocketStream) Close() error { return s.conn.Close() }
func (s *WebSocketStream) SetDeadline(t time.Time) error {
	if err := s.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return s.conn.SetWriteDeadline(t)
}
func (s *WebSocketStream) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
