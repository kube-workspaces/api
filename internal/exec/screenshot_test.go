package exec

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestCaptureOneFrameAgainstFakeVNC(t *testing.T) {
	up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		rd := &wsReader{ws: ws}

		// Server version.
		_ = ws.WriteMessage(websocket.BinaryMessage, []byte("RFB 003.008\n"))
		// Client version.
		if err := rd.readFull(make([]byte, 12)); err != nil {
			return
		}
		// Security types: one, None.
		_ = ws.WriteMessage(websocket.BinaryMessage, []byte{1, 1})
		// Client selection.
		sel := make([]byte, 1)
		if err := rd.readFull(sel); err != nil || sel[0] != 1 {
			return
		}
		// SecurityResult OK.
		_ = ws.WriteMessage(websocket.BinaryMessage, []byte{0, 0, 0, 0})
		// ClientInit.
		if err := rd.readFull(make([]byte, 1)); err != nil {
			return
		}
		// ServerInit: 2x2 + 16-byte pixfmt + namelen 0.
		var init bytes.Buffer
		_ = binary.Write(&init, binary.BigEndian, uint16(2))
		_ = binary.Write(&init, binary.BigEndian, uint16(2))
		init.Write(make([]byte, 16))
		_ = binary.Write(&init, binary.BigEndian, uint32(0))
		_ = ws.WriteMessage(websocket.BinaryMessage, init.Bytes())
		// Client SetPixelFormat (20), SetEncodings (4), FUR (10).
		if err := rd.readFull(make([]byte, 20)); err != nil {
			return
		}
		if err := rd.readFull(make([]byte, 4)); err != nil {
			return
		}
		if err := rd.readFull(make([]byte, 10)); err != nil {
			return
		}
		// One Raw rect 2x2: pixels B,G,R,pad.
		var upd bytes.Buffer
		upd.WriteByte(0)
		upd.WriteByte(0)
		_ = binary.Write(&upd, binary.BigEndian, uint16(1))
		_ = binary.Write(&upd, binary.BigEndian, uint16(0))
		_ = binary.Write(&upd, binary.BigEndian, uint16(0))
		_ = binary.Write(&upd, binary.BigEndian, uint16(2))
		_ = binary.Write(&upd, binary.BigEndian, uint16(2))
		_ = binary.Write(&upd, binary.BigEndian, int32(0))
		// red, green, blue, white
		upd.Write([]byte{0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0})
		_ = ws.WriteMessage(websocket.BinaryMessage, upd.Bytes())
		// Hold the connection briefly so the client can finish reading.
		select {}
	}))
	defer srv.Close()

	dialer := websocket.Dialer{Subprotocols: []string{"plain.kubevirt.io"}}
	ws, _, err := dialer.Dial(strings.Replace(srv.URL, "http://", "ws://", 1), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()

	img, err := captureOneFrame(t.Context(), ws)
	if err != nil {
		t.Fatalf("captureOneFrame: %v", err)
	}
	if img.Bounds().Dx() != 2 || img.Bounds().Dy() != 2 {
		t.Fatalf("bounds = %v, want 2x2", img.Bounds())
	}
	// Top-left pixel is red.
	r, g, b, _ := img.At(0, 0).RGBA()
	if r>>8 != 255 || g>>8 != 0 || b>>8 != 0 {
		t.Fatalf("pixel(0,0) = %d,%d,%d, want 255,0,0", r>>8, g>>8, b>>8)
	}
}

type wsReader struct {
	ws  *websocket.Conn
	buf bytes.Buffer
}

func (r *wsReader) readFull(p []byte) error {
	for len(p) > 0 {
		if r.buf.Len() > 0 {
			n := copy(p, r.buf.Bytes())
			r.buf.Next(n)
			p = p[n:]
			continue
		}
		_, msg, err := r.ws.ReadMessage()
		if err != nil {
			return err
		}
		r.buf.Write(msg)
	}
	return nil
}
