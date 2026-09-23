package exec

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kube-workspaces/api/internal/display"
	"k8s.io/client-go/rest"
)

// screenshotTimeout bounds the whole capture: dial, RFB handshake, one full
// frame and PNG encode. Screenshots are thumbnails for the client list, not a
// streaming path — a slow guest fails fast with 502/504 rather than wedging.
const screenshotTimeout = 15 * time.Second

// ScreenshotHandler returns an HTTP handler serving a one-shot PNG of the VM
// display: GET /v1/workspaces/{name}/vnc/screenshot?namespace=...
//
// It dials the same KubeVirt VMI VNC subresource as the interactive bridge but
// holds only the capture lease (display.AcquireCapture), so a thumbnail never
// evicts the viewer or the seat holder — and a held console answers 409
// instead of stealing the session. The RFB handshake advertises Raw only, so
// no pseudo-encoding acks or payloads are involved.
func ScreenshotHandler(opts *Options) http.HandlerFunc {
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
		if opts == nil || opts.RESTConfig == nil || opts.Display == nil {
			http.Error(w, "screenshot unavailable", http.StatusServiceUnavailable)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), screenshotTimeout)
		defer cancel()

		guard, err := display.AcquireCapture(ctx, opts.Display, namespace, name)
		if err != nil {
			status := http.StatusServiceUnavailable
			if isBusy(err) {
				status = http.StatusConflict
			}
			http.Error(w, "display is in use, try again shortly", status)
			return
		}
		defer guard.Close()

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
			Subprotocols:     []string{"plain.kubevirt.io"},
			TLSClientConfig:  tlsCfg,
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 10 * time.Second,
		}
		headers := http.Header{}
		if tok := consoleToken(opts.RESTConfig); tok != "" {
			headers.Set("Authorization", "Bearer "+tok)
		}
		vmConn, resp, err := dialer.DialContext(ctx, vncURL, headers)
		if err != nil {
			status := http.StatusBadGateway
			if resp != nil && resp.StatusCode != 0 {
				status = resp.StatusCode
			}
			http.Error(w, fmt.Sprintf("failed to connect to VM display: %v", err), status)
			return
		}
		defer vmConn.Close()
		_ = vmConn.SetReadDeadline(time.Now().Add(screenshotTimeout))
		_ = vmConn.SetWriteDeadline(time.Now().Add(10 * time.Second))

		img, err := captureOneFrame(ctx, vmConn)
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				http.Error(w, "screenshot timed out", http.StatusGatewayTimeout)
				return
			}
			http.Error(w, fmt.Sprintf("screenshot failed: %v", err), http.StatusBadGateway)
			return
		}

		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			http.Error(w, "failed to encode screenshot", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}
}

func isBusy(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, display.ErrBusy)
}

// rfbConn flattens WebSocket message boundaries into an RFB byte stream: the
// KubeVirt VNC subresource carries RFB over binary WS frames and may split a
// single RFB message across frames.
type rfbConn struct {
	ws  *websocket.Conn
	ctx context.Context
	buf bytes.Buffer
}

func (c *rfbConn) readFull(p []byte) error {
	for len(p) > 0 {
		if c.buf.Len() > 0 {
			n := copy(p, c.buf.Bytes())
			c.buf.Next(n)
			p = p[n:]
			continue
		}
		_, msg, err := c.ws.ReadMessage()
		if err != nil {
			return err
		}
		c.buf.Write(msg)
	}
	return nil
}

func (c *rfbConn) write(p []byte) error {
	return c.ws.WriteMessage(websocket.BinaryMessage, p)
}

// captureOneFrame performs the minimal RFB 3.8 handshake (None auth, shared,
// Raw encoding) and returns one full-frame image.
func captureOneFrame(ctx context.Context, ws *websocket.Conn) (image.Image, error) {
	c := &rfbConn{ws: ws, ctx: ctx}

	// 1. Version: server sends 12 bytes "RFB 003.008\n"; reply the same.
	ver := make([]byte, 12)
	if err := c.readFull(ver); err != nil {
		return nil, fmt.Errorf("reading version: %w", err)
	}
	if len(ver) < 12 || string(ver[:3]) != "RFB" {
		return nil, fmt.Errorf("not an RFB server")
	}
	if err := c.write([]byte("RFB 003.008\n")); err != nil {
		return nil, fmt.Errorf("writing version: %w", err)
	}

	// 2. Security types (3.8 form): count + list; pick None (1).
	hdr := make([]byte, 1)
	if err := c.readFull(hdr); err != nil {
		return nil, fmt.Errorf("reading security types: %w", err)
	}
	n := int(hdr[0])
	if n == 0 {
		// Failure reason follows as a string.
		lenBuf := make([]byte, 4)
		if err := c.readFull(lenBuf); err != nil {
			return nil, fmt.Errorf("security handshake failed")
		}
		reason := make([]byte, binary.BigEndian.Uint32(lenBuf))
		_, _ = io.ReadFull(struct{ io.Reader }{readerFunc(func(p []byte) (int, error) {
			if err := c.readFull(p); err != nil {
				return 0, err
			}
			return len(p), nil
		})}, reason)
		return nil, fmt.Errorf("security handshake failed: %s", string(reason))
	}
	types := make([]byte, n)
	if err := c.readFull(types); err != nil {
		return nil, fmt.Errorf("reading security types: %w", err)
	}
	hasNone := false
	for _, t := range types {
		if t == 1 {
			hasNone = true
		}
	}
	if !hasNone {
		return nil, fmt.Errorf("server requires authentication (no None type)")
	}
	if err := c.write([]byte{1}); err != nil {
		return nil, fmt.Errorf("selecting security type: %w", err)
	}

	// 3. SecurityResult u32 (0 = OK).
	res := make([]byte, 4)
	if err := c.readFull(res); err != nil {
		return nil, fmt.Errorf("reading security result: %w", err)
	}
	if binary.BigEndian.Uint32(res) != 0 {
		return nil, fmt.Errorf("security result failed")
	}

	// 4. ClientInit: shared flag = 1.
	if err := c.write([]byte{1}); err != nil {
		return nil, fmt.Errorf("writing client init: %w", err)
	}

	// 5. ServerInit: u16 w,h + 16-byte pixel format + u32 name len + name.
	init := make([]byte, 24)
	if err := c.readFull(init); err != nil {
		return nil, fmt.Errorf("reading server init: %w", err)
	}
	fbW := int(binary.BigEndian.Uint16(init[0:2]))
	fbH := int(binary.BigEndian.Uint16(init[2:4]))
	nameLen := int(binary.BigEndian.Uint32(init[20:24]))
	if fbW <= 0 || fbH <= 0 || fbW > 8192 || fbH > 8192 {
		return nil, fmt.Errorf("invalid framebuffer size %dx%d", fbW, fbH)
	}
	if nameLen > 0 {
		if nameLen > 1<<20 {
			return nil, fmt.Errorf("server name too long")
		}
		if err := c.readFull(make([]byte, nameLen)); err != nil {
			return nil, fmt.Errorf("reading server name: %w", err)
		}
	}

	// 6. SetPixelFormat: request 32bpp depth24 LE truecolor (R16 G8 B0).
	var spf bytes.Buffer
	spf.WriteByte(0) // msg type
	spf.Write([]byte{0, 0, 0})
	spf.WriteByte(32) // bits-per-pixel
	spf.WriteByte(24) // depth
	spf.WriteByte(0)  // big-endian flag (0 = LE)
	spf.WriteByte(1)  // true-color flag
	_ = binary.Write(&spf, binary.BigEndian, uint16(255))
	_ = binary.Write(&spf, binary.BigEndian, uint16(255))
	_ = binary.Write(&spf, binary.BigEndian, uint16(255))
	spf.WriteByte(16) // red shift
	spf.WriteByte(8)  // green shift
	spf.WriteByte(0)  // blue shift
	spf.Write([]byte{0, 0, 0})
	if err := c.write(spf.Bytes()); err != nil {
		return nil, fmt.Errorf("writing pixel format: %w", err)
	}

	// 7. SetEncodings: Raw only.
	var enc bytes.Buffer
	enc.WriteByte(2)
	enc.WriteByte(0)
	_ = binary.Write(&enc, binary.BigEndian, uint16(1))
	_ = binary.Write(&enc, binary.BigEndian, int32(0))
	if err := c.write(enc.Bytes()); err != nil {
		return nil, fmt.Errorf("writing encodings: %w", err)
	}

	// 8. FramebufferUpdateRequest: full, non-incremental.
	var fur bytes.Buffer
	fur.WriteByte(3)
	fur.WriteByte(0) // incremental
	_ = binary.Write(&fur, binary.BigEndian, uint16(0))
	_ = binary.Write(&fur, binary.BigEndian, uint16(0))
	_ = binary.Write(&fur, binary.BigEndian, uint16(fbW))
	_ = binary.Write(&fur, binary.BigEndian, uint16(fbH))
	if err := c.write(fur.Bytes()); err != nil {
		return nil, fmt.Errorf("writing update request: %w", err)
	}

	// 9. FramebufferUpdate: type 0, pad, u16 rect count; each rect Raw.
	msgType := make([]byte, 1)
	if err := c.readFull(msgType); err != nil {
		return nil, fmt.Errorf("reading update header: %w", err)
	}
	if msgType[0] != 0 {
		return nil, fmt.Errorf("expected framebuffer update, got message %d", msgType[0])
	}
	head := make([]byte, 3)
	if err := c.readFull(head); err != nil {
		return nil, fmt.Errorf("reading update header: %w", err)
	}
	nRects := int(binary.BigEndian.Uint16(head[1:3]))
	if nRects <= 0 || nRects > 1024 {
		return nil, fmt.Errorf("invalid rectangle count %d", nRects)
	}

	img := image.NewNRGBA(image.Rect(0, 0, fbW, fbH))
	for i := 0; i < nRects; i++ {
		rh := make([]byte, 12)
		if err := c.readFull(rh); err != nil {
			return nil, fmt.Errorf("reading rectangle %d: %w", i, err)
		}
		x := int(binary.BigEndian.Uint16(rh[0:2]))
		y := int(binary.BigEndian.Uint16(rh[2:4]))
		w := int(binary.BigEndian.Uint16(rh[4:6]))
		h := int(binary.BigEndian.Uint16(rh[6:8]))
		enctype := int32(binary.BigEndian.Uint32(rh[8:12]))
		if enctype != 0 {
			return nil, fmt.Errorf("unexpected encoding %d (requested Raw only)", enctype)
		}
		if x < 0 || y < 0 || w <= 0 || h <= 0 || x+w > fbW || y+h > fbH {
			return nil, fmt.Errorf("rectangle %d out of bounds", i)
		}
		raw := make([]byte, w*h*4)
		if err := c.readFull(raw); err != nil {
			return nil, fmt.Errorf("reading pixels for rectangle %d: %w", i, err)
		}
		// Server sends B,G,R,pad per pixel (LE u32 R16/G8/B0).
		for row := 0; row < h; row++ {
			for col := 0; col < w; col++ {
				o := (row*w + col) * 4
				b, g, r := raw[o], raw[o+1], raw[o+2]
				img.SetNRGBA(x+col, y+row, struct {
					R, G, B, A uint8
				}{R: r, G: g, B: b, A: 255})
			}
		}
	}
	return img, nil
}

type readerFunc func(p []byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }
