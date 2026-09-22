package broker

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/kube-workspaces/api/internal/rfb"
)

// ServeObserver owns c until disconnect, cancellation or broker shutdown.
// It blocks; callers run separate observers in separate goroutines. All input
// mutations are discarded.
func (b *Broker) ServeObserver(ctx context.Context, c Stream) error {
	return b.serve(ctx, c, false, nil)
}

// ServeParticipant serves c like ServeObserver but, when controller and gate
// are set, forwards guest-mutating RFB messages (keys, pointer, clipboard,
// desktop resize, extended keys) upstream through gate. Dropped writes and the
// gate's fencing errors surface to the caller. Observer-local messages
// (framebuffer requests, pixel format, encodings for the participant's own
// view) never reach the upstream.
func (b *Broker) ServeParticipant(ctx context.Context, c Stream, controller bool, gate InputGate) error {
	return b.serve(ctx, c, controller, gate)
}

func (b *Broker) serve(ctx context.Context, c Stream, controller bool, gate InputGate) error {
	defer c.Close()
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ErrClosed
	}
	if len(b.peers) >= MaxParticipants {
		b.mu.Unlock()
		return ErrCapacity
	}
	b.peers[c] = struct{}{}
	b.mu.Unlock()
	defer func() { b.mu.Lock(); delete(b.peers, c); b.mu.Unlock() }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	// Waiting for capture is bounded too: no zero-sized ServerInit or fake
	// black first frame while the upstream is still negotiating.
	timer := time.NewTimer(handshakeTimeout)
	defer timer.Stop()
	var initial *frame
	for initial == nil {
		f, changed, err := b.current()
		if err != nil {
			return err
		}
		initial = f
		if f != nil {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("timed out waiting for upstream frame")
		}
	}
	if err := downstreamHandshake(c, initial); err != nil {
		return err
	}
	width, height := initial.width, initial.height
	initial = nil // don't retain an extra generation while serving
	format, _ := parseFormat(canonicalFormat())
	desktopSize := false
	// Cursor shape/position pseudo-encodings are negotiated per participant
	// like any other encoding; lastCursor tracks what this stream already
	// received so a re-attached viewer immediately gets the current pointer.
	wantCursor, wantCursorPos := false, false
	var lastCursor uint64
	// zrle is negotiated by the participant's own SetEncodings; the encoder
	// (and its connection-scoped zlib dictionary) is created on first use.
	zrle := false
	var enc *zrleEncoder
	var lastVersion uint64
	// One bounded message in flight; the reader can notice disconnect while
	// the writer waits for a new incremental frame. No unbounded input queue.
	messages := make(chan rfb.ClientMessage)
	readError := make(chan error, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			message, err := rfb.ReadClientMessage(c)
			if err != nil {
				readError <- err
				cancel()
				return
			}
			select {
			case messages <- message:
			case <-ctx.Done():
				return
			}
		}
	}()
	defer func() { cancel(); _ = c.Close(); <-readerDone }()
	type updateRequest struct {
		x, y, w, h  int
		incremental bool
	}
	var pending *updateRequest
	for {
		f, changed, err := b.current()
		if err != nil {
			return err
		}
		cur, curVer, _, err := b.currentCursor()
		if err != nil {
			return err
		}
		// The remote pointer rides the participant's own request flow, but
		// on its own trigger: a moving mouse over a static desktop must not
		// wait for a pixel change. Cursor rects precede any pixel rects so
		// a viewer applies the pointer before the frame it belongs to.
		if pending != nil && curVer > lastCursor && (wantCursor || wantCursorPos) {
			if err = sendCursor(c, cur, format, wantCursor, wantCursorPos); err != nil {
				return err
			}
			lastCursor = curVer
		}
		if pending != nil && f != nil && (!pending.incremental || f.version != lastVersion) {
			x, y, w, h := pending.x, pending.y, pending.w, pending.h
			resized := f.width != width || f.height != height
			if resized && !desktopSize {
				return errors.New("viewer does not support desktop resize")
			}
			if resized {
				x, y, w, h = 0, 0, f.width, f.height
			}
			if zrle && enc == nil {
				enc = newZRLEEncoder()
			}
			if err = sendFrame(c, f, format, x, y, w, h, resized, enc); err != nil {
				return err
			}
			width, height = f.width, f.height
			// A partial region must not mark the remainder as received.
			if x == 0 && y == 0 && w == width && h == height {
				lastVersion = f.version
			}
			pending = nil
		}
		f = nil // only retain an immutable snapshot while actually writing it
		select {
		case <-ctx.Done():
			select {
			case err := <-readError:
				return err
			default:
				return ctx.Err()
			}
		case <-changed:
		case m := <-messages:
			if m.Scope() != rfb.ParticipantLocal {
				if controller && gate != nil {
					p := m.Bytes()
					var fwdErr error
					if err := gate.DispatchInput(func() { fwdErr = b.forward(p) }); err != nil {
						return err
					}
					if fwdErr != nil {
						return fwdErr
					}
				}
				continue
			}
			p := m.Bytes()
			switch p[0] {
			case rfb.SetPixelFormat:
				var err error
				format, err = parseFormat(p[4:])
				if err != nil {
					return err
				}
				lastVersion = 0
			case rfb.SetEncodings:
				desktopSize = false
				zrle = false
				wantCursor, wantCursorPos = false, false
				for i := 4; i < len(p); i += 4 {
					switch int32(binary.BigEndian.Uint32(p[i:])) {
					case -223:
						desktopSize = true
					case 16:
						zrle = true
					case -239:
						wantCursor = true
					case -232:
						wantCursorPos = true
					}
				}
				// Raw is mandatory in RFB, even if absent from SetEncodings.
			case rfb.FramebufferUpdateRequest:
				x, y := int(binary.BigEndian.Uint16(p[2:])), int(binary.BigEndian.Uint16(p[4:]))
				w, h := int(binary.BigEndian.Uint16(p[6:])), int(binary.BigEndian.Uint16(p[8:]))
				if p[1] > 1 || x+w > 65535 || y+h > 65535 {
					return errors.New("invalid downstream update region")
				}
				incremental := p[1] != 0
				if pending != nil {
					x1, y1 := max(x+w, pending.x+pending.w), max(y+h, pending.y+pending.h)
					x, y = min(x, pending.x), min(y, pending.y)
					w, h = x1-x, y1-y
					incremental = incremental && pending.incremental
				}
				pending = &updateRequest{x: x, y: y, w: w, h: h, incremental: incremental}
			}
		}
	}
}

func downstreamHandshake(c Stream, f *frame) error {
	if err := c.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}
	if err := writeAll(c, []byte(protocolVersion)); err != nil {
		return err
	}
	v, err := readBytes(c, 12)
	if err != nil {
		return err
	}
	if string(v) != protocolVersion {
		return errors.New("viewer requires unsupported RFB version")
	}
	if err = writeAll(c, []byte{1, 1}); err != nil {
		return err
	}
	security, err := readBytes(c, 1)
	if err != nil {
		return err
	}
	if security[0] != 1 {
		return errors.New("unsupported viewer RFB security type")
	}
	if err = writeAll(c, []byte{0, 0, 0, 0}); err != nil {
		return err
	}
	init, err := readBytes(c, 1)
	if err != nil {
		return err
	}
	if init[0] > 1 {
		return errors.New("invalid ClientInit")
	}
	// An exclusive ClientInit never evicts other participants: policy belongs
	// to the authenticated platform join contract, not this RFB hint.
	name := "Kube Workspaces shared display (observer)"
	header := make([]byte, 24)
	binary.BigEndian.PutUint16(header, uint16(f.width))
	binary.BigEndian.PutUint16(header[2:], uint16(f.height))
	copy(header[4:], canonicalFormat())
	binary.BigEndian.PutUint32(header[20:], uint32(len(name)))
	if err = writeAll(c, append(header, name...)); err != nil {
		return err
	}
	return c.SetDeadline(time.Time{})
}

func sendFrame(c Stream, f *frame, format pixelFormat, x, y, w, h int, resized bool, enc *zrleEncoder) error {
	if err := c.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	header := []byte{0, 0, 0, 1}
	// Requests already in flight when the desktop shrinks still refer to the
	// old size. Clip rather than disconnect a well-behaved viewer for that race.
	x, y = min(x, f.width), min(y, f.height)
	w, h = min(w, f.width-x), min(h, f.height-y)
	if w == 0 || h == 0 {
		return writeAll(c, []byte{0, 0, 0, 0})
	}
	if resized {
		header[3] = 2
	}
	if err := writeAll(c, header); err != nil {
		return err
	}
	if resized {
		p := rectangleHeader(0, 0, f.width, f.height, -223)
		if err := writeAll(c, p); err != nil {
			return err
		}
	}
	// ZRLE when the participant negotiated it, Raw otherwise (mandatory in
	// RFB, and the baseline every client decodes).
	if enc != nil {
		if err := writeAll(c, rectangleHeader(x, y, w, h, 16)); err != nil {
			return err
		}
		return writeAll(c, enc.rect(f, format, x, y, w, h))
	}
	if err := writeAll(c, rectangleHeader(x, y, w, h, 0)); err != nil {
		return err
	}
	row := make([]byte, w*format.size)
	for yy := y; yy < y+h; yy++ {
		start := (yy*f.width + x) * 4
		format.row(row, f.pixels[start:start+w*4])
		if err := writeAll(c, row); err != nil {
			return err
		}
	}
	return nil
}

// sendCursor emits the remote-pointer pseudo-rectangles a participant
// negotiated: the Cursor shape (hotspot header, pixels converted to the
// participant's own format, 1-bit mask unchanged) and/or the CursorPos
// position (header only). A zero-sized shape hides the pointer.
func sendCursor(c Stream, cur cursorState, format pixelFormat, shape, pos bool) error {
	sendShape := shape && cur.hasShape
	sendPos := pos && cur.hasPos
	if !sendShape && !sendPos {
		return nil
	}
	if err := c.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	nrects := 0
	if sendShape {
		nrects++
	}
	if sendPos {
		nrects++
	}
	if err := writeAll(c, []byte{0, 0, 0, byte(nrects)}); err != nil {
		return err
	}
	if sendShape {
		if err := writeAll(c, rectangleHeader(cur.hotX, cur.hotY, cur.w, cur.h, -239)); err != nil {
			return err
		}
		if cur.w > 0 && cur.h > 0 {
			pixels := make([]byte, cur.w*cur.h*format.size)
			format.row(pixels, cur.pixels)
			if err := writeAll(c, pixels); err != nil {
				return err
			}
			if err := writeAll(c, cur.mask); err != nil {
				return err
			}
		}
	}
	if sendPos {
		if err := writeAll(c, rectangleHeader(cur.posX, cur.posY, 0, 0, -232)); err != nil {
			return err
		}
	}
	return nil
}

func rectangleHeader(x, y, w, h int, encoding int32) []byte {
	p := make([]byte, 12)
	binary.BigEndian.PutUint16(p, uint16(x))
	binary.BigEndian.PutUint16(p[2:], uint16(y))
	binary.BigEndian.PutUint16(p[4:], uint16(w))
	binary.BigEndian.PutUint16(p[6:], uint16(h))
	binary.BigEndian.PutUint32(p[8:], uint32(encoding))
	return p
}
