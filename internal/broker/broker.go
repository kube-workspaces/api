// Package broker implements the read-only RFB multi-viewer feasibility spike.
// It is not wired into public routes. Callers must authenticate/authorize both
// transports before passing streams here; RFB security None is not platform auth.
package broker

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

const (
	MaxParticipants  = 8
	MaxPixels        = 4096 * 2160
	handshakeTimeout = 10 * time.Second
	writeTimeout     = 5 * time.Second
)

var (
	ErrClosed   = errors.New("display broker closed")
	ErrCapacity = errors.New("display broker participant limit reached")
)

// Stream is a deadline-capable byte stream (net.Conn or a binary WebSocket
// adapter). Close must unblock concurrent reads/writes. A WebSocket message is
// not an RFB message; its adapter must flatten message boundaries. Streams must
// tolerate one concurrent reader and one concurrent writer.
type Stream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// InputGate admits controller input writes. display.Fence satisfies it: writes
// only land while the caller still holds the registry controller role and the
// control lease is renewable, and stop at the fencing bound otherwise.
type InputGate interface {
	DispatchInput(fn func()) error
}

// Broker owns a single upstream and up to MaxParticipants observers. Frames
// are immutable snapshots: each observer holds at most one in-flight snapshot,
// while intervening updates coalesce into the current snapshot. No socket I/O
// runs under mu. A controller participant forwards guest-mutating RFB messages
// upstream through an InputGate, serialized against capture's own write side.
// Create a new Broker for each upstream connection generation.
type Broker struct {
	mu       sync.Mutex
	upstream Stream
	started  bool
	closed   bool
	frame    *frame
	// cursor is the latest remote-pointer shape and position. Like the
	// framebuffer it is an immutable snapshot: publishers replace it whole
	// under mu and bump cursorVersion, so readers never observe a torn
	// cursor.
	cursor        cursorState
	cursorVersion uint64
	changed       chan struct{}
	peers         map[Stream]struct{}
	// writeMu serializes upstream writes so a controller's forwarded input can
	// never interleave with capture's own client messages.
	writeMu sync.Mutex
}

func New(upstream Stream) *Broker {
	return &Broker{upstream: upstream, changed: make(chan struct{}), peers: make(map[Stream]struct{})}
}

// Run owns capture until EOF, protocol failure or cancellation. It is single-use
// and always closes the upstream and all attached observers before returning.
func (b *Broker) Run(ctx context.Context) error {
	b.mu.Lock()
	if b.started || b.closed || b.upstream == nil {
		b.mu.Unlock()
		return ErrClosed
	}
	b.started = true
	b.mu.Unlock()
	stop := context.AfterFunc(ctx, b.Close)
	defer stop()
	defer b.Close()
	err := b.capture()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Close is idempotent, including before Run. It wakes waiters and terminates
// blocked handshakes/readers/writers without holding the broker lock.
func (b *Broker) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	close(b.changed)
	peers := make([]Stream, 0, len(b.peers))
	for peer := range b.peers {
		peers = append(peers, peer)
	}
	b.mu.Unlock()
	if b.upstream != nil {
		_ = b.upstream.Close()
	}
	for _, peer := range peers {
		_ = peer.Close()
	}
}

func (b *Broker) publish(width, height int, pixels []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	var version uint64 = 1
	if b.frame != nil {
		version = b.frame.version + 1
	}
	b.frame = &frame{width: width, height: height, version: version, pixels: append([]byte(nil), pixels...)}
	close(b.changed)
	b.changed = make(chan struct{})
}

func (b *Broker) current() (*frame, <-chan struct{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, nil, ErrClosed
	}
	return b.frame, b.changed, nil
}

// cursorUpdate is one remote-pointer event from either producer: the
// console (shape and/or position rectangles) or the controller's own input
// stream (synthesized positions). Each half merges independently into the
// master snapshot, so a server-sent shape never wipes a synthesized
// position and vice versa.
type cursorUpdate struct {
	shape *cursorShape
	pos   *cursorPos
}

type cursorShape struct {
	hotX, hotY int
	w, h       int
	pixels     []byte
	mask       []byte
}

type cursorPos struct {
	x, y int
}

// publishCursor merges one pointer event into the master snapshot. It wakes
// waiters through the same changed channel as publish: serve loops re-check
// both the frame and the cursor versions.
func (b *Broker) publishCursor(up cursorUpdate) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	// Deep-copy the pixel/mask slices so the snapshot stays immutable even
	// though producers reuse their buffers.
	if up.shape != nil {
		b.cursor.hasShape = true
		b.cursor.hotX, b.cursor.hotY = up.shape.hotX, up.shape.hotY
		b.cursor.w, b.cursor.h = up.shape.w, up.shape.h
		b.cursor.pixels = append([]byte(nil), up.shape.pixels...)
		b.cursor.mask = append([]byte(nil), up.shape.mask...)
	}
	if up.pos != nil {
		b.cursor.hasPos = true
		b.cursor.posX, b.cursor.posY = up.pos.x, up.pos.y
	}
	b.cursorVersion++
	close(b.changed)
	b.changed = make(chan struct{})
}

func (b *Broker) currentCursor() (cursorState, uint64, <-chan struct{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return cursorState{}, 0, nil, ErrClosed
	}
	return b.cursor, b.cursorVersion, b.changed, nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// forward writes a controller's guest-mutating RFB message to the upstream.
// It shares capture's write lock so upstream messages never interleave.
// Absolute pointer moves double as the cursor position observers see: the
// console does not echo client-driven moves, so the broker publishes them
// itself, preserving any known shape. Observer input never reaches here.
func (b *Broker) forward(p []byte) error {
	if b.upstream == nil {
		return ErrClosed
	}
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	if err := b.upstream.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	if err := writeAll(b.upstream, p); err != nil {
		return err
	}
	if len(p) >= 6 && p[0] == 5 {
		b.publishCursor(cursorUpdate{pos: &cursorPos{
			x: int(binary.BigEndian.Uint16(p[2:])),
			y: int(binary.BigEndian.Uint16(p[4:])),
		}})
	}
	return nil
}
