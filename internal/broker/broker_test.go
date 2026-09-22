package broker

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func readTest(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	p, err := readBytes(c, n)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func writeTest(t *testing.T, c net.Conn, p []byte) {
	t.Helper()
	_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err := writeAll(c, p); err != nil {
		t.Fatal(err)
	}
}

func rawUpdate(x, y, w, h int, pixels []byte) []byte {
	p := append([]byte{0, 0, 0, 1}, rectangleHeader(x, y, w, h, 0)...)
	return append(p, pixels...)
}

func runFixture(c net.Conn, updates <-chan []byte) error {
	defer c.Close()
	if err := writeAll(c, []byte(protocolVersion)); err != nil {
		return err
	}
	p, err := readBytes(c, 12)
	if err != nil {
		return err
	}
	if string(p) != protocolVersion {
		return errors.New("incorrect client protocol")
	}
	if err := writeAll(c, []byte{1, 1}); err != nil {
		return err
	}
	p, err = readBytes(c, 1)
	if err != nil {
		return err
	}
	if p[0] != 1 {
		return errors.New("incorrect security selection")
	}
	if err := writeAll(c, []byte{0, 0, 0, 0}); err != nil {
		return err
	}
	p, err = readBytes(c, 1)
	if err != nil {
		return err
	}
	if p[0] != 1 {
		return errors.New("upstream must be shared")
	}
	header := make([]byte, 24)
	header[1], header[3] = 2, 1
	copy(header[4:], canonicalFormat())
	if err := writeAll(c, header); err != nil {
		return err
	}
	p, err = readBytes(c, 20)
	if err != nil {
		return err
	}
	if !bytes.Equal(p, append([]byte{0, 0, 0, 0}, canonicalFormat()...)) {
		return errors.New("incorrect capture pixel format")
	}
	p, err = readBytes(c, 24)
	if err != nil {
		return err
	}
	if !bytes.Equal(p, []byte{2, 0, 0, 5,
		0, 0, 0, 0,
		255, 255, 255, 17,
		255, 255, 255, 40,
		255, 255, 254, 253,
		255, 255, 255, 223}) {
		return errors.New("incorrect capture encodings")
	}
	for {
		p, err := readBytes(c, 10)
		if err != nil {
			return err
		}
		if p[0] != 3 {
			return fmt.Errorf("guest mutation leaked upstream: %x", p)
		}
		update, ok := <-updates
		if !ok {
			return nil
		}
		if err := writeAll(c, update); err != nil {
			return err
		}
	}
}

func startFixture(t *testing.T) (*Broker, chan<- []byte) {
	t.Helper()
	client, server := net.Pipe()
	b := New(client)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	serverDone := make(chan error, 1)
	updates := make(chan []byte, 8)
	go func() { done <- b.Run(ctx) }()
	go func() { serverDone <- runFixture(server, updates) }()
	t.Cleanup(func() {
		cancel()
		b.Close()
		close(updates)
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("capture did not stop")
		}
		select {
		case err := <-serverDone:
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("fixture did not stop")
		}
	})
	return b, updates
}

func awaitVersion(t *testing.T, b *Broker, version uint64) *frame {
	t.Helper()
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	for {
		f, changed, err := b.current()
		if err != nil {
			t.Fatal(err)
		}
		if f != nil && f.version >= version {
			return f
		}
		select {
		case <-changed:
		case <-timeout.C:
			t.Fatal("no frame published")
		}
	}
}

func observer(t *testing.T, b *Broker) (net.Conn, <-chan error) {
	t.Helper()
	return participant(t, b, false, nil)
}

func participant(t *testing.T, b *Broker, controller bool, gate InputGate) (net.Conn, <-chan error) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- b.ServeParticipant(context.Background(), server, controller, gate) }()
	t.Cleanup(func() { _ = client.Close() })
	if string(readTest(t, client, 12)) != protocolVersion {
		t.Fatal("missing server version")
	}
	// Fragment the version to exercise byte-stream rather than message parsing.
	for _, c := range []byte(protocolVersion) {
		writeTest(t, client, []byte{c})
	}
	if !bytes.Equal(readTest(t, client, 2), []byte{1, 1}) {
		t.Fatal("missing security types")
	}
	writeTest(t, client, []byte{1})
	if binary.BigEndian.Uint32(readTest(t, client, 4)) != 0 {
		t.Fatal("security failed")
	}
	writeTest(t, client, []byte{0}) // exclusive hint must not evict another viewer
	header := readTest(t, client, 24)
	_ = readTest(t, client, int(binary.BigEndian.Uint32(header[20:])))
	return client, done
}

func request(t *testing.T, c net.Conn, w, h int, incremental bool) {
	t.Helper()
	p := make([]byte, 10)
	p[0] = 3
	if incremental {
		p[1] = 1
	}
	binary.BigEndian.PutUint16(p[6:], uint16(w))
	binary.BigEndian.PutUint16(p[8:], uint16(h))
	writeTest(t, c, p)
}

func receive(t *testing.T, c net.Conn, size int) ([]byte, bool) {
	t.Helper()
	header := readTest(t, c, 4)
	if header[0] != 0 {
		t.Fatal("not a framebuffer update")
	}
	count := int(binary.BigEndian.Uint16(header[2:]))
	var pixels []byte
	resized := false
	for range count {
		p := readTest(t, c, 12)
		w, h := int(binary.BigEndian.Uint16(p[4:])), int(binary.BigEndian.Uint16(p[6:]))
		switch int32(binary.BigEndian.Uint32(p[8:])) {
		case -223:
			resized = true
		case 0:
			pixels = append(pixels, readTest(t, c, w*h*size)...)
		default:
			t.Fatal("unnegotiated encoding")
		}
	}
	return pixels, resized
}

func cursorShapeUpdate(hotX, hotY, w, h int, pixels, mask []byte) []byte {
	p := append([]byte{0, 0, 0, 1}, rectangleHeader(hotX, hotY, w, h, -239)...)
	p = append(p, pixels...)
	return append(p, mask...)
}

func cursorPosUpdate(x, y int) []byte {
	return append([]byte{0, 0, 0, 1}, rectangleHeader(x, y, 0, 0, -232)...)
}

func setEncodings(t *testing.T, c net.Conn, encs ...int32) {
	t.Helper()
	p := make([]byte, 4+4*len(encs))
	p[0] = 2
	binary.BigEndian.PutUint16(p[2:], uint16(len(encs)))
	for i, e := range encs {
		binary.BigEndian.PutUint32(p[4+4*i:], uint32(e))
	}
	writeTest(t, c, p)
}

func awaitCursor(t *testing.T, b *Broker, version uint64) cursorState {
	t.Helper()
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	for {
		cur, ver, _, err := b.currentCursor()
		if err != nil {
			t.Fatal(err)
		}
		if ver >= version {
			return cur
		}
		select {
		case <-timeout.C:
			t.Fatal("no cursor published")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

type wireRect struct {
	x, y, w, h int
	enc        int32
	payload    []byte
}

func receiveUpdate(t *testing.T, c net.Conn) []wireRect {
	t.Helper()
	header := readTest(t, c, 4)
	if header[0] != 0 {
		t.Fatal("not a framebuffer update")
	}
	count := int(binary.BigEndian.Uint16(header[2:]))
	var out []wireRect
	for range count {
		p := readTest(t, c, 12)
		r := wireRect{
			x:   int(binary.BigEndian.Uint16(p)),
			y:   int(binary.BigEndian.Uint16(p[2:])),
			w:   int(binary.BigEndian.Uint16(p[4:])),
			h:   int(binary.BigEndian.Uint16(p[6:])),
			enc: int32(binary.BigEndian.Uint32(p[8:])),
		}
		switch r.enc {
		case 0:
			r.payload = readTest(t, c, r.w*r.h*4)
		case -239:
			if r.w > 0 && r.h > 0 {
				r.payload = readTest(t, c, r.w*r.h*4+((r.w+7)/8)*r.h)
			}
		case -232, -223, -259:
		default:
			t.Fatalf("unexpected rect encoding %d", r.enc)
		}
		out = append(out, r)
	}
	return out
}

// A late joiner that negotiated the cursor pseudo-encodings receives the
// current shape and position ahead of its first frame; a joiner that did not
// negotiate them sees only pixel rects.
func TestCursorShapeAndPosForwardedToNegotiatingParticipant(t *testing.T) {
	b, updates := startFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, make([]byte, 8))
	awaitVersion(t, b, 1)
	pixels := []byte{1, 2, 3, 0, 4, 5, 6, 0, 7, 8, 9, 0, 10, 11, 12, 0}
	mask := []byte{0b11000000, 0b10100000}
	updates <- cursorShapeUpdate(1, 0, 2, 2, pixels, mask)
	updates <- cursorPosUpdate(1, 0)
	awaitCursor(t, b, 2)

	c, _ := observer(t, b)
	setEncodings(t, c, 0, -239, -232, -223)
	request(t, c, 2, 1, false)
	rects := receiveUpdate(t, c)
	if len(rects) != 2 || rects[0].enc != -239 || rects[1].enc != -232 {
		t.Fatalf("cursor update rects: %+v", rects)
	}
	shape := rects[0]
	if shape.x != 1 || shape.y != 0 || shape.w != 2 || shape.h != 2 {
		t.Fatalf("shape header: %+v", shape)
	}
	if !bytes.Equal(shape.payload, append(append([]byte{}, pixels...), mask...)) {
		t.Fatal("shape payload not forwarded intact")
	}
	if pos := rects[1]; pos.x != 1 || pos.y != 0 || pos.w != 0 || pos.h != 0 || len(pos.payload) != 0 {
		t.Fatalf("pos rect: %+v", pos)
	}
	frame := receiveUpdate(t, c)
	if len(frame) != 1 || frame[0].enc != 0 {
		t.Fatalf("frame after cursor: %+v", frame)
	}

	plain, _ := observer(t, b)
	request(t, plain, 2, 1, false)
	rects = receiveUpdate(t, plain)
	if len(rects) != 1 || rects[0].enc != 0 {
		t.Fatalf("non-negotiating observer got cursor rects: %+v", rects)
	}
}

// A cursor-only change on a static desktop is delivered on the next
// incremental request without any pixel rects.
func TestCursorOnlyChangeDeliveredWithoutFrameChange(t *testing.T) {
	b, updates := startFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, make([]byte, 8))
	awaitVersion(t, b, 1)
	c, _ := observer(t, b)
	setEncodings(t, c, 0, -239, -232, -223)
	request(t, c, 2, 1, false)
	if rects := receiveUpdate(t, c); len(rects) != 1 || rects[0].enc != 0 {
		t.Fatalf("initial frame: %+v", rects)
	}
	updates <- cursorPosUpdate(0, 0)
	awaitCursor(t, b, 1)
	request(t, c, 2, 1, true)
	rects := receiveUpdate(t, c)
	if len(rects) != 1 || rects[0].enc != -232 {
		t.Fatalf("cursor-only update: %+v", rects)
	}
	if rects[0].x != 0 || rects[0].y != 0 {
		t.Fatalf("cursor pos: %+v", rects[0])
	}
}

// A zero-sized shape hides the pointer and carries no payload.
func TestZeroSizeCursorHidesPointer(t *testing.T) {
	b, updates := startFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, make([]byte, 8))
	awaitVersion(t, b, 1)
	updates <- cursorShapeUpdate(0, 0, 0, 0, nil, nil)
	awaitCursor(t, b, 1)
	c, _ := observer(t, b)
	setEncodings(t, c, 0, -239, -232, -223)
	request(t, c, 2, 1, false)
	rects := receiveUpdate(t, c)
	if len(rects) != 1 || rects[0].enc != -239 || rects[0].w != 0 || rects[0].h != 0 || len(rects[0].payload) != 0 {
		t.Fatalf("hide rect: %+v", rects)
	}
}

// Malformed cursor rectangles fail the capture closed: oversize shapes,
// positions outside the framebuffer and truncated payloads are all rejected,
// and valid cursor traffic does not disturb pixel coverage.
func TestCursorBoundsFailClosed(t *testing.T) {
	s := newCapture(2, 1)
	if _, err := s.update(bytes.NewReader(append([]byte{0, 0, 1}, rectangleHeader(0, 0, 300, 300, -239)...))); err == nil {
		t.Fatal("accepted oversize cursor shape")
	}
	if _, err := s.update(bytes.NewReader(append([]byte{0, 0, 1}, rectangleHeader(9, 9, 0, 0, -232)...))); err == nil {
		t.Fatal("accepted out-of-frame cursor position")
	}
	hdr := append([]byte{0, 0, 1}, rectangleHeader(0, 0, 2, 2, -239)...)
	if _, err := s.update(bytes.NewReader(append(hdr, 1, 2, 3))); err == nil {
		t.Fatal("accepted truncated cursor payload")
	}
	if s.cursorDirty {
		t.Fatal("rejected cursor traffic marked the cursor dirty")
	}
	px := make([]byte, 16)
	if _, err := s.update(bytes.NewReader(append(append([]byte{0, 0, 1}, rectangleHeader(1, 0, 2, 2, -239)...), append(px, 0, 0)...))); err != nil {
		t.Fatalf("valid shape rejected: %v", err)
	}
	if !s.cursorDirty || s.cursor.shape == nil || s.cursor.shape.hotX != 1 || s.cursor.shape.w != 2 {
		t.Fatalf("valid shape not recorded: %+v", s.cursor.shape)
	}
	if _, err := s.update(bytes.NewReader(append([]byte{0, 0, 1}, rectangleHeader(1, 0, 0, 0, -232)...))); err != nil {
		t.Fatalf("valid pos rejected: %v", err)
	}
	if s.cursor.pos == nil || s.cursor.pos.x != 1 {
		t.Fatalf("valid pos not recorded: %+v", s.cursor.pos)
	}
	if s.missing != 2*1 {
		t.Fatalf("cursor traffic disturbed pixel coverage: missing=%d", s.missing)
	}
}

// audioAckUpdate is the console's audio acknowledgment: one zero-size
// audio pseudo-encoding rect carrying no payload.
func audioAckUpdate() []byte {
	return append([]byte{0, 0, 0, 1}, rectangleHeader(0, 0, 0, 0, -259)...)
}

// audioBatchMessage is one server-side PCM batch: type 255, audio sub,
// data command, u32 count and payload.
func audioBatchMessage(pcm []byte) []byte {
	p := []byte{255, 1, 0, 2, 0, 0, 0, byte(len(pcm))}
	return append(p, pcm...)
}

// audioCmd builds one downstream audio session message: enable, disable or
// set-format with the 6-byte sample format.
func audioCmd(t *testing.T, c net.Conn, cmd uint16, format []byte) {
	t.Helper()
	p := []byte{255, 1, byte(cmd >> 8), byte(cmd)}
	writeTest(t, c, append(p, format...))
}

func receiveAudioBatch(t *testing.T, c net.Conn) []byte {
	t.Helper()
	if hdr := readTest(t, c, 4); !bytes.Equal(hdr, []byte{255, 1, 0, 2}) {
		t.Fatalf("not an audio batch: %x", hdr)
	}
	n := readTest(t, c, 4)
	return readTest(t, c, int(binary.BigEndian.Uint32(n)))
}

// tcpPair returns a loopback TCP pair. Unlike net.Pipe it is full-duplex
// with kernel buffers, so fixture batch pushes never deadlock against the
// broker's own writes however they interleave.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accept := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accept <- c
		}
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case server = <-accept:
	case <-time.After(3 * time.Second):
		t.Fatal("loopback accept timed out")
	}
	return client, server
}

// startAudioFixture runs the broker against a console that acknowledges
// audio, answers the broker's format/enable handshake on the setup channel,
// and pushes queued PCM batches spontaneously over a full-duplex loopback
// pair, like a real server would.
func startAudioFixture(t *testing.T) (*Broker, chan<- []byte, chan<- []byte, <-chan []byte) {
	t.Helper()
	client, server := tcpPair(t)
	b := New(client)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	serverDone := make(chan error, 1)
	pusherDone := make(chan error, 1)
	updates := make(chan []byte, 8)
	audio := make(chan []byte, 8)
	setup := make(chan []byte, 8)
	var wmu sync.Mutex
	writeFixture := func(p []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		_ = server.SetWriteDeadline(time.Now().Add(3 * time.Second))
		return writeAll(server, p)
	}
	go func() { done <- b.Run(ctx) }()
	// Batch pusher: queued PCM flows whenever the test queues it, never
	// waiting for a frame request. Writes serialize with answers below.
	go func() {
		defer close(pusherDone)
		for {
			select {
			case batch, ok := <-audio:
				if !ok {
					return
				}
				if err := writeFixture(batch); err != nil {
					pusherDone <- err
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	runAudio := func() error {
		if err := audioHandshake(server, writeFixture); err != nil {
			return err
		}
		for {
			msg, err := readForwarded(server)
			if err != nil {
				return err
			}
			switch msg[0] {
			case 3: // framebuffer request: answer from the queue
				update, ok := <-updates
				if !ok {
					return nil
				}
				if err := writeFixture(update); err != nil {
					return err
				}
			case 255: // audio session control: record for assertions
				select {
				case setup <- msg:
				default:
					return errors.New("setup channel full")
				}
			default:
				return fmt.Errorf("guest mutation leaked upstream: %x", msg)
			}
		}
	}
	go func() {
		defer server.Close()
		defer close(setup)
		serverDone <- runAudio()
	}()
	t.Cleanup(func() {
		cancel()
		b.Close()
		close(updates)
		close(audio)
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, os.ErrClosed) && !errors.Is(err, syscall.ECONNRESET) {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("capture did not stop")
		}
		select {
		case err := <-serverDone:
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, os.ErrClosed) && !errors.Is(err, syscall.ECONNRESET) {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("fixture did not stop")
		}
		select {
		case err := <-pusherDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("pusher did not stop")
		}
	})
	return b, updates, audio, setup
}

func audioHandshake(c net.Conn, write func([]byte) error) error {
	if err := write([]byte(protocolVersion)); err != nil {
		return err
	}
	p, err := readBytes(c, 12)
	if err != nil {
		return err
	}
	if string(p) != protocolVersion {
		return errors.New("incorrect client protocol")
	}
	if err := write([]byte{1, 1}); err != nil {
		return err
	}
	p, err = readBytes(c, 1)
	if err != nil {
		return err
	}
	if p[0] != 1 {
		return errors.New("incorrect security selection")
	}
	if err := write([]byte{0, 0, 0, 0}); err != nil {
		return err
	}
	p, err = readBytes(c, 1)
	if err != nil {
		return err
	}
	if p[0] != 1 {
		return errors.New("upstream must be shared")
	}
	header := make([]byte, 24)
	header[1], header[3] = 2, 1
	copy(header[4:], canonicalFormat())
	if err := write(header); err != nil {
		return err
	}
	p, err = readBytes(c, 20)
	if err != nil {
		return err
	}
	if !bytes.Equal(p, append([]byte{0, 0, 0, 0}, canonicalFormat()...)) {
		return errors.New("incorrect capture pixel format")
	}
	p, err = readBytes(c, 24)
	if err != nil {
		return err
	}
	if !bytes.Equal(p, []byte{2, 0, 0, 5,
		0, 0, 0, 0,
		255, 255, 255, 17,
		255, 255, 255, 40,
		255, 255, 254, 253,
		255, 255, 255, 223}) {
		return errors.New("incorrect capture encodings")
	}
	return nil
}

func awaitAudio(t *testing.T, b *Broker, version uint64) {
	t.Helper()
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	for {
		_, ver, _, err := b.currentAudio()
		if err != nil {
			t.Fatal(err)
		}
		if ver >= version {
			return
		}
		select {
		case <-timeout.C:
			t.Fatal("no audio published")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// The console's audio acknowledgment drives exactly one upstream session in
// the broker's fixed PCM format, then streaming enable.
func TestAudioAckEnablesUpstreamSession(t *testing.T) {
	b, updates, _, setup := startAudioFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, make([]byte, 8))
	awaitVersion(t, b, 1)
	updates <- audioAckUpdate()
	var format, enable []byte
	for range 2 {
		select {
		case msg := <-setup:
			switch len(msg) {
			case 10:
				format = msg
			case 4:
				enable = msg
			default:
				t.Fatalf("unexpected setup message: %x", msg)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("broker did not open the upstream audio session")
		}
	}
	if !bytes.Equal(format, append([]byte{255, 1, 0, 2}, brokerAudioFormat...)) {
		t.Fatalf("upstream format: %x", format)
	}
	if !bytes.Equal(enable, []byte{255, 1, 0, 0}) {
		t.Fatalf("upstream enable: %x", enable)
	}
	live, _, _, err := b.currentAudio()
	if err != nil || !live {
		t.Fatalf("upstream audio not live: %v", live)
	}
}

// An enabled participant receives each PCM batch verbatim; a participant
// that never opted in sees only frames.
func TestAudioBatchRelayedToEnabledParticipant(t *testing.T) {
	b, updates, audio, _ := startAudioFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, make([]byte, 8))
	awaitVersion(t, b, 1)
	updates <- audioAckUpdate()
	awaitAudio(t, b, 1)
	c, _ := observer(t, b)
	setEncodings(t, c, 0, -259, -223)
	request(t, c, 2, 1, false)
	// The acknowledgment rides the pending request ahead of the frame.
	if rects := receiveUpdate(t, c); len(rects) != 1 || rects[0].enc != -259 {
		t.Fatalf("audio ack: %+v", rects)
	}
	if frame := receiveUpdate(t, c); len(frame) != 1 || frame[0].enc != 0 {
		t.Fatalf("frame after ack: %+v", frame)
	}
	audioCmd(t, c, 2, brokerAudioFormat)
	audioCmd(t, c, 0, nil)
	pcm := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	audio <- audioBatchMessage(pcm)
	awaitAudio(t, b, 2)
	if got := receiveAudioBatch(t, c); !bytes.Equal(got, pcm) {
		t.Fatalf("batch bytes: %x", got)
	}
	// A second batch flows without another request: audio pushes.
	pcm2 := []byte{9, 10, 11, 12}
	audio <- audioBatchMessage(pcm2)
	awaitAudio(t, b, 3)
	if got := receiveAudioBatch(t, c); !bytes.Equal(got, pcm2) {
		t.Fatalf("second batch: %x", got)
	}

	plain, _ := observer(t, b)
	request(t, plain, 2, 1, false)
	if rects := receiveUpdate(t, plain); len(rects) != 1 || rects[0].enc != 0 {
		t.Fatalf("non-audio observer got audio traffic: %+v", rects)
	}
}

// Disabling stops delivery for that participant while others keep flowing;
// a mismatched format fails the stream closed instead of serving
// mislabelled bytes.
func TestAudioDisableAndFormatMismatch(t *testing.T) {
	b, updates, audio, _ := startAudioFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, make([]byte, 8))
	awaitVersion(t, b, 1)
	updates <- audioAckUpdate()
	awaitAudio(t, b, 1)
	c, _ := observer(t, b)
	setEncodings(t, c, 0, -259, -223)
	request(t, c, 2, 1, false)
	receiveUpdate(t, c) // ack
	receiveUpdate(t, c) // frame
	audioCmd(t, c, 2, brokerAudioFormat)
	audioCmd(t, c, 0, nil)
	audio <- audioBatchMessage([]byte{1, 2})
	awaitAudio(t, b, 2)
	receiveAudioBatch(t, c)
	audioCmd(t, c, 1, nil)
	audio <- audioBatchMessage([]byte{3, 4})
	awaitAudio(t, b, 3)
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := readBytes(c, 1); err == nil {
		t.Fatal("disabled participant received audio")
	}
	_ = c.SetReadDeadline(time.Time{})

	d, done := observer(t, b)
	setEncodings(t, d, 0, -259, -223)
	request(t, d, 2, 1, false)
	receiveUpdate(t, d)                            // ack
	receiveUpdate(t, d)                            // frame
	audioCmd(t, d, 2, []byte{3, 2, 0, 0, 187, 68}) // 48000, not the shared 44100
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("format mismatch did not fail the stream")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("format mismatch left the stream running")
	}
}

// Malformed upstream audio fails closed before any allocation: bad
// sub-types/commands and an oversize batch count (with no payload sent)
// must already error, while a valid batch publishes.
func TestAudioBatchBoundsFailClosed(t *testing.T) {
	// audioMessage runs past the already-consumed type byte, so feed
	// strips it like the capture loop does.
	feed := func(msg []byte) (*Broker, error) {
		b := New(nil)
		client, server := net.Pipe()
		writeErr := make(chan error, 1)
		go func() {
			writeErr <- writeAll(client, msg[1:])
		}()
		err := b.audioMessage(server)
		// Unblock a writer holding bytes the failing read never consumed.
		client.Close()
		server.Close()
		<-writeErr
		return b, err
	}
	for _, msg := range [][]byte{
		{255, 2, 0, 2},                   // bad subtype
		{255, 1, 0, 9},                   // bad command
		{255, 1, 0, 2, 0, 32, 0, 0},      // 2 MiB batch, no payload sent
		{255, 1, 0, 2, 255, 255, 255, 0}, // near-u32-max batch
	} {
		if _, err := feed(msg); err == nil {
			t.Fatalf("accepted malformed audio message %x", msg)
		}
	}
	b, err := feed(append([]byte{255, 1, 0, 2, 0, 0, 0, 3}, 7, 8, 9))
	if err != nil {
		t.Fatalf("valid batch rejected: %v", err)
	}
	if live, ver, batch, err := b.currentAudio(); err != nil || live || ver != 1 || !bytes.Equal(batch, []byte{7, 8, 9}) {
		t.Fatalf("valid batch not published: live=%v ver=%d batch=%x err=%v", live, ver, batch, err)
	}
}

func TestIndependentObserversLateJoinAndResize(t *testing.T) {
	b, updates := startFixture(t)
	redGreen := []byte{255, 0, 0, 0, 0, 255, 0, 0}
	// Bell + clipboard + framebuffer can share the same transport read.
	updates <- append([]byte{2, 3, 0, 0, 0, 0, 0, 0, 1, 'x'}, rawUpdate(0, 0, 2, 1, redGreen)...)
	awaitVersion(t, b, 1)
	a, _ := observer(t, b)
	request(t, a, 2, 1, false)
	if p, _ := receive(t, a, 4); !bytes.Equal(p, redGreen) {
		t.Fatalf("initial: %x", p)
	}
	updates <- rawUpdate(0, 0, 1, 1, []byte{0, 0, 255, 0})
	awaitVersion(t, b, 2)
	c, _ := observer(t, b) // late join after a partial upstream update
	format565 := []byte{16, 16, 1, 1, 0, 31, 0, 63, 0, 31, 11, 5, 0, 0, 0, 0}
	writeTest(t, c, append([]byte{0, 0, 0, 0}, format565...))
	request(t, c, 2, 1, false)
	if p, _ := receive(t, c, 2); !bytes.Equal(p, []byte{0, 31, 7, 224}) {
		t.Fatalf("late RGB565 frame: %x", p)
	}
	request(t, a, 2, 1, true)
	if p, _ := receive(t, a, 4); !bytes.Equal(p, []byte{0, 0, 255, 0, 0, 255, 0, 0}) {
		t.Fatalf("independent 32bpp: %x", p)
	}
	writeTest(t, a, []byte{2, 0, 0, 1, 255, 255, 255, 33})
	updates <- append([]byte{0, 0, 0, 1}, rectangleHeader(0, 0, 1, 1, -223)...)
	updates <- rawUpdate(0, 0, 1, 1, []byte{255, 255, 255, 0})
	awaitVersion(t, b, 3)
	request(t, a, 2, 1, true)
	if p, resized := receive(t, a, 4); !resized || !bytes.Equal(p, []byte{255, 255, 255, 0}) {
		t.Fatalf("resize: %x %v", p, resized)
	}
}

func TestSlowObserverDoesNotBlockCaptureOrPeer(t *testing.T) {
	b, updates := startFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, make([]byte, 8))
	awaitVersion(t, b, 1)
	slow, slowDone := observer(t, b)
	request(t, slow, 2, 1, false) // never read the reply
	fast, _ := observer(t, b)
	for i := 1; i <= 5; i++ {
		updates <- rawUpdate(0, 0, 1, 1, []byte{byte(i), 0, 0, 0})
		awaitVersion(t, b, uint64(i+1))
		request(t, fast, 2, 1, false)
		p, _ := receive(t, fast, 4)
		if p[0] != byte(i) {
			t.Fatalf("fast observer stalled: %x", p)
		}
	}
	select {
	case err := <-slowDone:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("slow writer: %v", err)
		}
	case <-time.After(writeTimeout + time.Second):
		t.Fatal("slow writer was not bounded")
	}
}

func TestObserverInputIsNotForwarded(t *testing.T) {
	b, updates := startFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, make([]byte, 8))
	awaitVersion(t, b, 1)
	c, _ := observer(t, b)
	for _, p := range [][]byte{
		{4, 1, 0, 0, 0, 0, 0, 97}, {5, 1, 0, 0, 0, 0}, {6, 0, 0, 0, 0, 0, 0, 1, 'x'},
		{255, 0, 0, 1, 0, 0, 0, 97, 0, 0, 0, 30},
		append([]byte{251, 0, 0, 1, 0, 1, 1, 0}, make([]byte, 16)...),
	} {
		writeTest(t, c, p)
	}
	request(t, c, 2, 1, false)
	receive(t, c, 4)
	updates <- rawUpdate(0, 0, 1, 1, []byte{7, 0, 0, 0})
	awaitVersion(t, b, 2)
	request(t, c, 2, 1, true)
	if p, _ := receive(t, c, 4); p[0] != 7 {
		t.Fatal("capture broke after input attempts")
	}
}

func TestCaptureBoundsCoverageAndTruncation(t *testing.T) {
	s := newCapture(2, 1)
	u := rawUpdate(0, 0, 1, 1, []byte{1, 2, 3, 0})
	if _, err := s.update(bytes.NewReader(u[1:])); err != nil || s.missing != 1 {
		t.Fatalf("partial coverage: %v %d", err, s.missing)
	}
	if _, err := s.update(bytes.NewReader(u[1:])); err != nil || s.missing != 1 {
		t.Fatalf("duplicate coverage: %v %d", err, s.missing)
	}
	u = rawUpdate(1, 0, 1, 1, []byte{4, 5, 6, 0})
	if _, err := s.update(bytes.NewReader(u[1:])); err != nil || s.missing != 0 {
		t.Fatalf("complete coverage: %v %d", err, s.missing)
	}
	for end := 1; end < len(u); end++ {
		if _, err := newCapture(2, 1).update(bytes.NewReader(u[1:end])); err == nil {
			t.Fatalf("accepted truncated prefix %d", end)
		}
	}
	for _, rect := range [][]byte{
		rectangleHeader(2, 0, 1, 1, 0), rectangleHeader(0, 0, 65535, 65535, -223), rectangleHeader(0, 0, 1, 1, 7),
	} {
		if _, err := s.update(bytes.NewReader(append([]byte{0, 0, 1}, rect...))); err == nil {
			t.Fatal("accepted invalid rectangle")
		}
	}
}

func TestShutdownWakesHandshakeAndIncrementalWait(t *testing.T) {
	b, updates := startFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, make([]byte, 8))
	awaitVersion(t, b, 1)
	c, done := observer(t, b)
	request(t, c, 2, 1, false)
	receive(t, c, 4)
	request(t, c, 2, 1, true)
	stalled, server := net.Pipe()
	defer stalled.Close()
	handshakeDone := make(chan error, 1)
	go func() { handshakeDone <- b.ServeObserver(context.Background(), server) }()
	b.Close()
	b.Close()
	for _, done := range []<-chan error{done, handshakeDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("shutdown left observer running")
		}
	}
}

func TestPixelFormats(t *testing.T) {
	for _, p := range [][]byte{
		{8, 8, 0, 1, 0, 7, 0, 7, 0, 3, 0, 3, 6, 0, 0, 0},
		{16, 16, 0, 1, 0, 31, 0, 63, 0, 31, 11, 5, 0, 0, 0, 0},
		canonicalFormat(),
	} {
		f, err := parseFormat(p)
		if err != nil {
			t.Fatal(err)
		}
		dst := make([]byte, f.size)
		f.row(dst, []byte{255, 255, 255, 0})
		if dst[0] != 255 {
			t.Fatalf("white: %x", dst)
		}
	}
	for _, change := range []func([]byte){
		func(p []byte) { p[0] = 64 }, func(p []byte) { p[3] = 0 }, func(p []byte) { p[10] = 32 },
		func(p []byte) { p[11] = p[10] }, func(p []byte) { p[5] = 254 }, func(p []byte) { p[1] = 8 },
	} {
		p := canonicalFormat()
		change(p)
		if _, err := parseFormat(p); err == nil {
			t.Fatalf("accepted invalid format %x", p)
		}
	}
}

func TestPendingIncrementalAcceptsRefreshAndDisconnect(t *testing.T) {
	b, updates := startFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, make([]byte, 8))
	awaitVersion(t, b, 1)
	c, done := observer(t, b)
	request(t, c, 2, 1, false)
	receive(t, c, 4)
	request(t, c, 2, 1, true)
	request(t, c, 2, 1, false) // a forced refresh must not wait for new guest damage
	if p, _ := receive(t, c, 4); len(p) != 8 {
		t.Fatal("forced refresh lost")
	}
	request(t, c, 2, 1, true)
	writeTest(t, c, []byte{4, 1, 0, 0, 0, 0, 0, 97})
	_ = c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("static desktop retained disconnected observer")
	}
}

func TestParticipantLimitAndRelease(t *testing.T) {
	b := New(nil)
	b.publish(2, 1, make([]byte, 8))
	defer b.Close()
	var first net.Conn
	var firstDone <-chan error
	for i := 0; i < MaxParticipants; i++ {
		c, done := observer(t, b)
		if i == 0 {
			first, firstDone = c, done
		}
	}
	c, s := net.Pipe()
	defer c.Close()
	if err := b.ServeObserver(context.Background(), s); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity: %v", err)
	}
	_ = first.Close()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("slot not released")
	}
	observer(t, b)
}

func TestClosedBeforeRunAndUpstreamCancellation(t *testing.T) {
	c, s := net.Pipe()
	defer s.Close()
	b := New(c)
	b.Close()
	b.Close()
	if err := b.Run(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	c2, s2 := net.Pipe()
	defer s2.Close()
	b2 := New(c2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b2.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream handshake ignored cancellation")
	}
}

type stubGate struct {
	err error
}

func (g *stubGate) DispatchInput(fn func()) error {
	if g.err != nil {
		return g.err
	}
	fn()
	return nil
}

// readForwarded parses one RFB client message arriving from the capture side.
// It mirrors runFixture's update serving while recording forwarded input.
func readForwarded(c net.Conn) ([]byte, error) {
	kind, err := readBytes(c, 1)
	if err != nil {
		return nil, err
	}
	switch kind[0] {
	case 3:
		rest, err := readBytes(c, 9)
		if err != nil {
			return nil, err
		}
		return append(kind, rest...), nil
	case 4:
		rest, err := readBytes(c, 7)
		if err != nil {
			return nil, err
		}
		return append(kind, rest...), nil
	case 5:
		rest, err := readBytes(c, 5)
		if err != nil {
			return nil, err
		}
		return append(kind, rest...), nil
	case 6:
		hdr, err := readBytes(c, 7)
		if err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(hdr[3:])
		if n > 1<<20 {
			return nil, errors.New("clipboard exceeds bounds")
		}
		msg := append(append(kind, hdr...), make([]byte, 0, int(n))...)
		rest, err := readBytes(c, int(n))
		if err != nil {
			return nil, err
		}
		return append(msg, rest...), nil
	case 255: // QEMU audio session control from the broker under test.
		hdr, err := readBytes(c, 3)
		if err != nil {
			return nil, err
		}
		if hdr[0] != 1 {
			return nil, fmt.Errorf("unexpected audio subtype %d", hdr[0])
		}
		msg := append(kind, hdr...)
		if cmd := binary.BigEndian.Uint16(hdr[1:]); cmd == 2 {
			rest, err := readBytes(c, 6)
			if err != nil {
				return nil, err
			}
			msg = append(msg, rest...)
		} else if cmd != 0 && cmd != 1 {
			return nil, fmt.Errorf("unexpected audio command %d", cmd)
		}
		return msg, nil
	case 251: // SetDesktopSize
		hdr, err := readBytes(c, 11)
		if err != nil {
			return nil, err
		}
		n := int(hdr[4])
		if n < 1 || n > 256 {
			return nil, errors.New("invalid screen count")
		}
		msg := append(append(kind, hdr...), make([]byte, 0, 16*n)...)
		rest, err := readBytes(c, 16*n)
		if err != nil {
			return nil, err
		}
		return append(msg, rest...), nil
	default:
		return nil, fmt.Errorf("unexpected upstream read %d", kind[0])
	}
}

func runInputFixture(c net.Conn, updates <-chan []byte, input chan<- []byte) error {
	defer c.Close()
	if err := writeAll(c, []byte(protocolVersion)); err != nil {
		return err
	}
	p, err := readBytes(c, 12)
	if err != nil {
		return err
	}
	if string(p) != protocolVersion {
		return errors.New("incorrect client protocol")
	}
	if err := writeAll(c, []byte{1, 1}); err != nil {
		return err
	}
	p, err = readBytes(c, 1)
	if err != nil {
		return err
	}
	if p[0] != 1 {
		return errors.New("incorrect security selection")
	}
	if err := writeAll(c, []byte{0, 0, 0, 0}); err != nil {
		return err
	}
	p, err = readBytes(c, 1)
	if err != nil {
		return err
	}
	if p[0] != 1 {
		return errors.New("upstream must be shared")
	}
	header := make([]byte, 24)
	header[1], header[3] = 2, 1
	copy(header[4:], canonicalFormat())
	if err := writeAll(c, header); err != nil {
		return err
	}
	p, err = readBytes(c, 20)
	if err != nil {
		return err
	}
	if !bytes.Equal(p, append([]byte{0, 0, 0, 0}, canonicalFormat()...)) {
		return errors.New("incorrect capture pixel format")
	}
	p, err = readBytes(c, 24)
	if err != nil {
		return err
	}
	if !bytes.Equal(p, []byte{2, 0, 0, 5,
		0, 0, 0, 0,
		255, 255, 255, 17,
		255, 255, 255, 40,
		255, 255, 254, 253,
		255, 255, 255, 223}) {
		return errors.New("incorrect capture encodings")
	}
	for {
		msg, err := readForwarded(c)
		if err != nil {
			return err
		}
		if msg[0] != 3 {
			// A forwarded mutating message: record it and continue serving.
			select {
			case input <- append([]byte(nil), msg...):
			default:
			}
			continue
		}
		var update []byte
		select {
		case update = <-updates:
		default:
			update = []byte{0, 0, 0, 0} // no new damage; capture simply re-requests
		}
		if err := writeAll(c, update); err != nil {
			return err
		}
	}
}

func startInputFixture(t *testing.T) (*Broker, chan<- []byte, <-chan []byte) {
	t.Helper()
	client, server := net.Pipe()
	b := New(client)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	serverDone := make(chan error, 1)
	updates := make(chan []byte, 8)
	input := make(chan []byte, 8)
	go func() { done <- b.Run(ctx) }()
	go func() { serverDone <- runInputFixture(server, updates, input) }()
	t.Cleanup(func() {
		cancel()
		b.Close()
		close(updates)
		for _, ch := range []<-chan error{done, serverDone} {
			select {
			case err := <-ch:
				if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
					t.Error(err)
				}
			case <-time.After(3 * time.Second):
				t.Error("input fixture did not stop")
			}
		}
	})
	return b, updates, input
}

func TestControllerInputIsForwardedThroughGate(t *testing.T) {
	b, updates, input := startInputFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, make([]byte, 8))
	awaitVersion(t, b, 1)
	ctrl, ctrlDone := participant(t, b, true, &stubGate{})
	request(t, ctrl, 2, 1, false)
	receive(t, ctrl, 4)
	// A controller's keys must reach the upstream untouched.
	key := []byte{4, 1, 0, 0, 0, 0, 0, 97}
	writeTest(t, ctrl, key)
	select {
	case got := <-input:
		if !bytes.Equal(got, key) {
			t.Fatalf("forwarded key: %x", got)
		}
	case <-time.After(writeTimeout + time.Second):
		t.Fatal("controller key was not forwarded")
	}
	// The controller's view still works after forwarding.
	updates <- rawUpdate(0, 0, 1, 1, []byte{7, 0, 0, 0})
	awaitVersion(t, b, 2)
	request(t, ctrl, 2, 1, true)
	if p, _ := receive(t, ctrl, 4); p[0] != 7 {
		t.Fatal("controller view broke after forwarding")
	}
	// An observer alongside never forwards: same key is dropped.
	obs, _ := observer(t, b)
	writeTest(t, obs, key)
	request(t, obs, 2, 1, false)
	receive(t, obs, 4)
	updates <- rawUpdate(0, 0, 1, 1, []byte{8, 0, 0, 0})
	awaitVersion(t, b, 3)
	select {
	case got := <-input:
		if bytes.Equal(got, key) {
			t.Fatalf("observer key leaked upstream: %x", got)
		}
		t.Fatalf("unexpected forwarded message: %x", got)
	case <-time.After(200 * time.Millisecond):
	}
	// Capture still healthy.
	request(t, obs, 2, 1, true)
	if p, _ := receive(t, obs, 4); p[0] != 8 {
		t.Fatal("capture broke after observer input")
	}
	_ = ctrl.Close()
	select {
	case <-ctrlDone:
	case <-time.After(time.Second):
		t.Fatal("controller did not stop")
	}
}

// The console does not echo client-driven pointer moves, so the broker
// publishes the controller's absolute pointer as the cursor position
// observers see — preserving any server-sent shape.
func TestControllerPointerPublishesCursorPos(t *testing.T) {
	b, updates, input := startInputFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, make([]byte, 8))
	awaitVersion(t, b, 1)
	ctrl, _ := participant(t, b, true, &stubGate{})
	setEncodings(t, ctrl, 0, -239, -232, -223)
	request(t, ctrl, 2, 1, false)
	if rects := receiveUpdate(t, ctrl); len(rects) != 1 || rects[0].enc != 0 {
		t.Fatalf("initial frame: %+v", rects)
	}
	move := []byte{5, 0, 0, 1, 0, 0}
	writeTest(t, ctrl, move)
	select {
	case got := <-input:
		if !bytes.Equal(got, move) {
			t.Fatalf("forwarded move: %x", got)
		}
	case <-time.After(writeTimeout + time.Second):
		t.Fatal("controller move was not forwarded")
	}
	awaitCursor(t, b, 1)
	request(t, ctrl, 2, 1, true)
	rects := receiveUpdate(t, ctrl)
	if len(rects) != 1 || rects[0].enc != -232 {
		t.Fatalf("synthesized pos update: %+v", rects)
	}
	if rects[0].x != 1 || rects[0].y != 0 {
		t.Fatalf("synthesized pos: %+v", rects[0])
	}
	// A server-sent shape survives alongside the synthesized position.
	px := make([]byte, 16)
	updates <- cursorShapeUpdate(0, 0, 2, 2, px, []byte{0, 0})
	awaitCursor(t, b, 2)
	request(t, ctrl, 2, 1, true)
	rects = receiveUpdate(t, ctrl)
	if len(rects) != 2 || rects[0].enc != -239 || rects[1].enc != -232 {
		t.Fatalf("shape plus synthesized pos: %+v", rects)
	}
	if rects[1].x != 1 || rects[1].y != 0 {
		t.Fatalf("pos after shape: %+v", rects[1])
	}
}

func TestControllerInputIsFenced(t *testing.T) {
	b, updates, input := startInputFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, make([]byte, 8))
	awaitVersion(t, b, 1)
	fenced := errors.New("input fencing lost")
	ctrl, ctrlDone := participant(t, b, true, &stubGate{err: fenced})
	request(t, ctrl, 2, 1, false)
	receive(t, ctrl, 4)
	key := []byte{4, 1, 0, 0, 0, 0, 0, 97}
	writeTest(t, ctrl, key)
	// The gate drops the write and the participant loop surfaces the fencing
	// error; nothing reaches the upstream.
	select {
	case err := <-ctrlDone:
		if !errors.Is(err, fenced) {
			t.Fatalf("fencing error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fenced controller kept running")
	}
	select {
	case got := <-input:
		t.Fatalf("fenced input reached upstream: %x", got)
	case <-time.After(200 * time.Millisecond):
	}
}
