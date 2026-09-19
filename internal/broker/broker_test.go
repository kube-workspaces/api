package broker

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
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
	p, err = readBytes(c, 12)
	if err != nil {
		return err
	}
	if !bytes.Equal(p, []byte{2, 0, 0, 2, 0, 0, 0, 0, 255, 255, 255, 33}) {
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
	p, err = readBytes(c, 12)
	if err != nil {
		return err
	}
	if !bytes.Equal(p, []byte{2, 0, 0, 2, 0, 0, 0, 0, 255, 255, 255, 33}) {
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
