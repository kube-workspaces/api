package rfb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func clientFixtures() [][]byte {
	// Complete messages, including variable-length forms and extension framing.
	return [][]byte{
		{0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0},
		{2, 0, 0, 2, 0, 0, 0, 0, 255, 255, 255, 33}, // Raw and DesktopSize
		{3, 1, 0, 0, 0, 0, 4, 0, 3, 0},
		{4, 1, 0, 0, 0, 0, 0, 97},
		{5, 1, 0, 100, 0, 200},
		{6, 0, 0, 0, 0, 0, 0, 3, 'a', 'b', 'c'},
		{251, 0, 4, 0, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 3, 0, 0, 0, 0, 0},
		{255, 0, 0, 1, 0, 0, 0, 97, 0, 0, 0, 30},
	}
}

func TestClientMessagesAcrossReadBoundaries(t *testing.T) {
	fixtures := clientFixtures()
	stream := bytes.Join(fixtures, nil)
	for _, fragmented := range []bool{false, true} {
		var r io.Reader = bytes.NewReader(stream)
		if fragmented {
			r = iotest.OneByteReader(r)
		}
		for i, wire := range fixtures {
			message, err := ReadClientMessage(r)
			if err != nil {
				t.Fatalf("fragmented=%v type=%d: %v", fragmented, wire[0], err)
			}
			wantScope := GuestMutation
			if i < 3 {
				wantScope = ParticipantLocal
			}
			if !bytes.Equal(message.Bytes(), wire) || message.Scope() != wantScope {
				t.Fatalf("type=%d: bytes=%x scope=%v", wire[0], message.Bytes(), message.Scope())
			}
		}
		if _, err := ReadClientMessage(r); err != io.EOF {
			t.Fatalf("trailing data or unclean EOF: %v", err)
		}
	}
}

func TestEveryTruncatedMessageFails(t *testing.T) {
	for _, wire := range clientFixtures() {
		for end := 1; end < len(wire); end++ {
			message, err := ReadClientMessage(bytes.NewReader(wire[:end]))
			if !errors.Is(err, io.ErrUnexpectedEOF) || message.Scope() != Invalid {
				t.Fatalf("type=%d truncated at %d: scope=%v err=%v", wire[0], end, message.Scope(), err)
			}
		}
	}
}

func TestUnsupportedMessagesFailClosed(t *testing.T) {
	for _, wire := range [][]byte{
		{1}, {7}, {150}, {248}, // unknown, continuous updates, Fence
		{255, 1}, {255, 255}, // QEMU audio and unknown extension
		{6, 0, 0, 0, 255, 255, 255, 255}, // extended clipboard
		{6, 0, 0, 0, 128, 0, 0, 0},       // signed-length overflow
	} {
		message, err := ReadClientMessage(bytes.NewReader(wire))
		if !errors.Is(err, ErrUnsupported) || message.Scope() != Invalid || len(message.Bytes()) != 0 {
			t.Fatalf("%x: scope=%v err=%v", wire, message.Scope(), err)
		}
	}
}

// headerOnly catches attempts to read oversized payloads before checking limits.
type headerOnly struct{ *bytes.Reader }

func (r headerOnly) Read(p []byte) (int, error) {
	if r.Len() == 0 {
		panic("attempted to read rejected payload")
	}
	return r.Reader.Read(p)
}

func TestLimitsBeforePayloadRead(t *testing.T) {
	clipboard := []byte{6, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(clipboard[4:], MaxClipboardBytes+1)
	encodings := []byte{2, 0, 0, 0}
	binary.BigEndian.PutUint16(encodings[2:], MaxEncodings+1)
	for _, wire := range [][]byte{
		clipboard, encodings,
		{251, 0, 4, 0, 3, 0, MaxScreens + 1, 0},
		{251, 0, 4, 0, 3, 0, 0, 0},
	} {
		message, err := ReadClientMessage(headerOnly{bytes.NewReader(wire)})
		if !errors.Is(err, ErrLimit) || message.Scope() != Invalid {
			t.Fatalf("%x: scope=%v err=%v", wire, message.Scope(), err)
		}
	}
}

func TestVariableLengthBoundaries(t *testing.T) {
	for _, size := range []int{0, MaxClipboardBytes} {
		wire := make([]byte, 8+size)
		wire[0] = ClientCutText
		binary.BigEndian.PutUint32(wire[4:], uint32(size))
		message, err := ReadClientMessage(bytes.NewReader(wire))
		if err != nil || message.Scope() != GuestMutation || !bytes.Equal(message.Bytes(), wire) {
			t.Fatalf("clipboard size=%d: %v", size, err)
		}
	}
	for _, count := range []int{0, MaxEncodings} {
		wire := make([]byte, 4+4*count)
		wire[0] = SetEncodings
		binary.BigEndian.PutUint16(wire[2:], uint16(count))
		message, err := ReadClientMessage(bytes.NewReader(wire))
		if err != nil || message.Scope() != ParticipantLocal || !bytes.Equal(message.Bytes(), wire) {
			t.Fatalf("encoding count=%d: %v", count, err)
		}
	}
	wire := make([]byte, 8+16*MaxScreens)
	wire[0], wire[6] = SetDesktopSize, MaxScreens
	message, err := ReadClientMessage(bytes.NewReader(wire))
	if err != nil || message.Scope() != GuestMutation || !bytes.Equal(message.Bytes(), wire) {
		t.Fatalf("maximum screen count: %v", err)
	}
}

func TestMessageCannotBeChangedAfterClassification(t *testing.T) {
	message, err := ReadClientMessage(bytes.NewReader(clientFixtures()[0]))
	if err != nil {
		t.Fatal(err)
	}
	wire := message.Bytes()
	wire[0] = KeyEvent
	if message.Bytes()[0] != SetPixelFormat || message.Scope() != ParticipantLocal {
		t.Fatal("caller changed the classified message")
	}
	if (ClientMessage{}).Scope() != Invalid {
		t.Fatal("zero-value message must not be dispatchable")
	}
}

func FuzzReadClientMessage(f *testing.F) {
	for _, wire := range clientFixtures() {
		f.Add(wire)
	}
	f.Add([]byte{6, 0, 0, 0, 128, 0, 0, 0})
	f.Fuzz(func(t *testing.T, wire []byte) {
		r := bytes.NewReader(wire)
		message, err := ReadClientMessage(r)
		if err != nil {
			if message.Scope() != Invalid {
				t.Fatal("partial message was dispatchable")
			}
			return
		}
		parsed := message.Bytes()
		if len(parsed) > MaxClipboardBytes+8 || len(parsed) == 0 ||
			len(wire)-r.Len() != len(parsed) || !bytes.Equal(parsed, wire[:len(parsed)]) {
			t.Fatal("unbounded or incorrect message framing")
		}
		want := GuestMutation
		if parsed[0] == SetPixelFormat || parsed[0] == SetEncodings || parsed[0] == FramebufferUpdateRequest {
			want = ParticipantLocal
		}
		if message.Scope() != want {
			t.Fatalf("scope=%v want=%v", message.Scope(), want)
		}
	})
}
