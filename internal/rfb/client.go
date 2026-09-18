// Package rfb contains protocol primitives for the shared-display broker.
// The existing exclusive VNC bridge does not use this package yet.
package rfb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Scope distinguishes participant-local protocol state from guest mutation.
// Neither scope permits opaque forwarding to the upstream RFB connection:
// local messages must be terminated by the broker, and guest mutations require
// a current control claim checked at dispatch (not merely when parsed).
type Scope uint8

const (
	Invalid Scope = iota
	ParticipantLocal
	GuestMutation
)

const (
	SetPixelFormat           byte = 0
	SetEncodings             byte = 2
	FramebufferUpdateRequest byte = 3
	KeyEvent                 byte = 4
	PointerEvent             byte = 5
	ClientCutText            byte = 6
	SetDesktopSize           byte = 251
	QEMU                     byte = 255

	MaxEncodings      = 1024
	MaxClipboardBytes = 1 << 20
	MaxScreens        = 16
)

var (
	ErrUnsupported = errors.New("unsupported RFB client message")
	ErrLimit       = errors.New("RFB client message exceeds limit")
)

// ClientMessage is a complete, bounded post-handshake message. Its zero value
// has Invalid scope. Bytes returns a copy so consumers cannot change bytes
// after their scope has been determined.
type ClientMessage struct {
	wire  []byte
	scope Scope
}

func (m ClientMessage) Scope() Scope  { return m.scope }
func (m ClientMessage) Bytes() []byte { return bytes.Clone(m.wire) }

// ReadClientMessage reads exactly one message from the post-ServerInit RFB
// byte stream. It does not perform a handshake, authorize a participant, or
// validate negotiated pixel formats/encodings/geometry. The broker must do
// those checks before using a message. It must never forward ParticipantLocal
// messages directly: observer format/encoding choices are local to that viewer.
//
// Read boundaries are not message boundaries; flatten binary WebSocket data
// before calling. Every error is terminal for this stream. In particular, do
// not skip an unknown message and attempt to resynchronize. The transport must
// supply deadlines/cancellation by closing its reader; memory limits do not
// prevent a peer from stalling midway through a message.
//
// Supported extensions are SetDesktopSize and QEMU extended keys. Audio,
// continuous updates, Fence, extended clipboard and other extensions must not
// be advertised by the initial broker until explicitly implemented.
func ReadClientMessage(r io.Reader) (ClientMessage, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return ClientMessage{}, err
	}
	wire := []byte{first[0]}
	read := func(n int) error {
		start := len(wire)
		wire = append(wire, make([]byte, n)...)
		_, err := io.ReadFull(r, wire[start:])
		if err == io.EOF {
			return io.ErrUnexpectedEOF // the type byte was already consumed
		}
		return err
	}
	scope := GuestMutation
	var err error
	switch first[0] {
	case SetPixelFormat:
		scope = ParticipantLocal
		err = read(19)
	case SetEncodings:
		scope = ParticipantLocal
		if err = read(3); err == nil {
			count := int(binary.BigEndian.Uint16(wire[2:4]))
			if count > MaxEncodings {
				return ClientMessage{}, ErrLimit
			}
			err = read(4 * count)
		}
	case FramebufferUpdateRequest:
		scope = ParticipantLocal
		err = read(9)
	case KeyEvent:
		err = read(7)
	case PointerEvent:
		err = read(5)
	case ClientCutText:
		if err = read(7); err == nil {
			length := binary.BigEndian.Uint32(wire[4:8])
			// A negative signed length denotes the extended clipboard protocol;
			// reject before allocation, including INT32_MIN/absolute overflow.
			if length&0x80000000 != 0 {
				return ClientMessage{}, fmt.Errorf("%w: extended clipboard", ErrUnsupported)
			}
			if length > MaxClipboardBytes {
				return ClientMessage{}, ErrLimit
			}
			err = read(int(length))
		}
	case SetDesktopSize:
		if err = read(7); err == nil {
			count := int(wire[6])
			if count == 0 || count > MaxScreens {
				return ClientMessage{}, ErrLimit
			}
			err = read(16 * count)
		}
	case QEMU:
		if err = read(1); err == nil {
			if wire[1] != 0 { // subtype 0: down flag, keysym, keycode
				return ClientMessage{}, fmt.Errorf("%w: QEMU subtype %d", ErrUnsupported, wire[1])
			}
			err = read(10)
		}
	default:
		return ClientMessage{}, fmt.Errorf("%w: type %d", ErrUnsupported, first[0])
	}
	if err != nil {
		return ClientMessage{}, err
	}
	return ClientMessage{wire: wire, scope: scope}, nil
}
