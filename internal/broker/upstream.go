package broker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const protocolVersion = "RFB 003.008\n"

func readBytes(r io.Reader, n int) ([]byte, error) {
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	return p, err
}

func (b *Broker) capture() error {
	c := b.upstream
	if err := c.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}
	version, err := readBytes(c, 12)
	if err != nil {
		return err
	}
	if string(version) != protocolVersion {
		return errors.New("broker requires upstream RFB 3.8")
	}
	if err = writeAll(c, []byte(protocolVersion)); err != nil {
		return err
	}
	count, err := readBytes(c, 1)
	if err != nil {
		return err
	}
	if count[0] == 0 {
		return errors.New("upstream refused RFB security negotiation")
	}
	types, err := readBytes(c, int(count[0]))
	if err != nil {
		return err
	}
	none := false
	for _, kind := range types {
		none = none || kind == 1
	}
	if !none {
		return errors.New("upstream requires unsupported RFB authentication")
	}
	if err = writeAll(c, []byte{1}); err != nil {
		return err
	}
	result, err := readBytes(c, 4)
	if err != nil {
		return err
	}
	if binary.BigEndian.Uint32(result) != 0 {
		return errors.New("upstream RFB authentication failed")
	}
	if err = writeAll(c, []byte{1}); err != nil {
		return err
	} // shared ClientInit
	init, err := readBytes(c, 24)
	if err != nil {
		return err
	}
	w, h := int(binary.BigEndian.Uint16(init)), int(binary.BigEndian.Uint16(init[2:]))
	if !validSize(w, h) {
		return errors.New("upstream framebuffer exceeds bounds")
	}
	nameLen := binary.BigEndian.Uint32(init[20:])
	if nameLen > 4096 {
		return errors.New("upstream desktop name exceeds bounds")
	}
	if _, err = io.CopyN(io.Discard, c, int64(nameLen)); err != nil {
		return err
	}
	if err = writeAll(c, append([]byte{0, 0, 0, 0}, canonicalFormat()...)); err != nil {
		return err
	}
	// Raw plus DesktopSize, the cursor pseudo-encodings (Cursor, CursorPos)
	// and the QEMU audio pseudo-encoding: no stream compression state or
	// unparsed extensions.
	if err = writeAll(c, []byte{2, 0, 0, 5,
		0, 0, 0, 0,
		255, 255, 255, 17,
		255, 255, 255, 40,
		255, 255, 254, 253,
		255, 255, 255, 223}); err != nil {
		return err
	}
	if err = c.SetDeadline(time.Time{}); err != nil {
		return err
	}
	s := newCapture(w, h)
	if err = b.requestUpdate(w, h, false); err != nil {
		return err
	}
	for {
		kind, err := readBytes(c, 1)
		if err != nil {
			return err
		}
		switch kind[0] {
		case 0:
			changed, err := s.update(c)
			if err != nil {
				return err
			}
			if s.cursorDirty {
				s.cursorDirty = false
				up := s.cursor
				s.cursor = cursorUpdate{}
				b.publishCursor(up)
			}
			if s.audioAck {
				s.audioAck = false
				live, _, _, err := b.currentAudio()
				if err != nil {
					return err
				}
				if !live {
					if err := b.enableUpstreamAudio(); err != nil {
						return err
					}
				}
			}
			if changed && s.missing == 0 {
				b.publish(s.width, s.height, s.pixels)
			}
			if err = b.requestUpdate(s.width, s.height, s.missing == 0); err != nil {
				return err
			}
		case 2: // Bell has no payload; not forwarded in this observer-only spike.
		case 255: // QEMU extension: only the audio sub-stream is negotiated.
			if err = b.audioMessage(c); err != nil {
				return err
			}
		case 3:
			// FramebufferUpdate handled below; payload parsing lives in
			// update() so coverage and cursor/audio ack stay together.
			header, err := readBytes(c, 7)
			if err != nil {
				return err
			}
			n := binary.BigEndian.Uint32(header[3:])
			if n > 1<<20 {
				return errors.New("upstream clipboard exceeds bounds")
			}
			if _, err = io.CopyN(io.Discard, c, int64(n)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported upstream RFB message %d", kind[0])
		}
	}
}

// maxAudioBatch bounds one upstream PCM batch. QEMU bundles small batches;
// anything larger is a desynced stream, failed closed before allocation.
const maxAudioBatch = 1 << 20

// audioMessage consumes one QEMU extension server message (type 255). Only
// the audio sub-stream is negotiated; anything else fails the capture
// closed. Data batches publish to the shared audio snapshot; begin/end
// notifications carry no payload.
func (b *Broker) audioMessage(c Stream) error {
	hdr, err := readBytes(c, 3) // subtype, command (u16)
	if err != nil {
		return err
	}
	if hdr[0] != 1 {
		return fmt.Errorf("unsupported upstream QEMU subtype %d", hdr[0])
	}
	switch cmd := binary.BigEndian.Uint16(hdr[1:]); cmd {
	case 0, 1: // end/begin: capture state unchanged
		return nil
	case 2: // data: u32 count + PCM in the negotiated format
		n, err := readBytes(c, 4)
		if err != nil {
			return err
		}
		count := int(binary.BigEndian.Uint32(n))
		if count < 0 || count > maxAudioBatch {
			return errors.New("upstream audio batch outside bounds")
		}
		pcm, err := readBytes(c, count)
		if err != nil {
			return err
		}
		b.publishAudio(pcm)
		return nil
	default:
		return fmt.Errorf("unsupported upstream audio command %d", cmd)
	}
}

// enableUpstreamAudio opens the broker's single shared audio session once
// the console acknowledged the audio pseudo-encoding. It serializes with
// capture's own writes and forwarded input. The fixed PCM format keeps every
// downstream consumer on identical bytes.
func (b *Broker) enableUpstreamAudio() error {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	if err := b.upstream.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	if err := writeAll(b.upstream, append([]byte{255, 1, 0, 2}, brokerAudioFormat...)); err != nil {
		return err
	}
	if err := writeAll(b.upstream, []byte{255, 1, 0, 0}); err != nil {
		return err
	}
	b.setAudioLive()
	return nil
}

// requestUpdate asks the upstream for the next frame. It shares the upstream
// write lock with controller input forwarding so client messages never
// interleave with capture's own requests.
func (b *Broker) requestUpdate(w, h int, incremental bool) error {
	p := make([]byte, 10)
	p[0] = 3
	if incremental {
		p[1] = 1
	}
	binary.BigEndian.PutUint16(p[6:], uint16(w))
	binary.BigEndian.PutUint16(p[8:], uint16(h))
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	if err := b.upstream.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	return writeAll(b.upstream, p)
}
