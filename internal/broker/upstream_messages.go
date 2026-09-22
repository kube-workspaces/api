package broker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// captureState is confined to the upstream reader. Coverage tracking prevents
// publishing uninitialized pixels after handshake or resize, even if a server
// splits its response to the full-update request across several messages.
type captureState struct {
	width, height int
	pixels        []byte
	covered       []byte
	missing       int
	// cursor accumulates the latest remote-pointer shape and position, and
	// cursorDirty marks an unpublished change for the capture loop. Cursor
	// rectangles never touch framebuffer coverage: they describe the
	// pointer, not pixels.
	cursor      cursorState
	cursorDirty bool
}

// cursorState is one remote-pointer snapshot: an optional shape (hotspot,
// dimensions, canonical RGBX pixels plus the 1-bit mask) and an optional
// absolute position. A zero-sized shape hides the pointer.
type cursorState struct {
	hasShape   bool
	hotX, hotY int
	w, h       int
	pixels     []byte
	mask       []byte
	hasPos     bool
	posX, posY int
}

// maxCursorEdge bounds one cursor dimension. Real guest cursors are tens of
// pixels; anything larger is a malformed or hostile upstream, failed closed.
const maxCursorEdge = 256

func newCapture(w, h int) *captureState {
	return &captureState{width: w, height: h, pixels: make([]byte, w*h*4), covered: make([]byte, w*h), missing: w * h}
}

func (s *captureState) update(r io.Reader) (bool, error) {
	header, err := readBytes(r, 3) // padding, number-of-rectangles (u16)
	if err != nil {
		return false, err
	}
	count := int(binary.BigEndian.Uint16(header[1:]))
	if count > 4096 {
		return false, errors.New("too many upstream rectangles")
	}
	// Bound total pixel work per update as well as individual allocations.
	pixelBudget := 4 * MaxPixels
	changed := false
	resized := false
	for range count {
		p, err := readBytes(r, 12)
		if err != nil {
			return false, err
		}
		x, y := int(binary.BigEndian.Uint16(p)), int(binary.BigEndian.Uint16(p[2:]))
		w, h := int(binary.BigEndian.Uint16(p[4:])), int(binary.BigEndian.Uint16(p[6:]))
		encoding := int32(binary.BigEndian.Uint32(p[8:]))
		if encoding == -223 {
			if resized || x != 0 || y != 0 || !validSize(w, h) {
				return false, errors.New("invalid upstream resize")
			}
			resized = true
			*s = *newCapture(w, h)
			changed = true
			continue
		}
		if encoding == -239 {
			// Cursor shape: the header carries the hotspot, then w*h
			// canonical pixels plus the 1-bit mask. A zero-sized shape
			// hides the pointer and carries no payload.
			if w < 0 || h < 0 || w > maxCursorEdge || h > maxCursorEdge || w*h > pixelBudget {
				return false, errors.New("upstream cursor shape outside bounds")
			}
			pixelBudget -= w * h
			s.cursor.hasShape = true
			s.cursor.hotX, s.cursor.hotY = x, y
			s.cursor.w, s.cursor.h = w, h
			if w == 0 || h == 0 {
				s.cursor.pixels, s.cursor.mask = nil, nil
			} else {
				px, err := readBytes(r, w*h*4)
				if err != nil {
					return false, err
				}
				mask, err := readBytes(r, ((w+7)/8)*h)
				if err != nil {
					return false, err
				}
				s.cursor.pixels, s.cursor.mask = px, mask
			}
			s.cursorDirty = true
			continue
		}
		if encoding == -232 {
			// Cursor position: header only, no payload.
			if x > s.width || y > s.height {
				return false, errors.New("upstream cursor position outside bounds")
			}
			s.cursor.hasPos = true
			s.cursor.posX, s.cursor.posY = x, y
			s.cursorDirty = true
			continue
		}
		if encoding != 0 {
			return false, fmt.Errorf("unnegotiated upstream encoding %d", encoding)
		}
		if w == 0 || h == 0 || x+w > s.width || y+h > s.height || w*h > pixelBudget {
			return false, errors.New("upstream rectangle outside bounds")
		}
		pixelBudget -= w * h
		for row := y; row < y+h; row++ {
			start := row*s.width + x
			if _, err = io.ReadFull(r, s.pixels[start*4:(start+w)*4]); err != nil {
				return false, err
			}
			if s.missing > 0 {
				for pixel := start; pixel < start+w; pixel++ {
					if s.covered[pixel] == 0 {
						s.covered[pixel] = 1
						s.missing--
					}
				}
			}
		}
		changed = true
	}
	return changed, nil
}
