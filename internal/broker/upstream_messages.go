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
}

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
