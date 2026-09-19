package broker

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

type frame struct {
	width, height int
	version       uint64
	pixels        []byte // canonical R,G,B,padding; immutable once published
}

func validSize(w, h int) bool {
	return w > 0 && h > 0 && w <= 4096 && h <= 4096 && w*h <= MaxPixels
}

// The capture side always requests 32-bit RGB in little-endian byte order.
func canonicalFormat() []byte {
	return []byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 0, 8, 16, 0, 0, 0}
}

type pixelFormat struct {
	size  int
	big   bool
	max   [3]uint32
	shift [3]uint
}

// Only bounded, non-overlapping true-colour formats are supported. Indexed
// colour requires a colour map and is deliberately not implemented in A2.
func parseFormat(p []byte) (pixelFormat, error) {
	var f pixelFormat
	if len(p) != 16 || (p[0] != 8 && p[0] != 16 && p[0] != 32) ||
		p[1] == 0 || p[1] > p[0] || p[2] > 1 || p[3] != 1 {
		return f, errors.New("unsupported RFB pixel format")
	}
	f.size, f.big = int(p[0])/8, p[2] == 1
	var used uint32
	depth := 0
	for i := range 3 {
		m := uint32(binary.BigEndian.Uint16(p[4+2*i:]))
		s := uint(p[10+i])
		n := bits.Len32(m)
		if m == 0 || m&(m+1) != 0 || s+uint(n) > uint(p[0]) || used&(m<<s) != 0 {
			return pixelFormat{}, errors.New("invalid RFB colour masks")
		}
		used |= m << s
		depth += n
		f.max[i], f.shift[i] = m, s
	}
	if depth > int(p[1]) {
		return pixelFormat{}, errors.New("invalid RFB colour depth")
	}
	return f, nil
}

func (f pixelFormat) row(dst, src []byte) {
	for i := 0; i < len(src)/4; i++ {
		var v uint32
		for c := range 3 {
			v |= ((uint32(src[i*4+c])*f.max[c] + 127) / 255) << f.shift[c]
		}
		for j := 0; j < f.size; j++ {
			shift := j * 8
			if f.big {
				shift = (f.size - 1 - j) * 8
			}
			dst[i*f.size+j] = byte(v >> shift)
		}
	}
}
