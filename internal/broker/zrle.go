package broker

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
)

// zrleTileEdge is ZRLE's fixed tile edge length: every rectangle is split
// into 64x64 tiles (edges aside), each coded with its own subencoding.
const zrleTileEdge = 64

// ZRLE subencodings (RFC 6143 §7.7.6). Palette-RLE (130..255) is deliberately
// not emitted: plain RLE and packed palettes cover the same tiles, and fewer
// paths means fewer ways to be wrong.
const (
	zrleRaw      = 0
	zrleSolid    = 1
	zrlePlainRLE = 128
)

// zrleEncoder compresses one observer's rectangles with a connection-scoped
// zlib stream: the dictionary persists across frames, which is both the
// compression ZRLE gets and the reason one encoder belongs to one connection.
type zrleEncoder struct {
	zw     *zlib.Writer
	out    bytes.Buffer
	tile   []byte // CPIXEL conversion of one tile
	palBuf []byte // packed-palette candidate scratch
	rleBuf []byte // plain-RLE candidate scratch
}

func newZRLEEncoder() *zrleEncoder {
	e := &zrleEncoder{}
	e.zw = zlib.NewWriter(&e.out)
	return e
}

// rect encodes one rectangle and returns the ZRLE payload: a big-endian
// compressed length followed by the stream chunk, ready to follow the
// rectangle's header. The zlib stream is sync-flushed per rectangle, so the
// receiver parses each rect independently while the dictionary carries over.
func (e *zrleEncoder) rect(f *frame, format pixelFormat, x, y, w, h int) []byte {
	e.out.Reset()
	for ty := y; ty < y+h; ty += zrleTileEdge {
		th := min(zrleTileEdge, y+h-ty)
		for tx := x; tx < x+w; tx += zrleTileEdge {
			tw := min(zrleTileEdge, x+w-tx)
			e.encodeTile(f, format, tx, ty, tw, th)
		}
	}
	_ = e.zw.Flush()
	payload := make([]byte, 4+e.out.Len())
	binary.BigEndian.PutUint32(payload, uint32(e.out.Len()))
	copy(payload[4:], e.out.Bytes())
	return payload
}

// cpixelSize is the ZRLE compact pixel size for a supported true-colour
// format: 32bpp with depth 24 and full-byte channels drops the padding byte,
// every other format carries its plain pixel size. This must match the
// decoder's TPIXEL rule exactly.
func (f pixelFormat) cpixelSize() int {
	if f.size == 4 && f.max[0] == 255 && f.max[1] == 255 && f.max[2] == 255 {
		return 3
	}
	return f.size
}

// encodeTile converts one tile to CPIXELs and writes its smallest subencoding
// into the zlib stream.
func (e *zrleEncoder) encodeTile(f *frame, format pixelFormat, x, y, w, h int) {
	cpix := format.cpixelSize()
	n := w * h
	e.tile = growScratch(e.tile, n*cpix)
	tile := e.tile[:n*cpix]
	convertCPixels(tile, f, format, x, y, w, h)

	if solid, ok := solidColour(tile, n, cpix); ok {
		e.streamWrite([]byte{zrleSolid})
		e.streamWrite(solid)
		return
	}

	// Pack the palette into one scratch buffer and the RLE into another: the
	// two candidates must not alias, and the backing stores are kept across
	// tiles to avoid per-tile churn.
	var best []byte
	if pal, ok := packPalette(tile, n, cpix, w, append(e.palBuf[:0], 0)); ok {
		best = pal
		e.palBuf = pal[:0]
	}
	rle := plainRLE(tile, n, cpix, append(e.rleBuf[:0], 0))
	e.rleBuf = rle[:0]
	if best == nil || len(rle) < len(best) {
		best = rle
	}
	if 1+n*cpix <= len(best) {
		e.streamWrite([]byte{zrleRaw})
		e.streamWrite(tile)
		return
	}
	e.streamWrite(best)
}

func (e *zrleEncoder) streamWrite(p []byte) {
	// The only error a bytes.Buffer writer ever returns is nil.
	_, _ = e.zw.Write(p)
}

// growScratch returns buf grown to at least n bytes, keeping the allocation
// across tiles so a long-lived observer encodes without per-tile churn.
func growScratch(buf []byte, n int) []byte {
	if cap(buf) < n {
		return make([]byte, n)
	}
	return buf[:n]
}

// convertCPixels renders one tile of the canonical frame into CPIXEL bytes:
// compact 3-byte RGB for the common 32bpp/24-bit formats, otherwise the same
// scaled pixel bytes the Raw path emits.
func convertCPixels(dst []byte, f *frame, format pixelFormat, x, y, w, h int) {
	if format.cpixelSize() == 3 {
		i := 0
		for yy := y; yy < y+h; yy++ {
			start := (yy*f.width + x) * 4
			row := f.pixels[start : start+w*4]
			for xx := 0; xx < w; xx++ {
				dst[i], dst[i+1], dst[i+2] = row[xx*4], row[xx*4+1], row[xx*4+2]
				i += 3
			}
		}
		return
	}
	i := 0
	for yy := y; yy < y+h; yy++ {
		start := (yy*f.width + x) * 4
		format.row(dst[i:i+w*format.size], f.pixels[start:start+w*4])
		i += w * format.size
	}
}

// solidColour reports the tile's single colour, when there is one.
func solidColour(tile []byte, n, cpix int) ([]byte, bool) {
	for i := 1; i < n; i++ {
		for j := 0; j < cpix; j++ {
			if tile[i*cpix+j] != tile[j] {
				return nil, false
			}
		}
	}
	return tile[:cpix], true
}

// packPalette encodes subencodings 2..16: the palette followed by the pixel
// indices packed most-significant-bits first, each row restarting on a byte
// boundary. ok is false when the tile uses more than sixteen colours; the
// caller compares sizes against the other subencodings.
func packPalette(tile []byte, n, cpix, w int, dst []byte) ([]byte, bool) {
	var palette [16][]byte
	indices := make([]byte, n)
	count := 0
	// The CPIXEL key packs into a uint32 for the map; cpix is at most 4.
	key := func(i int) uint32 {
		var k uint32
		for j := 0; j < cpix; j++ {
			k = k<<8 | uint32(tile[i*cpix+j])
		}
		return k
	}
	seen := make(map[uint32]int, 17)
	for i := 0; i < n; i++ {
		k := key(i)
		idx, ok := seen[k]
		if !ok {
			if count == 16 {
				return nil, false
			}
			idx = count
			seen[k] = idx
			palette[idx] = tile[i*cpix : (i+1)*cpix]
			count++
		}
		indices[i] = byte(idx)
	}
	bits := 1
	switch {
	case count == 2:
		bits = 1
	case count <= 4:
		bits = 2
	default:
		bits = 4
	}
	dst = dst[:1]
	dst[0] = byte(count)
	for _, p := range palette[:count] {
		dst = append(dst, p...)
	}
	rowBytes := (w*bits + 7) / 8
	mask := byte(1<<bits) - 1
	for y := 0; y < n/w; y++ {
		row := make([]byte, rowBytes)
		for x := 0; x < w; x++ {
			bit := x * bits
			shift := 8 - bits - (bit % 8)
			row[bit/8] |= (indices[y*w+x] & mask) << shift
		}
		dst = append(dst, row...)
	}
	return dst, true
}

// plainRLE encodes subencoding 128: (colour, run-length) pairs in scanline
// order, the length stored as count-1 in 255 chunks.
func plainRLE(tile []byte, n, cpix int, dst []byte) []byte {
	dst = dst[:1]
	dst[0] = zrlePlainRLE
	for i := 0; i < n; {
		run := 1
		for i+run < n {
			a, b := i*cpix, (i+run)*cpix
			same := true
			for j := 0; j < cpix; j++ {
				if tile[a+j] != tile[b+j] {
					same = false
					break
				}
			}
			if !same {
				break
			}
			run++
		}
		dst = append(dst, tile[i*cpix:(i+1)*cpix]...)
		for rem := run - 1; ; {
			if rem >= 255 {
				dst = append(dst, 255)
				rem -= 255
				continue
			}
			dst = append(dst, byte(rem))
			break
		}
		i += run
	}
	return dst
}
