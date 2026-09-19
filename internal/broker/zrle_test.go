package broker

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"math/rand"
	"testing"
)

// --- reference decoder ------------------------------------------------------
//
// The tests decode the encoder's stream with a small decoder written straight
// from RFC 6143 §7.7.6, independent of the encoder's code, and compare the
// pixels byte-for-byte against the source frame's own CPIXEL conversion. The
// desktop client's real decoder exercises the same stream in the opt-in
// interop probe.

// inflateAvailable drains a zlib reader of everything the stream currently
// decodes. The encoder never closes its stream (the dictionary persists
// across rects), so there is no trailer: a sync flush just guarantees that
// every byte written so far is decodable, and the end of that is reported as
// an EOF of some flavour rather than a clean stream end.
func inflateAvailable(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var out []byte
	buf := make([]byte, 64*1024)
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return out
			}
			t.Fatalf("inflate: %v", err)
		}
	}
}

func inflateRect(t *testing.T, payload []byte) []byte {
	t.Helper()
	if binary.BigEndian.Uint32(payload) != uint32(len(payload)-4) {
		t.Fatalf("payload length prefix %d != %d", binary.BigEndian.Uint32(payload), len(payload)-4)
	}
	r, err := zlib.NewReader(bytes.NewReader(payload[4:]))
	if err != nil {
		t.Fatalf("zlib reader: %v", err)
	}
	defer func() { _ = r.Close() }()
	return inflateAvailable(t, r)
}

// inflateStream concatenates two payloads and inflates them with ONE reader,
// proving the dictionary really does carry over between rects.
func inflateStream(t *testing.T, payloads ...[]byte) []byte {
	t.Helper()
	var compressed []byte
	for _, p := range payloads {
		compressed = append(compressed, p[4:]...)
	}
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("zlib reader: %v", err)
	}
	defer func() { _ = r.Close() }()
	return inflateAvailable(t, r)
}

// decodeTiles parses the tile stream for a rect of w*h at cpix bytes per
// pixel, returning the pixels in scanline order and the first tile's
// subencoding byte.
func decodeTiles(t *testing.T, data []byte, w, h, cpix int) ([]byte, byte) {
	t.Helper()
	out := make([]byte, w*h*cpix)
	pos := 0
	first := byte(0)
	firstTile := true
	read := func(n int) []byte {
		if pos+n > len(data) {
			t.Fatalf("tile stream truncated: need %d bytes at %d of %d", n, pos, len(data))
		}
		p := data[pos : pos+n]
		pos += n
		return p
	}
	for ty := 0; ty < h; ty += zrleTileEdge {
		th := min(zrleTileEdge, h-ty)
		for tx := 0; tx < w; tx += zrleTileEdge {
			tw := min(zrleTileEdge, w-tx)
			subenc := read(1)[0]
			if firstTile {
				first = subenc
				firstTile = false
			}
			put := func(i int, cp []byte) {
				px, py := tx+i%tw, ty+i/tw
				copy(out[(py*w+px)*cpix:], cp)
			}
			switch {
			case subenc == zrleRaw:
				for i := 0; i < tw*th; i++ {
					put(i, read(cpix))
				}
			case subenc == zrleSolid:
				cp := read(cpix)
				for i := 0; i < tw*th; i++ {
					put(i, cp)
				}
			case subenc >= 2 && subenc <= 16:
				n := int(subenc)
				palette := make([][]byte, n)
				for i := range palette {
					palette[i] = read(cpix)
				}
				bits := 1
				switch {
				case n == 2:
					bits = 1
				case n <= 4:
					bits = 2
				default:
					bits = 4
				}
				rowBytes := (tw*bits + 7) / 8
				for y := 0; y < th; y++ {
					row := read(rowBytes)
					for x := 0; x < tw; x++ {
						bit := x * bits
						shift := 8 - bits - (bit % 8)
						idx := int((row[bit/8] >> shift) & byte(1<<bits-1))
						if idx >= n {
							t.Fatalf("palette index %d out of range %d", idx, n)
						}
						put(y*tw+x, palette[idx])
					}
				}
			case subenc == zrlePlainRLE:
				for i := 0; i < tw*th; {
					cp := read(cpix)
					run := 1
					for {
						b := read(1)[0]
						run += int(b)
						if b != 255 {
							break
						}
					}
					if i+run > tw*th {
						t.Fatalf("run overflows tile: %d+%d > %d", i, run, tw*th)
					}
					for ; run > 0; run-- {
						put(i, cp)
						i++
					}
				}
			default:
				t.Fatalf("unexpected subencoding %d", subenc)
			}
		}
	}
	if pos != len(data) {
		t.Fatalf("%d trailing bytes after tiles", len(data)-pos)
	}
	return out, first
}

// --- fixtures ---------------------------------------------------------------

// testFrame builds a frame whose pixels come from fn(x, y) → (r, g, b).
func testFrame(w, h int, fn func(x, y int) (byte, byte, byte)) *frame {
	pixels := make([]byte, w*h*4)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, g, b := fn(x, y)
			i := (y*w + x) * 4
			pixels[i], pixels[i+1], pixels[i+2] = r, g, b
		}
	}
	return &frame{width: w, height: h, pixels: pixels}
}

func expectedCPixels(t *testing.T, f *frame, format pixelFormat, x, y, w, h, cpix int) []byte {
	t.Helper()
	want := make([]byte, w*h*cpix)
	convertCPixels(want, f, format, x, y, w, h)
	return want
}

// --- tests ------------------------------------------------------------------

func TestZRLESolidFrame(t *testing.T) {
	format, _ := parseFormat(canonicalFormat())
	f := testFrame(64, 64, func(x, y int) (byte, byte, byte) { return 12, 34, 56 })
	enc := newZRLEEncoder()
	payload := enc.rect(f, format, 0, 0, 64, 64)

	data := inflateRect(t, payload)
	got, first := decodeTiles(t, data, 64, 64, 3)
	if first != zrleSolid {
		t.Fatalf("a solid frame encoded as subencoding %d, want solid (1)", first)
	}
	if want := expectedCPixels(t, f, format, 0, 0, 64, 64, 3); !bytes.Equal(got, want) {
		t.Fatal("decoded pixels differ from the source frame")
	}
	if len(payload) >= 64 {
		t.Fatalf("a solid 64x64 frame compressed to %d bytes, want tiny", len(payload))
	}
}

func TestZRLEPackedPaletteRoundTrip(t *testing.T) {
	format, _ := parseFormat(canonicalFormat())
	// Four colours in a checkerboard: packed-palette territory.
	f := testFrame(64, 64, func(x, y int) (byte, byte, byte) {
		switch (x + y) % 4 {
		case 0:
			return 255, 0, 0
		case 1:
			return 0, 255, 0
		case 2:
			return 0, 0, 255
		default:
			return 255, 255, 0
		}
	})
	enc := newZRLEEncoder()
	payload := enc.rect(f, format, 0, 0, 64, 64)

	data := inflateRect(t, payload)
	got, first := decodeTiles(t, data, 64, 64, 3)
	if first < 2 || first > 16 {
		t.Fatalf("a four-colour tile encoded as subencoding %d, want packed palette", first)
	}
	if want := expectedCPixels(t, f, format, 0, 0, 64, 64, 3); !bytes.Equal(got, want) {
		t.Fatal("decoded pixels differ from the source frame")
	}
}

func TestZRLEPlainRLERoundTrip(t *testing.T) {
	format, _ := parseFormat(canonicalFormat())
	// Long runs of many distinct colours: plain RLE, not palette.
	f := testFrame(128, 64, func(x, y int) (byte, byte, byte) {
		v := byte(x / 16)
		return v, v, v
	})
	enc := newZRLEEncoder()
	payload := enc.rect(f, format, 0, 0, 128, 64)

	data := inflateRect(t, payload)
	got, first := decodeTiles(t, data, 128, 64, 3)
	if first != zrlePlainRLE && first != zrleRaw {
		t.Fatalf("long-run tile encoded as subencoding %d, want plain RLE", first)
	}
	if want := expectedCPixels(t, f, format, 0, 0, 128, 64, 3); !bytes.Equal(got, want) {
		t.Fatal("decoded pixels differ from the source frame")
	}
}

func TestZRLENoiseFallsBackToRaw(t *testing.T) {
	format, _ := parseFormat(canonicalFormat())
	rng := rand.New(rand.NewSource(42))
	f := testFrame(64, 64, func(x, y int) (byte, byte, byte) {
		return byte(rng.Uint32()), byte(rng.Uint32()), byte(rng.Uint32())
	})
	enc := newZRLEEncoder()
	payload := enc.rect(f, format, 0, 0, 64, 64)

	data := inflateRect(t, payload)
	got, first := decodeTiles(t, data, 64, 64, 3)
	if first != zrleRaw {
		t.Fatalf("noise encoded as subencoding %d, want raw fallback", first)
	}
	if want := expectedCPixels(t, f, format, 0, 0, 64, 64, 3); !bytes.Equal(got, want) {
		t.Fatal("decoded pixels differ from the source frame")
	}
}

func TestZRLEEdgeTilesAndSubRects(t *testing.T) {
	format, _ := parseFormat(canonicalFormat())
	f := testFrame(130, 70, func(x, y int) (byte, byte, byte) {
		return byte(x), byte(y), byte(x + y)
	})
	enc := newZRLEEncoder()
	// A sub-rectangle crossing tile boundaries and the odd right/bottom edges.
	x, y, w, h := 61, 62, 66, 8
	payload := enc.rect(f, format, x, y, w, h)

	data := inflateRect(t, payload)
	got, _ := decodeTiles(t, data, w, h, 3)
	if want := expectedCPixels(t, f, format, x, y, w, h, 3); !bytes.Equal(got, want) {
		t.Fatal("decoded edge/subrect pixels differ from the source frame")
	}
}

func TestZRLEStreamContinuityAcrossRects(t *testing.T) {
	format, _ := parseFormat(canonicalFormat())
	f1 := testFrame(64, 64, func(x, y int) (byte, byte, byte) { return 1, 2, 3 })
	f2 := testFrame(64, 64, func(x, y int) (byte, byte, byte) { return 4, 5, 6 })
	enc := newZRLEEncoder()
	p1 := enc.rect(f1, format, 0, 0, 64, 64)
	p2 := enc.rect(f2, format, 0, 0, 64, 64)

	// One inflater over both chunks, exactly how a client consumes them.
	data := inflateStream(t, p1, p2)
	solid := 1 + 3
	if len(data) != 2*solid {
		t.Fatalf("stream for two solid rects inflated to %d bytes, want %d", len(data), 2*solid)
	}
	if data[0] != zrleSolid || !bytes.Equal(data[1:4], []byte{1, 2, 3}) ||
		data[4] != zrleSolid || !bytes.Equal(data[5:8], []byte{4, 5, 6}) {
		t.Fatalf("stream lost a rect: %v", data)
	}
}

func TestZRLE16BitAnd8BitFormats(t *testing.T) {
	f := testFrame(64, 64, func(x, y int) (byte, byte, byte) { return byte(x), byte(y), 128 })
	for _, tt := range []struct {
		name   string
		format []byte
		cpix   int
	}{
		// RGB565 little-endian.
		{"rgb565", []byte{16, 16, 0, 1, 0, 31, 0, 63, 0, 31, 11, 5, 0, 0, 0, 0}, 2},
		// 8-bit 3-3-2.
		{"rgb332", []byte{8, 8, 0, 1, 0, 7, 0, 7, 0, 3, 5, 2, 0, 0, 0, 0}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			format, err := parseFormat(tt.format)
			if err != nil {
				t.Fatalf("parseFormat: %v", err)
			}
			if got := format.cpixelSize(); got != tt.cpix {
				t.Fatalf("cpixelSize = %d, want %d", got, tt.cpix)
			}
			enc := newZRLEEncoder()
			payload := enc.rect(f, format, 0, 0, 64, 64)
			data := inflateRect(t, payload)
			got, _ := decodeTiles(t, data, 64, 64, tt.cpix)
			if want := expectedCPixels(t, f, format, 0, 0, 64, 64, tt.cpix); !bytes.Equal(got, want) {
				t.Fatal("decoded pixels differ from the source frame")
			}
		})
	}
}

// TestZRLECompressionBeatsRawOnDesktopContent measures the wire-size win on
// plausible desktop content: the A2 note priced Raw at ~8.3 MB per 1080p
// frame per observer, which is what keeps the shared display off the default
// path until an encoding lands.
func TestZRLECompressionBeatsRawOnDesktopContent(t *testing.T) {
	format, _ := parseFormat(canonicalFormat())
	raw := 1920 * 1080 * 4
	for _, tt := range []struct {
		name string
		fn   func(x, y int) (byte, byte, byte)
		max  float64 // upper bound on compressed size as a fraction of raw
	}{
		{"solid", func(x, y int) (byte, byte, byte) { return 30, 30, 30 }, 0.001},
		// Windowed desktop: large solid regions, gradient wallpaper, text-ish
		// stripes.
		{"desktop", func(x, y int) (byte, byte, byte) {
			if y%8 < 5 && x%120 < 100 {
				return 40, 40, 40
			}
			return byte(x / 8), byte(y / 8), 180
		}, 0.05},
	} {
		f := testFrame(1920, 1080, tt.fn)
		enc := newZRLEEncoder()
		payload := enc.rect(f, format, 0, 0, 1920, 1080)
		got := len(payload)
		t.Logf("%s: raw=%d zrle=%d ratio=%.4f", tt.name, raw, got, float64(got)/float64(raw))
		if float64(got) > float64(raw)*tt.max {
			t.Fatalf("%s: ZRLE size %d exceeds %.1f%% of raw", tt.name, got, tt.max*100)
		}
		// And it still decodes exactly.
		data := inflateRect(t, payload)
		dec, _ := decodeTiles(t, data, 1920, 1080, 3)
		if want := expectedCPixels(t, f, format, 0, 0, 1920, 1080, 3); !bytes.Equal(dec, want) {
			t.Fatalf("%s: decoded pixels differ", tt.name)
		}
	}
}

func BenchmarkZRLEEncode1080p(b *testing.B) {
	format, _ := parseFormat(canonicalFormat())
	for _, tt := range []struct {
		name string
		fn   func(x, y int) (byte, byte, byte)
	}{
		{"solid", func(x, y int) (byte, byte, byte) { return 30, 30, 30 }},
		{"desktop", func(x, y int) (byte, byte, byte) {
			if y%8 < 5 && x%120 < 100 {
				return 40, 40, 40
			}
			return byte(x / 8), byte(y / 8), 180
		}},
		{"noise", func(x, y int) (byte, byte, byte) {
			rng := rand.New(rand.NewSource(int64(x*1080 + y)))
			return byte(rng.Uint32()), byte(rng.Uint32()), byte(rng.Uint32())
		}},
	} {
		f := testFrame(1920, 1080, tt.fn)
		enc := newZRLEEncoder()
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			var size int
			b.ResetTimer()
			for range b.N {
				size = len(enc.rect(f, format, 0, 0, 1920, 1080))
			}
			b.ReportMetric(float64(size), "bytes")
		})
	}
}

// An observer that advertises ZRLE receives encoding-16 rectangles whose
// inflated payload carries exactly the published pixels.
func TestZRLEOnTheWire(t *testing.T) {
	b, updates := startFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, []byte{255, 0, 0, 0, 0, 255, 0, 0})
	awaitVersion(t, b, 1)

	c, _ := observer(t, b)
	// Advertise ZRLE (16) and DesktopSize (-223).
	writeTest(t, c, []byte{2, 0, 0, 2, 0, 0, 0, 16, 255, 255, 255, 33})
	request(t, c, 2, 1, false)

	header := readTest(t, c, 4)
	if header[0] != 0 || binary.BigEndian.Uint16(header[2:]) != 1 {
		t.Fatalf("expected one-rectangle update, got %v", header)
	}
	p := readTest(t, c, 12)
	w, h := int(binary.BigEndian.Uint16(p[4:])), int(binary.BigEndian.Uint16(p[6:]))
	if enc := int32(binary.BigEndian.Uint32(p[8:])); enc != 16 {
		t.Fatalf("a ZRLE-negotiated observer got encoding %d, want 16", enc)
	}
	length := int(binary.BigEndian.Uint32(readTest(t, c, 4)))
	payload := make([]byte, 4+length)
	binary.BigEndian.PutUint32(payload, uint32(length))
	copy(payload[4:], readTest(t, c, length))

	data := inflateRect(t, payload)
	got, _ := decodeTiles(t, data, w, h, 3)
	// The fixture published red, green in canonical RGB32.
	if want := []byte{255, 0, 0, 0, 255, 0}; !bytes.Equal(got, want) {
		t.Fatalf("decoded ZRLE payload = %v, want %v", got, want)
	}
}
