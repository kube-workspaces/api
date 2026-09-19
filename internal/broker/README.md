# Read-only display broker feasibility spike (A2)

This package is an internal prototype, not a public route. `New(stream)` owns
one already-connected upstream RFB 3.8 stream; `Run(ctx)` captures it and
`ServeObserver(ctx, stream)` serves independently negotiated observers. Use a
fresh Broker for each upstream generation. Each serving call blocks until its
observer exits. `Close` cancels every connection, including blocked handshakes.

**Authorization is the caller's job.** The only RFB security type is None,
appropriate after platform HTTP authorization. The package does not dial
KubeVirt, acquire a display claim or expose an unauthenticated listener.
`NewWebSocketStream` adapts an already-authenticated binary WebSocket. The
existing `VMVNCHandler` remains the active exclusive bridge.

## Implemented

- Upstream RFB 3.8 handshake, fixed RGB32 capture, Raw and DesktopSize parsing.
- Framebuffer bounds, complete initial pixel coverage before publication, and
  preservation of prior pixels across partial updates. Resizing waits for a
  fully initialized new frame before publishing it.
- Independent downstream handshake, 8/16/32-bit true-colour format conversion,
  region requests, incremental waits, Raw output and DesktopSize notification.
- ZRLE output (`zrle.go`) when a participant's SetEncodings advertises it:
  64x64 tiles coded as solid / packed palette (2–16 colours) / plain RLE / raw,
  smallest per tile, one connection-scoped zlib stream sync-flushed per
  rectangle. Raw remains the mandatory fallback.
- All key/pointer/clipboard/resize/extended-key mutations from observers are
  consumed and discarded. No control-claim placeholder or input forwarding.
- At most eight attached observers including stalled handshakes. An observer
  holds one in-flight immutable framebuffer; intermediate generations coalesce
  rather than accumulating a frame queue. Socket writes expire after five
  seconds. No socket I/O holds the broker lock.
- Context cancellation and upstream failure close all transports. Reader
  workers are joined when their observer returns. A pending incremental request
  does not block processing a later forced refresh or detecting disconnect.

## Resource envelope and limitations

Maximum dimensions are 4096 on either axis and at most 4096×2160 pixels.
Snapshot publication copies the whole framebuffer, irrespective of damage.
Each viewer converts one tile at a time and writes full requested regions.
There is no Tight/JPEG encoding, controller role, audio, cursor extension,
observer clipboard delivery, public membership API, owner routing or fencing.
Unsupported upstream encodings and downstream extensions terminate the stream.
Idle membership expiry is a future membership-layer responsibility.

At 1080p a snapshot is 8,294,400 bytes. Retained pixel storage is bounded by the
capture working buffer, the current snapshot, and up to eight in-flight old
snapshots, plus initial-coverage bytes, per-client bounded RFB messages and row
buffers. Full-frame wire cost per observer is now encoding-dependent: Raw stays
~8.3 MB per 1080p frame; ZRLE measured locally (Linux/amd64, i7-13700K,
2026-09-19) at ~24 B for a solid frame, ~111 KB for desktop-like content
(~75× smaller than Raw) and ~6.2 MB for pure noise, at ~5/16/71 ms encode
time respectively — enough for typical desktops, with noisy video content the
expensive remainder. Live-VM throughput is still unmeasured; see the encoding
decision note in the tracking plan.

Local Linux/amd64 publication microbenchmark (2026-09-18, i7-13700K): about
0.84 ms and 8.30 MB allocated per 1080p publication (3 allocations). This is
copy/publication cost, not live VM capture throughput or end-to-end latency.

## Verification

From the API root:

```sh
go test -race ./internal/broker ./internal/rfb
go test ./internal/broker -run '^$' -bench BenchmarkPublish1080p -benchmem
```

Fixtures exercise independent 32-bit/RGB565 observers, late join, partial
updates, resize, coverage, malformed/truncated data, mutation suppression,
slow-reader timeout, capacity/release, static-display disconnect and shutdown.

The optional external-client test uses the real sibling desktop-client decoder
and noVNC 1.7.0 in Chromium. It checks pixel colours for initial and partial
updates and a 2×1 → 1×2 resize. It is a loopback synthetic-upstream check, not a
live KubeVirt or physical-display test. The nested native module's relative
replace expects `api` and `desktop-client` to be sibling checkouts.

```sh
go -C internal/broker/testdata/interop/native build -o /tmp/kw-broker-native-client .
npm ci --prefix internal/broker/testdata/interop
internal/broker/testdata/interop/node_modules/.bin/playwright install chromium
KW_BROKER_NATIVE_CLIENT=/tmp/kw-broker-native-client \
KW_BROKER_BROWSER_CLIENT="$PWD/internal/broker/testdata/interop/browser.mjs" \
go test -race ./internal/broker -run '^TestExternalClients$' -v
```

Both clients passed locally against the same capture connection, with the
browser joining after the native client. Dependency downloads are test-only;
they are not included in the API image or its root Go module.

## Next gate

Before enabling routes: define the public membership/control contract in Goa,
implement authorization and capture/control lease separation, resolve
multi-replica broker routing, and measure the pilot on a real VM with realistic
resolutions/observer counts. Production encoding selection remains gated on
those performance measurements.
