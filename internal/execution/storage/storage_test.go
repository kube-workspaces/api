package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testKey() []byte { return bytes.Repeat([]byte{0x42}, keySize) }

// ---------------------------------------------------------------------------
// cipher + chain
// ---------------------------------------------------------------------------

func TestChunkRoundTripAndPositionBinding(t *testing.T) {
	gcm, err := newGCM(testKey())
	if err != nil {
		t.Fatalf("newGCM: %v", err)
	}
	plaintext := []byte("echo-disabled secret input")
	payload := sealChunk(gcm, "rec-1", "kid-1", 0, plaintext)

	got, err := openChunk(gcm, "rec-1", "kid-1", 0, payload)
	if err != nil {
		t.Fatalf("openChunk: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: %q", got)
	}

	for _, tc := range []struct {
		name      string
		recording string
		keyID     string
		index     uint64
		mutate    func([]byte) []byte
	}{
		{"other recording", "rec-2", "kid-1", 0, nil},
		{"other key", "rec-1", "kid-2", 0, nil},
		{"other index", "rec-1", "kid-1", 1, nil},
		{"flipped ciphertext", "rec-1", "kid-1", 0, func(p []byte) []byte {
			clone := append([]byte(nil), p...)
			clone[len(clone)-1] ^= 0x01
			return clone
		}},
		{"flipped nonce", "rec-1", "kid-1", 0, func(p []byte) []byte {
			clone := append([]byte(nil), p...)
			clone[0] ^= 0x01
			return clone
		}},
	} {
		mutated := payload
		if tc.mutate != nil {
			mutated = tc.mutate(payload)
		}
		if _, err := openChunk(gcm, tc.recording, tc.keyID, tc.index, mutated); !errors.Is(err, ErrTampered) {
			t.Fatalf("%s: want ErrTampered, got %v", tc.name, err)
		}
	}
}

func TestHashChainDetectsReordering(t *testing.T) {
	gcm, _ := newGCM(testKey())
	a := sealChunk(gcm, "rec", "kid", 0, []byte("a"))
	b := sealChunk(gcm, "rec", "kid", 1, []byte("b"))

	chain := chainStart("kid", "rec")
	chain = chainNext(chain, 0, a)
	chain = chainNext(chain, 1, b)
	inOrder := chainHex(chain)

	reordered := chainStart("kid", "rec")
	reordered = chainNext(reordered, 0, b)
	reordered = chainNext(reordered, 1, a)

	if inOrder == chainHex(reordered) {
		t.Fatal("hash chain did not detect reordering")
	}
}

// ---------------------------------------------------------------------------
// ephemeral metadata
// ---------------------------------------------------------------------------

func sampleRecord(id string) ExecutionRecord {
	return ExecutionRecord{
		ExecutionID:   id,
		ActorID:       "user-1",
		Operation:     OperationCommand,
		Namespace:     "team",
		WorkspaceName: "vm-a",
		WorkspaceUID:  "uid-1",
		RecordingID:   "rec-" + id,
		Mode:          "ephemeral",
		Durability:    DurabilityNone,
		AdmissionTime: time.Now(),
		Admitted:      true,
	}
}

func TestEphemeralMetadataCreateIsIdempotentAndConflicting(t *testing.T) {
	m := NewEphemeralMetadata()
	ctx := context.Background()
	rec := sampleRecord("exec-1")
	if err := m.Create(ctx, rec); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if err := m.Create(ctx, rec); err != nil {
		t.Fatalf("identical retry should be idempotent: %v", err)
	}
	conflict := rec
	conflict.ActorID = "someone-else"
	if err := m.Create(ctx, conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
}

func TestEphemeralMetadataTransitionIsMonotonic(t *testing.T) {
	m := NewEphemeralMetadata()
	ctx := context.Background()
	rec := sampleRecord("exec-2")
	if err := m.Create(ctx, rec); err != nil {
		t.Fatalf("create: %v", err)
	}
	code := 0
	if err := m.Transition(ctx, "exec-2", ExecutionOutcome{State: StateSucceeded, ExitCode: &code}); err != nil {
		t.Fatalf("transition: %v", err)
	}
	if err := m.Transition(ctx, "exec-2", ExecutionOutcome{State: StateFailed}); !errors.Is(err, ErrConflict) {
		t.Fatalf("terminal transition should conflict, got %v", err)
	}
	if err := m.Transition(ctx, "missing", ExecutionOutcome{State: StateRunning}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing transition should be ErrNotFound, got %v", err)
	}
	_, outcome, err := m.Get(ctx, "exec-2")
	if err != nil || outcome.State != StateSucceeded || outcome.ExitCode == nil || *outcome.ExitCode != 0 {
		t.Fatalf("unexpected outcome: %+v err=%v", outcome, err)
	}
}

func TestEphemeralMetadataListFilters(t *testing.T) {
	m := NewEphemeralMetadata()
	ctx := context.Background()
	a := sampleRecord("exec-a")
	b := sampleRecord("exec-b")
	b.Namespace = "other"
	b.AdmissionTime = time.Now().Add(time.Second)
	_ = m.Create(ctx, a)
	_ = m.Create(ctx, b)

	got, err := m.List(ctx, Filter{Namespace: "team"})
	if err != nil || len(got) != 1 || got[0].ExecutionID != "exec-a" {
		t.Fatalf("namespace filter: got %+v err=%v", got, err)
	}
	all, _ := m.List(ctx, Filter{})
	if len(all) != 2 || all[0].ExecutionID != "exec-b" {
		t.Fatalf("expected newest first, got %+v", all)
	}
}

// ---------------------------------------------------------------------------
// ephemeral recording
// ---------------------------------------------------------------------------

func newTestRecording(t *testing.T, maxBytes int64) (RecordingStore, string) {
	t.Helper()
	dir := t.TempDir()
	rec, err := NewEphemeralRecording(dir, testKey(), DeriveKeyID(testKey()), maxBytes)
	if err != nil {
		t.Fatalf("NewEphemeralRecording: %v", err)
	}
	return rec, dir
}

func TestEphemeralRecordingRoundTripAndVerify(t *testing.T) {
	rec, _ := newTestRecording(t, 1<<20)
	ctx := context.Background()
	r, err := rec.Begin(ctx, "rec-1")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	chunks := [][]byte{[]byte("line one\n"), []byte("password: \n"), []byte("line three\n")}
	for i, c := range chunks {
		if err := r.PutChunk(ctx, uint64(i), c); err != nil {
			t.Fatalf("PutChunk %d: %v", i, err)
		}
	}
	if err := r.Finalize(ctx, FinalizeMeta{}); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	reader, err := rec.Open(ctx, "rec-1")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if reader.Manifest().Chunks != uint64(len(chunks)) {
		t.Fatalf("manifest chunks = %d", reader.Manifest().Chunks)
	}
	if err := reader.Verify(ctx); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for i, want := range chunks {
		got, err := reader.ReadChunk(ctx, uint64(i))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("ReadChunk %d: got %q err=%v", i, got, err)
		}
	}
}

func TestEphemeralRecordingSequenceGap(t *testing.T) {
	rec, _ := newTestRecording(t, 1<<20)
	r, _ := rec.Begin(context.Background(), "rec-gap")
	if err := r.PutChunk(context.Background(), 1, []byte("x")); !errors.Is(err, ErrSeqGap) {
		t.Fatalf("want ErrSeqGap, got %v", err)
	}
}

func TestEphemeralRecordingCapacity(t *testing.T) {
	rec, _ := newTestRecording(t, 64)
	r, _ := rec.Begin(context.Background(), "rec-cap")
	big := bytes.Repeat([]byte("x"), 256)
	if err := r.PutChunk(context.Background(), 0, big); !errors.Is(err, ErrOverCapacity) {
		t.Fatalf("want ErrOverCapacity, got %v", err)
	}
}

func TestEphemeralRecordingDetectsTruncationAndTamper(t *testing.T) {
	rec, dir := newTestRecording(t, 1<<20)
	ctx := context.Background()
	r, _ := rec.Begin(ctx, "rec-t")
	_ = r.PutChunk(ctx, 0, []byte("one"))
	_ = r.PutChunk(ctx, 1, []byte("two"))
	_ = r.Finalize(ctx, FinalizeMeta{})

	// Tamper: flip a byte of chunk 0.
	chunk0 := filepath.Join(dir, "recordings", "rec-t", "chunk-0000000000000000.bin")
	raw, _ := os.ReadFile(chunk0)
	raw[len(raw)-1] ^= 0x01
	_ = os.WriteFile(chunk0, raw, 0o600)
	reader, _ := rec.Open(ctx, "rec-t")
	if err := reader.Verify(ctx); !errors.Is(err, ErrTampered) {
		t.Fatalf("tampered verify: want ErrTampered, got %v", err)
	}

	// Restore, then truncate chunk 1.
	raw[len(raw)-1] ^= 0x01
	_ = os.WriteFile(chunk0, raw, 0o600)
	chunk1 := filepath.Join(dir, "recordings", "rec-t", "chunk-0000000000000001.bin")
	_ = os.Remove(chunk1)
	reader, _ = rec.Open(ctx, "rec-t")
	if err := reader.Verify(ctx); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated verify: want ErrTruncated, got %v", err)
	}
	if _, err := reader.ReadChunk(ctx, 1); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated read: want ErrTruncated, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// factory + fail-closed readiness
// ---------------------------------------------------------------------------

func TestOpenDisabledAndUnknownModes(t *testing.T) {
	ctx := context.Background()
	if _, err := Open(ctx, Options{Mode: "disabled"}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled: want ErrDisabled, got %v", err)
	}
	if _, err := Open(ctx, Options{Mode: ""}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("empty: want ErrDisabled, got %v", err)
	}
	if _, err := Open(ctx, Options{Mode: "nonsense"}); err == nil {
		t.Fatal("unknown mode should error")
	}
	if _, err := Open(ctx, Options{Mode: "external", DatabaseURL: "postgres://x"}); err == nil {
		t.Fatal("persistent mode without key should error")
	}
}

func TestOpenEphemeralIsReady(t *testing.T) {
	rec, _ := newTestRecording(t, 1<<20)
	_ = rec
	st, err := Open(context.Background(), Options{Mode: "ephemeral", EphemeralDir: t.TempDir(), EphemeralMaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Open ephemeral: %v", err)
	}
	defer st.Close()
	if st.Durability() != DurabilityNone {
		t.Fatalf("ephemeral durability = %s", st.Durability())
	}
	if err := st.Ready(context.Background()); err != nil {
		t.Fatalf("ephemeral Ready: %v", err)
	}
}

type stubMeta struct {
	MetadataStore
	readyErr error
}

func (s stubMeta) Ready(context.Context) error { return s.readyErr }

type stubRec struct {
	RecordingStore
	readyErr error
}

func (s stubRec) Ready(context.Context) error { return s.readyErr }

func TestStoreReadinessIsFailClosed(t *testing.T) {
	ctx := context.Background()
	st := &store{mode: "external", meta: stubMeta{readyErr: ErrNotReady}, rec: stubRec{}}
	if err := st.Ready(ctx); !errors.Is(err, ErrNotReady) {
		t.Fatalf("meta not ready: want ErrNotReady, got %v", err)
	}
	st = &store{mode: "external", meta: stubMeta{}, rec: stubRec{readyErr: ErrNotReady}}
	if err := st.Ready(ctx); !errors.Is(err, ErrNotReady) {
		t.Fatalf("recording not ready: want ErrNotReady, got %v", err)
	}
	st = &store{mode: "external", meta: stubMeta{}, rec: stubRec{}}
	if err := st.Ready(ctx); err != nil {
		t.Fatalf("both ready: %v", err)
	}
}

func TestDeriveKeyIDIsStable(t *testing.T) {
	if DeriveKeyID(testKey()) != DeriveKeyID(testKey()) {
		t.Fatal("key id not stable")
	}
	if DeriveKeyID(testKey()) == DeriveKeyID(bytes.Repeat([]byte{0x43}, keySize)) {
		t.Fatal("different keys share a key id")
	}
}
