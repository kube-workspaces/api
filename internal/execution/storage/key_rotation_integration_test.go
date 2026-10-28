package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Called from TestS3Integration so the existing opt-in real-S3 CI gate exercises
// rotation without changing the default no-external-services test behavior.
func testS3KeyRotation(t *testing.T, cfg S3Options) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a, b := bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x42}, 32)
	aID, bID := DeriveKeyID(a), DeriveKeyID(b)
	open := func(active []byte, previous ...[]byte) RecordingStore {
		t.Helper()
		s, err := NewS3Recording(cfg, active, DeriveKeyID(active), previous...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	original := open(a)
	staged := open(a, b)
	rotated := open(b, a)
	prefix := fmt.Sprintf("rotation-%d-", time.Now().UnixNano())
	write := func(s RecordingStore, id string, terminal bool) {
		t.Helper()
		w, err := s.Begin(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.PutChunk(ctx, 0, []byte("protected rotation input")); err != nil {
			t.Fatal(err)
		}
		meta := FinalizeMeta{}
		if terminal {
			intent := sampleTerminalIntent(id)
			meta.Terminal = &intent
			meta.ActorID, meta.EndTime = intent.Admission.ActorID, intent.Outcome.EndTime
		}
		if err := w.Finalize(ctx, meta); err != nil {
			t.Fatal(err)
		}
	}
	legacy, sealed, newest := prefix+"legacy", prefix+"sealed", prefix+"new"
	write(original, legacy, false)
	write(original, sealed, true)
	// An old replica's already-open writer retains A through rotation. The
	// rotated replica must read it after that writer finalizes, not rewrite it.
	inflight := prefix + "inflight"
	w, err := staged.Begin(ctx, inflight)
	if err != nil {
		t.Fatal(err)
	}
	write(rotated, newest, true)
	if err := w.PutChunk(ctx, 0, []byte("protected rotation input")); err != nil {
		t.Fatal(err)
	}
	if err := w.Finalize(ctx, FinalizeMeta{}); err != nil {
		t.Fatal(err)
	}
	backing := original.(*s3Recording)
	snapshot := map[string][]byte{}
	for _, id := range []string{legacy, sealed, newest, inflight} {
		for _, object := range []string{backing.manifestObject(id), backing.chunkObject(id, 0)} {
			raw, err := backing.getContext(ctx, object)
			if err != nil {
				t.Fatal(err)
			}
			snapshot[object] = raw
		}
	}
	for _, s := range []RecordingStore{staged, rotated} {
		for _, id := range []string{legacy, sealed, newest, inflight} {
			r, err := s.Open(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			data, err := r.ReadChunk(ctx, 0)
			if err != nil || !bytes.Equal(data, []byte("protected rotation input")) || r.Verify(ctx) != nil {
				t.Fatalf("rotated read failed: %v", err)
			}
			wantKey := aID
			if id == newest {
				wantKey = bID
			}
			if r.Manifest().KeyID != wantKey {
				t.Fatal("new writer did not use its configured active key")
			}
			proof, err := r.TerminalIntent(ctx)
			if id == sealed || id == newest {
				if err != nil || proof == nil {
					t.Fatalf("key rotation lost terminal recovery evidence: %v", err)
				}
			} else if !errors.Is(err, ErrNoTerminalIntent) {
				t.Fatal("legacy recording gained fabricated recovery evidence")
			}
		}
	}
	for object, before := range snapshot {
		after, err := backing.getContext(ctx, object)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("rotated replay rewrote immutable recording evidence")
		}
	}
	// Removing a still-needed key fails closed; the remaining active-key
	// recording remains readable. No trial-decrypt or downgrade fallback exists.
	retired := open(b)
	if _, err := retired.Open(ctx, sealed); !errors.Is(err, ErrTampered) {
		t.Fatalf("retired key unexpectedly remained readable: %v", err)
	}
	if _, err := original.Open(ctx, newest); !errors.Is(err, ErrTampered) {
		t.Fatalf("unstaged replica accepted a new key: %v", err)
	}
	if r, err := retired.Open(ctx, newest); err != nil {
		t.Fatal(err)
	} else {
		defer r.Close()
		if err := r.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// A manifest key ID is only an untrusted selector. Substituting either an
	// unknown ID or another configured key must fail authentication.
	object := backing.manifestObject(sealed)
	raw, err := backing.getContext(ctx, object)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, substitute := range []string{"unknown-key", bID} {
		manifest.KeyID = substitute
		altered, _ := json.Marshal(manifest)
		if err := backing.putContext(ctx, object, altered); err != nil {
			t.Fatal(err)
		}
		if _, err := rotated.Open(ctx, sealed); !errors.Is(err, ErrTampered) {
			t.Fatalf("substituted manifest key ID accepted: %v", err)
		}
	}
	if err := backing.putContext(ctx, object, raw); err != nil {
		t.Fatal(err)
	}
	if r, err := rotated.Open(ctx, sealed); err != nil {
		t.Fatal(err)
	} else {
		defer r.Close()
		if _, err := r.TerminalIntent(ctx); err != nil {
			t.Fatal(err)
		}
		// Retained-key readers must still reject cross-recording/new-key
		// ciphertext. Possessing both configured keys is not a fallback path.
		chunk := backing.chunkObject(sealed, 0)
		if err := backing.putContext(ctx, chunk, snapshot[backing.chunkObject(newest, 0)]); err != nil {
			t.Fatal(err)
		}
		if _, err := r.ReadChunk(ctx, 0); err == nil {
			t.Fatal("retained-key reader accepted substituted ciphertext")
		}
		if err := r.Verify(ctx); err == nil {
			t.Fatal("retained-key verification accepted substituted ciphertext")
		}
		if _, err := r.TerminalIntent(ctx); err == nil {
			t.Fatal("retained-key recovery accepted corrupt recording")
		}
		if err := backing.putContext(ctx, chunk, snapshot[chunk]); err != nil {
			t.Fatal(err)
		}
	}
}
