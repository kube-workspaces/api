package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/golang-migrate/migrate/v4/source/iofs"
)

func TestEmbeddedMigrationsAreDiscoverable(t *testing.T) {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	v, err := src.First()
	if err != nil || v != 1 {
		t.Fatalf("first migration = %d, %v", v, err)
	}
	next, err := src.Next(v)
	if err != nil || next != 2 {
		t.Fatalf("second migration = %d, %v", next, err)
	}
	r, _, err := src.ReadUp(v)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
}

func TestReservationHasOneWinner(t *testing.T) {
	m := NewEphemeralMetadata()
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := m.Reserve(context.Background(), sampleRecord("exclusive"))
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("got %d reservation winners", winners.Load())
	}
	other := sampleRecord("other")
	other.RecordingID = sampleRecord("exclusive").RecordingID
	if err := m.Reserve(context.Background(), other); !errors.Is(err, ErrConflict) {
		t.Fatalf("shared recording identity: %v", err)
	}
}

func TestManifestCannotHideTruncation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := NewEphemeralRecording(dir, make([]byte, 32), "key", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	w, err := s.Begin(ctx, "recording")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PutChunk(ctx, 0, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := w.PutChunk(ctx, 1, []byte("last")); err != nil {
		t.Fatal(err)
	}
	if err := w.Finalize(ctx, FinalizeMeta{}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "recordings", "recording", "manifest.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(filepath.Join(dir, "recordings", "recording", "chunk-0000000000000000.bin"))
	if err != nil {
		t.Fatal(err)
	}
	// A storage attacker can recompute every public hash after removing a tail.
	m.Chunks = 1
	m.PlaintextBytes = 5
	m.Chain = chainHex(chainNext(chainStart(m.KeyID, m.RecordingID), 0, payload))
	forged, _ := json.Marshal(m)
	if err := os.WriteFile(path, forged, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(ctx, "recording"); !errors.Is(err, ErrTampered) {
		t.Fatalf("rewritten manifest accepted: %v", err)
	}
}
