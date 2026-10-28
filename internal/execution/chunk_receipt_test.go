package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/kube-workspaces/api/internal/execution/storage"
)

func TestConcurrentChunkReceiptsBindActualProtectedBytes(t *testing.T) {
	ctx := context.Background()
	store := mustEphemeral(t)
	session, err := NewService(store).Admit(ctx, validRequest())
	if err != nil {
		t.Fatal(err)
	}
	type appended struct {
		receipt storage.ChunkReceipt
		raw     []byte
		err     error
	}
	results := make(chan appended, 32)
	var wg sync.WaitGroup
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			raw := []byte(fmt.Sprintf("private-evidence-%d", n))
			receipt, err := session.AppendChunkReceipt(ctx, raw)
			results <- appended{receipt, raw, err}
		}(n)
	}
	wg.Wait()
	close(results)
	if err := session.Finish(ctx, storage.ExecutionOutcome{State: storage.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	reader, err := store.Recording().Open(ctx, session.Record().RecordingID)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := reader.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	seen := map[uint64]bool{}
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		r := result.receipt
		sum := sha256.Sum256(result.raw)
		if seen[r.ChunkIndex] || r.ChunkIndex >= 32 || r.RecordingID != session.Record().RecordingID || r.ChunkSHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("incorrect/duplicate receipt: %+v", r)
		}
		seen[r.ChunkIndex] = true
		raw, err := reader.ReadChunk(ctx, r.ChunkIndex)
		if err != nil || string(raw) != string(result.raw) {
			t.Fatalf("receipt not bound to recorded bytes: %q %v", raw, err)
		}
	}
	if r, err := session.AppendChunkReceipt(ctx, []byte("after finalization")); !errors.Is(err, storage.ErrFinalized) || r != (storage.ChunkReceipt{}) {
		t.Fatalf("finalized session returned receipt: %+v %v", r, err)
	}
	if !errors.Is(session.CheckRecording(), storage.ErrFinalized) {
		t.Fatal("finalized writer reported healthy")
	}
}

type uncertainChunkWriter struct {
	storage.Recorder
	calls int
}

func (w *uncertainChunkWriter) PutChunk(context.Context, uint64, []byte) error {
	w.calls++
	return errors.New("synthetic uncertain chunk ACK")
}

func TestChunkReceiptNeverEscapesOnUncertainWrite(t *testing.T) {
	writer := &uncertainChunkWriter{}
	session := &Session{record: storage.ExecutionRecord{RecordingID: "rec-test"}, writer: writer}
	for n := 0; n < 2; n++ {
		if r, err := session.AppendChunkReceipt(context.Background(), []byte("intent")); err == nil || r != (storage.ChunkReceipt{}) {
			t.Fatalf("uncertain recording returned receipt: %+v %v", r, err)
		}
	}
	if writer.calls != 1 || session.next != 0 {
		t.Fatal("uncertain write retried or advanced the recording index")
	}
	if session.CheckRecording() == nil {
		t.Fatal("uncertain writer reported healthy")
	}
}
