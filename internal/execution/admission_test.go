package execution

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/kube-workspaces/api/internal/execution/storage"
)

func TestConcurrentAdmissionCannotReplaceWinnerRecording(t *testing.T) {
	ctx := context.Background()
	svc := NewService(mustEphemeral(t)).WithReplayAuthorizer(allowAll{})
	winner := make(chan *Session, 32)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := svc.Admit(ctx, validRequest())
			if err == nil {
				winner <- s
			}
		}()
	}
	wg.Wait()
	close(winner)
	if len(winner) != 1 {
		t.Fatalf("got %d process-start permits", len(winner))
	}
	s := <-winner
	if err := s.AppendChunk(ctx, []byte("winner evidence")); err != nil {
		t.Fatal(err)
	}
	if err := s.Abort(ctx, "disconnect"); err != nil {
		t.Fatal(err)
	}
	r, _, err := svc.Replay(ctx, "reader", "exec-1")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := r.ReadChunk(ctx, 0)
	if err != nil || string(b) != "winner evidence" {
		t.Fatalf("evidence lost: %q, %v", b, err)
	}
}

func TestRecordingFailureCannotFinalizeAsSuccess(t *testing.T) {
	ctx := context.Background()
	store := mustEphemeral(t)
	s, err := NewService(store).Admit(ctx, validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AppendChunk(ctx, make([]byte, storage.MaxChunkBytes+1)); !errors.Is(err, storage.ErrChunkTooLarge) {
		t.Fatal(err)
	}
	if err := s.AppendChunk(ctx, []byte("retry")); !errors.Is(err, storage.ErrChunkTooLarge) {
		t.Fatal("recording error did not latch", err)
	}
	if err := s.Finish(ctx, storage.ExecutionOutcome{State: storage.StateSucceeded}); err == nil {
		t.Fatal("lost recording reported success")
	}
	_, outcome, err := store.Metadata().Get(ctx, "exec-1")
	if err != nil || outcome.State != storage.StateRecordingLost || !outcome.RecordingLost {
		t.Fatalf("outcome: %+v, %v", outcome, err)
	}
	reader, err := store.Recording().Open(ctx, "rec-1")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	intent, err := reader.TerminalIntent(ctx)
	if err != nil || intent.Snapshot().Outcome.State != storage.StateRecordingLost || !intent.Snapshot().Outcome.RecordingLost {
		t.Fatalf("recording failure left a successful recovery intent: %+v %v", intent, err)
	}
}

// allowAll is a permissive ReplayAuthorizer used only in tests.
type allowAll struct{}

func (allowAll) AuthorizeReplay(context.Context, string, storage.ExecutionRecord) error { return nil }

// failingStore is a Store whose readiness always fails.
type failingStore struct{ err error }

func (f failingStore) Metadata() storage.MetadataStore   { return nil }
func (f failingStore) Recording() storage.RecordingStore { return nil }
func (f failingStore) Mode() string                      { return "external" }
func (f failingStore) Durability() storage.Durability    { return storage.DurabilityDurable }
func (f failingStore) Ready(context.Context) error       { return f.err }
func (f failingStore) Close() error                      { return nil }

func mustEphemeral(t *testing.T) storage.Store {
	t.Helper()
	store, err := storage.Open(context.Background(), storage.Options{
		Mode:              "ephemeral",
		EphemeralDir:      t.TempDir(),
		EphemeralMaxBytes: 8 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("open ephemeral: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func validRequest() AdmissionRequest {
	return AdmissionRequest{
		ExecutionID:   "exec-1",
		RecordingID:   "rec-1",
		ActorID:       "user-1",
		Operation:     storage.OperationShell,
		Namespace:     "team-a",
		WorkspaceName: "vm-1",
		WorkspaceUID:  "uid-1",
		OSIdentity:    "root",
	}
}

func TestAdmitRecordsAndReplays(t *testing.T) {
	ctx := context.Background()
	svc := NewService(mustEphemeral(t)).WithReplayAuthorizer(allowAll{})
	sess, err := svc.Admit(ctx, validRequest())
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if err := sess.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	for _, chunk := range [][]byte{[]byte("hello "), []byte("world")} {
		if err := sess.AppendChunk(ctx, chunk); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := sess.Finish(ctx, storage.ExecutionOutcome{State: storage.StateSucceeded}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	reader, rec, err := svc.Replay(ctx, "user-1", "exec-1")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	defer reader.Close()
	if rec.ExecutionID != "exec-1" || rec.RecordingID != "rec-1" {
		t.Fatalf("unexpected record: %+v", rec)
	}
	if err := reader.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	want := [][]byte{[]byte("hello "), []byte("world")}
	for i, w := range want {
		got, err := reader.ReadChunk(ctx, uint64(i))
		if err != nil {
			t.Fatalf("read chunk %d: %v", i, err)
		}
		if string(got) != string(w) {
			t.Fatalf("chunk %d = %q, want %q", i, got, w)
		}
	}
}

func TestAdmitDeniedWhenDisabled(t *testing.T) {
	_, err := NewService(nil).Admit(context.Background(), validRequest())
	if !errors.Is(err, ErrAdmissionDenied) || !errors.Is(err, storage.ErrDisabled) {
		t.Fatalf("want denied+disabled, got %v", err)
	}
}

func TestAdmitDeniedWhenStoreNotReady(t *testing.T) {
	svc := NewService(failingStore{err: errors.New("db down")})
	_, err := svc.Admit(context.Background(), validRequest())
	if !errors.Is(err, ErrAdmissionDenied) {
		t.Fatalf("want denied, got %v", err)
	}
}

func TestAdmitValidatesRequest(t *testing.T) {
	svc := NewService(mustEphemeral(t))
	bad := validRequest()
	bad.ExecutionID = ""
	if _, err := svc.Admit(context.Background(), bad); !errors.Is(err, ErrAdmissionDenied) {
		t.Fatalf("want denied, got %v", err)
	}
}

func TestAdmitDuplicateDenied(t *testing.T) {
	ctx := context.Background()
	svc := NewService(mustEphemeral(t))
	if _, err := svc.Admit(ctx, validRequest()); err != nil {
		t.Fatalf("first admit: %v", err)
	}
	if _, err := svc.Admit(ctx, validRequest()); !errors.Is(err, ErrAdmissionDenied) {
		t.Fatalf("want denied duplicate, got %v", err)
	}
}

func TestReplayDeniedByDefault(t *testing.T) {
	ctx := context.Background()
	svc := NewService(mustEphemeral(t))
	sess, err := svc.Admit(ctx, validRequest())
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if err := sess.AppendChunk(ctx, []byte("x")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := sess.Finish(ctx, storage.ExecutionOutcome{State: storage.StateSucceeded}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if _, _, err := svc.Replay(ctx, "user-1", "exec-1"); !errors.Is(err, ErrAdmissionDenied) {
		t.Fatalf("want denied, got %v", err)
	}
}

func TestReplayBeforeFinalize(t *testing.T) {
	ctx := context.Background()
	svc := NewService(mustEphemeral(t)).WithReplayAuthorizer(allowAll{})
	sess, err := svc.Admit(ctx, validRequest())
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if err := sess.AppendChunk(ctx, []byte("x")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, _, err := svc.Replay(ctx, "user-1", "exec-1"); !errors.Is(err, storage.ErrNotFinalized) {
		t.Fatalf("want not finalized, got %v", err)
	}
}

func TestSessionAppendAfterFinishDenied(t *testing.T) {
	ctx := context.Background()
	svc := NewService(mustEphemeral(t))
	sess, err := svc.Admit(ctx, validRequest())
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if err := sess.Finish(ctx, storage.ExecutionOutcome{State: storage.StateSucceeded}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if err := sess.AppendChunk(ctx, []byte("late")); !errors.Is(err, storage.ErrFinalized) {
		t.Fatalf("want finalized, got %v", err)
	}
}

func TestAbortMarksFailed(t *testing.T) {
	ctx := context.Background()
	store := mustEphemeral(t)
	sess, err := NewService(store).Admit(ctx, validRequest())
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if err := sess.Abort(ctx, "transport closed"); err != nil {
		t.Fatalf("abort: %v", err)
	}
	_, outcome, err := store.Metadata().Get(ctx, "exec-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if outcome.State != storage.StateFailed {
		t.Fatalf("want failed, got %s", outcome.State)
	}
}
