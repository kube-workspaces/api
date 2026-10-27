package execution

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/execution/storage"
)

type recoveryTestStore struct {
	storage.Store
	meta *completionFault
}

func (s recoveryTestStore) Metadata() storage.MetadataStore { return s.meta }
func (s recoveryTestStore) Mode() string                    { return "external" }
func (s recoveryTestStore) Durability() storage.Durability  { return storage.DurabilityDurable }

type completionFault struct {
	storage.MetadataStore
	recovered chan struct{}
}

func (m *completionFault) Complete(context.Context, string, storage.ExecutionOutcome) error {
	return storage.ErrNotReady
}
func (m *completionFault) RecoverTerminal(ctx context.Context, proof *storage.VerifiedTerminalIntent) (bool, error) {
	changed, err := m.MetadataStore.RecoverTerminal(ctx, proof)
	if changed && m.recovered != nil {
		select {
		case m.recovered <- struct{}{}:
		default:
		}
	}
	return changed, err
}

func newRecoveryTestService(t *testing.T) (*Service, storage.Store, string, *completionFault) {
	t.Helper()
	dir := t.TempDir()
	base, err := storage.Open(context.Background(), storage.Options{Mode: "ephemeral", EphemeralDir: dir, EphemeralMaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = base.Close() })
	meta := &completionFault{MetadataStore: base.Metadata(), recovered: make(chan struct{}, 16)}
	store := recoveryTestStore{Store: base, meta: meta}
	return NewService(store), store, dir, meta
}

func pendingTerminal(t *testing.T, svc *Service, id string, state storage.State) *Session {
	t.Helper()
	req := validRequest()
	req.ExecutionID, req.RecordingID, req.Operation = id, "rec-"+id, storage.OperationCommand
	sess, err := svc.Admit(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sess.AppendChunk(context.Background(), []byte("recorded input/output")); err != nil {
		t.Fatal(err)
	}
	if err := sess.Finish(context.Background(), storage.ExecutionOutcome{State: state}); !errors.Is(err, storage.ErrNotReady) {
		t.Fatalf("completion fault did not leave pending metadata: %v", err)
	}
	return sess
}

func TestTerminalRecoveryCoordinatorAndWorker(t *testing.T) {
	ctx := context.Background()
	svc, store, _, meta := newRecoveryTestService(t)
	pendingTerminal(t, svc, "recover", storage.StateUnknown)
	_, old, _ := store.Metadata().Get(ctx, "recover")
	if old.State != storage.StateRunning {
		t.Fatal("test did not strand a running row")
	}
	// Persistent-mode worker's immediate pass uses the same coordinator tested
	// against real PostgreSQL/S3. Stop joins it before storage teardown.
	stop := svc.StartTerminalRecovery(ctx)
	defer stop()
	select {
	case <-meta.recovered:
	case <-time.After(5 * time.Second):
		t.Fatal("persistent recovery worker did not reconcile")
	}
	_, got, err := store.Metadata().Get(ctx, "recover")
	if err != nil || got.State != storage.StateUnknown {
		t.Fatalf("unknown outcome was upgraded: %+v %v", got, err)
	}
	if changed, err := svc.ReconcileTerminal(ctx, "recover"); err != nil || changed {
		t.Fatalf("terminal recovery duplicated completion: %v %v", changed, err)
	}
}

func TestTerminalRecoveryBatchSkipsIncompleteCorruptAndLegacy(t *testing.T) {
	ctx := context.Background()
	svc, store, dir, _ := newRecoveryTestService(t)
	pendingTerminal(t, svc, "a-corrupt", storage.StateSucceeded)
	if err := os.Remove(filepath.Join(dir, "recordings", "rec-a-corrupt", "chunk-0000000000000000.bin")); err != nil {
		t.Fatal(err)
	}
	req := validRequest()
	req.ExecutionID, req.RecordingID, req.Operation = "b-live", "rec-b-live", storage.OperationCommand
	live, err := svc.Admit(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := live.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// No finalized manifest: an active owner must not be reaped or interrupted.
	if changed, err := svc.ReconcileTerminal(ctx, "b-live"); err != nil || changed {
		t.Fatalf("active owner was recovered: %v %v", changed, err)
	}
	req.ExecutionID, req.RecordingID = "c-legacy", "rec-c-legacy"
	legacy, err := svc.Admit(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := legacy.writer.Finalize(ctx, storage.FinalizeMeta{}); err != nil {
		t.Fatal(err)
	}
	pendingTerminal(t, svc, "d-recover", storage.StateFailed)
	cursor, first, err := svc.ReconcileTerminalBatch(ctx, "", 2)
	if err != nil || cursor != "b-live" || first.Checked != 2 || first.Failed != 1 || first.Recovered != 0 {
		t.Fatalf("first bounded batch: %s %+v %v", cursor, first, err)
	}
	cursor, next, err := svc.ReconcileTerminalBatch(ctx, cursor, 2)
	if err != nil || cursor != "d-recover" || next.Checked != 2 || next.Failed != 0 || next.Recovered != 1 {
		t.Fatalf("later candidate starved: %s %+v %v", cursor, next, err)
	}
	for _, id := range []string{"a-corrupt", "b-live", "c-legacy"} {
		_, outcome, err := store.Metadata().Get(ctx, id)
		if err != nil || outcome.State != storage.StateRunning {
			t.Fatalf("incomplete evidence was guessed: %s %+v %v", id, outcome, err)
		}
	}
	if cursor, _, err := svc.ReconcileTerminalBatch(ctx, cursor, 2); err != nil || cursor != "" {
		t.Fatalf("cursor did not wrap after final page: %s %v", cursor, err)
	}
	// Stop cancels/joins even when there is nothing eligible; ephemeral stores
	// intentionally do not start a history-recovery worker.
	base := mustEphemeral(t)
	NewService(base).StartTerminalRecovery(ctx)()
}
