package upgrades

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/execution/storage"
)

func newUpgradeTestService(t *testing.T) (*Service, storage.Store, storage.AgentUpgradeStore) {
	t.Helper()
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Mode: "ephemeral", EphemeralDir: t.TempDir(), EphemeralMaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	attempts, err := storage.NewMemoryAgentUpgrades(100)
	if err != nil {
		t.Fatal(err)
	}
	return NewService(store, attempts), store, attempts
}

func admitRequest(key string) AdmitRequest {
	return AdmitRequest{
		Namespace:                        "team",
		WorkspaceName:                    "vm",
		WorkspaceUID:                     "ws-uid",
		VMUID:                            "vm-uid",
		ActorUID:                         "actor-uid",
		TargetID:                         "windows11-amd64-v2",
		TargetManifestSHA256:             strings.Repeat("a", 64),
		ExpectedInstalledInventorySHA256: strings.Repeat("b", 64),
		ExpectedRevocationEpoch:          4,
		IdempotencyKey:                   key,
	}
}

func TestAdmitRecordsDurableAdmission(t *testing.T) {
	ctx := context.Background()
	svc, store, _ := newUpgradeTestService(t)
	attempt, replayed, err := svc.Admit(ctx, admitRequest("run-1"))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if replayed {
		t.Fatal("first admission must not be a replay")
	}
	if !strings.HasPrefix(attempt.AttemptID, "upg_") || attempt.State != storage.AttemptAdmitted {
		t.Fatalf("unexpected attempt: %+v", attempt)
	}
	if !strings.HasPrefix(attempt.ExecutionID, "exec_") || !strings.HasPrefix(attempt.RecordingID, "rec_") {
		t.Fatalf("unexpected linked identities: %+v", attempt)
	}
	rec, outcome, err := store.Metadata().Get(ctx, attempt.ExecutionID)
	if err != nil {
		t.Fatalf("execution record: %v", err)
	}
	if rec.Operation != storage.OperationUpgrade || !rec.Elevated || rec.OSIdentity != "SYSTEM" || rec.WorkspaceUID != "ws-uid" {
		t.Fatalf("unexpected execution record: %+v", rec)
	}
	if outcome.State == storage.StateSucceeded {
		t.Fatal("an open recording must not be finished")
	}
	// The reservation is exclusive per VM.
	if _, _, err := svc.Admit(ctx, admitRequest("run-2")); !errors.Is(err, ErrConflict) {
		t.Fatalf("second attempt must conflict: %v", err)
	}
	// Cancelling finalizes the recording; its single admission-start chunk is
	// durable and verifiable evidence of exactly what was admitted.
	if _, err := svc.Cancel(ctx, attempt.AttemptID); err != nil {
		t.Fatal(err)
	}
	reader, err := store.Recording().Open(ctx, attempt.RecordingID)
	if err != nil {
		t.Fatalf("recording: %v", err)
	}
	defer reader.Close()
	if err := reader.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if reader.Manifest().Chunks != 1 {
		t.Fatalf("expected the admission-start chunk, got %d", reader.Manifest().Chunks)
	}
	chunk, err := reader.ReadChunk(ctx, 0)
	if err != nil || !strings.Contains(string(chunk), `"type":"agent-upgrade-admission"`) || !strings.Contains(string(chunk), `"target_id":"windows11-amd64-v2"`) {
		t.Fatalf("unexpected admission chunk: %q (%v)", chunk, err)
	}
}

func TestAdmitIdempotentReplay(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newUpgradeTestService(t)
	first, _, err := svc.Admit(ctx, admitRequest("run-1"))
	if err != nil {
		t.Fatal(err)
	}
	second, replayed, err := svc.Admit(ctx, admitRequest("run-1"))
	if err != nil || !replayed {
		t.Fatalf("identical replay: %+v %v", second, err)
	}
	if second.AttemptID != first.AttemptID {
		t.Fatalf("replay minted a new attempt: %s", second.AttemptID)
	}
	// A different request under the same key is a conflict, never a replay.
	conflict := admitRequest("run-1")
	conflict.TargetID = "windows11-amd64-v3"
	if _, _, err := svc.Admit(ctx, conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("idempotency conflict: %v", err)
	}
}

func TestAdmitRejectsInvalidRequests(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newUpgradeTestService(t)
	for name, mutate := range map[string]func(*AdmitRequest){
		"missing-identity":     func(r *AdmitRequest) { r.VMUID = "" },
		"bad-target":           func(r *AdmitRequest) { r.TargetID = "Bad Target" },
		"bad-manifest-digest":  func(r *AdmitRequest) { r.TargetManifestSHA256 = "abc" },
		"bad-inventory-digest": func(r *AdmitRequest) { r.ExpectedInstalledInventorySHA256 = "ABC" },
		"bad-idempotency-key":  func(r *AdmitRequest) { r.IdempotencyKey = " bad key " },
	} {
		t.Run(name, func(t *testing.T) {
			req := admitRequest("run-1")
			mutate(&req)
			if _, _, err := svc.Admit(ctx, req); !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected invalid, got %v", err)
			}
		})
	}
}

func TestCancelBeforeInstallClosesAttempt(t *testing.T) {
	ctx := context.Background()
	svc, store, _ := newUpgradeTestService(t)
	attempt, _, err := svc.Admit(ctx, admitRequest("run-1"))
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := svc.Cancel(ctx, attempt.AttemptID)
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if cancelled.State != storage.AttemptCancelled {
		t.Fatalf("state = %s", cancelled.State)
	}
	// The recording is finalized with the terminal outcome.
	_, outcome, err := store.Metadata().Get(ctx, attempt.ExecutionID)
	if err != nil || outcome.State != storage.StateCancelled {
		t.Fatalf("recording outcome: %+v %v", outcome, err)
	}
	// Cancelling a finished attempt is a conflict.
	if _, err := svc.Cancel(ctx, attempt.AttemptID); !errors.Is(err, ErrConflict) {
		t.Fatalf("double cancel: %v", err)
	}
}

func TestCancelDuringInstallRequestsSafeStop(t *testing.T) {
	ctx := context.Background()
	svc, _, attempts := newUpgradeTestService(t)
	attempt, _, err := svc.Admit(ctx, admitRequest("run-1"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, step := range []struct{ from, to storage.AttemptState }{
		{storage.AttemptAdmitted, storage.AttemptStaging},
		{storage.AttemptStaging, storage.AttemptPrepared},
		{storage.AttemptPrepared, storage.AttemptInstalling},
	} {
		if err := attempts.Transition(ctx, attempt.AttemptID, step.from, storage.AttemptTransition{To: step.to, Now: now}); err != nil {
			t.Fatalf("advance to %s: %v", step.to, err)
		}
	}
	cancelled, err := svc.Cancel(ctx, attempt.AttemptID)
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if cancelled.State != storage.AttemptInstalling || !cancelled.CancelRequested {
		t.Fatalf("mid-mutation cancel must only record the request: %+v", cancelled)
	}
	// Idempotent re-request.
	if _, err := svc.Cancel(ctx, attempt.AttemptID); err != nil {
		t.Fatalf("idempotent cancel: %v", err)
	}
}

func TestCancelClearsStuckUncertainStates(t *testing.T) {
	ctx := context.Background()
	svc, store, attempts := newUpgradeTestService(t)
	attempt, _, err := svc.Admit(ctx, admitRequest("run-1"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, step := range []struct{ from, to storage.AttemptState }{
		{storage.AttemptAdmitted, storage.AttemptStaging},
		{storage.AttemptStaging, storage.AttemptPrepared},
		{storage.AttemptPrepared, storage.AttemptInstalling},
		{storage.AttemptInstalling, storage.AttemptUnknown},
	} {
		if err := attempts.Transition(ctx, attempt.AttemptID, step.from, storage.AttemptTransition{To: step.to, Now: now}); err != nil {
			t.Fatalf("advance to %s: %v", step.to, err)
		}
	}
	cleared, err := svc.Cancel(ctx, attempt.AttemptID)
	if err != nil || cleared.State != storage.AttemptCancelled {
		t.Fatalf("clear stuck attempt: %+v %v", cleared, err)
	}
	// The reservation is released and the uncertain recording is finalized as
	// unknown, never success.
	if _, err := svc.ActiveAttempt(ctx, "vm-uid"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reservation must be released: %v", err)
	}
	_, outcome, err := store.Metadata().Get(ctx, attempt.ExecutionID)
	if err != nil || outcome.State != storage.StateUnknown {
		t.Fatalf("uncertain outcome: %+v %v", outcome, err)
	}
}

func TestRollbackAdmission(t *testing.T) {
	ctx := context.Background()
	svc, _, attempts := newUpgradeTestService(t)
	attempt, _, err := svc.Admit(ctx, admitRequest("run-1"))
	if err != nil {
		t.Fatal(err)
	}
	// Only failed attempts admit a rollback.
	if _, err := svc.Rollback(ctx, attempt.AttemptID); !errors.Is(err, ErrConflict) {
		t.Fatalf("rollback of admitted attempt: %v", err)
	}
	now := time.Now().UTC()
	if err := attempts.Transition(ctx, attempt.AttemptID, storage.AttemptAdmitted, storage.AttemptTransition{To: storage.AttemptFailed, Now: now}); err != nil {
		t.Fatal(err)
	}
	// A failed attempt without a pinned predecessor cannot roll back.
	if _, err := svc.Rollback(ctx, attempt.AttemptID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rollback without predecessor: %v", err)
	}
	// failed releases the reservation, so a fresh attempt can admit and fail
	// with the predecessor pinned on the failure transition.
	predecessor := &storage.AttemptPredecessor{TargetID: "windows11-amd64-v1", ManifestSHA256: strings.Repeat("c", 64)}
	attempt2, _, err := svc.Admit(ctx, admitRequest("run-2"))
	if err != nil {
		t.Fatalf("second admission after failed first: %v", err)
	}
	for _, step := range []struct {
		from, to    storage.AttemptState
		predecessor *storage.AttemptPredecessor
	}{
		{storage.AttemptAdmitted, storage.AttemptStaging, nil},
		{storage.AttemptStaging, storage.AttemptFailed, predecessor},
	} {
		if err := attempts.Transition(ctx, attempt2.AttemptID, step.from, storage.AttemptTransition{
			To: step.to, Now: now, Predecessor: step.predecessor,
		}); err != nil {
			t.Fatalf("advance to %s: %v", step.to, err)
		}
	}
	rolled, err := svc.Rollback(ctx, attempt2.AttemptID)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rolled.State != storage.AttemptRollbackPending {
		t.Fatalf("state = %s", rolled.State)
	}
	if rolled.Predecessor.TargetID != predecessor.TargetID || rolled.Predecessor.ManifestSHA256 != predecessor.ManifestSHA256 {
		t.Fatalf("predecessor not pinned: %+v", rolled.Predecessor)
	}
	// Rollback of a rollback-pending attempt is a conflict.
	if _, err := svc.Rollback(ctx, attempt2.AttemptID); !errors.Is(err, ErrConflict) {
		t.Fatalf("double rollback: %v", err)
	}
}

func TestFinalizeDeferredAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	svc, store, attempts := newUpgradeTestService(t)
	attempt, _, err := svc.Admit(ctx, admitRequest("run-1"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := attempts.Transition(ctx, attempt.AttemptID, storage.AttemptAdmitted, storage.AttemptTransition{To: storage.AttemptUnknown, Now: now}); err != nil {
		t.Fatal(err)
	}
	// A different replica (no retained recording session) clears the stuck
	// state and still finalizes the linked execution record.
	replica := NewService(store, attempts)
	cleared, err := replica.Cancel(ctx, attempt.AttemptID)
	if err != nil || cleared.State != storage.AttemptCancelled {
		t.Fatalf("replica cancel: %+v %v", cleared, err)
	}
	_, outcome, err := store.Metadata().Get(ctx, attempt.ExecutionID)
	if err != nil || outcome.State != storage.StateUnknown {
		t.Fatalf("deferred finalize outcome: %+v %v", outcome, err)
	}
}

func TestRecordingOutcomeMapping(t *testing.T) {
	for state, want := range map[storage.AttemptState]storage.State{
		storage.AttemptSucceeded:     storage.StateSucceeded,
		storage.AttemptCancelled:     storage.StateCancelled,
		storage.AttemptRolledBack:    storage.StateFailed,
		storage.AttemptUnknown:       storage.StateUnknown,
		storage.AttemptRecordingLost: storage.StateRecordingLost,
	} {
		outcome, ok := recordingOutcome(state)
		if !ok || outcome.State != want {
			t.Fatalf("outcome for %s: %+v %v", state, outcome, ok)
		}
	}
	if _, ok := recordingOutcome(storage.AttemptFailed); ok {
		t.Fatal("failed must keep its recording open")
	}
	if outcome, _ := recordingOutcome(storage.AttemptRolledBack); outcome.RecordingLost {
		t.Fatal("rolled back is not recording-lost")
	}
}

func TestServiceDisabledFailsClosed(t *testing.T) {
	ctx := context.Background()
	svc := NewService(nil, nil)
	if err := svc.Ready(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ready: %v", err)
	}
	if _, _, err := svc.Admit(ctx, admitRequest("run-1")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("admit: %v", err)
	}
	if _, err := svc.Get(ctx, "upg_x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("get: %v", err)
	}
	if _, err := svc.Cancel(ctx, "upg_x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := svc.Rollback(ctx, "upg_x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("rollback: %v", err)
	}
}
