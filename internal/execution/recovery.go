package execution

import (
	"context"
	"errors"
	"time"

	"github.com/kube-workspaces/api/internal/execution/storage"
)

// ReconcileTerminal repairs only a synchronous command/script with complete,
// authenticated terminal evidence. It never calls a guest or recreates a writer.
// Missing/legacy/incomplete evidence is a no-op, not an inferred unknown/success.
func (s *Service) ReconcileTerminal(ctx context.Context, executionID string) (bool, error) {
	store, err := s.readyStore(ctx)
	if err != nil {
		return false, err
	}
	rec, outcome, err := store.Metadata().Get(ctx, executionID)
	if err != nil {
		return false, err
	}
	if outcome.State.Terminal() || (rec.Operation != storage.OperationCommand && rec.Operation != storage.OperationScript) {
		return false, nil
	}
	r, err := store.Recording().Open(ctx, rec.RecordingID)
	if errors.Is(err, storage.ErrNotFinalized) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer r.Close()
	proof, err := r.TerminalIntent(ctx)
	if errors.Is(err, storage.ErrNoTerminalIntent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !proof.MatchesAdmission(rec) {
		return false, storage.ErrConflict
	}
	return store.Metadata().RecoverTerminal(ctx, proof)
}

// RecoveryBatch summarizes metadata-only work. No recording contents appear in
// diagnostics. The keyset cursor advances over failures/incomplete recordings so
// one old/corrupt entry cannot starve later candidates.
type RecoveryBatch struct{ Checked, Recovered, Failed int }

func (s *Service) ReconcileTerminalBatch(ctx context.Context, after string, limit int) (string, RecoveryBatch, error) {
	var result RecoveryBatch
	store, err := s.readyStore(ctx)
	if err != nil {
		return after, result, err
	}
	records, err := store.Metadata().RecoveryCandidates(ctx, after, limit)
	if err != nil {
		return after, result, err
	}
	if len(records) == 0 {
		return "", result, nil
	}
	for _, rec := range records {
		if err := ctx.Err(); err != nil {
			return after, result, err
		}
		recovered, err := s.ReconcileTerminal(ctx, rec.ExecutionID)
		result.Checked++
		if err != nil {
			result.Failed++
		}
		if recovered {
			result.Recovered++
		}
		after = rec.ExecutionID
	}
	return after, result, nil
}

// StartTerminalRecovery starts a bounded persistent-mode sweep. The finalized
// single-writer recording is the completion fence; row locks/CAS arbitrate only
// metadata completion, not active guest ownership. There is no lease-expiry
// inference, running-row reaper, shell/upgrade recovery or guest redispatch.
// Call stop before closing storage; it cancels and joins the worker.
func (s *Service) StartTerminalRecovery(ctx context.Context) (stop func()) {
	if s.Durability() != storage.DurabilityDurable {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		cursor := ""
		for {
			batchCtx, batchCancel := context.WithTimeout(ctx, 10*time.Second)
			next, _, _ := s.ReconcileTerminalBatch(batchCtx, cursor, 32)
			batchCancel()
			cursor = next
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}
