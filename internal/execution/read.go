package execution

import (
	"context"

	"github.com/kube-workspaces/api/internal/execution/storage"
)

// Get returns the stored admission record and its last known outcome. It fails
// closed when storage is disabled or unready.
func (s *Service) Get(ctx context.Context, executionID string) (storage.ExecutionRecord, storage.ExecutionOutcome, error) {
	store, err := s.readyStore(ctx)
	if err != nil {
		return storage.ExecutionRecord{}, storage.ExecutionOutcome{}, err
	}
	return store.Metadata().Get(ctx, executionID)
}

// List returns admission records matching the filter. The caller must scope the
// filter to what the actor is allowed to see before calling; this method only
// enforces storage readiness.
func (s *Service) List(ctx context.Context, f storage.Filter) ([]storage.ExecutionRecord, error) {
	store, err := s.readyStore(ctx)
	if err != nil {
		return nil, err
	}
	return store.Metadata().List(ctx, f)
}

// ReplayRecording authorizes and opens the finalized recording bound to
// executionID, mirroring Replay but keyed by the execution the caller saw.
func (s *Service) ReplayRecording(ctx context.Context, actorID, executionID string) (storage.Reader, storage.ExecutionRecord, error) {
	return s.Replay(ctx, actorID, executionID)
}

// RecordingStatus reports whether the store can admit and replay recordings
// right now. It never returns an error; callers use it for capability display.
func (s *Service) RecordingStatus(ctx context.Context) (mode string, durable bool, available bool) {
	mode = s.Mode()
	durable = s.Durability() == storage.DurabilityDurable
	available = s.Ready(ctx) == nil && s.store != nil
	return mode, durable, available
}
