package execution

import (
	"context"
	"fmt"
	"time"

	"github.com/kube-workspaces/api/internal/execution/storage"
	"goa.design/clue/log"
)

type RetentionBatch struct{ Checked, Expired, Pending, Failed int }

// ExpireRecordingsBatch fences playback durably before bounded object deletion.
// It never deletes metadata/audit, infers guest death, or dispatches guest work.
func (s *Service) ExpireRecordingsBatch(ctx context.Context, after string, retention time.Duration, limit int) (string, RetentionBatch, error) {
	var result RetentionBatch
	if retention <= 0 || limit < 1 || limit > 100 {
		return after, result, storage.ErrConflict
	}
	store, err := s.readyStore(ctx)
	if err != nil {
		return after, result, err
	}
	meta, ok := store.Metadata().(storage.RecordingRetentionMetadata)
	deleter, deletes := store.Recording().(storage.RecordingDeleter)
	if !ok || !deletes || store.Durability() != storage.DurabilityDurable {
		return after, result, fmt.Errorf("persistent recording retention unavailable")
	}
	now := s.now().UTC()
	cutoff := now.Add(-retention)
	records, err := meta.RecordingExpiryCandidates(ctx, after, cutoff, limit)
	if err != nil {
		return after, result, err
	}
	if len(records) == 0 {
		return "", result, nil
	}
	for _, candidate := range records {
		if err := ctx.Err(); err != nil {
			return after, result, err
		}
		rec, pending, err := meta.BeginRecordingExpiry(ctx, candidate.ExecutionID, cutoff, now)
		result.Checked++
		if err != nil {
			result.Failed++
		} else if pending {
			complete, deleteErr := deleter.DeleteRecording(ctx, rec.RecordingID, 128)
			if deleteErr != nil {
				result.Failed++
			} else if !complete {
				result.Pending++
			} else if err := meta.FinishRecordingExpiry(ctx, rec.ExecutionID, rec.RecordingID, s.now().UTC()); err != nil {
				result.Failed++
			} else {
				result.Expired++
			}
		}
		after = candidate.ExecutionID
	}
	return after, result, nil
}

// StartRecordingRetention is explicitly enabled by startup configuration, never
// by proposed/default retention durations. Stop cancels and joins before storage
// closes. Each pass and each recording's object count are bounded.
func (s *Service) StartRecordingRetention(ctx context.Context, retention time.Duration) (func(), error) {
	if s.store == nil || s.Durability() != storage.DurabilityDurable || retention <= 0 {
		return nil, fmt.Errorf("persistent recording retention unavailable")
	}
	if _, ok := s.store.Metadata().(storage.RecordingRetentionMetadata); !ok {
		return nil, fmt.Errorf("persistent recording retention metadata unavailable")
	}
	if _, ok := s.store.Recording().(storage.RecordingDeleter); !ok {
		return nil, fmt.Errorf("persistent recording retention deletion unavailable")
	}
	return startRetentionWorker(ctx, "recordings", func(ctx context.Context, cursor string) (string, RetentionBatch, error) {
		return s.ExpireRecordingsBatch(ctx, cursor, retention, 16)
	}), nil
}

// ExpireMetadataBatch retains every event within its own retention window, not
// merely executions with an old end date. Recording cleanup must already be done.
func (s *Service) ExpireMetadataBatch(ctx context.Context, after string, retention time.Duration, limit int) (string, RetentionBatch, error) {
	var batch RetentionBatch
	if retention <= 0 || limit < 1 || limit > 100 {
		return after, batch, storage.ErrConflict
	}
	store, err := s.readyStore(ctx)
	if err != nil {
		return after, batch, err
	}
	meta, ok := store.Metadata().(storage.MetadataRetentionStore)
	if !ok || s.Durability() != storage.DurabilityDurable {
		return after, batch, fmt.Errorf("persistent metadata retention unavailable")
	}
	now := s.now().UTC()
	cutoff := now.Add(-retention)
	records, err := meta.MetadataExpiryCandidates(ctx, after, cutoff, limit)
	if err != nil {
		return after, batch, err
	}
	if len(records) == 0 {
		return "", batch, nil
	}
	for _, rec := range records {
		if err := ctx.Err(); err != nil {
			return after, batch, err
		}
		purged, err := meta.PurgeExpiredMetadata(ctx, rec.ExecutionID, cutoff, now)
		batch.Checked++
		if err != nil {
			batch.Failed++
		} else if purged {
			batch.Expired++
		}
		after = rec.ExecutionID
	}
	return after, batch, nil
}

func (s *Service) StartMetadataRetention(ctx context.Context, retention time.Duration) (func(), error) {
	if s.store == nil || s.Durability() != storage.DurabilityDurable || retention <= 0 {
		return nil, fmt.Errorf("persistent metadata retention unavailable")
	}
	if _, ok := s.store.Metadata().(storage.MetadataRetentionStore); !ok {
		return nil, fmt.Errorf("persistent metadata retention unavailable")
	}
	return startRetentionWorker(ctx, "metadata", func(ctx context.Context, cursor string) (string, RetentionBatch, error) {
		return s.ExpireMetadataBatch(ctx, cursor, retention, 16)
	}), nil
}

func startRetentionWorker(ctx context.Context, scope string, sweep func(context.Context, string) (string, RetentionBatch, error)) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		cursor := ""
		for {
			batchCtx, stopBatch := context.WithTimeout(ctx, 10*time.Second)
			next, batch, err := sweep(batchCtx, cursor)
			stopBatch()
			cursor = next
			if err != nil || batch.Failed > 0 {
				// Deliberately log counts only, not storage/credential errors or
				// recording content. Failures remain retryable behind the fence.
				log.Printf(ctx, "executions.retention scope=%s failed=true checked=%d expired=%d pending=%d failures=%d", scope, batch.Checked, batch.Expired, batch.Pending, batch.Failed)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}
