package storage

import (
	"context"
	"errors"
	"time"
)

// ErrRecordingExpired means protected playback was fenced by committed operator
// retention policy. It is distinct from corruption, recording loss or guest loss.
var ErrRecordingExpired = errors.New("recording expired by retention")

// RecordingRetentionMetadata is deliberately separate from general metadata:
// only persistent stores support this opt-in, terminal-command/script expiry.
type RecordingRetentionMetadata interface {
	RecordingExpiryCandidates(context.Context, string, time.Time, int) ([]ExecutionRecord, error)
	BeginRecordingExpiry(context.Context, string, time.Time, time.Time) (ExecutionRecord, bool, error)
	FinishRecordingExpiry(context.Context, string, string, time.Time) error
}

// RecordingDeleter removes bounded batches of current objects beneath one exact
// recording prefix. Call only after the matching durable expiry fence commits.
// False means partial progress; retry the same deletion, never a guest execution.
type RecordingDeleter interface {
	DeleteRecording(context.Context, string, int) (bool, error)
}
