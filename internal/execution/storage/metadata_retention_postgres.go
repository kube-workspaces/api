package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Keep any current upgrade references, even if a legacy caller misclassified the
// execution as a command/script. No upgrade authority/lifecycle is modified.
const noUpgradeReferences = `NOT EXISTS (SELECT 1 FROM agent_upgrade_attempts u WHERE u.execution_id=e.execution_id OR u.recording_id=e.recording_id)
	AND NOT EXISTS (SELECT 1 FROM agent_upgrade_phase_intents p WHERE p.recording_id=e.recording_id)
	AND NOT EXISTS (SELECT 1 FROM agent_upgrade_journal_steps j WHERE j.recording_id=e.recording_id)`

func (m *postgresMetadata) MetadataExpiryCandidates(ctx context.Context, after string, cutoff time.Time, limit int) ([]ExecutionRecord, error) {
	if cutoff.IsZero() || limit < 1 || limit > 100 {
		return nil, ErrConflict
	}
	rows, err := m.pool.Query(ctx, `SELECT `+executionColumns+` FROM execution_executions e
		WHERE execution_id>$1 AND admitted AND operation IN ('command','script') AND state IN `+retentionTerminalStates+`
		AND end_time<$2
		AND EXISTS (SELECT 1 FROM execution_recording_retention r WHERE r.execution_id=e.execution_id AND r.recording_id=e.recording_id AND r.end_time=e.end_time AND r.completed_at<$2)
		AND EXISTS (SELECT 1 FROM execution_audit a WHERE a.execution_id=e.execution_id AND a.kind='finished' AND a.actor_id=e.actor_id AND a.detail->>'state'=e.state)
		AND NOT EXISTS (SELECT 1 FROM execution_audit a WHERE a.execution_id=e.execution_id AND a.ts >= $2)
		AND `+noUpgradeReferences+` ORDER BY execution_id LIMIT $3`, after, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []ExecutionRecord
	for rows.Next() {
		rec, _, err := scanExecution(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

func (m *postgresMetadata) PurgeExpiredMetadata(ctx context.Context, id string, cutoff, now time.Time) (bool, error) {
	if now.IsZero() || cutoff.IsZero() || !cutoff.Before(now) {
		return false, ErrConflict
	}
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var recordingID string
	var purged *time.Time
	err = tx.QueryRow(ctx, `SELECT recording_id,metadata_purged_at FROM execution_identities WHERE execution_id=$1 FOR UPDATE`, id).Scan(&recordingID, &purged)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil || purged != nil {
		return false, err
	}
	// This conflicts with the audit insertion trigger's KEY SHARE lock. Audit
	// arriving first becomes visible below; arriving later cannot be orphaned.
	rec, outcome, err := scanExecution(tx.QueryRow(ctx, `SELECT `+executionColumns+` FROM execution_executions WHERE execution_id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	if rec.RecordingID != recordingID || !rec.Admitted || !outcome.State.Terminal() || outcome.EndTime.IsZero() || !outcome.EndTime.Before(cutoff) || (rec.Operation != OperationCommand && rec.Operation != OperationScript) {
		return false, nil
	}
	var completed time.Time
	err = tx.QueryRow(ctx, `SELECT completed_at FROM execution_recording_retention WHERE execution_id=$1 AND recording_id=$2 AND end_time=$3 AND completed_at<$4`, id, recordingID, outcome.EndTime, cutoff).Scan(&completed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var eligible bool
	err = tx.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM execution_audit a WHERE a.execution_id=e.execution_id AND a.kind='finished' AND a.actor_id=e.actor_id AND a.detail->>'state'=e.state)
		AND NOT EXISTS (SELECT 1 FROM execution_audit a WHERE a.execution_id=e.execution_id AND a.ts >= $2)
		AND `+noUpgradeReferences+` FROM execution_executions e WHERE execution_id=$1`, id, cutoff).Scan(&eligible)
	if err != nil || !eligible {
		return false, err
	}
	deleted, err := tx.Exec(ctx, `DELETE FROM execution_audit WHERE execution_id=$1`, id)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM execution_recording_retention WHERE execution_id=$1`, id); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM execution_executions WHERE execution_id=$1`, id); err != nil {
		return false, err
	}
	// This minimal system receipt is atomic with deletion. No original actor,
	// scope, invocation, outcome or audit payload survives in this table.
	if _, err := tx.Exec(ctx, `UPDATE execution_identities SET metadata_purged_at=$2,metadata_cutoff=$3,recording_expired_at=$4,audit_events_deleted=$5,system_actor='system:execution-retention' WHERE execution_id=$1`, id, now, cutoff, completed, deleted.RowsAffected()); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}
