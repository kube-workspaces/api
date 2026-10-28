package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const retentionTerminalStates = `('succeeded','failed','cancelled','timed_out','revoked','recording_lost','unknown')`

func (m *postgresMetadata) RecordingExpired(ctx context.Context, id string) (bool, error) {
	var expired bool
	err := m.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM execution_recording_retention WHERE execution_id=$1)`, id).Scan(&expired)
	return expired, err
}

func (m *postgresMetadata) RecordingExpiryCandidates(ctx context.Context, after string, cutoff time.Time, limit int) ([]ExecutionRecord, error) {
	if cutoff.IsZero() || limit < 1 || limit > 100 {
		return nil, ErrConflict
	}
	rows, err := m.pool.Query(ctx, `SELECT `+executionColumns+` FROM execution_executions e
		WHERE execution_id>$1 AND operation IN ('command','script') AND admitted
		AND state IN `+retentionTerminalStates+` AND end_time IS NOT NULL
		AND NOT EXISTS (SELECT 1 FROM execution_recording_retention r WHERE r.execution_id=e.execution_id AND r.completed_at IS NOT NULL)
		AND ((end_time<$2 AND EXISTS (SELECT 1 FROM execution_audit a WHERE a.execution_id=e.execution_id AND a.kind='finished' AND a.actor_id=e.actor_id AND a.detail->>'state'=e.state))
		OR EXISTS (SELECT 1 FROM execution_recording_retention r WHERE r.execution_id=e.execution_id AND r.completed_at IS NULL))
		ORDER BY execution_id LIMIT $3`, after, cutoff, limit)
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

func (m *postgresMetadata) BeginRecordingExpiry(ctx context.Context, id string, cutoff, now time.Time) (ExecutionRecord, bool, error) {
	if now.IsZero() || cutoff.IsZero() || !cutoff.Before(now) {
		return ExecutionRecord{}, false, ErrConflict
	}
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return ExecutionRecord{}, false, err
	}
	defer tx.Rollback(ctx)
	rec, outcome, err := scanExecution(tx.QueryRow(ctx, `SELECT `+executionColumns+` FROM execution_executions WHERE execution_id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ExecutionRecord{}, false, ErrNotFound
	}
	if err != nil {
		return ExecutionRecord{}, false, err
	}
	if !rec.Admitted || !outcome.State.Terminal() || outcome.EndTime.IsZero() || (rec.Operation != OperationCommand && rec.Operation != OperationScript) {
		return rec, false, nil
	}
	var recordingID string
	var end time.Time
	var completed *time.Time
	err = tx.QueryRow(ctx, `SELECT recording_id,end_time,completed_at FROM execution_recording_retention WHERE execution_id=$1`, id).Scan(&recordingID, &end, &completed)
	if err == nil {
		if recordingID != rec.RecordingID || !end.Equal(outcome.EndTime) {
			return rec, false, ErrConflict
		}
		// A committed deletion plan remains fenced across a longer future
		// retention setting. Never reopen partially deleted evidence.
		return rec, completed == nil, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return rec, false, err
	}
	if !outcome.EndTime.Before(cutoff) {
		return rec, false, nil
	}
	var finished bool
	err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM execution_audit WHERE execution_id=$1 AND kind='finished' AND actor_id=$2 AND detail->>'state'=$3)`, id, rec.ActorID, string(outcome.State)).Scan(&finished)
	if err != nil || !finished {
		return rec, false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO execution_recording_retention(execution_id,recording_id,end_time,planned_at) VALUES($1,$2,$3,$4)`, id, rec.RecordingID, outcome.EndTime, now); err != nil {
		return rec, false, err
	}
	if err := insertExecutionAudit(ctx, tx, AuditEvent{ExecutionID: id, Time: now, Kind: "recording.expiry_started", ActorID: "system:execution-retention", Detail: map[string]string{"recordingID": rec.RecordingID, "cutoff": cutoff.UTC().Format(time.RFC3339Nano)}}); err != nil {
		return rec, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return rec, false, err // Never delete objects on an uncertain admission.
	}
	return rec, true, nil
}

func (m *postgresMetadata) FinishRecordingExpiry(ctx context.Context, id, recordingID string, now time.Time) error {
	if now.IsZero() {
		return ErrConflict
	}
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var storedID string
	var planned time.Time
	var completed *time.Time
	err = tx.QueryRow(ctx, `SELECT recording_id,planned_at,completed_at FROM execution_recording_retention WHERE execution_id=$1 FOR UPDATE`, id).Scan(&storedID, &planned, &completed)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if storedID != recordingID || now.Before(planned) {
		return ErrConflict
	}
	if completed != nil {
		return nil
	}
	if _, err := tx.Exec(ctx, `UPDATE execution_recording_retention SET completed_at=$2 WHERE execution_id=$1`, id, now); err != nil {
		return err
	}
	if err := insertExecutionAudit(ctx, tx, AuditEvent{ExecutionID: id, Time: now, Kind: "recording.expired", ActorID: "system:execution-retention", Detail: map[string]string{"recordingID": recordingID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
