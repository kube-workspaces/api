package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

func (m *postgresMetadata) RecoverTerminal(ctx context.Context, proof *VerifiedTerminalIntent) (bool, error) {
	i, err := recoveryIntent(proof)
	if err != nil {
		return false, err
	}
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	rec, outcome, err := scanExecution(tx.QueryRow(ctx, `SELECT `+executionColumns+` FROM execution_executions WHERE execution_id=$1 FOR UPDATE`, i.Admission.ExecutionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	if !i.MatchesAdmission(rec) {
		return false, ErrConflict
	}
	if outcome.State.Terminal() {
		if sameOutcome(outcome, i.Outcome) {
			return false, nil
		}
		return false, ErrConflict
	}
	if !recoveryCandidate(rec, outcome) {
		return false, ErrConflict
	}
	// Complete uses the same row lock. A still-live original completer and any
	// other recovery replica therefore cannot overwrite or duplicate this commit.
	if err := updateExecution(ctx, tx, rec.ExecutionID, outcome.State, i.Outcome); err != nil {
		return false, err
	}
	for _, event := range append(completionEvents(rec.ExecutionID, rec.ActorID, i.Outcome), recoveredEvent(i, time.Now().UTC())) {
		if err := insertExecutionAudit(ctx, tx, event); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (m *postgresMetadata) RecoveryCandidates(ctx context.Context, after string, limit int) ([]ExecutionRecord, error) {
	if limit < 1 || limit > 100 {
		return nil, ErrConflict
	}
	rows, err := m.pool.Query(ctx, `SELECT `+executionColumns+` FROM execution_executions WHERE execution_id>$1 AND operation IN ('command','script') AND state IN ('admitted','running') ORDER BY execution_id LIMIT $2`, after, limit)
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
