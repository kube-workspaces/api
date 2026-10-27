package storage

import (
	"context"
	"sort"
	"time"
)

func (m *ephemeralMetadata) RecoverTerminal(ctx context.Context, proof *VerifiedTerminalIntent) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	i, err := recoveryIntent(proof)
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[i.Admission.ExecutionID]
	if !ok {
		return false, ErrNotFound
	}
	if !i.MatchesAdmission(rec) {
		return false, ErrConflict
	}
	outcome := m.outcomes[rec.ExecutionID]
	if outcome.State.Terminal() {
		if sameOutcome(outcome, i.Outcome) {
			return false, nil
		}
		return false, ErrConflict
	}
	if !recoveryCandidate(rec, outcome) {
		return false, ErrConflict
	}
	m.outcomes[rec.ExecutionID] = i.Outcome
	for _, event := range completionEvents(rec.ExecutionID, rec.ActorID, i.Outcome) {
		m.appendAudit(event)
	}
	m.appendAudit(recoveredEvent(i, time.Now().UTC()))
	return true, nil
}

func (m *ephemeralMetadata) RecoveryCandidates(ctx context.Context, after string, limit int) ([]ExecutionRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 100 {
		return nil, ErrConflict
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var records []ExecutionRecord
	for id, rec := range m.records {
		if id > after && recoveryCandidate(rec, m.outcomes[id]) {
			records = append(records, rec)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ExecutionID < records[j].ExecutionID })
	if len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}
