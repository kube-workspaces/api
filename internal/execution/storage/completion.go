package storage

// completionEvents derives metadata-only terminal audit from trusted admission
// and outcome. Both stores commit these events together with the state change.
func completionEvents(id, actor string, outcome ExecutionOutcome) []AuditEvent {
	events := make([]AuditEvent, 0, 2)
	if outcome.RecordingLost {
		events = append(events, AuditEvent{ExecutionID: id, ActorID: actor, Time: outcome.EndTime,
			Kind: "recording.lost", Detail: map[string]string{"reason": "recording storage failure"}})
	}
	return append(events, AuditEvent{ExecutionID: id, ActorID: actor, Time: outcome.EndTime,
		Kind: "finished", Detail: map[string]string{"state": string(outcome.State)}})
}

func validCompletion(outcome ExecutionOutcome) bool {
	return outcome.State.Terminal() && !outcome.EndTime.IsZero() &&
		(outcome.RecordingLost == (outcome.State == StateRecordingLost))
}
