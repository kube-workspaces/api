package storage

import "time"

func recoveryIntent(v *VerifiedTerminalIntent) (TerminalIntent, error) {
	i := v.Snapshot()
	if !i.valid(i.Admission.RecordingID) ||
		(i.Admission.Operation != OperationCommand && i.Admission.Operation != OperationScript) {
		return TerminalIntent{}, ErrConflict
	}
	return i, nil
}

func recoveryCandidate(rec ExecutionRecord, outcome ExecutionOutcome) bool {
	return (rec.Operation == OperationCommand || rec.Operation == OperationScript) &&
		(outcome.State == "" || outcome.State == StateAdmitted || outcome.State == StateRunning)
}

func sameOutcome(a, b ExecutionOutcome) bool {
	// PostgreSQL timestamp precision is microseconds. Do not change the protected
	// source intent; normalize only when comparing an already-committed outcome.
	return a.State == b.State && a.Termination == b.Termination && a.RecordingLost == b.RecordingLost &&
		a.StartTime.Truncate(time.Microsecond).Equal(b.StartTime.Truncate(time.Microsecond)) &&
		a.EndTime.Truncate(time.Microsecond).Equal(b.EndTime.Truncate(time.Microsecond)) &&
		((a.ExitCode == nil && b.ExitCode == nil) || (a.ExitCode != nil && b.ExitCode != nil && *a.ExitCode == *b.ExitCode))
}

func recoveredEvent(i TerminalIntent, now time.Time) AuditEvent {
	return AuditEvent{ExecutionID: i.Admission.ExecutionID, ActorID: "system:execution-recovery", Time: now,
		Kind: "completion.recovered", Detail: map[string]string{"state": string(i.Outcome.State), "recordingID": i.Admission.RecordingID, "source": "verified-terminal-intent"}}
}

func hasRecoveredCompletion(events []AuditEvent, actor string, state State) bool {
	finished, recovered := false, false
	for _, event := range events {
		if event.Detail["state"] != string(state) {
			continue
		}
		if event.Kind == "finished" && event.ActorID == actor {
			finished = true
		}
		if event.Kind == "completion.recovered" && event.ActorID == "system:execution-recovery" {
			recovered = true
		}
	}
	return finished && recovered
}
