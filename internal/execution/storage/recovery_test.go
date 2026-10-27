package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func verifiedIntent(t *testing.T, intent TerminalIntent) *VerifiedTerminalIntent {
	t.Helper()
	ctx := context.Background()
	s, _ := newTestRecording(t, 1<<20)
	w, err := s.Begin(ctx, intent.Admission.RecordingID)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PutChunk(ctx, 0, []byte("recorded invocation/result")); err != nil {
		t.Fatal(err)
	}
	if err := w.Finalize(ctx, FinalizeMeta{ActorID: intent.Admission.ActorID, EndTime: intent.Outcome.EndTime, Terminal: &intent}); err != nil {
		t.Fatal(err)
	}
	r, err := s.Open(ctx, intent.Admission.RecordingID)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	proof, err := r.TerminalIntent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestEphemeralTerminalRecovery(t *testing.T) {
	m := NewEphemeralMetadata().(*ephemeralMetadata)
	testTerminalRecovery(t, m, m, func(id string) []AuditEvent {
		m.mu.Lock()
		defer m.mu.Unlock()
		return append([]AuditEvent(nil), m.audit[id]...)
	})
}

func testTerminalRecovery(t *testing.T, m, competitor MetadataStore, audit func(string) []AuditEvent) {
	t.Helper()
	ctx := context.Background()
	prefix := fmt.Sprintf("zz-recover-%d-", time.Now().UnixNano())
	makeIntent := func(suffix string, state State) TerminalIntent {
		i := sampleTerminalIntent(prefix + suffix + "-recording")
		i.Admission.ExecutionID = prefix + suffix
		i.Outcome.State, i.Outcome.RecordingLost = state, state == StateRecordingLost
		return i
	}
	reserve := func(i TerminalIntent) {
		t.Helper()
		if err := m.Reserve(ctx, i.Admission); err != nil {
			t.Fatal(err)
		}
		if err := m.Transition(ctx, i.Admission.ExecutionID, ExecutionOutcome{State: StateRunning, StartTime: i.Outcome.StartTime}); err != nil {
			t.Fatal(err)
		}
	}
	for _, state := range []State{StateSucceeded, StateFailed, StateTimedOut, StateCancelled, StateRevoked, StateUnknown, StateRecordingLost} {
		t.Run(string(state), func(t *testing.T) {
			i := makeIntent(string(state), state)
			reserve(i)
			proof := verifiedIntent(t, i)
			// Exported snapshots must not expose mutable proof state/pointers.
			copy := proof.Snapshot()
			copy.Admission.ActorID = "substituted"
			copy.Outcome.State = StateSucceeded
			*copy.Outcome.ExitCode = 99
			recovered, err := m.RecoverTerminal(ctx, proof)
			if err != nil || !recovered {
				t.Fatalf("recover: %v %v", recovered, err)
			}
			_, outcome, err := m.Get(ctx, i.Admission.ExecutionID)
			if err != nil || !sameOutcome(outcome, i.Outcome) {
				t.Fatalf("recovery changed intended outcome: %+v %v", outcome, err)
			}
			events := audit(i.Admission.ExecutionID)
			want := 2
			if state == StateRecordingLost {
				want++
			}
			if len(events) != want || events[want-1].Kind != "completion.recovered" || events[want-1].ActorID != "system:execution-recovery" || events[want-2].Kind != "finished" || events[want-2].ActorID != i.Admission.ActorID {
				t.Fatalf("recovery audit: %+v", events)
			}
			if recovered, err := m.RecoverTerminal(ctx, proof); err != nil || recovered || len(audit(i.Admission.ExecutionID)) != want {
				t.Fatalf("retry duplicated recovery/audit: %v %v", recovered, err)
			}
			if err := m.Complete(ctx, i.Admission.ExecutionID, i.Outcome); err != nil || len(audit(i.Admission.ExecutionID)) != want {
				t.Fatalf("original completer rejected audited matching recovery: %v", err)
			}
			different := i
			if state == StateSucceeded {
				different.Outcome.State = StateUnknown
			} else {
				different.Outcome.State = StateSucceeded
			}
			different.Outcome.RecordingLost = false
			if _, err := m.RecoverTerminal(ctx, verifiedIntent(t, different)); !errors.Is(err, ErrConflict) {
				t.Fatalf("terminal rewrite: %v", err)
			}
		})
	}
	t.Run("admission-and-scope", func(t *testing.T) {
		i := makeIntent("binding", StateSucceeded)
		reserve(i)
		wrong := i
		wrong.Admission.ActorID += "-other"
		if _, err := m.RecoverTerminal(ctx, verifiedIntent(t, wrong)); !errors.Is(err, ErrConflict) {
			t.Fatalf("substituted admission: %v", err)
		}
		if _, err := m.RecoverTerminal(ctx, nil); !errors.Is(err, ErrConflict) {
			t.Fatal("nil proof accepted")
		}
		if _, err := m.RecoverTerminal(ctx, &VerifiedTerminalIntent{}); !errors.Is(err, ErrConflict) {
			t.Fatal("zero proof accepted")
		}
		_, outcome, _ := m.Get(ctx, i.Admission.ExecutionID)
		if outcome.State != StateRunning || len(audit(i.Admission.ExecutionID)) != 0 {
			t.Fatal("failed recovery modified metadata")
		}
		for _, op := range []Operation{OperationShell, OperationUpgrade} {
			other := makeIntent(string(op), StateSucceeded)
			other.Admission.Operation = op
			reserve(other)
			if _, err := m.RecoverTerminal(ctx, verifiedIntent(t, other)); !errors.Is(err, ErrConflict) {
				t.Fatalf("unsupported owner contract recovered: %s %v", op, err)
			}
		}
	})
	t.Run("completion-race", func(t *testing.T) {
		i := makeIntent("race", StateUnknown)
		reserve(i)
		proof := verifiedIntent(t, i)
		var wg sync.WaitGroup
		results := make(chan error, 16)
		for n := 0; n < 16; n++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				if n%2 == 0 {
					results <- m.Complete(ctx, i.Admission.ExecutionID, i.Outcome)
				} else {
					_, err := competitor.RecoverTerminal(ctx, proof)
					results <- err
				}
			}(n)
		}
		wg.Wait()
		close(results)
		for err := range results {
			if err != nil && !errors.Is(err, ErrConflict) {
				t.Fatal(err)
			}
		}
		_, outcome, err := m.Get(ctx, i.Admission.ExecutionID)
		events := audit(i.Admission.ExecutionID)
		finished, recovered := 0, 0
		for _, event := range events {
			if event.Kind == "finished" {
				finished++
			}
			if event.Kind == "completion.recovered" {
				recovered++
			}
		}
		if err != nil || !sameOutcome(outcome, i.Outcome) || finished != 1 || recovered > 1 || len(events) != finished+recovered {
			t.Fatalf("completion race corrupted result/audit: %+v %+v %v", outcome, events, err)
		}
	})
	t.Run("bounded-keyset", func(t *testing.T) {
		for n, op := range []Operation{OperationCommand, OperationScript, OperationCommand, OperationShell, OperationUpgrade} {
			i := makeIntent(fmt.Sprintf("page%d", n), StateSucceeded)
			i.Admission.Operation = op
			reserve(i)
		}
		after := prefix + "page"
		var ids []string
		for n := 0; n < 10; n++ {
			records, err := m.RecoveryCandidates(ctx, after, 2)
			if err != nil || len(records) > 2 {
				t.Fatalf("candidate bound: %v", err)
			}
			if len(records) == 0 {
				break
			}
			for _, rec := range records {
				if rec.ExecutionID <= after {
					t.Fatal("cursor did not advance")
				}
				after = rec.ExecutionID
				if strings.HasPrefix(rec.ExecutionID, prefix+"page") {
					ids = append(ids, rec.ExecutionID)
				}
			}
		}
		if len(ids) != 3 {
			t.Fatalf("candidate operation/state filtering: %v", ids)
		}
		for _, limit := range []int{0, 101} {
			if _, err := m.RecoveryCandidates(ctx, "", limit); !errors.Is(err, ErrConflict) {
				t.Fatalf("invalid batch bound: %v", err)
			}
		}
	})
}
