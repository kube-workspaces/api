package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestEphemeralMetadataCompletion(t *testing.T) {
	m := NewEphemeralMetadata().(*ephemeralMetadata)
	testMetadataCompletion(t, m, func(id string) []AuditEvent {
		m.mu.Lock()
		defer m.mu.Unlock()
		return append([]AuditEvent(nil), m.audit[id]...)
	})
}

// Shared contract runs against both real PostgreSQL and bounded memory stores.
func testMetadataCompletion(t *testing.T, m MetadataStore, audit func(string) []AuditEvent) {
	t.Helper()
	ctx := context.Background()
	prefix := fmt.Sprintf("complete-%d", time.Now().UnixNano())
	for _, state := range []State{StateSucceeded, StateFailed, StateTimedOut, StateCancelled, StateRevoked, StateRecordingLost, StateUnknown} {
		t.Run(string(state), func(t *testing.T) {
			id := prefix + "-" + string(state)
			rec := sampleRecord(id)
			if err := m.Reserve(ctx, rec); err != nil {
				t.Fatal(err)
			}
			start, end := time.Now().UTC().Truncate(time.Microsecond), time.Now().UTC().Truncate(time.Microsecond)
			if err := m.Transition(ctx, id, ExecutionOutcome{State: StateRunning, StartTime: start}); err != nil {
				t.Fatal(err)
			}
			code := 7
			outcome := ExecutionOutcome{State: state, StartTime: start, EndTime: end, ExitCode: &code, RecordingLost: state == StateRecordingLost, Termination: "bounded termination"}
			if err := m.Complete(ctx, id, outcome); err != nil {
				t.Fatal(err)
			}
			_, got, err := m.Get(ctx, id)
			if err != nil || got.State != state || !got.StartTime.Equal(start) || !got.EndTime.Equal(end) || got.ExitCode == nil || *got.ExitCode != code || got.Termination != outcome.Termination || got.RecordingLost != outcome.RecordingLost {
				t.Fatalf("terminal metadata: %+v %v", got, err)
			}
			events := audit(id)
			want := 1
			if state == StateRecordingLost {
				want = 2
			}
			if len(events) != want || events[want-1].Kind != "finished" || events[want-1].Detail["state"] != string(state) {
				t.Fatalf("terminal audit: %+v", events)
			}
			for _, event := range events {
				if event.ExecutionID != id || event.ActorID != rec.ActorID || !event.Time.Equal(end) {
					t.Fatalf("audit not admission-bound: %+v", event)
				}
			}
			if state == StateRecordingLost && events[0].Kind != "recording.lost" {
				t.Fatal("missing recording-loss audit")
			}
			if err := m.Complete(ctx, id, outcome); !errors.Is(err, ErrConflict) {
				t.Fatalf("terminal rewrite: %v", err)
			}
			if len(audit(id)) != want {
				t.Fatal("duplicate completion appended audit")
			}
		})
	}
	t.Run("validation", func(t *testing.T) {
		id := prefix + "-validation"
		if err := m.Reserve(ctx, sampleRecord(id)); err != nil {
			t.Fatal(err)
		}
		for _, outcome := range []ExecutionOutcome{
			{State: StateRunning, EndTime: time.Now()},
			{State: StateSucceeded},
			{State: StateSucceeded, EndTime: time.Now(), RecordingLost: true},
			{State: StateRecordingLost, EndTime: time.Now()},
		} {
			if err := m.Complete(ctx, id, outcome); !errors.Is(err, ErrConflict) {
				t.Fatalf("invalid completion: %v", err)
			}
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if err := m.Complete(cancelled, id, ExecutionOutcome{State: StateFailed, EndTime: time.Now()}); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled completion: %v", err)
		}
		_, outcome, err := m.Get(ctx, id)
		if err != nil || outcome.State.Terminal() || len(audit(id)) != 0 {
			t.Fatal("rejected completion mutated metadata/audit")
		}
		if err := m.Complete(ctx, prefix+"-missing", ExecutionOutcome{State: StateFailed, EndTime: time.Now()}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing completion: %v", err)
		}
	})
	t.Run("competing-completions", func(t *testing.T) {
		id := prefix + "-race"
		if err := m.Reserve(ctx, sampleRecord(id)); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errors := make(chan error, 16)
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				state := StateSucceeded
				if i%2 == 1 {
					state = StateUnknown
				}
				errors <- m.Complete(ctx, id, ExecutionOutcome{State: state, EndTime: time.Now().UTC()})
			}(i)
		}
		wg.Wait()
		close(errors)
		wins := 0
		for err := range errors {
			if err == nil {
				wins++
			} else if err != ErrConflict {
				t.Fatalf("competing completion: %v", err)
			}
		}
		_, outcome, err := m.Get(ctx, id)
		events := audit(id)
		if err != nil || wins != 1 || len(events) != 1 || events[0].Detail["state"] != string(outcome.State) {
			t.Fatalf("completion race: wins=%d outcome=%+v audit=%+v err=%v", wins, outcome, events, err)
		}
	})
}
