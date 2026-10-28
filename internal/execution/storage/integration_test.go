package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// These tests require isolated disposable services. They do not discover or use
// deployment credentials and are skipped during ordinary unit-test runs.
func TestPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("KW_EXECUTION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set KW_EXECUTION_TEST_DATABASE_URL for disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	m, err := NewPostgresMetadata(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("integration-%d", time.Now().UnixNano())
	rec := sampleRecord(id)
	rec.RecordingID = "recording-" + id
	if err := m.Reserve(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := m.Reserve(ctx, rec); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate reserve: %v", err)
	}
	other := rec
	other.ExecutionID += "-other"
	if err := m.Reserve(ctx, other); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate recording: %v", err)
	}
	if err := m.Audit(ctx, AuditEvent{ExecutionID: id, Time: time.Now(), Kind: "admitted", ActorID: rec.ActorID}); err != nil {
		t.Fatal(err)
	}
	if err := m.Transition(ctx, id, ExecutionOutcome{State: StateRunning, StartTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := m.Transition(ctx, id, ExecutionOutcome{State: StateSucceeded, EndTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
	_, outcome, err := m.Get(ctx, id)
	if err != nil || outcome.State != StateSucceeded {
		t.Fatalf("outcome: %+v, %v", outcome, err)
	}
	if err := m.Transition(ctx, id, ExecutionOutcome{State: StateRunning}); !errors.Is(err, ErrConflict) {
		t.Fatalf("terminal regression: %v", err)
	}
	// Reopening must preserve state and apply migrations idempotently.
	next, err := NewPostgresMetadata(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if _, _, err := next.Get(ctx, id); err != nil {
		t.Fatal(err)
	}
	t.Run("atomic-completion", func(t *testing.T) {
		backing := m.(*postgresMetadata)
		readAudit := func(id string) []AuditEvent {
			t.Helper()
			rows, err := backing.pool.Query(ctx, `SELECT execution_id, ts, kind, actor_id, detail FROM execution_audit WHERE execution_id=$1 ORDER BY seq`, id)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var events []AuditEvent
			for rows.Next() {
				var event AuditEvent
				if err := rows.Scan(&event.ExecutionID, &event.Time, &event.Kind, &event.ActorID, &event.Detail); err != nil {
					t.Fatal(err)
				}
				events = append(events, event)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			return events
		}
		testMetadataCompletion(t, m, readAudit)
		t.Run("terminal-recovery", func(t *testing.T) { testTerminalRecovery(t, m, next, readAudit) })
	})
	t.Run("completion-audit-rollback", func(t *testing.T) {
		backing := m.(*postgresMetadata)
		// A dedicated connection owns the temporary trigger function. Only this
		// unique execution is affected, even if other campaigns use this database.
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, `CREATE FUNCTION pg_temp.reject_completion_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'disposable completion audit fault'; END $$`); err != nil {
			t.Fatal(err)
		}
		id := fmt.Sprintf("audit-rollback-%d", time.Now().UnixNano())
		trigger := pgx.Identifier{id}.Sanitize()
		if _, err := conn.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON execution_audit FOR EACH ROW WHEN (NEW.execution_id = '%s' AND NEW.kind = 'finished') EXECUTE FUNCTION pg_temp.reject_completion_audit()`, trigger, id)); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := conn.Exec(ctx, `DROP TRIGGER `+trigger+` ON execution_audit`); err != nil {
				t.Error(err)
			}
		}()
		intent := sampleTerminalIntent("rec-" + id)
		intent.Admission.ExecutionID = id
		proof := verifiedIntent(t, intent)
		if err := m.Reserve(ctx, intent.Admission); err != nil {
			t.Fatal(err)
		}
		if err := m.Transition(ctx, id, ExecutionOutcome{State: StateRunning}); err != nil {
			t.Fatal(err)
		}
		for _, state := range []State{StateSucceeded, StateRecordingLost} {
			err := m.Complete(ctx, id, ExecutionOutcome{State: state, EndTime: time.Now(), RecordingLost: state == StateRecordingLost})
			if err == nil {
				t.Fatal("audit outage committed completion")
			}
			_, outcome, err := m.Get(ctx, id)
			if err != nil || outcome.State != StateRunning {
				t.Fatalf("audit failure left terminal metadata: %+v %v", outcome, err)
			}
			var count int
			if err := backing.pool.QueryRow(ctx, `SELECT count(*) FROM execution_audit WHERE execution_id=$1`, id).Scan(&count); err != nil || count != 0 {
				t.Fatalf("audit failure left partial events: %d %v", count, err)
			}
		}
		if _, err := m.RecoverTerminal(ctx, proof); err == nil {
			t.Fatal("recovery ignored finished audit fault")
		}
		if _, err := conn.Exec(ctx, `DROP TRIGGER `+trigger+` ON execution_audit`); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON execution_audit FOR EACH ROW WHEN (NEW.execution_id = '%s' AND NEW.kind = 'completion.recovered') EXECUTE FUNCTION pg_temp.reject_completion_audit()`, trigger, id)); err != nil {
			t.Fatal(err)
		}
		if _, err := m.RecoverTerminal(ctx, proof); err == nil {
			t.Fatal("recovery ignored its own audit fault")
		}
		_, stillRunning, err := m.Get(ctx, id)
		var partial int
		if err != nil || stillRunning.State != StateRunning {
			t.Fatal("recovery audit fault left a terminal row")
		}
		if err := backing.pool.QueryRow(ctx, `SELECT count(*) FROM execution_audit WHERE execution_id=$1`, id).Scan(&partial); err != nil || partial != 0 {
			t.Fatalf("recovery audit fault left partial events: %d %v", partial, err)
		}
		if _, err := conn.Exec(ctx, `CREATE OR REPLACE FUNCTION pg_temp.reject_completion_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`); err != nil {
			t.Fatal(err)
		}
		if recovered, err := m.RecoverTerminal(ctx, proof); err != nil || !recovered {
			t.Fatalf("recovery after audit restoration: %v %v", recovered, err)
		}
		_, outcome, err := m.Get(ctx, id)
		var count int
		if err != nil || !sameOutcome(outcome, intent.Outcome) {
			t.Fatalf("completion after audit recovery: %+v %v", outcome, err)
		}
		if err := backing.pool.QueryRow(ctx, `SELECT count(*) FROM execution_audit WHERE execution_id=$1 AND kind='finished'`, id).Scan(&count); err != nil || count != 1 {
			t.Fatalf("completion audit after recovery: %d %v", count, err)
		}
	})
}

func TestS3Integration(t *testing.T) {
	endpoint := os.Getenv("KW_EXECUTION_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("set KW_EXECUTION_TEST_S3_ENDPOINT for disposable S3")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s, err := NewS3Recording(S3Options{Endpoint: endpoint, Bucket: "execution-integration", Region: "us-east-1", AccessKey: os.Getenv("KW_EXECUTION_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("KW_EXECUTION_TEST_S3_SECRET_KEY"), CreateBucket: true, ForcePathStyle: true}, make([]byte, 32), "integration-key")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("integration-%d", time.Now().UnixNano())
	w, err := s.Begin(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PutChunk(ctx, 0, []byte("protected integration output")); err != nil {
		t.Fatal(err)
	}
	if err := w.Finalize(ctx, FinalizeMeta{}); err != nil {
		t.Fatal(err)
	}
	r, err := s.Open(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	data, err := r.ReadChunk(ctx, 0)
	if err != nil || string(data) != "protected integration output" {
		t.Fatalf("read = %q, %v", data, err)
	}
	// Corrupt the authenticated terminal count, as a compromised object store.
	backing := s.(*s3Recording)
	m := r.Manifest()
	m.Chunks = 0
	m.Chain = chainHex(chainStart(m.KeyID, m.RecordingID))
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := backing.put(backing.manifestObject(id), raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(ctx, id); !errors.Is(err, ErrTampered) {
		t.Fatalf("tampered S3 manifest: %v", err)
	}
	t.Run("key-rotation", func(t *testing.T) {
		testS3KeyRotation(t, S3Options{Endpoint: endpoint, Bucket: "execution-integration", Region: "us-east-1", AccessKey: os.Getenv("KW_EXECUTION_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("KW_EXECUTION_TEST_S3_SECRET_KEY"), CreateBucket: true, ForcePathStyle: true})
	})
}
