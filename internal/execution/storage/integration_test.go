package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
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
}
