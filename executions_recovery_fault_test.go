package kubeworkspaces

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution"
	"github.com/kube-workspaces/api/internal/execution/qga"
	"github.com/kube-workspaces/api/internal/execution/storage"
)

func disposableRecoveryOptions(t *testing.T) storage.Options {
	t.Helper()
	dsn, endpoint := os.Getenv("KW_EXECUTION_TEST_DATABASE_URL"), os.Getenv("KW_EXECUTION_TEST_S3_ENDPOINT")
	if dsn == "" || endpoint == "" {
		t.Skip("set disposable PostgreSQL/S3 integration variables")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return storage.Options{Mode: "external", DatabaseURL: dsn, RecordingKey: key, KeyID: storage.DeriveKeyID(key), S3: storage.S3Options{
		Endpoint: endpoint, Region: "us-east-1", Bucket: "execution-recovery-faults", CreateBucket: true, ForcePathStyle: true,
		AccessKey: os.Getenv("KW_EXECUTION_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("KW_EXECUTION_TEST_S3_SECRET_KEY"),
	}}
}

func openRecoveryStore(t *testing.T, ctx context.Context, opts storage.Options) storage.Store {
	t.Helper()
	s, err := storage.Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// Only for disposable plaintext PostgreSQL. Observe a real backend COMMIT
// CommandComplete before dropping its acknowledgement, never a simulated error
// or a guessed delay. No SQL/request/output text is inspected or logged.
func newCommitAckLossGate(t *testing.T, address string) (*postgresFaultGate, *atomic.Bool, *atomic.Int64) {
	t.Helper()
	armed, dropped := &atomic.Bool{}, &atomic.Int64{}
	g := newPostgresFaultGate(t, address, func(client, server net.Conn) {
		for {
			var header [5]byte
			if _, err := io.ReadFull(server, header[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(header[1:])
			if n < 4 || n > 1<<20 {
				return
			}
			payload := make([]byte, int(n)-4)
			if _, err := io.ReadFull(server, payload); err != nil {
				return
			}
			if header[0] == 'C' && bytes.Equal(payload, []byte("COMMIT\x00")) && armed.CompareAndSwap(true, false) {
				dropped.Add(1)
				return // Outer gate closes both connections before forwarding C/Z.
			}
			if _, err := io.Copy(client, bytes.NewReader(append(header[:], payload...))); err != nil {
				return
			}
		}
	})
	return g, armed, dropped
}

func assertRecoveryAudit(t *testing.T, ctx context.Context, dsn, id string, wantRecovered int) {
	t.Helper()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	var finished, recovered int
	if err := db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE kind='finished'), count(*) FILTER (WHERE kind='completion.recovered') FROM execution_audit WHERE execution_id=$1`, id).Scan(&finished, &recovered); err != nil {
		t.Fatal(err)
	}
	if finished != 1 || recovered != wantRecovered {
		t.Fatalf("completion audit duplicated/lost: finished=%d recovered=%d, want=1/%d", finished, recovered, wantRecovered)
	}
}

func TestExecutionCommitResponseLossIntegration(t *testing.T) {
	opts := disposableRecoveryOptions(t)
	u, err := url.Parse(opts.DatabaseURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" || u.Query().Get("sslmode") != "disable" {
		t.Fatal("wire ACK-loss campaign requires a disposable PostgreSQL URL with sslmode=disable; it never weakens deployment TLS")
	}
	address := u.Host
	if u.Port() == "" {
		address = net.JoinHostPort(u.Hostname(), "5432")
	}
	for _, phase := range []string{"original-completion", "recovery-completion"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			raw := newPostgresFaultGate(t, address)
			ack, armed, dropped := newCommitAckLossGate(t, raw.listener.Addr().String())
			through := *u
			through.Host = ack.listener.Addr().String()
			query := through.Query()
			query.Set("connect_timeout", "2")
			through.RawQuery = query.Encode()
			gateOpts := opts
			gateOpts.DatabaseURL = through.String()
			s := openRecoveryStore(t, ctx, gateOpts)
			code := 0
			stub := &stubQGA{target: eligibleTarget(), result: &qga.GuestResult{Outcome: "completed", ExitCode: &code, Stdout: []byte("one recorded result")}}
			stub.execute = func(ctx context.Context, _ qga.Target, _ qga.Command) (*qga.GuestResult, error) {
				if phase == "original-completion" {
					armed.Store(true)
				} else {
					raw.setBlocked(true)
					if err := s.Metadata().Ready(ctx); err == nil {
						t.Fatal("original completion fault missed the database connection")
					}
				}
				return stub.result, nil
			}
			stack := newStoredStartStack(t, "team", "vm", []string{string(auth.PermissionExec), string(auth.PermissionElevated)}, enabledElevatedPolicy(), stub, s)
			w := stack.postCtx(ctx, `{"namespace":"team","workspace_name":"vm","executable":"cmd.exe","args":["/c","echo proof"]}`)
			if w.Code != 503 || len(stub.commands) != 1 {
				t.Fatalf("uncertain commit must not report success/rerun: HTTP %d dispatches=%d", w.Code, len(stub.commands))
			}
			cmd := stub.commands[0]
			wantRecovered := 0
			if phase == "recovery-completion" {
				raw.setBlocked(false)
				if err := s.Ready(ctx); err != nil {
					t.Fatal(err)
				}
				armed.Store(true)
				if changed, err := stack.execution.ReconcileTerminal(ctx, cmd.ExecutionID); err == nil || changed {
					t.Fatal("lost recovery COMMIT acknowledgement fabricated a known response")
				}
				wantRecovered = 1
			}
			if dropped.Load() != 1 || armed.Load() {
				t.Fatal("did not drop exactly one observed backend COMMIT acknowledgement")
			}
			// Bypass the broken connection to prove the database really committed.
			observer := openRecoveryStore(t, ctx, opts)
			rec, outcome, err := observer.Metadata().Get(ctx, cmd.ExecutionID)
			if err != nil || outcome.State != storage.StateSucceeded {
				t.Fatalf("backend did not actually commit: %+v %v", outcome, err)
			}
			r, err := observer.Recording().Open(ctx, cmd.RecordingID)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			proof, err := r.TerminalIntent(ctx)
			if err != nil || !proof.MatchesAdmission(rec) {
				t.Fatalf("committed outcome lost protected evidence: %v", err)
			}
			recovery := execution.NewService(observer)
			for n := 0; n < 3; n++ {
				if changed, err := recovery.ReconcileTerminal(ctx, cmd.ExecutionID); err != nil || changed {
					t.Fatalf("lost-response retry was not an audited no-op: %v %v", changed, err)
				}
			}
			assertRecoveryAudit(t, ctx, opts.DatabaseURL, cmd.ExecutionID, wantRecovered)
			if len(stub.commands) != 1 {
				t.Fatal("recovery replayed a guest command")
			}
		})
	}
}

type pausedCompletionStore struct {
	storage.Store
	marker string
}

func (s pausedCompletionStore) Metadata() storage.MetadataStore {
	return pausedCompletionMetadata{MetadataStore: s.Store.Metadata(), marker: s.marker}
}

type pausedCompletionMetadata struct {
	storage.MetadataStore
	marker string
}

func (m pausedCompletionMetadata) Complete(ctx context.Context, id string, _ storage.ExecutionOutcome) error {
	// Session.Finish calls Complete only after the real recording is sealed.
	if err := os.WriteFile(m.marker+".tmp", []byte(id), 0o600); err != nil {
		return err
	}
	if err := os.Rename(m.marker+".tmp", m.marker); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

// Only the parent test opts this helper in. It exercises the production HTTP/
// recording path in a separate address space; account/policy/guest are fixtures.
func TestExecutionRecoveryProcessHelper(t *testing.T) {
	if os.Getenv("KW_EXECUTION_TEST_PROCESS_HELPER") != "1" {
		t.Skip("private subprocess helper")
	}
	opts := disposableRecoveryOptions(t)
	key, err := os.ReadFile(os.Getenv("KW_EXECUTION_TEST_PROCESS_KEY_FILE"))
	if err != nil || len(key) != 32 {
		t.Fatal("missing private disposable recording key")
	}
	opts.RecordingKey, opts.KeyID = key, storage.DeriveKeyID(key)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s := openRecoveryStore(t, ctx, opts)
	paused := pausedCompletionStore{Store: s, marker: os.Getenv("KW_EXECUTION_TEST_PROCESS_MARKER")}
	code := 0
	stub := &stubQGA{target: eligibleTarget(), result: &qga.GuestResult{Outcome: "completed", ExitCode: &code, Stdout: []byte("sealed before process death")}}
	stub.execute = func(_ context.Context, _ qga.Target, cmd qga.Command) (*qga.GuestResult, error) {
		ledger, err := os.OpenFile(os.Getenv("KW_EXECUTION_TEST_PROCESS_LEDGER"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = fmt.Fprintln(ledger, cmd.ExecutionID)
		_ = ledger.Close()
		if err != nil {
			t.Fatal(err)
		}
		return stub.result, nil
	}
	stack := newStoredStartStack(t, "team", "vm", []string{string(auth.PermissionExec), string(auth.PermissionElevated)}, enabledElevatedPolicy(), stub, paused)
	_ = stack.postCtx(ctx, `{"namespace":"team","workspace_name":"vm","executable":"cmd.exe","args":["/c","echo proof"]}`)
	t.Fatal("helper returned before the parent killed the paused coordinator")
}

func TestExecutionProcessLossIntegration(t *testing.T) {
	opts := disposableRecoveryOptions(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	dir := t.TempDir()
	keyFile, marker, ledger := filepath.Join(dir, "key"), filepath.Join(dir, "sealed"), filepath.Join(dir, "dispatches")
	if err := os.WriteFile(keyFile, opts.RecordingKey, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestExecutionRecoveryProcessHelper$", "-test.count=1", "-test.timeout=50s")
	cmd.Env = append(os.Environ(), "KW_EXECUTION_TEST_PROCESS_HELPER=1", "KW_EXECUTION_TEST_PROCESS_KEY_FILE="+keyFile, "KW_EXECUTION_TEST_PROCESS_MARKER="+marker, "KW_EXECUTION_TEST_PROCESS_LEDGER="+ledger)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(done) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-done })
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var id string
	for id == "" {
		if raw, err := os.ReadFile(marker); err == nil {
			id = string(raw)
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			<-done
			t.Fatalf("helper did not reach sealed recording: %s", output.String())
		case <-done:
			t.Fatalf("helper exited before fault boundary: %v %s", waitErr, output.String())
		case <-ticker.C:
		}
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-done
	if waitErr == nil {
		t.Fatal("coordinator was not terminated")
	}
	before, err := os.ReadFile(ledger)
	if err != nil || string(before) != id+"\n" {
		t.Fatal("helper did not dispatch exactly once before process death")
	}
	s := openRecoveryStore(t, ctx, opts)
	rec, outcome, err := s.Metadata().Get(ctx, id)
	if err != nil || outcome.State != storage.StateRunning {
		t.Fatalf("hard kill did not strand metadata: %+v %v", outcome, err)
	}
	r, err := s.Recording().Open(ctx, rec.RecordingID)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	proof, err := r.TerminalIntent(ctx)
	if err != nil || !proof.MatchesAdmission(rec) || proof.Snapshot().Outcome.State != storage.StateSucceeded {
		t.Fatalf("process death lost sealed evidence: %v", err)
	}
	recovery := execution.NewService(s) // No guest executor or recovered writer.
	if changed, err := recovery.ReconcileTerminal(ctx, id); err != nil || !changed {
		t.Fatalf("cross-process recovery failed: %v %v", changed, err)
	}
	if changed, err := recovery.ReconcileTerminal(ctx, id); err != nil || changed {
		t.Fatalf("repeated cross-process recovery duplicated completion: %v %v", changed, err)
	}
	_, outcome, err = s.Metadata().Get(ctx, id)
	if err != nil || outcome.State != storage.StateSucceeded {
		t.Fatalf("process recovery lost known outcome: %+v %v", outcome, err)
	}
	assertRecoveryAudit(t, ctx, opts.DatabaseURL, id, 1)
	after, err := os.ReadFile(ledger)
	if err != nil || !bytes.Equal(before, after) || len(strings.Fields(string(after))) != 1 {
		t.Fatal("process recovery changed the dispatch ledger")
	}
}
