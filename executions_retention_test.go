package kubeworkspaces

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution"
	"github.com/kube-workspaces/api/internal/execution/qga"
	"github.com/kube-workspaces/api/internal/execution/storage"
)

// Uses its own throwaway database and object bucket so the destructive retention
// sweep cannot select evidence belonging to any other integration campaign.
func TestExecutionRetentionIntegration(t *testing.T) {
	dsn, endpoint := os.Getenv("KW_EXECUTION_TEST_DATABASE_URL"), os.Getenv("KW_EXECUTION_TEST_S3_ENDPOINT")
	if dsn == "" || endpoint == "" {
		t.Skip("set disposable PostgreSQL/S3 test endpoints; this campaign creates/drops a private test database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	name := fmt.Sprintf("execution_retention_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+identifier+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
	})
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() == "" {
		t.Fatal("retention campaign requires a disposable PostgreSQL URL")
	}
	u.Path = "/" + name
	u.RawPath = ""
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	upstream, err := url.Parse(endpoint)
	if err != nil || upstream.Host == "" {
		t.Fatal("invalid disposable S3 endpoint")
	}
	var blockDelete, unfencedDelete atomic.Bool
	var deletes atomic.Int64
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes.Add(1)
			parts := strings.Split(r.URL.Path, "/")
			var fenced bool
			if len(parts) < 4 || pool.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM execution_recording_retention WHERE recording_id=$1)`, parts[3]).Scan(&fenced) != nil || !fenced {
				unfencedDelete.Store(true)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if blockDelete.Load() {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>disposable retention fault</Message></Error>")
				return
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(gate.Close)
	key := []byte(strings.Repeat("r", 32))
	opts := storage.Options{Mode: "external", DatabaseURL: u.String(), RecordingKey: key, KeyID: storage.DeriveKeyID(key), S3: storage.S3Options{
		Endpoint: gate.URL, Region: "us-east-1", Bucket: strings.ReplaceAll(name, "_", "-"), CreateBucket: true, ForcePathStyle: true,
		AccessKey: os.Getenv("KW_EXECUTION_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("KW_EXECUTION_TEST_S3_SECRET_KEY"),
	}}
	open := func() storage.Store {
		t.Helper()
		s, err := storage.Open(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	s := open()
	code := 0
	stub := &stubQGA{target: eligibleTarget(), result: &qga.GuestResult{Outcome: "completed", ExitCode: &code, Stdout: []byte("protected retention output")}}
	permissions := []string{string(auth.PermissionExec), string(auth.PermissionElevated), string(auth.PermissionManage), string(auth.PermissionReadRecordings)}
	stack := newStoredStartStack(t, "team", "vm", permissions, enabledElevatedPolicy(), stub, s)
	w := stack.post(`{"namespace":"team","workspace_name":"vm","executable":"whoami","args":[]}`, "")
	if w.Code != 200 || len(stub.commands) != 1 {
		t.Fatalf("retention fixture did not execute once: %d %s", w.Code, w.Body.String())
	}
	command := stub.commands[0]
	path := "/v1/executions/" + command.ExecutionID
	if _, batch, err := stack.execution.ExpireRecordingsBatch(ctx, "", time.Hour, 16); err != nil || batch.Checked != 0 || deletes.Load() != 0 {
		t.Fatalf("fresh evidence was expired: %+v %v", batch, err)
	}
	// Old active/unaudited/unsupported rows must never become deletion candidates.
	for _, kind := range []string{"admitted", "running", "unaudited", "shell", "upgrade"} {
		rec := storage.ExecutionRecord{ExecutionID: "protected-" + kind, RecordingID: "recording-" + kind, ActorID: "operator-uid", Operation: storage.OperationCommand, Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "workspace-uid", OSIdentity: "SYSTEM", Mode: "external", Durability: storage.DurabilityDurable, Admitted: true, AdmissionTime: time.Now().Add(-72 * time.Hour)}
		if kind == "shell" {
			rec.Operation = storage.OperationShell
		}
		if kind == "upgrade" {
			rec.Operation = storage.OperationUpgrade
		}
		if err := s.Metadata().Reserve(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if kind == "running" {
			if err := s.Metadata().Transition(ctx, rec.ExecutionID, storage.ExecutionOutcome{State: storage.StateRunning}); err != nil {
				t.Fatal(err)
			}
		} else if kind == "unaudited" {
			if err := s.Metadata().Transition(ctx, rec.ExecutionID, storage.ExecutionOutcome{State: storage.StateFailed, EndTime: time.Now().Add(-48 * time.Hour)}); err != nil {
				t.Fatal(err)
			}
		} else if kind == "shell" || kind == "upgrade" {
			if err := s.Metadata().Complete(ctx, rec.ExecutionID, storage.ExecutionOutcome{State: storage.StateSucceeded, EndTime: time.Now().Add(-48 * time.Hour)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	control, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close(context.Background()) })
	if _, err := control.Exec(ctx, `CREATE FUNCTION pg_temp.reject_retention_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'disposable retention audit fault'; END $$`); err != nil {
		t.Fatal(err)
	}
	fault := func(kind string) func() {
		t.Helper()
		query := fmt.Sprintf(`CREATE TRIGGER reject_retention_audit BEFORE INSERT ON execution_audit FOR EACH ROW WHEN (NEW.execution_id='%s' AND NEW.kind='%s') EXECUTE FUNCTION pg_temp.reject_retention_audit()`, command.ExecutionID, kind)
		if _, err := control.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
		return func() {
			if _, err := control.Exec(ctx, `DROP TRIGGER reject_retention_audit ON execution_audit`); err != nil {
				t.Fatal(err)
			}
		}
	}
	restore := fault("recording.expiry_started")
	if _, batch, err := stack.execution.ExpireRecordingsBatch(ctx, "", time.Nanosecond, 16); err != nil || batch.Failed != 1 || batch.Checked != 1 || deletes.Load() != 0 {
		t.Fatalf("audit failure did not block deletion: %+v %v", batch, err)
	}
	if expired, err := s.Metadata().RecordingExpired(ctx, command.ExecutionID); err != nil || expired {
		t.Fatal("failed expiry admission left a replay fence")
	}
	if w := stack.get(path+"/recording", true); w.Code != 200 {
		t.Fatal("failed expiry admission destroyed playback")
	}
	restore()
	blockDelete.Store(true)
	if _, batch, err := stack.execution.ExpireRecordingsBatch(ctx, "", time.Nanosecond, 16); err != nil || batch.Failed != 1 || batch.Checked != 1 || deletes.Load() == 0 {
		t.Fatalf("object deletion fault was not retained as pending: %+v %v", batch, err)
	}
	if expired, err := s.Metadata().RecordingExpired(ctx, command.ExecutionID); err != nil || !expired {
		t.Fatal("committed deletion intent did not fence replay")
	}
	stillPresent, err := s.Recording().Open(ctx, command.RecordingID)
	if err != nil {
		t.Fatal(err)
	}
	if err := stillPresent.Verify(ctx); err != nil {
		t.Fatal("delete-denial fixture unexpectedly removed recording objects")
	}
	_ = stillPresent.Close()
	for _, suffix := range []string{"/recording", "/recording/chunks/0", "/recording/chunks/1"} {
		if w := stack.get(path+suffix, true); w.Code != 404 || !strings.Contains(w.Body.String(), "expired by retention") {
			t.Fatalf("expired recording was not explicit: %d %s", w.Code, w.Body.String())
		}
	}
	if w := stack.get(path+"/recording", false); w.Code != 401 {
		t.Fatal("expired recording bypassed authentication")
	}
	denied := newStoredStartStack(t, "team", "vm", []string{string(auth.PermissionManage)}, enabledElevatedPolicy(), nil, s)
	if w := denied.get(path+"/recording", true); w.Code != http.StatusForbidden {
		t.Fatal("expiry status bypassed independent recording-read permission")
	}
	if w := stack.get(path, true); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"succeeded"`) {
		t.Fatal("expiry rewrote or hid known execution metadata")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// New process/store state resumes a committed plan even when the newly
	// configured duration would otherwise retain this recording for a year.
	reopened := open()
	recovery := execution.NewService(reopened)
	blockDelete.Store(false)
	restore = fault("recording.expired")
	if _, batch, err := recovery.ExpireRecordingsBatch(ctx, "", 365*24*time.Hour, 16); err != nil || batch.Failed != 1 || batch.Checked != 1 {
		t.Fatalf("terminal audit loss falsely completed expiry: %+v %v", batch, err)
	}
	var completed bool
	if err := pool.QueryRow(ctx, `SELECT completed_at IS NOT NULL FROM execution_recording_retention WHERE execution_id=$1`, command.ExecutionID).Scan(&completed); err != nil || completed {
		t.Fatal("expiry audit failure committed a completed marker")
	}
	restore()
	other := open()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := reopened
			if i%2 == 0 {
				store = other
			}
			if _, _, err := execution.NewService(store).ExpireRecordingsBatch(ctx, "", 365*24*time.Hour, 16); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	var started, expired, finished int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE kind='recording.expiry_started'),count(*) FILTER (WHERE kind='recording.expired'),count(*) FILTER (WHERE kind='finished') FROM execution_audit WHERE execution_id=$1`, command.ExecutionID).Scan(&started, &expired, &finished); err != nil || started != 1 || expired != 1 || finished != 1 {
		t.Fatalf("expiry duplicated/lost audit: %d/%d/%d %v", started, expired, finished, err)
	}
	if unfencedDelete.Load() || len(stub.commands) != 1 {
		t.Fatal("retention deleted without durable fencing or redispatched guest work")
	}
	rec, outcome, err := reopened.Metadata().Get(ctx, command.ExecutionID)
	if err != nil || outcome.State != storage.StateSucceeded {
		t.Fatal("retention deleted or rewrote terminal execution metadata")
	}
	if err := reopened.Metadata().Reserve(ctx, rec); !errors.Is(err, storage.ErrConflict) {
		t.Fatal("expired execution ID became reusable")
	}
	rec.ExecutionID = "replacement-execution"
	if err := reopened.Metadata().Reserve(ctx, rec); !errors.Is(err, storage.ErrConflict) {
		t.Fatal("expired recording ID became reusable")
	}
	if _, batch, err := recovery.ExpireRecordingsBatch(ctx, "", time.Nanosecond, 16); err != nil || batch.Checked != 0 {
		t.Fatalf("completed expiry repeated or protected work was selected: %+v %v", batch, err)
	}
	if _, err := reopened.Recording().Open(ctx, command.RecordingID); !errors.Is(err, storage.ErrNotFinalized) {
		t.Fatalf("recording objects survived completed deletion: %v", err)
	}
	// Worker startup/shutdown has a real cancellation/join path, not a detached
	// goroutine touching a closed pool. No additional guest executor is supplied.
	stop, err := recovery.StartRecordingRetention(ctx, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	stop()
}
