package kubeworkspaces

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution"
	"github.com/kube-workspaces/api/internal/execution/qga"
	"github.com/kube-workspaces/api/internal/execution/storage"
)

// The parent owns an isolated throwaway database/bucket and a DELETE fault gate.
// Timestamp aging below is an explicit fixture, not real-time/deployed acceptance.
func testMetadataRetention(t *testing.T, ctx context.Context, opts storage.Options, survivingID string) {
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
	meta := s.Metadata().(storage.MetadataRetentionStore)
	control, err := pgx.Connect(ctx, opts.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close(context.Background()) })
	code := 0
	stub := &stubQGA{target: eligibleTarget(), result: &qga.GuestResult{Outcome: "completed", ExitCode: &code}}
	grants := []string{string(auth.PermissionExec), string(auth.PermissionElevated), string(auth.PermissionManage), string(auth.PermissionReadRecordings)}
	stack := newStoredStartStack(t, "team", "vm", grants, enabledElevatedPolicy(), stub, s)
	old := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Microsecond)
	create := func(expire, unknown bool) qga.Command {
		t.Helper()
		if unknown {
			stub.result, stub.execErr = nil, qga.ErrTransport
		}
		w := stack.post(`{"namespace":"team","workspace_name":"vm","executable":"whoami","args":[]}`, "")
		stub.result, stub.execErr = &qga.GuestResult{Outcome: "completed", ExitCode: &code}, nil
		if w.Code != 200 {
			t.Fatalf("metadata fixture failed: %d %s", w.Code, w.Body.String())
		}
		command := stub.commands[len(stub.commands)-1]
		if expire {
			if _, batch, err := stack.execution.ExpireRecordingsBatch(ctx, "", time.Nanosecond, 100); err != nil || batch.Failed != 0 {
				t.Fatalf("recording cleanup failed: %+v %v", batch, err)
			}
		}
		// Keep fixture admission/outcome/expiry timestamps mutually consistent.
		if _, err := control.Exec(ctx, `UPDATE execution_executions SET admission_time=$2,end_time=$3 WHERE execution_id=$1`, command.ExecutionID, old, old.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := control.Exec(ctx, `UPDATE execution_recording_retention SET end_time=$2,planned_at=$3,completed_at=$4 WHERE execution_id=$1`, command.ExecutionID, old.Add(time.Hour), old.Add(2*time.Hour), old.Add(3*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := control.Exec(ctx, `UPDATE execution_audit SET ts=$2 WHERE execution_id=$1`, command.ExecutionID, old.Add(4*time.Hour)); err != nil {
			t.Fatal(err)
		}
		return command
	}
	eligible := create(true, false)
	uncertain := create(true, true)
	recent := create(true, false)
	referenced := create(true, false)
	// Create this last: no later recording sweep should finish its pending plan.
	pending := create(false, false)
	if _, pendingExpiry, err := s.Metadata().(storage.RecordingRetentionMetadata).BeginRecordingExpiry(ctx, pending.ExecutionID, time.Now().Add(-time.Hour), time.Now()); err != nil || !pendingExpiry {
		t.Fatalf("pending plan fixture: %v %v", pendingExpiry, err)
	}
	if err := s.Metadata().Audit(ctx, storage.AuditEvent{ExecutionID: recent.ExecutionID, Time: time.Now(), Kind: "replay.expired", ActorID: "operator-uid"}); err != nil {
		t.Fatal(err)
	}
	// Deliberately misclassified legacy reference: it must still be retained.
	if _, err := control.Exec(ctx, `INSERT INTO agent_upgrade_attempts(attempt_id,idempotency_key,namespace,workspace_name,workspace_uid,vm_uid,actor_uid,target_id,target_manifest_sha256,expected_installed_inventory_sha256,expected_revocation_epoch,allow_reboot,execution_id,recording_id,state,created_at,updated_at)
		VALUES('retention-reference','retention-reference','team','vm','workspace-uid','vm-uid','operator-uid','target',$3,$3,0,false,$1,$2,'succeeded',$4,$4)`, referenced.ExecutionID, referenced.RecordingID, strings.Repeat("a", 64), old); err != nil {
		t.Fatal(err)
	}
	cutoff, now := time.Now().Add(-time.Hour), time.Now()
	candidates, err := meta.MetadataExpiryCandidates(ctx, "", cutoff, 100)
	if err != nil || len(candidates) != 2 {
		t.Fatalf("unexpected metadata candidates: %d %v", len(candidates), err)
	}
	for _, rec := range candidates {
		if rec.ExecutionID != eligible.ExecutionID && rec.ExecutionID != uncertain.ExecutionID {
			t.Fatal("recent/unfinished/referenced metadata was selected")
		}
	}
	for _, id := range []string{recent.ExecutionID, referenced.ExecutionID, pending.ExecutionID, survivingID, "protected-running", "protected-unaudited", "protected-shell", "protected-upgrade"} {
		if purged, err := meta.PurgeExpiredMetadata(ctx, id, cutoff, now); err != nil || purged {
			t.Fatalf("protected metadata purged: %s %v %v", id, purged, err)
		}
	}
	// Audit insertion locks the execution parent. Purging cannot race past an
	// uncommitted recent event, then discard it using only an old end time.
	auditTx, err := control.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditTx.Exec(ctx, `INSERT INTO execution_audit(execution_id,ts,kind,actor_id) VALUES($1,$2,'recent-race','operator-uid')`, eligible.ExecutionID, time.Now()); err != nil {
		t.Fatal(err)
	}
	blocked, stop := context.WithTimeout(ctx, 150*time.Millisecond)
	if purged, err := meta.PurgeExpiredMetadata(blocked, eligible.ExecutionID, cutoff, now); err == nil || purged {
		t.Fatal("purge bypassed a concurrent audit lock")
	}
	stop()
	if err := auditTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if purged, err := meta.PurgeExpiredMetadata(ctx, eligible.ExecutionID, cutoff, now); err != nil || purged {
		t.Fatal("new audit did not renew retention protection")
	}
	if _, err := control.Exec(ctx, `UPDATE execution_audit SET ts=$2 WHERE execution_id=$1 AND kind='recent-race'`, eligible.ExecutionID, old.Add(4*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Exec(ctx, `CREATE FUNCTION pg_temp.reject_metadata_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'disposable deletion receipt fault'; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Exec(ctx, `CREATE TRIGGER reject_metadata_receipt BEFORE UPDATE ON execution_identities FOR EACH ROW WHEN (NEW.execution_id='`+eligible.ExecutionID+`' AND NEW.metadata_purged_at IS NOT NULL) EXECUTE FUNCTION pg_temp.reject_metadata_receipt()`); err != nil {
		t.Fatal(err)
	}
	if purged, err := meta.PurgeExpiredMetadata(ctx, eligible.ExecutionID, cutoff, now); err == nil || purged {
		t.Fatal("receipt fault allowed partial metadata deletion")
	}
	if _, _, err := s.Metadata().Get(ctx, eligible.ExecutionID); err != nil {
		t.Fatal("receipt failure deleted execution row")
	}
	var auditCount int
	if err := control.QueryRow(ctx, `SELECT count(*) FROM execution_audit WHERE execution_id=$1`, eligible.ExecutionID).Scan(&auditCount); err != nil || auditCount == 0 {
		t.Fatal("receipt failure deleted audit history")
	}
	if _, err := control.Exec(ctx, `DROP TRIGGER reject_metadata_receipt ON execution_identities`); err != nil {
		t.Fatal(err)
	}
	var oldRecords []storage.ExecutionRecord
	for _, command := range []qga.Command{eligible, uncertain} {
		rec, _, err := s.Metadata().Get(ctx, command.ExecutionID)
		if err != nil {
			t.Fatal(err)
		}
		oldRecords = append(oldRecords, rec)
	}
	t.Run("lost-metadata-commit-ack", func(t *testing.T) {
		u, err := url.Parse(opts.DatabaseURL)
		if err != nil || u.Query().Get("sslmode") != "disable" {
			t.Skip("wire inspection requires an explicitly plaintext disposable PostgreSQL URL")
		}
		address := u.Host
		if u.Port() == "" {
			address = net.JoinHostPort(u.Hostname(), "5432")
		}
		gate, armed, dropped := newCommitAckLossGate(t, address)
		u.Host = gate.listener.Addr().String()
		through := opts
		through.DatabaseURL = u.String()
		gated := openRecoveryStore(t, ctx, through)
		gatedMeta := gated.Metadata().(storage.MetadataRetentionStore)
		armed.Store(true)
		if purged, err := gatedMeta.PurgeExpiredMetadata(ctx, uncertain.ExecutionID, cutoff, time.Now()); err == nil || purged {
			t.Fatal("lost COMMIT acknowledgement did not surface uncertainty")
		}
		if dropped.Load() != 1 {
			t.Fatal("metadata purge did not drop exactly one actual COMMIT acknowledgement")
		}
		var receiptTime time.Time
		if err := control.QueryRow(ctx, `SELECT metadata_purged_at FROM execution_identities WHERE execution_id=$1`, uncertain.ExecutionID).Scan(&receiptTime); err != nil {
			t.Fatal("lost ACK erased the committed deletion receipt")
		}
		if _, _, err := s.Metadata().Get(ctx, uncertain.ExecutionID); !errors.Is(err, storage.ErrNotFound) {
			t.Fatal("lost ACK did not commit metadata deletion atomically")
		}
		if purged, err := gatedMeta.PurgeExpiredMetadata(ctx, uncertain.ExecutionID, cutoff, time.Now()); err != nil || purged {
			t.Fatal("lost-ACK retry was not an idempotent no-op")
		}
		var after time.Time
		if err := control.QueryRow(ctx, `SELECT metadata_purged_at FROM execution_identities WHERE execution_id=$1`, uncertain.ExecutionID).Scan(&after); err != nil || !after.Equal(receiptTime) {
			t.Fatal("lost-ACK retry rewrote the deletion receipt")
		}
	})
	beforeDispatch := len(stub.commands)
	other := open()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := s
			if i%2 == 0 {
				store = other
			}
			if _, _, err := execution.NewService(store).ExpireMetadataBatch(ctx, "", time.Hour, 16); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if len(stub.commands) != beforeDispatch {
		t.Fatal("metadata retention redispatched guest work")
	}
	for _, rec := range oldRecords {
		if _, _, err := s.Metadata().Get(ctx, rec.ExecutionID); !errors.Is(err, storage.ErrNotFound) {
			t.Fatal("expired metadata survived purge")
		}
		var receipt []byte
		if err := control.QueryRow(ctx, `SELECT row_to_json(i) FROM execution_identities i WHERE execution_id=$1 AND metadata_purged_at IS NOT NULL AND audit_events_deleted>0`, rec.ExecutionID).Scan(&receipt); err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if json.Unmarshal(receipt, &fields) != nil || fields["system_actor"] != "system:execution-retention" || strings.Contains(string(receipt), "operator-uid") || strings.Contains(string(receipt), "workspace-uid") {
			t.Fatal("deletion receipt lost audit or retained original identity/scope")
		}
		if err := control.QueryRow(ctx, `SELECT count(*) FROM execution_audit WHERE execution_id=$1`, rec.ExecutionID).Scan(&auditCount); err != nil || auditCount != 0 {
			t.Fatal("purge left orphan audit payloads")
		}
		if err := s.Metadata().Reserve(ctx, rec); !errors.Is(err, storage.ErrConflict) {
			t.Fatal("purged execution ID was readmitted")
		}
		changed := rec
		changed.ExecutionID += "-retry"
		if err := s.Metadata().Reserve(ctx, changed); !errors.Is(err, storage.ErrConflict) {
			t.Fatal("purged recording ID was reused")
		}
		if err := s.Metadata().Audit(ctx, storage.AuditEvent{ExecutionID: rec.ExecutionID, Time: time.Now(), Kind: "late-reader"}); err == nil {
			t.Fatal("late reader created orphan audit after purge")
		}
		// Bypass the Go admission helper to model a legacy writer. The database
		// reservation trigger itself must reject resurrecting either identity.
		_, err := control.Exec(ctx, `INSERT INTO execution_executions(execution_id,actor_id,operation,namespace,workspace_name,workspace_uid,workspace_generation,grant_version,os_identity,elevated,recording_id,mode,durability,admission_time,admitted)
			SELECT $1,actor_id,operation,namespace,workspace_name,workspace_uid,workspace_generation,grant_version,os_identity,elevated,$2,mode,durability,admission_time,admitted FROM execution_executions WHERE execution_id=$3`, rec.ExecutionID, rec.RecordingID, survivingID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			t.Fatal("legacy SQL bypassed lifetime identity reservation")
		}
		if w := stack.get("/v1/executions/"+rec.ExecutionID, true); w.Code != 404 {
			t.Fatal("purged execution was still served over HTTP")
		}
	}
	if _, batch, err := stack.execution.ExpireMetadataBatch(ctx, "", time.Hour, 16); err != nil || batch.Checked != 0 {
		t.Fatalf("metadata expiry repeated or selected protected history: %+v %v", batch, err)
	}
	reopened := open()
	for _, rec := range oldRecords {
		if err := reopened.Metadata().Reserve(ctx, rec); !errors.Is(err, storage.ErrConflict) {
			t.Fatal("store reopen forgot purged ID reservation")
		}
		if purged, err := reopened.Metadata().(storage.MetadataRetentionStore).PurgeExpiredMetadata(ctx, rec.ExecutionID, cutoff, time.Now()); err != nil || purged {
			t.Fatal("purge retry was not an idempotent no-op")
		}
	}
	stopWorker, err := execution.NewService(reopened).StartMetadataRetention(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	stopWorker()
}
