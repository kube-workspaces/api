package storage

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/execution/updates"
)

func phaseFixture(t *testing.T, attempts AgentUpgradeStore, metadata MetadataStore, now time.Time) (UpgradePhaseIntent, updates.PhasePermit) {
	t.Helper()
	ctx := context.Background()
	raw, err := os.ReadFile("../updates/testdata/journal-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot updates.JournalSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	a := validUpgradeAttempt(fmt.Sprintf("upg_%d", time.Now().UnixNano()))
	a.VMUID = a.AttemptID
	a.ExpectedRevocationEpoch = 7
	if err := attempts.Reserve(ctx, a); err != nil {
		t.Fatal(err)
	}
	fence, err := attempts.ClaimLease(ctx, a.AttemptID, "worker", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	predecessor := AttemptPredecessor{TargetID: "previous", ManifestSHA256: snapshot.Plan.Binding.PreviousSHA256}
	if err := attempts.Transition(ctx, a.AttemptID, AttemptAdmitted, AttemptTransition{
		To: AttemptStaging, Now: now, Fence: &fence, Predecessor: &predecessor,
	}); err != nil {
		t.Fatal(err)
	}
	rec := ExecutionRecord{
		ExecutionID: a.ExecutionID, RecordingID: a.RecordingID, ActorID: a.ActorUID,
		Operation: OperationUpgrade, Namespace: a.Namespace, WorkspaceName: a.WorkspaceName, WorkspaceUID: a.WorkspaceUID,
		OSIdentity: "SYSTEM", Elevated: true, Durability: DurabilityDurable, Mode: "external", AdmissionTime: now, Admitted: true,
	}
	if err := metadata.Reserve(ctx, rec); err != nil {
		t.Fatal(err)
	}
	snapshot.Plan.Binding = updates.JournalBinding{
		AttemptID: a.AttemptID, Namespace: a.Namespace, WorkspaceName: a.WorkspaceName,
		WorkspaceUID: a.WorkspaceUID, VMUID: a.VMUID, RevocationEpoch: a.ExpectedRevocationEpoch,
		ActorUID: a.ActorUID, RecordingID: a.RecordingID, TargetSHA256: a.TargetManifestSHA256,
		PreviousSHA256: predecessor.ManifestSHA256, InventorySHA256: a.ExpectedInstalledInventorySHA256,
	}
	snapshot.OwnerFence = fence
	snapshot.StartedAt, snapshot.UpdatedAt, snapshot.ExpiresAt = now.Unix(), now.Unix(), now.Unix()+updates.AttemptSeconds
	raw, err = json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	i := UpgradePhaseIntent{
		AttemptID: a.AttemptID, Owner: "worker", Fence: fence, PlanSHA256: snapshot.Plan.SHA256(),
		CheckpointSHA256: updates.Digest(append([]byte("kw-agent-upgrade-journal/v1\x00"), raw...)),
		Checkpoint:       raw, RecordedAt: now,
		Receipt: PhaseRecordingReceipt{RecordingID: a.RecordingID, ChunkIndex: 1, ChunkSHA256: updates.Digest(raw)},
	}
	if _, err := i.Journal(); err != nil {
		t.Fatalf("invalid synthetic intent: %v", err)
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	permit := updates.PhasePermit{
		Version: 1, Audience: "agent-upgrade.phase.v1", PlanSHA256: i.PlanSHA256,
		Action: *snapshot.Active, OwnerFence: fence, Challenge: base64.RawURLEncoding.EncodeToString(nonce[:]),
		PeerSHA256: updates.Digest([]byte("synthetic peer")), IssuedAt: now.Unix(), ExpiresAt: now.Unix() + 15,
	}
	return i, permit
}

func TestPostgresUpgradePhasesIntegration(t *testing.T) {
	dsn := os.Getenv("KW_EXECUTION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set KW_EXECUTION_TEST_DATABASE_URL for disposable PostgreSQL")
	}
	ctx := context.Background()
	attempts, err := NewPostgresAgentUpgrades(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer attempts.Close()
	metadata, err := NewPostgresMetadata(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Close()
	first, err := NewPostgresUpgradePhases(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewPostgresUpgradePhases(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	t.Run("one-durable-claim-across-replicas", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		i, permit := phaseFixture(t, attempts, metadata, now)
		if err := first.ClaimPhase(ctx, i.AttemptID, i.Owner, permit, now); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unrecorded intent: %v", err)
		}
		if err := first.RecordIntent(ctx, i); err != nil {
			t.Fatal(err)
		}
		if err := second.RecordIntent(ctx, i); !errors.Is(err, ErrConflict) {
			t.Fatalf("duplicate intent: %v", err)
		}
		var wg sync.WaitGroup
		errs := make(chan error, 16)
		for n := 0; n < 16; n++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				ledger := first
				if n%2 != 0 {
					ledger = second
				}
				errs <- ledger.ClaimPhase(ctx, i.AttemptID, i.Owner, permit, now)
			}(n)
		}
		wg.Wait()
		close(errs)
		winners := 0
		for err := range errs {
			if err == nil {
				winners++
			} else if !errors.Is(err, ErrConflict) {
				t.Fatal(err)
			}
		}
		if winners != 1 {
			t.Fatalf("claim winners: %d", winners)
		}
		reopened, err := NewPostgresUpgradePhases(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		if err := reopened.ClaimPhase(ctx, i.AttemptID, i.Owner, permit, now); !errors.Is(err, ErrConflict) {
			t.Fatalf("reopen replay: %v", err)
		}
		// Even a different action/attempt cannot reuse a guest challenge.
		other, otherPermit := phaseFixture(t, attempts, metadata, now)
		if err := first.RecordIntent(ctx, other); err != nil {
			t.Fatal(err)
		}
		otherPermit.Challenge = permit.Challenge
		if err := second.ClaimPhase(ctx, other.AttemptID, other.Owner, otherPermit, now); !errors.Is(err, ErrConflict) {
			t.Fatalf("cross-attempt challenge replay: %v", err)
		}
	})
	for _, mutation := range []string{"cancel", "expired", "stolen", "owner", "boot", "action", "plan", "fence", "deadline", "recording-terminal", "journal-ahead"} {
		t.Run(mutation, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Millisecond)
			var err error
			i, permit := phaseFixture(t, attempts, metadata, now)
			if err := first.RecordIntent(ctx, i); err != nil {
				t.Fatal(err)
			}
			at, owner := now, i.Owner
			switch mutation {
			case "cancel":
				err = attempts.RequestCancel(ctx, i.AttemptID, now)
			case "expired":
				at = now.Add(time.Minute)
				permit.IssuedAt, permit.ExpiresAt = at.Unix(), at.Unix()+15
			case "stolen":
				_, err = attempts.ClaimLease(ctx, i.AttemptID, "replacement", now.Add(time.Minute), time.Minute)
			case "owner":
				owner = "other"
			case "boot":
				permit.Action.BootID = "other-boot"
			case "action":
				permit.Action.Kind = "uninstall_target_msi"
			case "plan":
				permit.PlanSHA256 = updates.Digest([]byte("other plan"))
			case "fence":
				permit.OwnerFence++
			case "deadline":
				permit.IssuedAt = now.Add(50 * time.Second).Unix()
				permit.ExpiresAt = permit.IssuedAt + 15
				at = now.Add(50 * time.Second)
			case "recording-terminal":
				a, getErr := attempts.Get(ctx, i.AttemptID)
				if getErr != nil {
					t.Fatal(getErr)
				}
				err = metadata.Transition(ctx, a.ExecutionID, ExecutionOutcome{State: StateRecordingLost, EndTime: now, RecordingLost: true})
			case "journal-ahead":
				sequence := permit.Action.Sequence + 1
				err = attempts.Transition(ctx, i.AttemptID, AttemptStaging, AttemptTransition{To: AttemptPrepared, Now: now, Fence: &i.Fence, JournalSequence: &sequence})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := second.ClaimPhase(ctx, i.AttemptID, owner, permit, at); err == nil {
				t.Fatal("changed authority allowed phase")
			}
		})
	}
	t.Run("stale-caller-clock-cannot-extend-lease", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		i, permit := phaseFixture(t, attempts, metadata, now)
		if err := first.RecordIntent(ctx, i); err != nil {
			t.Fatal(err)
		}
		// Model a caller sampled before a lock wait. At acquisition the lease
		// has expired, but the caller's original timestamp still predates it.
		if _, err := first.(*postgresPhases).pool.Exec(ctx, `UPDATE agent_upgrade_attempts
			SET lease_expires_at=clock_timestamp() WHERE attempt_id=$1`, i.AttemptID); err != nil {
			t.Fatal(err)
		}
		if err := second.ClaimPhase(ctx, i.AttemptID, i.Owner, permit, now); !errors.Is(err, ErrLeaseExpired) {
			t.Fatalf("stale caller time extended lease: %v", err)
		}
	})
	t.Run("receipt-and-plan-pinning", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		i, _ := phaseFixture(t, attempts, metadata, now)
		bad := i
		bad.Receipt.RecordingID = "other"
		if err := first.RecordIntent(ctx, bad); err == nil {
			t.Fatal("wrong recording accepted")
		}
		bad = i
		bad.Receipt.ChunkSHA256 = updates.Digest([]byte("wrong chunk"))
		if err := first.RecordIntent(ctx, bad); err == nil {
			t.Fatal("wrong chunk accepted")
		}
		if err := first.RecordIntent(ctx, i); err != nil {
			t.Fatal(err)
		}
		var snapshot updates.JournalSnapshot
		if err := json.Unmarshal(i.Checkpoint, &snapshot); err != nil {
			t.Fatal(err)
		}
		snapshot.Plan.TargetProductCode = "abcdef12-1234-1234-1234-123456789abc"
		snapshot.Sequence++
		snapshot.Active.Sequence++
		i.Checkpoint, _ = json.Marshal(snapshot)
		i.PlanSHA256 = snapshot.Plan.SHA256()
		i.CheckpointSHA256 = updates.Digest(append([]byte("kw-agent-upgrade-journal/v1\x00"), i.Checkpoint...))
		i.Receipt.ChunkIndex++
		i.Receipt.ChunkSHA256 = updates.Digest(i.Checkpoint)
		if err := first.RecordIntent(ctx, i); !errors.Is(err, ErrConflict) {
			t.Fatalf("changed plan accepted: %v", err)
		}
	})
}
