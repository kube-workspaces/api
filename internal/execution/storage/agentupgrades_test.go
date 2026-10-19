package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func validUpgradeAttempt(attemptID string) AgentUpgradeAttempt {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return AgentUpgradeAttempt{
		AttemptID:                        attemptID,
		IdempotencyKey:                   "idem-" + attemptID,
		Namespace:                        "team",
		WorkspaceName:                    "vm",
		WorkspaceUID:                     "ws-uid",
		VMUID:                            "vm-uid",
		ActorUID:                         "actor-uid",
		TargetID:                         "windows11-amd64-v2",
		TargetManifestSHA256:             strings.Repeat("a", 64),
		ExpectedInstalledInventorySHA256: strings.Repeat("b", 64),
		ExecutionID:                      "exec_" + attemptID[len("upg_"):],
		RecordingID:                      "rec_" + attemptID[len("upg_"):],
		State:                            AttemptAdmitted,
		CreatedAt:                        now,
		UpdatedAt:                        now,
	}
}

func TestAttemptStateClassification(t *testing.T) {
	reservationHolding := []AttemptState{
		AttemptAdmitted, AttemptStaging, AttemptPrepared, AttemptInstalling,
		AttemptVerifying, AttemptAwaitingReboot, AttemptRollbackPending, AttemptRollingBack,
		AttemptManualRecoveryRequired, AttemptUnknown, AttemptRecordingLost,
	}
	released := []AttemptState{AttemptSucceeded, AttemptCancelled, AttemptFailed, AttemptRolledBack}
	for _, st := range reservationHolding {
		if !st.HoldsReservation() {
			t.Fatalf("%s must hold the VM reservation", st)
		}
	}
	for _, st := range released {
		if st.HoldsReservation() {
			t.Fatalf("%s must release the VM reservation", st)
		}
	}
	claimable := []AttemptState{
		AttemptAdmitted, AttemptStaging, AttemptPrepared, AttemptInstalling,
		AttemptVerifying, AttemptAwaitingReboot, AttemptRollbackPending, AttemptRollingBack,
	}
	for _, st := range ValidAttemptStates {
		want := false
		for _, c := range claimable {
			if c == st {
				want = true
			}
		}
		if st.Claimable() != want {
			t.Fatalf("claimable mismatch for %s", st)
		}
	}
	// A failed attempt keeps its recording open for an admitted rollback.
	if !AttemptFailed.Valid() || AttemptFailed.Terminal() != true || AttemptFailed.RecordingFinal() {
		t.Fatal("failed must be terminal but not recording-final")
	}
	if AttemptRecordingLost.Terminal() != true || !AttemptRecordingLost.RecordingFinal() {
		t.Fatal("recording_lost must be terminal and recording-final")
	}
}

func TestValidAttemptTransitions(t *testing.T) {
	valid := map[[2]AttemptState]bool{
		{AttemptAdmitted, AttemptStaging}:                 true,
		{AttemptAdmitted, AttemptCancelled}:               true,
		{AttemptAdmitted, AttemptFailed}:                  true,
		{AttemptStaging, AttemptPrepared}:                 true,
		{AttemptPrepared, AttemptInstalling}:              true,
		{AttemptInstalling, AttemptVerifying}:             true,
		{AttemptInstalling, AttemptAwaitingReboot}:        true,
		{AttemptVerifying, AttemptSucceeded}:              true,
		{AttemptVerifying, AttemptAwaitingReboot}:         true,
		{AttemptAwaitingReboot, AttemptInstalling}:        true,
		{AttemptFailed, AttemptRollbackPending}:           true,
		{AttemptFailed, AttemptCancelled}:                 true,
		{AttemptRollbackPending, AttemptRollingBack}:      true,
		{AttemptRollingBack, AttemptRolledBack}:           true,
		{AttemptManualRecoveryRequired, AttemptCancelled}: true,
		{AttemptUnknown, AttemptCancelled}:                true,
		{AttemptRecordingLost, AttemptCancelled}:          true,
		{AttemptSucceeded, AttemptCancelled}:              false,
		{AttemptSucceeded, AttemptInstalling}:             false,
		{AttemptAdmitted, AttemptSucceeded}:               false,
		{AttemptAdmitted, AttemptAdmitted}:                false,
		{AttemptCancelled, AttemptCancelled}:              false,
		{AttemptFailed, AttemptStaging}:                   false,
	}
	for _, from := range ValidAttemptStates {
		for _, to := range ValidAttemptStates {
			want, known := valid[[2]AttemptState{from, to}]
			if !known {
				continue
			}
			if got := validAttemptTransition(from, to); got != want {
				t.Fatalf("transition %s -> %s = %v, want %v", from, to, got, want)
			}
		}
	}
}

func TestMemoryAgentUpgradeStoreReservations(t *testing.T) {
	ctx := context.Background()
	store, err := NewMemoryAgentUpgrades(10)
	if err != nil {
		t.Fatal(err)
	}
	a := validUpgradeAttempt("upg_aaaaaaaaaaaaaaaa")
	if err := store.Reserve(ctx, a); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// Duplicate attempt id conflicts.
	if err := store.Reserve(ctx, a); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate attempt id: %v", err)
	}
	// Same idempotency key with a different request conflicts.
	idem := validUpgradeAttempt("upg_bbbbbbbbbbbbbbbb")
	idem.IdempotencyKey = a.IdempotencyKey
	if err := store.Reserve(ctx, idem); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict: %v", err)
	}
	// A different idempotency key still cannot take the same VM.
	other := validUpgradeAttempt("upg_cccccccccccccccc")
	if err := store.Reserve(ctx, other); !errors.Is(err, ErrVMReserved) {
		t.Fatalf("vm reservation: %v", err)
	}
	// Cancelled/succeeded/failed/rolled_back release the reservation.
	if err := store.Transition(ctx, a.AttemptID, AttemptAdmitted, AttemptTransition{To: AttemptCancelled, Now: time.Now().UTC()}); err != nil {
		t.Fatalf("transition: %v", err)
	}
	if err := store.Reserve(ctx, other); err != nil {
		t.Fatalf("reserve after release: %v", err)
	}
	// GetByIdempotency finds the admitted attempt.
	got, err := store.GetByIdempotency(ctx, "team", "vm", other.IdempotencyKey)
	if err != nil || got.AttemptID != other.AttemptID {
		t.Fatalf("get by idempotency: %+v %v", got, err)
	}
	// ActiveAttempt returns the reservation-holding attempt.
	active, err := store.ActiveAttempt(ctx, "vm-uid")
	if err != nil || active.AttemptID != other.AttemptID {
		t.Fatalf("active attempt: %+v %v", active, err)
	}
}

func TestMemoryAgentUpgradeStoreLeaseFencing(t *testing.T) {
	ctx := context.Background()
	store, err := NewMemoryAgentUpgrades(10)
	if err != nil {
		t.Fatal(err)
	}
	a := validUpgradeAttempt("upg_aaaaaaaaaaaaaaaa")
	if err := store.Reserve(ctx, a); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	fence, err := store.ClaimLease(ctx, a.AttemptID, "worker-1", now, time.Minute)
	if err != nil || fence == 0 {
		t.Fatalf("claim: %d %v", fence, err)
	}
	// A second worker cannot steal an unexpired lease.
	if _, err := store.ClaimLease(ctx, a.AttemptID, "worker-2", now, time.Minute); !errors.Is(err, ErrConflict) {
		t.Fatalf("steal attempt: %v", err)
	}
	// Renewal requires the exact owner and fence.
	if err := store.RenewLease(ctx, a.AttemptID, "worker-1", fence+1, now, time.Minute); !errors.Is(err, ErrFenced) {
		t.Fatalf("fenced renewal: %v", err)
	}
	if err := store.RenewLease(ctx, a.AttemptID, "worker-1", fence, now.Add(2*time.Minute), time.Minute); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired renewal: %v", err)
	}
	// An expired lease may be stolen, bumping the fence.
	stolenFence, err := store.ClaimLease(ctx, a.AttemptID, "worker-2", now.Add(2*time.Minute), time.Minute)
	if err != nil || stolenFence <= fence {
		t.Fatalf("steal after expiry: %d %v", stolenFence, err)
	}
	// Worker transitions must prove the fence; the old fence is rejected.
	if err := store.Transition(ctx, a.AttemptID, AttemptAdmitted, AttemptTransition{
		To: AttemptStaging, Now: now, Fence: &fence,
	}); !errors.Is(err, ErrFenced) {
		t.Fatalf("stale fence transition: %v", err)
	}
	// The current holder advances the attempt; the lease is kept.
	current := stolenFence
	if err := store.Transition(ctx, a.AttemptID, AttemptAdmitted, AttemptTransition{
		To: AttemptStaging, Now: now, Fence: &current,
	}); err != nil {
		t.Fatalf("fenced transition: %v", err)
	}
	// Administrative transitions fence the worker out.
	if err := store.Transition(ctx, a.AttemptID, AttemptStaging, AttemptTransition{To: AttemptCancelled, Now: now}); err != nil {
		t.Fatalf("admin transition: %v", err)
	}
	if err := store.RenewLease(ctx, a.AttemptID, "worker-2", current, now, time.Minute); !errors.Is(err, ErrFenced) {
		t.Fatalf("lease survived admin transition: %v", err)
	}
	// Release requires owner+fence.
	a2 := validUpgradeAttempt("upg_dddddddddddddddd")
	a2.VMUID = "vm-uid-2"
	if err := store.Reserve(ctx, a2); err != nil {
		t.Fatal(err)
	}
	f2, err := store.ClaimLease(ctx, a2.AttemptID, "worker-1", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReleaseLease(ctx, a2.AttemptID, "worker-1", f2); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := store.ReleaseLease(ctx, a2.AttemptID, "worker-1", f2); !errors.Is(err, ErrFenced) {
		t.Fatalf("double release: %v", err)
	}
}

func TestMemoryAgentUpgradeStoreRequestCancel(t *testing.T) {
	ctx := context.Background()
	store, err := NewMemoryAgentUpgrades(10)
	if err != nil {
		t.Fatal(err)
	}
	a := validUpgradeAttempt("upg_aaaaaaaaaaaaaaaa")
	if err := store.Reserve(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := store.RequestCancel(ctx, "upg_missing", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing attempt: %v", err)
	}
	now := time.Now().UTC()
	if err := store.RequestCancel(ctx, a.AttemptID, now); err != nil {
		t.Fatalf("request cancel: %v", err)
	}
	got, err := store.Get(ctx, a.AttemptID)
	if err != nil || !got.CancelRequested || got.State != AttemptAdmitted {
		t.Fatalf("cancel flag must not change the state: %+v %v", got, err)
	}
	// Idempotent re-request is a no-op.
	if err := store.RequestCancel(ctx, a.AttemptID, now); err != nil {
		t.Fatalf("idempotent cancel: %v", err)
	}
}
