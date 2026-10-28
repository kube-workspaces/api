package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Run the same authority contract against RAM and two independent database
// connections. The database variant uses only explicitly supplied test storage.
func exerciseUpgradeAuthority(t *testing.T, first, second AgentUpgradeStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	a := validUpgradeAttempt(fmt.Sprintf("upg_%d", time.Now().UnixNano()))
	a.VMUID = a.AttemptID
	if err := first.Reserve(ctx, a); err != nil {
		t.Fatal(err)
	}
	fence, err := first.ClaimLease(ctx, a.AttemptID, "worker-1", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{now.Add(time.Minute), now.Add(2 * time.Minute)} {
		err := second.Transition(ctx, a.AttemptID, AttemptAdmitted, AttemptTransition{
			To: AttemptStaging, Now: at, Fence: &fence,
		})
		if !errors.Is(err, ErrLeaseExpired) {
			t.Fatalf("expired transition at %s: %v", at, err)
		}
	}
	for _, ttl := range []time.Duration{0, -time.Second} {
		if err := first.RenewLease(ctx, a.AttemptID, "worker-1", fence, now, ttl); !errors.Is(err, ErrConflict) {
			t.Fatalf("invalid renewal ttl: %v", err)
		}
	}
	if err := first.RenewLease(ctx, a.AttemptID, "", fence, now, time.Minute); !errors.Is(err, ErrConflict) {
		t.Fatalf("empty renewal owner: %v", err)
	}
	sequence := uint64(10)
	if err := first.Transition(ctx, a.AttemptID, AttemptAdmitted, AttemptTransition{
		To: AttemptStaging, Now: now, Fence: &fence, JournalSequence: &sequence,
	}); err != nil {
		t.Fatal(err)
	}
	sequence--
	if err := second.Transition(ctx, a.AttemptID, AttemptStaging, AttemptTransition{
		To: AttemptPrepared, Now: now, Fence: &fence, JournalSequence: &sequence,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("journal regression: %v", err)
	}
	if err := second.RequestCancel(ctx, a.AttemptID, now); err != nil {
		t.Fatal(err)
	}
	clearCancel := false
	sequence++
	if err := first.Transition(ctx, a.AttemptID, AttemptStaging, AttemptTransition{
		To: AttemptPrepared, Now: now, Fence: &fence, JournalSequence: &sequence, CancelRequested: &clearCancel,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := second.Get(ctx, a.AttemptID)
	if err != nil || !got.CancelRequested || got.JournalSequence != sequence {
		t.Fatalf("cancellation/sequence lost: %+v %v", got, err)
	}
	// Cancellation is sticky but does not kill an already-running transaction:
	// safe-boundary progress and administrator cancellation remain possible.
	if err := second.Transition(ctx, a.AttemptID, AttemptPrepared, AttemptTransition{
		To: AttemptCancelled, Now: now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if err := first.RenewLease(ctx, a.AttemptID, "worker-1", fence, now, time.Minute); !errors.Is(err, ErrFenced) {
		t.Fatalf("administrative transition did not fence worker: %v", err)
	}

	// Cancellation and progress race on separate connections; neither ordering
	// may lose the cancel flag or the worker's journal checkpoint.
	for i := 0; i < 32; i++ {
		a := validUpgradeAttempt(fmt.Sprintf("upg_%d_%d", time.Now().UnixNano(), i))
		a.VMUID = a.AttemptID
		if err := first.Reserve(ctx, a); err != nil {
			t.Fatal(err)
		}
		fence, err := first.ClaimLease(ctx, a.AttemptID, "worker", now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			errs <- first.Transition(ctx, a.AttemptID, AttemptAdmitted, AttemptTransition{
				To: AttemptStaging, Now: now, Fence: &fence, JournalSequence: &sequence,
			})
		}()
		go func() {
			defer wg.Done()
			<-start
			errs <- second.RequestCancel(ctx, a.AttemptID, now)
		}()
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := second.Get(ctx, a.AttemptID)
		if err != nil || !got.CancelRequested || got.JournalSequence != sequence || got.State != AttemptStaging {
			t.Fatalf("concurrent checkpoint/cancel lost: %+v %v", got, err)
		}
	}
}

func TestMemoryUpgradeAuthority(t *testing.T) {
	store, err := NewMemoryAgentUpgrades(100)
	if err != nil {
		t.Fatal(err)
	}
	exerciseUpgradeAuthority(t, store, store)
}

func TestPostgresUpgradeAuthorityIntegration(t *testing.T) {
	dsn := os.Getenv("KW_EXECUTION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set KW_EXECUTION_TEST_DATABASE_URL for disposable PostgreSQL")
	}
	first, err := NewPostgresAgentUpgrades(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewPostgresAgentUpgrades(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	exerciseUpgradeAuthority(t, first, second)
	t.Run("cancel-while-transition-blocked", func(t *testing.T) {
		exerciseBlockedUpgradeCancel(t, first.(*postgresUpgrades), second.(*postgresUpgrades))
	})
}

// Force the lost-update interleaving: hold a row lock, start a transition,
// persist cancellation under that lock, then let the transition finish. Without
// locking the initial read, the transition reads false and overwrites true.
func exerciseBlockedUpgradeCancel(t *testing.T, first, second *postgresUpgrades) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Millisecond)
	a := validUpgradeAttempt(fmt.Sprintf("upg_%d_blocked", time.Now().UnixNano()))
	a.VMUID = a.AttemptID
	if err := first.Reserve(ctx, a); err != nil {
		t.Fatal(err)
	}
	fence, err := first.ClaimLease(ctx, a.AttemptID, "worker", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	config := first.pool.Config()
	config.ConnConfig.RuntimeParams["application_name"] = a.AttemptID
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	worker := &postgresUpgrades{pool: pool}
	blocker, err := second.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, `SELECT attempt_id FROM agent_upgrade_attempts WHERE attempt_id=$1 FOR UPDATE`, a.AttemptID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- worker.Transition(ctx, a.AttemptID, AttemptAdmitted, AttemptTransition{
			To: AttemptStaging, Now: now, Fence: &fence,
		})
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := second.pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'
		)`, a.AttemptID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("transition finished without waiting for row lock: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	if _, err := blocker.Exec(ctx, `UPDATE agent_upgrade_attempts SET cancel_requested=true WHERE attempt_id=$1`, a.AttemptID); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got, err := second.Get(ctx, a.AttemptID)
	if err != nil || !got.CancelRequested || got.State != AttemptStaging {
		t.Fatalf("blocked transition erased cancellation: %+v %v", got, err)
	}
}
