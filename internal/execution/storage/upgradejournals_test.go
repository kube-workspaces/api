package storage

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/execution/updates"
)

func TestJournalWitnessRejectsZeroAndNoncanonicalDigest(t *testing.T) {
	for _, digest := range []string{"", strings.Repeat("z", 64), strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if digestPatternForJournal(digest) {
			t.Fatalf("noncanonical digest accepted: %q", digest)
		}
	}
	if !digestPatternForJournal(strings.Repeat("a", 64)) {
		t.Fatal("valid SHA256 denied")
	}
	if validPrepared(nil) || validPrepared(&PreparedUpgradeJournal{}) {
		t.Fatal("empty witness accepted")
	}
}

func TestPostgresUpgradeJournalsIntegration(t *testing.T) {
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
	phases, err := NewPostgresUpgradePhases(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer phases.Close()
	first, err := NewPostgresUpgradeJournals(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewPostgresUpgradeJournals(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	fixture := func(t *testing.T) (UpgradePhaseIntent, updates.PhasePermit, updates.JournalPlan, updates.JournalContext) {
		t.Helper()
		i, permit := phaseFixture(t, attempts, metadata, time.Now().UTC())
		j, err := i.Journal()
		if err != nil {
			t.Fatal(err)
		}
		plan := j.Snapshot().Plan
		current := updates.JournalContext{Binding: plan.Binding, OwnerFence: i.Fence, Now: time.Now().Unix(), BootID: "boot-1", Authorized: true, RecordingAvailable: true}
		return i, permit, plan, current
	}
	seed := func(t *testing.T, i UpgradePhaseIntent, plan updates.JournalPlan) {
		t.Helper()
		if err := first.Initialize(ctx, i.AttemptID, i.Owner, plan, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	prepare := func(t *testing.T, i UpgradePhaseIntent, current updates.JournalContext) *PreparedUpgradeJournal {
		t.Helper()
		p, err := first.Prepare(ctx, i.AttemptID, i.Owner, updates.JournalEvent{Kind: "begin"}, current)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	intent := func(i UpgradePhaseIntent, p *PreparedUpgradeJournal) UpgradePhaseIntent {
		j := p.Journal()
		i.Checkpoint, i.CheckpointSHA256, i.PlanSHA256 = j.Encode(), j.SHA256(), j.Snapshot().Plan.SHA256()
		i.RecordedAt = time.Now()
		i.Receipt.ChunkSHA256 = updates.Digest(j.Encode())
		return i
	}

	t.Run("no-adoption-or-reset", func(t *testing.T) {
		i, _, plan, _ := fixture(t)
		if err := phases.RecordIntent(ctx, i); err != nil {
			t.Fatal(err)
		}
		if err := first.Initialize(ctx, i.AttemptID, i.Owner, plan, time.Now()); err == nil {
			t.Fatal("existing intent adopted")
		}
		i, _, plan, _ = fixture(t)
		bad := plan
		bad.Binding.ActorUID = "other"
		if err := first.Initialize(ctx, i.AttemptID, i.Owner, bad, time.Now()); err == nil {
			t.Fatal("changed admitted scope accepted")
		}
		seed(t, i, plan)
		head, err := second.Head(ctx, i.AttemptID)
		if err != nil {
			t.Fatal(err)
		}
		a, err := attempts.Get(ctx, i.AttemptID)
		if err != nil {
			t.Fatal(err)
		}
		if head.Snapshot().Sequence != 0 || head.Snapshot().Phase != "ready" || head.Snapshot().StartedAt != a.CreatedAt.Unix() {
			t.Fatal("head not seeded from admission")
		}
		if err := first.Initialize(ctx, i.AttemptID, i.Owner, plan, time.Now()); err == nil {
			t.Fatal("deadline reset accepted")
		}
	})
	t.Run("issued-forward-lineage-and-reopen", func(t *testing.T) {
		i, permit, plan, current := fixture(t)
		seed(t, i, plan)
		p := prepare(t, i, current)
		if err := second.CheckPrepared(ctx, p, p.Journal()); err != nil {
			t.Fatal(err)
		}
		guest, _ := i.Journal()
		if err := second.CheckPrepared(ctx, p, guest); err == nil {
			t.Fatal("guest checkpoint substituted")
		}
		if err := first.CheckCommitted(ctx, i.AttemptID, i.Owner, p.Journal()); err == nil {
			t.Fatal("uncommitted action accepted")
		}
		i = intent(i, p)
		if err := first.Commit(ctx, p, i.Receipt); err == nil {
			t.Fatal("missing protected intent accepted")
		}
		if err := phases.RecordIntent(ctx, i); err != nil {
			t.Fatal(err)
		}
		bad := i.Receipt
		bad.ChunkSHA256 = updates.Digest([]byte("other"))
		if err := first.Commit(ctx, p, bad); err == nil {
			t.Fatal("wrong receipt accepted")
		}
		bad = i.Receipt
		bad.RecordingID = "other"
		if err := first.Commit(ctx, p, bad); err == nil {
			t.Fatal("wrong recording accepted")
		}
		if err := second.Commit(ctx, p, i.Receipt); err != nil {
			t.Fatal(err)
		}
		if err := first.Commit(ctx, p, i.Receipt); err == nil {
			t.Fatal("witness replay accepted")
		}
		if err := first.CheckPrepared(ctx, p, p.Journal()); err == nil {
			t.Fatal("stale witness accepted")
		}
		if err := second.CheckCommitted(ctx, i.AttemptID, i.Owner, p.Journal()); err != nil {
			t.Fatal(err)
		}
		event := updates.JournalEvent{Kind: "complete", Receipt: &updates.ActionReceipt{Sequence: 1, Kind: p.Journal().Snapshot().Active.Kind, Outcome: "ok", ServiceState: "stopped"}}
		if _, err := first.Prepare(ctx, i.AttemptID, i.Owner, event, current); err == nil {
			t.Fatal("unissued completion accepted")
		}
		permit.Action = *p.Journal().Snapshot().Active
		now := time.Now()
		permit.IssuedAt, permit.ExpiresAt = now.Unix(), now.Unix()+15
		if err := phases.ClaimPhase(ctx, i.AttemptID, i.Owner, permit, now); err != nil {
			t.Fatal(err)
		}
		otherBoot := current
		otherBoot.BootID = "unexpected-boot"
		if _, err := first.Prepare(ctx, i.AttemptID, i.Owner, event, otherBoot); err == nil {
			t.Fatal("completion from a different boot accepted")
		}
		completion, err := first.Prepare(ctx, i.AttemptID, i.Owner, event, current)
		if err != nil {
			t.Fatal(err)
		}
		receipt := ChunkReceipt{RecordingID: i.Receipt.RecordingID, ChunkIndex: 2, ChunkSHA256: updates.Digest(completion.Journal().Encode())}
		if err := first.Commit(ctx, completion, receipt); err != nil {
			t.Fatal(err)
		}
		reopened, err := NewPostgresUpgradeJournals(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		head, err := reopened.Head(ctx, i.AttemptID)
		if err != nil {
			t.Fatal(err)
		}
		if head.SHA256() != completion.Journal().SHA256() || head.Snapshot().Sequence != 2 {
			t.Fatal("lineage not durable")
		}
		if err := first.CheckCommitted(ctx, i.AttemptID, i.Owner, p.Journal()); err == nil {
			t.Fatal("old issued head accepted")
		}
		current.Now = time.Now().Unix()
		if next := prepare(t, i, current); next.Journal().Snapshot().Sequence != 3 {
			t.Fatal("nonmonotonic successor")
		}
	})
	for _, mode := range []string{"owner", "fence", "cancel", "expired", "unapproved", "recording", "claim", "boot"} {
		t.Run(mode, func(t *testing.T) {
			i, _, plan, current := fixture(t)
			seed(t, i, plan)
			p := prepare(t, i, current)
			i = intent(i, p)
			if err := phases.RecordIntent(ctx, i); err != nil {
				t.Fatal(err)
			}
			event := updates.JournalEvent{Kind: "begin"}
			switch mode {
			case "owner":
				i.Owner = "other"
			case "fence":
				_, err = first.(*postgresJournals).pool.Exec(ctx, `UPDATE agent_upgrade_attempts SET lease_fence=lease_fence+1 WHERE attempt_id=$1`, i.AttemptID)
			case "cancel":
				err = attempts.RequestCancel(ctx, i.AttemptID, time.Now())
			case "expired":
				_, err = first.(*postgresJournals).pool.Exec(ctx, `UPDATE agent_upgrade_attempts SET lease_expires_at=clock_timestamp() WHERE attempt_id=$1`, i.AttemptID)
			case "unapproved":
				current.Authorized = false
			case "recording":
				current.RecordingAvailable = false
			case "claim":
				event.Kind = "claim"
			case "boot":
				event.Kind = "observe_boot"
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := second.Prepare(ctx, i.AttemptID, i.Owner, event, current); err == nil {
				t.Fatal("changed authority accepted")
			}
			if mode == "fence" || mode == "cancel" || mode == "expired" {
				if err := second.Commit(ctx, p, i.Receipt); err == nil {
					t.Fatal("stale authority committed")
				}
			}
		})
	}
	t.Run("one-commit-across-replicas", func(t *testing.T) {
		i, _, plan, current := fixture(t)
		seed(t, i, plan)
		p := prepare(t, i, current)
		i = intent(i, p)
		if err := phases.RecordIntent(ctx, i); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		results := make(chan error, 8)
		for n := 0; n < 8; n++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				store := first
				if n%2 != 0 {
					store = second
				}
				results <- store.Commit(ctx, p, i.Receipt)
			}(n)
		}
		wg.Wait()
		close(results)
		wins := 0
		for err := range results {
			if err == nil {
				wins++
			}
		}
		if wins != 1 {
			t.Fatalf("commit winners: %d", wins)
		}
	})
}
