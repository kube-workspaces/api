package storage

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kube-workspaces/api/internal/execution/updates"
)

// PreparedUpgradeJournal is a process-local server-derived transition witness,
// not an execution grant. Fields are private: a guest checkpoint/hash cannot
// construct one. After process loss, reconcile independently; never deserialize
// a witness from guest data or automatically reissue an old action.
type PreparedUpgradeJournal struct {
	id, owner, previous, event string
	fence                      uint64
	next                       *updates.Journal
}

func (p *PreparedUpgradeJournal) AttemptID() string {
	if p == nil {
		return ""
	}
	return p.id
}
func (p *PreparedUpgradeJournal) Owner() string {
	if p == nil {
		return ""
	}
	return p.owner
}
func (p *PreparedUpgradeJournal) Fence() uint64 {
	if p == nil {
		return 0
	}
	return p.fence
}
func (p *PreparedUpgradeJournal) Journal() *updates.Journal {
	if p == nil {
		return nil
	}
	return p.next
}
func (p *PreparedUpgradeJournal) action() bool {
	return p != nil && p.next != nil && p.event == "begin" && p.next.Snapshot().Active != nil
}

// UpgradeJournalStore retains independently seeded heads and server-derived
// steps. Initialize accepts only an ALREADY approved plan/current identity and
// authenticated initial inventory, never a guest-proposed checkpoint. All event
// contexts and native receipts must also be independently authorized/authenticated.
// No production initializer, receipt transport or takeover/recovery is supplied.
type UpgradeJournalStore interface {
	Initialize(context.Context, string, string, updates.JournalPlan, time.Time) error
	Head(context.Context, string) (*updates.Journal, error)
	Prepare(context.Context, string, string, updates.JournalEvent, updates.JournalContext) (*PreparedUpgradeJournal, error)
	CheckPrepared(context.Context, *PreparedUpgradeJournal, *updates.Journal) error
	Commit(context.Context, *PreparedUpgradeJournal, ChunkReceipt) error
	CheckCommitted(context.Context, string, string, *updates.Journal) error
	Durability() Durability
	Ready(context.Context) error
	Close() error
}

func NewPostgresUpgradeJournals(ctx context.Context, databaseURL string) (UpgradeJournalStore, error) {
	m, err := NewPostgresMetadata(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	return &postgresJournals{postgresUpgrades{pool: m.(*postgresMetadata).pool}}, nil
}

type postgresJournals struct{ postgresUpgrades }

func (*postgresJournals) Durability() Durability { return DurabilityDurable }

const journalHeadColumns = `plan_sha256,checkpoint_sha256,checkpoint,sequence,owner_fence`

func scanUpgradeJournal(row pgx.Row) (*updates.Journal, error) {
	var plan, digest string
	var raw []byte
	var sequence, fence uint64
	if err := row.Scan(&plan, &digest, &raw, &sequence, &fence); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	j, err := updates.DecodeJournal(raw, plan, digest, sequence)
	if err != nil || j.Snapshot().Sequence != sequence || j.Snapshot().OwnerFence != fence {
		return nil, ErrTampered
	}
	return j, nil
}

func (p *postgresJournals) Head(ctx context.Context, id string) (*updates.Journal, error) {
	return scanUpgradeJournal(p.pool.QueryRow(ctx, `SELECT `+journalHeadColumns+` FROM agent_upgrade_journal_heads WHERE attempt_id=$1`, id))
}

func journalAttemptBinding(a AgentUpgradeAttempt, plan updates.JournalPlan) bool {
	b := plan.Binding
	return plan.Validate() == nil && b.AttemptID == a.AttemptID && b.Namespace == a.Namespace && b.WorkspaceName == a.WorkspaceName &&
		b.WorkspaceUID == a.WorkspaceUID && b.VMUID == a.VMUID && b.ActorUID == a.ActorUID && b.RecordingID == a.RecordingID &&
		b.RevocationEpoch == a.ExpectedRevocationEpoch && b.TargetSHA256 == a.TargetManifestSHA256 &&
		b.PreviousSHA256 == a.Predecessor.ManifestSHA256 && a.Predecessor.TargetID != "" &&
		b.InventorySHA256 == a.ExpectedInstalledInventorySHA256 && plan.AllowReboot == a.AllowReboot
}

func journalLease(a AgentUpgradeAttempt, owner string, fence uint64, now time.Time) error {
	if owner == "" || a.LeaseOwner != owner || a.LeaseFence != fence || fence == 0 || fence > updates.MaxJournalSequence {
		return ErrFenced
	}
	if !now.Before(a.LeaseExpiresAt) {
		return ErrLeaseExpired
	}
	if !a.State.Claimable() || a.CancelRequested {
		return ErrConflict
	}
	return nil
}

func (p *postgresJournals) Initialize(ctx context.Context, id, owner string, plan updates.JournalPlan, now time.Time) error {
	if now.IsZero() || !validUpgradeID(id) || plan.Validate() != nil {
		return ErrConflict
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	a, err := lockPhaseAttempt(ctx, tx, id)
	if err != nil {
		return err
	}
	at, err := phaseTransactionTime(ctx, tx, now)
	if err != nil {
		return err
	}
	if err := journalLease(a, owner, a.LeaseFence, at); err != nil {
		return err
	}
	if !journalAttemptBinding(a, plan) || a.JournalSequence != 0 || at.Before(a.CreatedAt) {
		return ErrConflict
	}
	// Admission time fixes the deadline; repeated initialization cannot extend it.
	j, err := updates.NewJournal(plan, a.LeaseFence, a.CreatedAt.Unix())
	if err != nil || at.Unix() >= j.Snapshot().ExpiresAt {
		return ErrConflict
	}
	var existing bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_upgrade_phase_intents WHERE attempt_id=$1)`, id).Scan(&existing); err != nil {
		return err
	}
	if existing {
		return ErrConflict
	} // no backfill/adoption of old guest intent
	_, err = tx.Exec(ctx, `INSERT INTO agent_upgrade_journal_heads
		(attempt_id,plan_sha256,checkpoint_sha256,checkpoint,sequence,owner_fence) VALUES ($1,$2,$3,$4,0,$5)`, id, plan.SHA256(), j.SHA256(), j.Encode(), a.LeaseFence)
	if err != nil {
		return mapUpgradePGError(err)
	}
	return tx.Commit(ctx)
}

func lockedJournal(ctx context.Context, tx pgx.Tx, id, owner string, now time.Time) (AgentUpgradeAttempt, *updates.Journal, time.Time, error) {
	a, err := lockPhaseAttempt(ctx, tx, id)
	if err != nil {
		return a, nil, time.Time{}, err
	}
	j, err := scanUpgradeJournal(tx.QueryRow(ctx, `SELECT `+journalHeadColumns+` FROM agent_upgrade_journal_heads WHERE attempt_id=$1 FOR UPDATE`, id))
	if err != nil {
		return a, nil, time.Time{}, err
	}
	at, err := phaseTransactionTime(ctx, tx, now)
	if err != nil {
		return a, nil, at, err
	}
	s := j.Snapshot()
	if err := journalLease(a, owner, s.OwnerFence, at); err != nil {
		return a, nil, at, err
	}
	if !journalAttemptBinding(a, s.Plan) || at.Unix() < s.UpdatedAt {
		return a, nil, at, ErrConflict
	}
	deadline := s.ExpiresAt
	if s.Phase == "awaiting_reboot" {
		deadline = s.WaitingSince + updates.RebootWaitSeconds
	}
	if at.Unix() >= deadline {
		return a, nil, at, ErrLeaseExpired
	}
	return a, j, at, nil
}

func requireIssuedJournalAction(ctx context.Context, tx pgx.Tx, id string, head *updates.Journal, event string) error {
	s := head.Snapshot()
	if event == "observe_boot" && s.Active == nil {
		return ErrConflict
	}
	if s.Active == nil || (event != "complete" && event != "observe_boot") {
		return nil
	}
	var issued bool
	if err := tx.QueryRow(ctx, `SELECT issued_at IS NOT NULL FROM agent_upgrade_phase_intents
		WHERE attempt_id=$1 AND action_sequence=$2 AND checkpoint_sha256=$3`, id, s.Active.Sequence, head.SHA256()).Scan(&issued); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrConflict
		}
		return err
	}
	if !issued {
		return ErrConflict
	}
	return nil
}

func (p *postgresJournals) Prepare(ctx context.Context, id, owner string, event updates.JournalEvent, current updates.JournalContext) (*PreparedUpgradeJournal, error) {
	// This bounded adapter handles issued forward actions only. Cancellation,
	// compensation, unsolicited reboot and takeover need independent recovery.
	if event.Kind != "begin" && event.Kind != "complete" && event.Kind != "observe_boot" {
		return nil, ErrConflict
	}
	if current.Now <= 0 || !current.Authorized || !current.RecordingAvailable || current.InstallerBusy || event.Kind == "claim" {
		return nil, ErrConflict
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	a, head, at, err := lockedJournal(ctx, tx, id, owner, time.Unix(current.Now, 0))
	if err != nil {
		return nil, err
	}
	if current.Binding != head.Snapshot().Plan.Binding || current.OwnerFence != a.LeaseFence || a.JournalSequence != head.Snapshot().Sequence {
		return nil, ErrConflict
	}
	if event.Kind == "complete" && (head.Snapshot().Active == nil || current.BootID != head.Snapshot().Active.BootID) {
		return nil, ErrConflict
	}
	if err := requireIssuedJournalAction(ctx, tx, id, head, event.Kind); err != nil {
		return nil, err
	}
	current.Now = at.Unix() // never freeze authority at the pre-lock timestamp
	transition, err := head.Prepare(event, current)
	if err != nil {
		return nil, ErrConflict
	}
	next, err := updates.DecodeJournal(transition.Bytes(), head.Snapshot().Plan.SHA256(), transition.SHA256(), transition.Sequence())
	if err != nil {
		return nil, ErrTampered
	}
	// No action descriptor or authorization is returned, and no head is changed.
	return &PreparedUpgradeJournal{id: id, owner: owner, previous: head.SHA256(), event: event.Kind, fence: a.LeaseFence, next: next}, nil
}

func validPrepared(p *PreparedUpgradeJournal) bool {
	return p != nil && p.next != nil && validUpgradeID(p.id) && p.owner != "" && p.fence > 0 &&
		digestPatternForJournal(p.previous) && p.next.Snapshot().Plan.Binding.AttemptID == p.id && p.next.Snapshot().OwnerFence == p.fence
}

func digestPatternForJournal(s string) bool {
	_, err := hex.DecodeString(s)
	return len(s) == 64 && s == strings.ToLower(s) && err == nil
}

func checkPreparedJournal(a AgentUpgradeAttempt, head *updates.Journal, p *PreparedUpgradeJournal, candidate *updates.Journal) error {
	if !validPrepared(p) || candidate == nil || p.previous != head.SHA256() || candidate.SHA256() != p.next.SHA256() ||
		!bytes.Equal(candidate.Encode(), p.next.Encode()) || p.next.Snapshot().Sequence != head.Snapshot().Sequence+1 ||
		p.next.Snapshot().Plan != head.Snapshot().Plan || a.LeaseFence != p.fence ||
		(a.JournalSequence != head.Snapshot().Sequence && a.JournalSequence != p.next.Snapshot().Sequence) {
		return ErrConflict
	}
	return nil
}

func (p *postgresJournals) CheckPrepared(ctx context.Context, prepared *PreparedUpgradeJournal, candidate *updates.Journal) error {
	if !validPrepared(prepared) {
		return ErrConflict
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	a, head, _, err := lockedJournal(ctx, tx, prepared.id, prepared.owner, time.Now())
	if err != nil {
		return err
	}
	return checkPreparedJournal(a, head, prepared, candidate)
}

func (p *postgresJournals) Commit(ctx context.Context, prepared *PreparedUpgradeJournal, receipt ChunkReceipt) error {
	if !validPrepared(prepared) || receipt.ChunkIndex > math.MaxInt64 {
		return ErrConflict
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	a, head, at, err := lockedJournal(ctx, tx, prepared.id, prepared.owner, time.Now())
	if err != nil {
		return err
	}
	if err := checkPreparedJournal(a, head, prepared, prepared.next); err != nil {
		return err
	}
	if receipt.RecordingID != a.RecordingID || receipt.ChunkSHA256 != updates.Digest(prepared.next.Encode()) {
		return ErrConflict
	}
	if err := requireIssuedJournalAction(ctx, tx, prepared.id, head, prepared.event); err != nil {
		return err
	}
	sequence := prepared.next.Snapshot().Sequence
	if prepared.action() {
		var recorded bool
		if err := tx.QueryRow(ctx, `SELECT owner=$3 AND owner_fence=$4 AND checkpoint_sha256=$5 AND recording_id=$6
			AND chunk_index=$7 AND chunk_sha256=$8 AND issued_at IS NULL
			FROM agent_upgrade_phase_intents WHERE attempt_id=$1 AND action_sequence=$2`, prepared.id, sequence,
			prepared.owner, prepared.fence, prepared.next.SHA256(), receipt.RecordingID, receipt.ChunkIndex, receipt.ChunkSHA256).Scan(&recorded); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConflict
			}
			return err
		}
		if !recorded || a.JournalSequence != sequence {
			return ErrConflict
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_upgrade_journal_steps
		(attempt_id,sequence,previous_sha256,checkpoint_sha256,checkpoint,event_kind,owner,owner_fence,recording_id,chunk_index,chunk_sha256,committed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, prepared.id, sequence, prepared.previous, prepared.next.SHA256(), prepared.next.Encode(),
		prepared.event, prepared.owner, prepared.fence, receipt.RecordingID, receipt.ChunkIndex, receipt.ChunkSHA256, at)
	if err != nil {
		return mapUpgradePGError(err)
	}
	_, err = tx.Exec(ctx, `UPDATE agent_upgrade_journal_heads SET checkpoint_sha256=$2,checkpoint=$3,sequence=$4 WHERE attempt_id=$1`, prepared.id, prepared.next.SHA256(), prepared.next.Encode(), sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE agent_upgrade_attempts SET journal_sequence=$2,updated_at=$3 WHERE attempt_id=$1`, prepared.id, sequence, at)
	if err != nil {
		return err
	}
	return tx.Commit(ctx) // uncertain result returns no permission; never replay
}

func (p *postgresJournals) CheckCommitted(ctx context.Context, id, owner string, candidate *updates.Journal) error {
	if candidate == nil {
		return ErrConflict
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	a, head, _, err := lockedJournal(ctx, tx, id, owner, time.Now())
	if err != nil {
		return err
	}
	s := head.Snapshot()
	if s.Active == nil || s.Active.Sequence != s.Sequence || (s.Phase != "active" && s.Phase != "awaiting_reboot") ||
		a.JournalSequence != s.Sequence || head.SHA256() != candidate.SHA256() || !bytes.Equal(head.Encode(), candidate.Encode()) {
		return ErrConflict
	}
	return nil
}
