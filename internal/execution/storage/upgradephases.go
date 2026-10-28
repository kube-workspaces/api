package storage

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kube-workspaces/api/internal/execution/updates"
)

// PhaseRecordingReceipt acknowledges the exact journal bytes in the independent
// encrypted recording. Only a recorder that durably committed the chunk may
// produce it. A guest message, journal hash or metadata row is not such a receipt.
type PhaseRecordingReceipt struct {
	RecordingID string
	ChunkIndex  uint64
	ChunkSHA256 string
}

// UpgradePhaseIntent is an exact active journal checkpoint, verified against
// independent plan/current authority and recorded before calling RecordIntent.
type UpgradePhaseIntent struct {
	AttemptID        string
	Owner            string
	Fence            uint64
	PlanSHA256       string
	CheckpointSHA256 string
	Checkpoint       []byte
	Receipt          PhaseRecordingReceipt
	RecordedAt       time.Time
}

func (i UpgradePhaseIntent) Journal() (*updates.Journal, error) {
	j, err := updates.DecodeJournal(i.Checkpoint, i.PlanSHA256, i.CheckpointSHA256, 1)
	if err != nil {
		return nil, ErrConflict
	}
	s := j.Snapshot()
	if !validUpgradeID(i.AttemptID) || i.Owner == "" || len(i.Owner) > 255 ||
		i.RecordedAt.IsZero() || i.Fence == 0 || i.Fence > updates.MaxJournalSequence ||
		s.OwnerFence != i.Fence || s.Active == nil || s.Active.Sequence != s.Sequence ||
		(s.Phase != "active" && s.Phase != "awaiting_reboot") || s.CancelRequested ||
		s.Plan.Binding.AttemptID != i.AttemptID || i.Receipt.ChunkIndex > math.MaxInt64 ||
		i.Receipt.ChunkSHA256 != updates.Digest(i.Checkpoint) {
		return nil, ErrConflict
	}
	return j, nil
}

// UpgradePhaseLedger is a durable one-shot authorization ledger, not a transport
// or current policy source. No memory fallback is supplied. Uncertain commits
// deny and must never be retried as permission to run an installer.
type UpgradePhaseLedger interface {
	RecordIntent(context.Context, UpgradePhaseIntent) error
	GetIntent(context.Context, string, uint64) (UpgradePhaseIntent, error)
	// ClaimPhase atomically rechecks the attempt, active lease/cancellation,
	// exact recorded intent and linked execution, then irreversibly reserves
	// this action/challenge before any signature is returned.
	ClaimPhase(context.Context, string, string, updates.PhasePermit, time.Time) error
	Durability() Durability
	Ready(context.Context) error
	Close() error
}

func NewPostgresUpgradePhases(ctx context.Context, databaseURL string) (UpgradePhaseLedger, error) {
	m, err := NewPostgresMetadata(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	return &postgresPhases{postgresUpgrades{pool: m.(*postgresMetadata).pool}}, nil
}

type postgresPhases struct{ postgresUpgrades }

func (*postgresPhases) Durability() Durability { return DurabilityDurable }

func phaseAttempt(a AgentUpgradeAttempt, owner string, i UpgradePhaseIntent, now time.Time) (*updates.Journal, error) {
	j, err := i.Journal()
	if err != nil {
		return nil, err
	}
	s := j.Snapshot()
	b := s.Plan.Binding
	if a.LeaseOwner != owner || a.LeaseFence != i.Fence {
		return nil, ErrFenced
	}
	if now.IsZero() || !now.Before(a.LeaseExpiresAt) {
		return nil, ErrLeaseExpired
	}
	if !a.State.Claimable() || a.CancelRequested || now.Unix() < s.UpdatedAt || now.Unix() >= s.ExpiresAt ||
		a.JournalSequence > s.Sequence || b.Namespace != a.Namespace || b.WorkspaceName != a.WorkspaceName ||
		b.WorkspaceUID != a.WorkspaceUID || b.VMUID != a.VMUID || b.RevocationEpoch != a.ExpectedRevocationEpoch ||
		b.ActorUID != a.ActorUID || b.RecordingID != a.RecordingID || i.Receipt.RecordingID != a.RecordingID ||
		b.TargetSHA256 != a.TargetManifestSHA256 || b.InventorySHA256 != a.ExpectedInstalledInventorySHA256 ||
		b.PreviousSHA256 != a.Predecessor.ManifestSHA256 || s.Plan.AllowReboot != a.AllowReboot ||
		(s.Active.Kind == "reboot" && !a.AllowReboot) {
		return nil, ErrConflict
	}
	return j, nil
}

// lockPhaseAttempt shares the attempt row lock with cancellation/lease/admin
// writes. The linked execution lock also serializes terminal recording outcomes.
func lockPhaseAttempt(ctx context.Context, tx pgx.Tx, id string) (AgentUpgradeAttempt, error) {
	a, err := scanUpgradeAttempt(tx.QueryRow(ctx, `SELECT `+attemptColumns+` FROM agent_upgrade_attempts WHERE attempt_id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, err
	}
	var healthy bool
	err = tx.QueryRow(ctx, `SELECT admitted AND operation='upgrade' AND durability='durable'
		AND state IN ('admitted','running') AND NOT recording_lost AND recording_id=$2
		AND actor_id=$3 AND workspace_uid=$4 AND namespace=$5 AND workspace_name=$6 AND elevated AND os_identity='SYSTEM'
		FROM execution_executions WHERE execution_id=$1 FOR UPDATE`, a.ExecutionID, a.RecordingID,
		a.ActorUID, a.WorkspaceUID, a.Namespace, a.WorkspaceName).Scan(&healthy)
	if err != nil {
		return a, err
	}
	if !healthy {
		return a, ErrConflict
	}
	return a, nil
}

func (p *postgresPhases) RecordIntent(ctx context.Context, i UpgradePhaseIntent) error {
	if _, err := i.Journal(); err != nil {
		return err
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	a, err := lockPhaseAttempt(ctx, tx, i.AttemptID)
	if err != nil {
		return err
	}
	at, err := phaseTransactionTime(ctx, tx, i.RecordedAt)
	if err != nil {
		return err
	}
	j, err := phaseAttempt(a, i.Owner, i, at)
	if err != nil {
		return err
	}
	// An attempt pins ONE verified plan; subsequent phases cannot change product,
	// driver or predecessor identities while retaining the admitted manifest hash.
	var changed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_upgrade_phase_intents
		WHERE attempt_id=$1 AND plan_sha256<>$2)`, i.AttemptID, i.PlanSHA256).Scan(&changed); err != nil {
		return err
	}
	if changed {
		return ErrConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_upgrade_phase_intents
		(attempt_id,action_sequence,owner,owner_fence,plan_sha256,checkpoint_sha256,checkpoint,
		recording_id,chunk_index,chunk_sha256,recorded_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		i.AttemptID, j.Snapshot().Sequence, i.Owner, i.Fence, i.PlanSHA256, i.CheckpointSHA256,
		i.Checkpoint, i.Receipt.RecordingID, i.Receipt.ChunkIndex, i.Receipt.ChunkSHA256, i.RecordedAt)
	if err != nil {
		return mapUpgradePGError(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_upgrade_attempts SET journal_sequence=$2, updated_at=$3 WHERE attempt_id=$1`,
		i.AttemptID, j.Snapshot().Sequence, i.RecordedAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const phaseIntentColumns = `attempt_id,owner,owner_fence,plan_sha256,checkpoint_sha256,checkpoint,recording_id,chunk_index,chunk_sha256,recorded_at`

// Lock waits must not freeze authority at a pre-transaction caller timestamp.
// Sample after ALL authority row locks using clock_timestamp, not PostgreSQL's
// transaction-start now(). Clock disagreement only shortens authority.
func phaseTransactionTime(ctx context.Context, tx pgx.Tx, requested time.Time) (time.Time, error) {
	var current time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&current); err != nil {
		return time.Time{}, err
	}
	if requested.After(current) {
		return requested, nil
	}
	return current, nil
}

func scanPhaseIntent(row pgx.Row) (UpgradePhaseIntent, error) {
	var i UpgradePhaseIntent
	err := row.Scan(&i.AttemptID, &i.Owner, &i.Fence, &i.PlanSHA256, &i.CheckpointSHA256,
		&i.Checkpoint, &i.Receipt.RecordingID, &i.Receipt.ChunkIndex, &i.Receipt.ChunkSHA256, &i.RecordedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return i, ErrNotFound
	}
	return i, err
}

func (p *postgresPhases) GetIntent(ctx context.Context, id string, sequence uint64) (UpgradePhaseIntent, error) {
	if sequence == 0 || sequence > updates.MaxJournalSequence {
		return UpgradePhaseIntent{}, ErrConflict
	}
	return scanPhaseIntent(p.pool.QueryRow(ctx, `SELECT `+phaseIntentColumns+` FROM agent_upgrade_phase_intents
		WHERE attempt_id=$1 AND action_sequence=$2`, id, sequence))
}

func (p *postgresPhases) ClaimPhase(ctx context.Context, id, owner string, permit updates.PhasePermit, now time.Time) error {
	if permit.Validate() != nil || permit.IssuedAt != now.Unix() {
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
	i, err := scanPhaseIntent(tx.QueryRow(ctx, `SELECT `+phaseIntentColumns+` FROM agent_upgrade_phase_intents
		WHERE attempt_id=$1 AND action_sequence=$2 FOR UPDATE`, id, permit.Action.Sequence))
	if err != nil {
		return err
	}
	at, err := phaseTransactionTime(ctx, tx, now)
	if err != nil {
		return err
	}
	if at.Unix() >= permit.ExpiresAt {
		return ErrLeaseExpired
	}
	j, err := phaseAttempt(a, owner, i, at)
	if err != nil {
		return err
	}
	s := j.Snapshot()
	if i.Owner != owner || permit.PlanSHA256 != i.PlanSHA256 || permit.Action != *s.Active || permit.OwnerFence != i.Fence ||
		a.JournalSequence != s.Sequence || now.Before(i.RecordedAt) || permit.ExpiresAt > s.ExpiresAt || permit.ExpiresAt > a.LeaseExpiresAt.Unix() {
		return ErrConflict
	}
	tag, err := tx.Exec(ctx, `UPDATE agent_upgrade_phase_intents SET issued_at=$3,challenge=$4,peer_sha256=$5,permit_sha256=$6
		WHERE attempt_id=$1 AND action_sequence=$2 AND issued_at IS NULL`, id, s.Sequence, now,
		permit.Challenge, permit.PeerSHA256, updates.Digest(permit.Encode()))
	if err != nil {
		return mapUpgradePGError(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return tx.Commit(ctx)
}
