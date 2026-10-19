package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPostgresAgentUpgrades opens the durable attempt store on the execution
// database and applies the same embedded schema migrations. It never falls
// back to RAM: a configured persistent mode that cannot open this store must
// fail closed.
func NewPostgresAgentUpgrades(ctx context.Context, databaseURL string) (AgentUpgradeStore, error) {
	m, err := NewPostgresMetadata(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	return &postgresUpgrades{pool: m.(*postgresMetadata).pool}, nil
}

type postgresUpgrades struct {
	pool *pgxpool.Pool
}

const attemptColumns = `attempt_id, idempotency_key, namespace, workspace_name, workspace_uid,
	vm_uid, actor_uid, target_id, target_manifest_sha256, expected_installed_inventory_sha256,
	expected_revocation_epoch, allow_reboot, execution_id, recording_id, state, phase_times,
	cancel_requested, journal_sequence, error_code, predecessor_target_id, predecessor_manifest_sha256,
	lease_owner, lease_expires_at, lease_fence, created_at, updated_at`

const holdsReservationSQL = `state IN (
	'admitted', 'staging', 'prepared', 'installing', 'verifying',
	'awaiting_reboot', 'rollback_pending', 'rolling_back',
	'manual_recovery_required', 'unknown', 'recording_lost'
)`

func (p *postgresUpgrades) Reserve(ctx context.Context, a AgentUpgradeAttempt) error {
	if err := validateUpgradeAttempt(a); err != nil {
		return err
	}
	phaseTimes, err := json.Marshal(orderedPhaseTimes(a))
	if err != nil {
		return err
	}
	const q = `INSERT INTO agent_upgrade_attempts (` + attemptColumns + `)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
		ON CONFLICT (attempt_id) DO NOTHING`
	tag, err := p.pool.Exec(ctx, q,
		a.AttemptID, a.IdempotencyKey, a.Namespace, a.WorkspaceName, a.WorkspaceUID,
		a.VMUID, a.ActorUID, a.TargetID, a.TargetManifestSHA256, a.ExpectedInstalledInventorySHA256,
		a.ExpectedRevocationEpoch, a.AllowReboot, a.ExecutionID, a.RecordingID, string(AttemptAdmitted), phaseTimes,
		false, a.JournalSequence, "", "", "",
		"", nil, 0, a.CreatedAt, a.UpdatedAt)
	if err != nil {
		return mapUpgradePGError(err)
	}
	if tag.RowsAffected() == 0 {
		// Distinguish the conflicting unique constraint: attempt id, idem
		// key or the per-VM active reservation.
		var exists string
		err := p.pool.QueryRow(ctx, `SELECT state FROM agent_upgrade_attempts WHERE attempt_id=$1`, a.AttemptID).Scan(&exists)
		if err == nil {
			return ErrConflict
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var idemState string
		err = p.pool.QueryRow(ctx,
			`SELECT state FROM agent_upgrade_attempts WHERE namespace=$1 AND workspace_name=$2 AND idempotency_key=$3`,
			a.Namespace, a.WorkspaceName, a.IdempotencyKey).Scan(&idemState)
		if err == nil {
			return ErrIdempotencyConflict
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var activeID string
		err = p.pool.QueryRow(ctx,
			`SELECT attempt_id FROM agent_upgrade_attempts WHERE vm_uid=$1 AND `+holdsReservationSQL,
			a.VMUID).Scan(&activeID)
		if err == nil {
			return ErrVMReserved
		}
		if errors.Is(err, pgx.ErrNoRows) {
			// Concurrent writer won a race between the insert and the
			// follow-up reads; treat as a plain conflict.
			return ErrConflict
		}
		return err
	}
	return nil
}

// orderedPhaseTimes normalizes the phase map so identical admissions encode
// identical JSON, keeping idempotent retries byte-stable.
func orderedPhaseTimes(a AgentUpgradeAttempt) map[string]string {
	out := map[string]string{}
	if t, ok := a.PhaseTimes[AttemptAdmitted]; ok {
		out[string(AttemptAdmitted)] = t.UTC().Format(time.RFC3339Nano)
	} else {
		out[string(AttemptAdmitted)] = a.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}

func mapUpgradePGError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		switch pgErr.ConstraintName {
		case "idx_agent_upgrades_idem":
			return ErrIdempotencyConflict
		case "idx_agent_upgrades_active_vm":
			return ErrVMReserved
		default:
			return ErrConflict
		}
	}
	return err
}

func (p *postgresUpgrades) Get(ctx context.Context, attemptID string) (AgentUpgradeAttempt, error) {
	return p.scanOne(ctx, `SELECT `+attemptColumns+` FROM agent_upgrade_attempts WHERE attempt_id=$1`, attemptID)
}

func (p *postgresUpgrades) GetByIdempotency(ctx context.Context, namespace, workspaceName, key string) (AgentUpgradeAttempt, error) {
	return p.scanOne(ctx,
		`SELECT `+attemptColumns+` FROM agent_upgrade_attempts WHERE namespace=$1 AND workspace_name=$2 AND idempotency_key=$3`,
		namespace, workspaceName, key)
}

func (p *postgresUpgrades) ActiveAttempt(ctx context.Context, vmUID string) (AgentUpgradeAttempt, error) {
	return p.scanOne(ctx,
		`SELECT `+attemptColumns+` FROM agent_upgrade_attempts WHERE vm_uid=$1 AND `+holdsReservationSQL+` LIMIT 1`,
		vmUID)
}

func (p *postgresUpgrades) scanOne(ctx context.Context, q string, args ...any) (AgentUpgradeAttempt, error) {
	row := p.pool.QueryRow(ctx, q, args...)
	a, err := scanUpgradeAttempt(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return AgentUpgradeAttempt{}, ErrNotFound
	}
	return a, err
}

func scanUpgradeAttempt(row pgx.Row) (AgentUpgradeAttempt, error) {
	var a AgentUpgradeAttempt
	var state string
	var phaseTimes []byte
	var leaseExpires sql.NullTime
	var fence int64
	err := row.Scan(
		&a.AttemptID, &a.IdempotencyKey, &a.Namespace, &a.WorkspaceName, &a.WorkspaceUID,
		&a.VMUID, &a.ActorUID, &a.TargetID, &a.TargetManifestSHA256, &a.ExpectedInstalledInventorySHA256,
		&a.ExpectedRevocationEpoch, &a.AllowReboot, &a.ExecutionID, &a.RecordingID, &state, &phaseTimes,
		&a.CancelRequested, &a.JournalSequence, &a.ErrorCode, &a.Predecessor.TargetID, &a.Predecessor.ManifestSHA256,
		&a.LeaseOwner, &leaseExpires, &fence, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return AgentUpgradeAttempt{}, err
	}
	a.State = AttemptState(state)
	if fence < 0 {
		return AgentUpgradeAttempt{}, fmt.Errorf("%w: negative lease fence", ErrTampered)
	}
	a.LeaseFence = uint64(fence)
	if leaseExpires.Valid {
		a.LeaseExpiresAt = leaseExpires.Time
	}
	a.PhaseTimes = map[AttemptState]time.Time{}
	var raw map[string]string
	if err := json.Unmarshal(phaseTimes, &raw); err != nil {
		return AgentUpgradeAttempt{}, fmt.Errorf("%w: corrupt phase times: %v", ErrTampered, err)
	}
	for name, value := range raw {
		t, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return AgentUpgradeAttempt{}, fmt.Errorf("%w: corrupt phase time %q", ErrTampered, name)
		}
		a.PhaseTimes[AttemptState(name)] = t
	}
	return a, nil
}

// postgresActiveStateSQL matches the current state so a fenced UPDATE is a
// single compare-and-swap. Worker transitions carry the fence; administrative
// transitions require no lease and bump the fence to fence the worker out.
const postgresActiveStateSQL = `UPDATE agent_upgrade_attempts SET
	state=$3, phase_times=$4, cancel_requested=$5, journal_sequence=$6, error_code=$7,
	predecessor_target_id=$8, predecessor_manifest_sha256=$9, updated_at=$10,
	lease_owner=CASE WHEN $11::bigint IS NULL THEN '' ELSE lease_owner END,
	lease_expires_at=CASE WHEN $11::bigint IS NULL THEN NULL ELSE lease_expires_at END,
	lease_fence=CASE WHEN $11::bigint IS NULL THEN lease_fence + 1 ELSE lease_fence END
	WHERE attempt_id=$1 AND state=$2 AND (
		$11::bigint IS NULL OR (lease_fence = $11::bigint AND lease_owner <> '')
	)`

func (p *postgresUpgrades) Transition(ctx context.Context, attemptID string, from AttemptState, t AttemptTransition) error {
	if t.Now.IsZero() {
		return fmt.Errorf("%w: transition time required", ErrConflict)
	}
	if !t.To.Valid() || !validAttemptTransition(from, t.To) {
		return fmt.Errorf("%w: %s -> %s is not allowed", ErrConflict, from, t.To)
	}
	a, err := p.Get(ctx, attemptID)
	if err != nil {
		return err
	}
	if a.State != from {
		return ErrConflict
	}
	if t.CancelRequested != nil {
		a.CancelRequested = *t.CancelRequested
	}
	if t.JournalSequence != nil {
		a.JournalSequence = *t.JournalSequence
	}
	if t.ErrorCode != "" {
		a.ErrorCode = t.ErrorCode
	}
	if t.Predecessor != nil {
		a.Predecessor = *t.Predecessor
	}
	phaseTimes := map[string]string{}
	for st, ts := range a.PhaseTimes {
		phaseTimes[string(st)] = ts.UTC().Format(time.RFC3339Nano)
	}
	if _, ok := phaseTimes[string(t.To)]; !ok {
		phaseTimes[string(t.To)] = t.Now.UTC().Format(time.RFC3339Nano)
	}
	encoded, err := json.Marshal(phaseTimes)
	if err != nil {
		return err
	}
	var fence sql.NullInt64
	if t.Fence != nil {
		if *t.Fence > 1<<62 {
			return fmt.Errorf("%w: lease fence out of range", ErrConflict)
		}
		fence = sql.NullInt64{Int64: int64(*t.Fence), Valid: true}
	}
	tag, err := p.pool.Exec(ctx, postgresActiveStateSQL,
		attemptID, string(from), string(t.To), encoded, a.CancelRequested, a.JournalSequence,
		a.ErrorCode, a.Predecessor.TargetID, a.Predecessor.ManifestSHA256, t.Now, fence)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Re-read to report the accurate failure: wrong state, missing
		// attempt, expired/stolen lease or a fence mismatch.
		current, err := p.Get(ctx, attemptID)
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if current.State != from {
			return ErrConflict
		}
		if t.Fence != nil {
			return ErrFenced
		}
		return ErrConflict
	}
	return nil
}

const postgresClaimSQL = `UPDATE agent_upgrade_attempts SET
	lease_owner=$2, lease_expires_at=$3, lease_fence=lease_fence + 1, updated_at=$4
	WHERE attempt_id=$1 AND ` + holdsReservationSQL + `
	AND state IN ('admitted','staging','prepared','installing','verifying','awaiting_reboot','rollback_pending','rolling_back')
	AND (lease_owner = '' OR lease_owner = $2 OR lease_expires_at IS NULL OR lease_expires_at <= $4)
	RETURNING lease_fence`

func (p *postgresUpgrades) ClaimLease(ctx context.Context, attemptID, owner string, now time.Time, ttl time.Duration) (uint64, error) {
	if owner == "" || ttl <= 0 || now.IsZero() {
		return 0, fmt.Errorf("%w: lease owner, ttl and time are required", ErrConflict)
	}
	var fence int64
	err := p.pool.QueryRow(ctx, postgresClaimSQL, attemptID, owner, now.Add(ttl), now).Scan(&fence)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, p.claimError(ctx, attemptID, owner, now)
	}
	if err != nil {
		return 0, err
	}
	if fence < 0 {
		return 0, fmt.Errorf("%w: negative lease fence", ErrTampered)
	}
	return uint64(fence), nil
}

func (p *postgresUpgrades) claimError(ctx context.Context, attemptID, owner string, now time.Time) error {
	a, err := p.Get(ctx, attemptID)
	if errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !a.State.Claimable() {
		return fmt.Errorf("%w: attempt is not claimable in state %s", ErrConflict, a.State)
	}
	if a.LeaseOwner != "" && a.LeaseOwner != owner && now.Before(a.LeaseExpiresAt) {
		return ErrConflict
	}
	return ErrConflict
}

const postgresRenewSQL = `UPDATE agent_upgrade_attempts SET lease_expires_at=$4
	WHERE attempt_id=$1 AND lease_owner=$2 AND lease_fence=$3 AND lease_expires_at > $5
	AND state IN ('admitted','staging','prepared','installing','verifying','awaiting_reboot','rollback_pending','rolling_back')`

func (p *postgresUpgrades) RenewLease(ctx context.Context, attemptID, owner string, fence uint64, now time.Time, ttl time.Duration) error {
	if fence > 1<<62 {
		return ErrFenced
	}
	if ttl <= 0 || now.IsZero() {
		return fmt.Errorf("%w: lease ttl and time are required", ErrConflict)
	}
	tag, err := p.pool.Exec(ctx, postgresRenewSQL, attemptID, owner, int64(fence), now.Add(ttl), now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		a, err := p.Get(ctx, attemptID)
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if a.LeaseOwner != owner || a.LeaseFence != fence {
			return ErrFenced
		}
		if !now.Before(a.LeaseExpiresAt) {
			return ErrLeaseExpired
		}
		return fmt.Errorf("%w: attempt is not claimable in state %s", ErrConflict, a.State)
	}
	return nil
}

const postgresReleaseSQL = `UPDATE agent_upgrade_attempts SET
	lease_owner='', lease_expires_at=NULL, lease_fence=lease_fence + 1
	WHERE attempt_id=$1 AND lease_owner=$2 AND lease_fence=$3`

func (p *postgresUpgrades) ReleaseLease(ctx context.Context, attemptID, owner string, fence uint64) error {
	if fence > 1<<62 {
		return ErrFenced
	}
	tag, err := p.pool.Exec(ctx, postgresReleaseSQL, attemptID, owner, int64(fence))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if _, err := p.Get(ctx, attemptID); errors.Is(err, ErrNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		return ErrFenced
	}
	return nil
}

const postgresRequestCancelSQL = `UPDATE agent_upgrade_attempts SET
	cancel_requested=true, updated_at=$2
	WHERE attempt_id=$1`

func (p *postgresUpgrades) RequestCancel(ctx context.Context, attemptID string, now time.Time) error {
	if now.IsZero() {
		return fmt.Errorf("%w: transition time required", ErrConflict)
	}
	tag, err := p.pool.Exec(ctx, postgresRequestCancelSQL, attemptID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if _, err := p.Get(ctx, attemptID); errors.Is(err, ErrNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
	}
	return nil
}

func (p *postgresUpgrades) Ready(ctx context.Context) error {
	if err := p.pool.Ping(ctx); err != nil {
		return ErrNotReady
	}
	return nil
}

func (p *postgresUpgrades) Close() error {
	p.pool.Close()
	return nil
}
