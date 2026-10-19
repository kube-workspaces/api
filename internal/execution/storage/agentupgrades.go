package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// AttemptState is the durable lifecycle state of one admitted agent upgrade.
// The API state machine mirrors the engineering design: a linear install path
// plus an explicit rollback branch from a failed attempt. manual_recovery_required,
// unknown and recording_lost are terminal for worker progress but still hold
// the VM reservation until an administrator cancels them, so uncertain guest
// state is never silently re-admitted.
type AttemptState string

const (
	AttemptAdmitted               AttemptState = "admitted"
	AttemptStaging                AttemptState = "staging"
	AttemptPrepared               AttemptState = "prepared"
	AttemptInstalling             AttemptState = "installing"
	AttemptVerifying              AttemptState = "verifying"
	AttemptSucceeded              AttemptState = "succeeded"
	AttemptAwaitingReboot         AttemptState = "awaiting_reboot"
	AttemptRollbackPending        AttemptState = "rollback_pending"
	AttemptRollingBack            AttemptState = "rolling_back"
	AttemptRolledBack             AttemptState = "rolled_back"
	AttemptCancelled              AttemptState = "cancelled"
	AttemptFailed                 AttemptState = "failed"
	AttemptManualRecoveryRequired AttemptState = "manual_recovery_required"
	AttemptUnknown                AttemptState = "unknown"
	AttemptRecordingLost          AttemptState = "recording_lost"
)

// ValidAttemptStates enumerates every legal state value.
var ValidAttemptStates = []AttemptState{
	AttemptAdmitted, AttemptStaging, AttemptPrepared, AttemptInstalling,
	AttemptVerifying, AttemptSucceeded, AttemptAwaitingReboot,
	AttemptRollbackPending, AttemptRollingBack, AttemptRolledBack,
	AttemptCancelled, AttemptFailed, AttemptManualRecoveryRequired,
	AttemptUnknown, AttemptRecordingLost,
}

// Valid reports whether the state is a known attempt state.
func (s AttemptState) Valid() bool {
	for _, st := range ValidAttemptStates {
		if s == st {
			return true
		}
	}
	return false
}

// Terminal reports whether worker progress is over for the attempt. Terminal
// does not imply the reservation was released: uncertain outcomes hold it.
func (s AttemptState) Terminal() bool {
	switch s {
	case AttemptSucceeded, AttemptCancelled, AttemptFailed, AttemptRolledBack,
		AttemptManualRecoveryRequired, AttemptUnknown, AttemptRecordingLost:
		return true
	default:
		return false
	}
}

// HoldsReservation reports whether the state blocks a new attempt for the
// same VM UID. Uncertain outcomes hold the reservation until an administrator
// clears them with a cancel; terminal releases happen for succeeded, failed,
// rolled_back and cancelled only.
func (s AttemptState) HoldsReservation() bool {
	switch s {
	case AttemptSucceeded, AttemptCancelled, AttemptFailed, AttemptRolledBack:
		return false
	default:
		return true
	}
}

// Claimable reports whether a worker may take or renew the lease in this
// state. A failed attempt only re-enters work through an explicit rollback
// admission (rollback_pending); uncertain states are never claimable.
func (s AttemptState) Claimable() bool {
	switch s {
	case AttemptAdmitted, AttemptStaging, AttemptPrepared, AttemptInstalling,
		AttemptVerifying, AttemptAwaitingReboot, AttemptRollbackPending, AttemptRollingBack:
		return true
	default:
		return false
	}
}

// RecordingFinal reports whether the attempt's admission recording may be
// finalized and its linked execution record finished. A failed attempt keeps
// its recording open because an admitted rollback continues the same evidence
// trail.
func (s AttemptState) RecordingFinal() bool {
	switch s {
	case AttemptSucceeded, AttemptCancelled, AttemptRolledBack,
		AttemptManualRecoveryRequired, AttemptUnknown, AttemptRecordingLost:
		return true
	default:
		return false
	}
}

// validAttemptTransition is the monotonic state machine. Transitions out of a
// final state never happen; rollback admission and administrator cancellation
// are API-side transitions from failed/stuck states.
func validAttemptTransition(from, to AttemptState) bool {
	if !from.Valid() || !to.Valid() || from == to {
		return false
	}
	switch from {
	case AttemptAdmitted:
		return to == AttemptStaging || cancellingOrFailingAttempt(to)
	case AttemptStaging:
		return to == AttemptPrepared || cancellingOrFailingAttempt(to)
	case AttemptPrepared:
		return to == AttemptInstalling || cancellingOrFailingAttempt(to)
	case AttemptInstalling:
		return to == AttemptVerifying || to == AttemptAwaitingReboot || cancellingOrFailingAttempt(to)
	case AttemptVerifying:
		return to == AttemptSucceeded || to == AttemptAwaitingReboot || cancellingOrFailingAttempt(to)
	case AttemptAwaitingReboot:
		return to == AttemptInstalling || to == AttemptVerifying || cancellingOrFailingAttempt(to)
	case AttemptFailed:
		// Rollback admission and administrator close-out only.
		return to == AttemptRollbackPending || to == AttemptCancelled
	case AttemptRollbackPending:
		return to == AttemptRollingBack || to == AttemptCancelled || to == AttemptManualRecoveryRequired || to == AttemptUnknown || to == AttemptRecordingLost
	case AttemptRollingBack:
		return to == AttemptRolledBack || to == AttemptCancelled || to == AttemptManualRecoveryRequired || to == AttemptUnknown || to == AttemptRecordingLost
	case AttemptManualRecoveryRequired, AttemptUnknown, AttemptRecordingLost:
		// An administrator clears a stuck reservation; no other path out.
		return to == AttemptCancelled
	default:
		return false
	}
}

func cancellingOrFailingAttempt(to AttemptState) bool {
	switch to {
	case AttemptCancelled, AttemptFailed, AttemptManualRecoveryRequired, AttemptUnknown, AttemptRecordingLost:
		return true
	default:
		return false
	}
}

// AttemptPredecessor pins the rollback payload an admitted rollback may
// restore. The worker records it from the verified target manifest before any
// mutation; rollback admission refuses attempts without one.
type AttemptPredecessor struct {
	TargetID       string `json:"target_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

// AgentUpgradeAttempt is the durable off-guest record of one admitted agent
// upgrade. It is the authoritative reservation: annotations and guest
// messages are receipts or hints, never authority.
type AgentUpgradeAttempt struct {
	AttemptID                        string
	IdempotencyKey                   string
	Namespace                        string
	WorkspaceName                    string
	WorkspaceUID                     string
	VMUID                            string
	ActorUID                         string
	TargetID                         string
	TargetManifestSHA256             string
	ExpectedInstalledInventorySHA256 string
	ExpectedRevocationEpoch          uint64
	AllowReboot                      bool
	ExecutionID                      string
	RecordingID                      string
	State                            AttemptState
	PhaseTimes                       map[AttemptState]time.Time
	CancelRequested                  bool
	JournalSequence                  uint64
	ErrorCode                        string
	Predecessor                      AttemptPredecessor
	LeaseOwner                       string
	LeaseExpiresAt                   time.Time
	LeaseFence                       uint64
	CreatedAt                        time.Time
	UpdatedAt                        time.Time
}

// RequestFingerprint returns the stable identity of the admission request for
// idempotent-replay comparison. Two starts with the same idempotency key but
// different fingerprints are a conflict, never a silent replay.
func (a AgentUpgradeAttempt) RequestFingerprint() string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%v\x00%d",
		a.Namespace, a.WorkspaceName, a.VMUID, a.TargetID,
		a.TargetManifestSHA256, a.AllowReboot, a.ExpectedRevocationEpoch)
}

// Clone returns a deep copy safe to hand across package boundaries.
func (a AgentUpgradeAttempt) Clone() AgentUpgradeAttempt {
	out := a
	if a.PhaseTimes != nil {
		out.PhaseTimes = make(map[AttemptState]time.Time, len(a.PhaseTimes))
		for st, t := range a.PhaseTimes {
			out.PhaseTimes[st] = t
		}
	}
	return out
}

// AttemptTransition applies one monotonic state change plus its bounded
// progress patch. Fence nil means the API/admin path: it requires no lease
// and fences any worker out by incrementing the fence and clearing the lease.
// A non-nil fence is the worker path and must match the currently held lease.
type AttemptTransition struct {
	To              AttemptState
	Now             time.Time
	Fence           *uint64
	ErrorCode       string
	CancelRequested *bool
	JournalSequence *uint64
	Predecessor     *AttemptPredecessor
}

// Common agent-upgrade store failures.
var (
	ErrVMReserved          = errors.New("another active upgrade attempt holds this VM reservation")
	ErrIdempotencyConflict = errors.New("idempotency key already used with a different request")
	ErrLeaseExpired        = errors.New("upgrade attempt lease expired")
	ErrFenced              = errors.New("upgrade attempt lease fence rejected the caller")
)

// AgentUpgradeStore durably admits, reserves and fences agent-upgrade
// attempts. Reserve is exclusive: attempt id, (namespace, workspace,
// idempotency key) and the per-VM active reservation each conflict rather
// than silently coexist. Implementations must be safe for concurrent use by
// multiple API replicas.
type AgentUpgradeStore interface {
	// Reserve atomically claims a new attempt. ErrConflict means the attempt
	// id exists, ErrVMReserved means another active attempt holds the VM, and
	// ErrIdempotencyConflict means the key exists with a different request.
	Reserve(ctx context.Context, a AgentUpgradeAttempt) error
	// Get returns the attempt or ErrNotFound.
	Get(ctx context.Context, attemptID string) (AgentUpgradeAttempt, error)
	// GetByIdempotency returns the attempt previously admitted under the key
	// or ErrNotFound.
	GetByIdempotency(ctx context.Context, namespace, workspaceName, key string) (AgentUpgradeAttempt, error)
	// ActiveAttempt returns the reservation-holding attempt for a VM UID or
	// ErrNotFound when the VM is free.
	ActiveAttempt(ctx context.Context, vmUID string) (AgentUpgradeAttempt, error)
	// Transition applies a fenced or administrative state change. It fails
	// with ErrNotFound, ErrConflict (wrong current state), ErrFenced or
	// ErrLeaseExpired.
	Transition(ctx context.Context, attemptID string, from AttemptState, t AttemptTransition) error
	// ClaimLease takes or steals an expired worker lease, returning the new
	// monotonically increasing fence.
	ClaimLease(ctx context.Context, attemptID, owner string, now time.Time, ttl time.Duration) (uint64, error)
	// RenewLease extends a held lease without changing the fence.
	RenewLease(ctx context.Context, attemptID, owner string, fence uint64, now time.Time, ttl time.Duration) error
	// ReleaseLease drops a held lease early, fencing the worker out.
	ReleaseLease(ctx context.Context, attemptID, owner string, fence uint64) error
	// RequestCancel records a safe-cancellation request without changing the
	// attempt state or the held lease. The worker observes the flag and stops
	// at its next safe transaction boundary; it is idempotent.
	RequestCancel(ctx context.Context, attemptID string, now time.Time) error
	Ready(ctx context.Context) error
	Close() error
}

// ---------------------------------------------------------------------------
// In-memory agent-upgrade store (ephemeral mode / tests)
// ---------------------------------------------------------------------------

// DefaultMemoryUpgradeAttempts is the bounded process-local capacity used in
// ephemeral mode.
const DefaultMemoryUpgradeAttempts = 1000

// NewMemoryAgentUpgrades returns a bounded, process-local attempt store. It
// makes no durability promise; persistent modes must use the postgres store
// and never fall back to RAM.
func NewMemoryAgentUpgrades(capacity int) (AgentUpgradeStore, error) {
	if capacity < 1 || capacity > 65536 {
		return nil, ErrOverCapacity
	}
	return &memoryUpgrades{attempts: make(map[string]AgentUpgradeAttempt), max: capacity}, nil
}

type memoryUpgrades struct {
	mu       sync.Mutex
	attempts map[string]AgentUpgradeAttempt
	order    []string
	max      int
}

func (m *memoryUpgrades) Reserve(_ context.Context, a AgentUpgradeAttempt) error {
	if err := validateUpgradeAttempt(a); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.attempts[a.AttemptID]; exists {
		return ErrConflict
	}
	for _, existing := range m.attempts {
		if existing.Namespace == a.Namespace && existing.WorkspaceName == a.WorkspaceName && existing.IdempotencyKey == a.IdempotencyKey {
			return ErrIdempotencyConflict
		}
		if existing.VMUID == a.VMUID && existing.State.HoldsReservation() {
			return ErrVMReserved
		}
	}
	if len(m.attempts) >= m.max {
		return ErrOverCapacity
	}
	stored := a.Clone()
	if stored.PhaseTimes == nil {
		stored.PhaseTimes = map[AttemptState]time.Time{}
	}
	if _, ok := stored.PhaseTimes[AttemptAdmitted]; !ok {
		stored.PhaseTimes[AttemptAdmitted] = a.CreatedAt
	}
	m.attempts[a.AttemptID] = stored
	m.order = append(m.order, a.AttemptID)
	for len(m.order) > m.max {
		oldest := m.order[0]
		m.order = m.order[1:]
		delete(m.attempts, oldest)
	}
	return nil
}

func validateUpgradeAttempt(a AgentUpgradeAttempt) error {
	switch {
	case !validUpgradeID(a.AttemptID):
		return fmt.Errorf("%w: invalid attempt id", ErrConflict)
	case a.IdempotencyKey == "" || a.Namespace == "" || a.WorkspaceName == "" || a.WorkspaceUID == "" ||
		a.VMUID == "" || a.ActorUID == "" || a.TargetID == "" || a.ExecutionID == "" || a.RecordingID == "":
		return fmt.Errorf("%w: missing attempt identity", ErrConflict)
	case a.State != AttemptAdmitted:
		return fmt.Errorf("%w: new attempts must start admitted", ErrConflict)
	case a.CreatedAt.IsZero() || a.UpdatedAt.IsZero():
		return fmt.Errorf("%w: attempt timestamps are required", ErrConflict)
	}
	return nil
}

func (m *memoryUpgrades) Get(_ context.Context, attemptID string) (AgentUpgradeAttempt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.attempts[attemptID]
	if !ok {
		return AgentUpgradeAttempt{}, ErrNotFound
	}
	return a.Clone(), nil
}

func (m *memoryUpgrades) GetByIdempotency(_ context.Context, namespace, workspaceName, key string) (AgentUpgradeAttempt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.attempts {
		if a.Namespace == namespace && a.WorkspaceName == workspaceName && a.IdempotencyKey == key {
			return a.Clone(), nil
		}
	}
	return AgentUpgradeAttempt{}, ErrNotFound
}

func (m *memoryUpgrades) ActiveAttempt(_ context.Context, vmUID string) (AgentUpgradeAttempt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.attempts {
		if a.VMUID == vmUID && a.State.HoldsReservation() {
			return a.Clone(), nil
		}
	}
	return AgentUpgradeAttempt{}, ErrNotFound
}

func (m *memoryUpgrades) Transition(_ context.Context, attemptID string, from AttemptState, t AttemptTransition) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.attempts[attemptID]
	if !ok {
		return ErrNotFound
	}
	if a.State != from {
		return ErrConflict
	}
	if !validAttemptTransition(from, t.To) {
		return fmt.Errorf("%w: %s -> %s is not allowed", ErrConflict, from, t.To)
	}
	if t.Fence != nil {
		if a.LeaseOwner == "" || a.LeaseFence != *t.Fence {
			return ErrFenced
		}
	}
	if t.Now.IsZero() {
		return fmt.Errorf("%w: transition time required", ErrConflict)
	}
	a.State = t.To
	a.UpdatedAt = t.Now
	if a.PhaseTimes == nil {
		a.PhaseTimes = map[AttemptState]time.Time{}
	}
	if _, ok := a.PhaseTimes[t.To]; !ok {
		a.PhaseTimes[t.To] = t.Now
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
	// Administrative transitions fence any in-flight worker out; worker
	// transitions (fence supplied) keep the lease they proved.
	if t.Fence == nil {
		a.LeaseOwner = ""
		a.LeaseExpiresAt = time.Time{}
		a.LeaseFence++
	}
	m.attempts[attemptID] = a
	return nil
}

func (m *memoryUpgrades) ClaimLease(_ context.Context, attemptID, owner string, now time.Time, ttl time.Duration) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.attempts[attemptID]
	if !ok {
		return 0, ErrNotFound
	}
	if !a.State.Claimable() {
		return 0, fmt.Errorf("%w: attempt is not claimable in state %s", ErrConflict, a.State)
	}
	if owner == "" || ttl <= 0 || now.IsZero() {
		return 0, fmt.Errorf("%w: lease owner, ttl and time are required", ErrConflict)
	}
	if a.LeaseOwner != "" && a.LeaseOwner != owner && now.Before(a.LeaseExpiresAt) {
		return 0, ErrConflict
	}
	a.LeaseOwner = owner
	a.LeaseExpiresAt = now.Add(ttl)
	a.LeaseFence++
	a.UpdatedAt = now
	m.attempts[attemptID] = a
	return a.LeaseFence, nil
}

func (m *memoryUpgrades) RenewLease(_ context.Context, attemptID, owner string, fence uint64, now time.Time, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.attempts[attemptID]
	if !ok {
		return ErrNotFound
	}
	if a.LeaseOwner != owner || a.LeaseFence != fence {
		return ErrFenced
	}
	if !now.Before(a.LeaseExpiresAt) {
		return ErrLeaseExpired
	}
	if !a.State.Claimable() {
		return fmt.Errorf("%w: attempt is not claimable in state %s", ErrConflict, a.State)
	}
	a.LeaseExpiresAt = now.Add(ttl)
	m.attempts[attemptID] = a
	return nil
}

func (m *memoryUpgrades) ReleaseLease(_ context.Context, attemptID, owner string, fence uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.attempts[attemptID]
	if !ok {
		return ErrNotFound
	}
	if a.LeaseOwner != owner || a.LeaseFence != fence {
		return ErrFenced
	}
	a.LeaseOwner = ""
	a.LeaseExpiresAt = time.Time{}
	a.LeaseFence++
	m.attempts[attemptID] = a
	return nil
}

func (m *memoryUpgrades) RequestCancel(_ context.Context, attemptID string, now time.Time) error {
	if now.IsZero() {
		return fmt.Errorf("%w: transition time required", ErrConflict)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.attempts[attemptID]
	if !ok {
		return ErrNotFound
	}
	if a.CancelRequested {
		return nil
	}
	a.CancelRequested = true
	a.UpdatedAt = now
	m.attempts[attemptID] = a
	return nil
}

func (m *memoryUpgrades) Ready(context.Context) error { return nil }
func (m *memoryUpgrades) Close() error                { return nil }

func validUpgradeID(id string) bool {
	if len(id) < len("upg_")+8 || len(id) > len("upg_")+64 {
		return false
	}
	if id[:4] != "upg_" {
		return false
	}
	return safeID.MatchString(id[4:])
}
