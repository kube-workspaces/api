// Package upgrades implements durable off-guest agent-upgrade admission: an
// exclusive per-VM reservation, idempotent start, safe cancellation, explicit
// rollback admission and the recording/audit evidence trail. It admits and
// records only; artifact verification, guest dispatch and the updater
// transport are separate mandatory slices and never implicit here.
package upgrades

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/kube-workspaces/api/internal/execution"
	"github.com/kube-workspaces/api/internal/execution/storage"
)

// OperationAgentUpgradeStart is the durable grant/attempt operation name.
const OperationAgentUpgradeStart = "agent-upgrade.start.v1"

var (
	// ErrUnavailable is returned when durable admission cannot proceed. Callers
	// must never downgrade a persistent outage to an in-memory reservation.
	ErrUnavailable = errors.New("agent upgrade admission unavailable")
	// ErrDenied is returned when policy or authorization refuses the request.
	ErrDenied = errors.New("agent upgrade admission denied")
	// ErrInvalid is returned for structurally invalid requests.
	ErrInvalid = errors.New("invalid agent upgrade request")
	// ErrNotFound is returned for unknown attempts.
	ErrNotFound = errors.New("upgrade attempt not found")
	// ErrConflict is returned for conflicting reservations, idempotency keys
	// or illegal state transitions.
	ErrConflict = errors.New("upgrade attempt conflicts with existing state")
)

var (
	digestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	targetIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	safeIdentifier     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)
)

// Service coordinates durable upgrade attempts with the execution recording
// store. A nil store or attempts store disables admission entirely.
type Service struct {
	store    storage.Store
	attempts storage.AgentUpgradeStore
	now      func() time.Time

	mu       sync.Mutex
	sessions map[string]*execution.Session
}

// NewService builds the coordinator. Both dependencies may be nil, which
// disables admission fail-closed.
func NewService(store storage.Store, attempts storage.AgentUpgradeStore) *Service {
	return &Service{
		store:    store,
		attempts: attempts,
		now:      time.Now,
		sessions: make(map[string]*execution.Session),
	}
}

// Ready reports whether both the recording/metadata store and the attempt
// store can admit work.
func (s *Service) Ready(ctx context.Context) error {
	if s.store == nil || s.attempts == nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, storage.ErrDisabled)
	}
	if err := s.store.Ready(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if err := s.attempts.Ready(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return nil
}

// Durability describes the active recording store, or "none" when disabled.
func (s *Service) Durability() storage.Durability {
	if s.store == nil {
		return storage.DurabilityNone
	}
	return s.store.Durability()
}

// AdmitRequest is the already-authorized admission of one upgrade attempt.
// The caller must have authenticated a UID-bound administrator, checked
// platform policy and resolved the exact workspace/VM identity.
type AdmitRequest struct {
	Namespace                        string
	WorkspaceName                    string
	WorkspaceUID                     string
	VMUID                            string
	ActorUID                         string
	TargetID                         string
	TargetManifestSHA256             string
	ExpectedInstalledInventorySHA256 string
	ExpectedRevocationEpoch          uint64
	IdempotencyKey                   string
	AllowReboot                      bool
}

func (r AdmitRequest) validate() error {
	switch {
	case r.Namespace == "" || r.WorkspaceName == "" || r.WorkspaceUID == "" || r.VMUID == "" || r.ActorUID == "":
		return fmt.Errorf("%w: namespace, workspace, VM and actor identity are required", ErrInvalid)
	case !safeIdentifier.MatchString(r.WorkspaceUID) || !safeIdentifier.MatchString(r.VMUID):
		return fmt.Errorf("%w: workspace and VM identity are out of bounds", ErrInvalid)
	case !targetIDPattern.MatchString(r.TargetID):
		return fmt.Errorf("%w: target id is out of bounds", ErrInvalid)
	case !digestPattern.MatchString(r.TargetManifestSHA256) || !digestPattern.MatchString(r.ExpectedInstalledInventorySHA256):
		return fmt.Errorf("%w: manifest and inventory digests must be lowercase sha256", ErrInvalid)
	case !idempotencyPattern.MatchString(r.IdempotencyKey):
		return fmt.Errorf("%w: idempotency key is out of bounds", ErrInvalid)
	}
	return nil
}

// admissionStart is the first committed recording chunk: the durable record
// of exactly what was admitted, before any staging, download or installer
// process exists.
type admissionStart struct {
	Type                             string `json:"type"`
	Time                             string `json:"time"`
	AttemptID                        string `json:"attempt_id"`
	Operation                        string `json:"operation"`
	VMUID                            string `json:"vm_uid"`
	WorkspaceUID                     string `json:"workspace_uid"`
	TargetID                         string `json:"target_id"`
	TargetManifestSHA256             string `json:"target_manifest_sha256"`
	ExpectedInstalledInventorySHA256 string `json:"expected_installed_inventory_sha256"`
	ExpectedRevocationEpoch          uint64 `json:"expected_revocation_epoch"`
	AllowReboot                      bool   `json:"allow_reboot"`
	IdempotencyKey                   string `json:"idempotency_key"`
}

// Admit durably records the admission before any guest effect, opens the
// mandatory attempt recording and reserves the exclusive per-VM attempt. An
// identical idempotent replay returns the original attempt with replayed
// true; a replay with a different request is a conflict.
func (s *Service) Admit(ctx context.Context, req AdmitRequest) (storage.AgentUpgradeAttempt, bool, error) {
	if err := req.validate(); err != nil {
		return storage.AgentUpgradeAttempt{}, false, err
	}
	if s.store == nil || s.attempts == nil {
		return storage.AgentUpgradeAttempt{}, false, fmt.Errorf("%w: %w", ErrUnavailable, storage.ErrDisabled)
	}
	if err := s.store.Ready(ctx); err != nil {
		return storage.AgentUpgradeAttempt{}, false, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if err := s.attempts.Ready(ctx); err != nil {
		return storage.AgentUpgradeAttempt{}, false, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	// Fast path for an already-admitted idempotent replay. The uniqueness
	// constraint below closes the concurrent double-submit race.
	if existing, err := s.attempts.GetByIdempotency(ctx, req.Namespace, req.WorkspaceName, req.IdempotencyKey); err == nil {
		if existing.RequestFingerprint() != req.fingerprint() {
			return storage.AgentUpgradeAttempt{}, false, fmt.Errorf("%w: idempotency key already used", ErrConflict)
		}
		return existing, true, nil
	} else if !errors.Is(err, storage.ErrNotFound) {
		return storage.AgentUpgradeAttempt{}, false, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	attemptID, err := mintID("upg")
	if err != nil {
		return storage.AgentUpgradeAttempt{}, false, fmt.Errorf("%w: cannot mint attempt identity", ErrUnavailable)
	}
	executionID, err := mintID("exec")
	if err != nil {
		return storage.AgentUpgradeAttempt{}, false, fmt.Errorf("%w: cannot mint attempt identity", ErrUnavailable)
	}
	recordingID, err := mintID("rec")
	if err != nil {
		return storage.AgentUpgradeAttempt{}, false, fmt.Errorf("%w: cannot mint attempt identity", ErrUnavailable)
	}
	now := s.now().UTC()
	attempt := storage.AgentUpgradeAttempt{
		AttemptID:                        attemptID,
		IdempotencyKey:                   req.IdempotencyKey,
		Namespace:                        req.Namespace,
		WorkspaceName:                    req.WorkspaceName,
		WorkspaceUID:                     req.WorkspaceUID,
		VMUID:                            req.VMUID,
		ActorUID:                         req.ActorUID,
		TargetID:                         req.TargetID,
		TargetManifestSHA256:             req.TargetManifestSHA256,
		ExpectedInstalledInventorySHA256: req.ExpectedInstalledInventorySHA256,
		ExpectedRevocationEpoch:          req.ExpectedRevocationEpoch,
		AllowReboot:                      req.AllowReboot,
		ExecutionID:                      executionID,
		RecordingID:                      recordingID,
		State:                            storage.AttemptAdmitted,
		PhaseTimes:                       map[storage.AttemptState]time.Time{storage.AttemptAdmitted: now},
		CreatedAt:                        now,
		UpdatedAt:                        now,
	}
	execSvc := execution.NewService(s.store)
	session, err := execSvc.Admit(ctx, execution.AdmissionRequest{
		ExecutionID:   executionID,
		RecordingID:   recordingID,
		ActorID:       req.ActorUID,
		Operation:     storage.OperationUpgrade,
		Namespace:     req.Namespace,
		WorkspaceName: req.WorkspaceName,
		WorkspaceUID:  req.WorkspaceUID,
		GrantVersion:  "1",
		OSIdentity:    "SYSTEM",
		Elevated:      true,
	})
	if err != nil {
		return storage.AgentUpgradeAttempt{}, false, fmt.Errorf("%w: execution admission unavailable", ErrUnavailable)
	}
	chunk, err := json.Marshal(admissionStart{
		Type:                             "agent-upgrade-admission",
		Time:                             now.Format(time.RFC3339),
		AttemptID:                        attemptID,
		Operation:                        OperationAgentUpgradeStart,
		VMUID:                            req.VMUID,
		WorkspaceUID:                     req.WorkspaceUID,
		TargetID:                         req.TargetID,
		TargetManifestSHA256:             req.TargetManifestSHA256,
		ExpectedInstalledInventorySHA256: req.ExpectedInstalledInventorySHA256,
		ExpectedRevocationEpoch:          req.ExpectedRevocationEpoch,
		AllowReboot:                      req.AllowReboot,
		IdempotencyKey:                   req.IdempotencyKey,
	})
	if err == nil {
		err = session.AppendChunk(ctx, chunk)
	}
	if err != nil {
		_ = session.Abort(ctx, "upgrade admission recording unavailable")
		return storage.AgentUpgradeAttempt{}, false, fmt.Errorf("%w: attempt recording unavailable", ErrUnavailable)
	}
	if err := s.attempts.Reserve(ctx, attempt); err != nil {
		_ = session.Abort(ctx, "upgrade reservation denied: "+err.Error())
		if errors.Is(err, storage.ErrIdempotencyConflict) {
			// A concurrent identical submit won the uniqueness constraint.
			if existing, getErr := s.attempts.GetByIdempotency(ctx, req.Namespace, req.WorkspaceName, req.IdempotencyKey); getErr == nil {
				if existing.RequestFingerprint() != req.fingerprint() {
					return storage.AgentUpgradeAttempt{}, false, fmt.Errorf("%w: idempotency key already used", ErrConflict)
				}
				return existing, true, nil
			}
		}
		return storage.AgentUpgradeAttempt{}, false, mapStoreError(err)
	}
	s.mu.Lock()
	s.sessions[attemptID] = session
	s.mu.Unlock()
	_ = s.store.Metadata().Audit(ctx, storage.AuditEvent{
		ExecutionID: executionID,
		Time:        now,
		Kind:        "upgrade.admitted",
		ActorID:     req.ActorUID,
		Detail: map[string]string{
			"attemptID":       attemptID,
			"operation":       OperationAgentUpgradeStart,
			"targetID":        req.TargetID,
			"targetManifest":  req.TargetManifestSHA256,
			"inventoryDigest": req.ExpectedInstalledInventorySHA256,
			"revocationEpoch": fmt.Sprintf("%d", req.ExpectedRevocationEpoch),
			"allowReboot":     fmt.Sprintf("%v", req.AllowReboot),
			"vmUID":           req.VMUID,
		},
	})
	return attempt, false, nil
}

func (r AdmitRequest) fingerprint() string {
	a := storage.AgentUpgradeAttempt{
		Namespace:               r.Namespace,
		WorkspaceName:           r.WorkspaceName,
		VMUID:                   r.VMUID,
		TargetID:                r.TargetID,
		TargetManifestSHA256:    r.TargetManifestSHA256,
		AllowReboot:             r.AllowReboot,
		ExpectedRevocationEpoch: r.ExpectedRevocationEpoch,
	}
	return a.RequestFingerprint()
}

// Get returns one attempt the caller has already authorized.
func (s *Service) Get(ctx context.Context, attemptID string) (storage.AgentUpgradeAttempt, error) {
	if s.attempts == nil {
		return storage.AgentUpgradeAttempt{}, fmt.Errorf("%w: %w", ErrUnavailable, storage.ErrDisabled)
	}
	a, err := s.attempts.Get(ctx, attemptID)
	if errors.Is(err, storage.ErrNotFound) {
		return storage.AgentUpgradeAttempt{}, ErrNotFound
	}
	if err != nil {
		return storage.AgentUpgradeAttempt{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return a, nil
}

// ActiveAttempt returns the reservation-holding attempt for a VM.
func (s *Service) ActiveAttempt(ctx context.Context, vmUID string) (storage.AgentUpgradeAttempt, error) {
	if s.attempts == nil {
		return storage.AgentUpgradeAttempt{}, fmt.Errorf("%w: %w", ErrUnavailable, storage.ErrDisabled)
	}
	a, err := s.attempts.ActiveAttempt(ctx, vmUID)
	if errors.Is(err, storage.ErrNotFound) {
		return storage.AgentUpgradeAttempt{}, ErrNotFound
	}
	if err != nil {
		return storage.AgentUpgradeAttempt{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return a, nil
}

// Cancel closes out or requests safe cancellation. Before any install phase
// the attempt is cancelled immediately; during mutation it only records the
// request and the worker stops at its next safe transaction boundary. Stuck
// uncertain states are cleared by administrators through the same route.
func (s *Service) Cancel(ctx context.Context, attemptID string) (storage.AgentUpgradeAttempt, error) {
	if s.attempts == nil {
		return storage.AgentUpgradeAttempt{}, fmt.Errorf("%w: %w", ErrUnavailable, storage.ErrDisabled)
	}
	a, err := s.Get(ctx, attemptID)
	if err != nil {
		return storage.AgentUpgradeAttempt{}, err
	}
	now := s.now().UTC()
	switch a.State {
	case storage.AttemptAdmitted, storage.AttemptStaging, storage.AttemptPrepared:
		if err := s.attempts.Transition(ctx, a.AttemptID, a.State, storage.AttemptTransition{To: storage.AttemptCancelled, Now: now}); err != nil {
			return storage.AgentUpgradeAttempt{}, mapStoreError(err)
		}
		s.finalize(ctx, attemptID, "cancelled", storage.AttemptCancelled)
	case storage.AttemptInstalling, storage.AttemptVerifying, storage.AttemptAwaitingReboot, storage.AttemptRollbackPending, storage.AttemptRollingBack:
		if a.CancelRequested {
			return a, nil // idempotent: the request is already recorded
		}
		if err := s.attempts.RequestCancel(ctx, a.AttemptID, now); err != nil {
			return storage.AgentUpgradeAttempt{}, mapStoreError(err)
		}
	case storage.AttemptManualRecoveryRequired, storage.AttemptUnknown, storage.AttemptRecordingLost, storage.AttemptFailed:
		prior := a.State
		if err := s.attempts.Transition(ctx, a.AttemptID, a.State, storage.AttemptTransition{To: storage.AttemptCancelled, Now: now, ErrorCode: a.ErrorCode}); err != nil {
			return storage.AgentUpgradeAttempt{}, mapStoreError(err)
		}
		// An administrator closing out a stuck uncertain state must not
		// rewrite its unknown outcome as a routine cancellation: the guest
		// may still be mid-mutation and must never be auto-rerun.
		finalizeState := storage.AttemptCancelled
		switch prior {
		case storage.AttemptManualRecoveryRequired, storage.AttemptUnknown, storage.AttemptRecordingLost:
			finalizeState = prior
		}
		s.finalize(ctx, attemptID, "cleared", finalizeState)
	default:
		return storage.AgentUpgradeAttempt{}, fmt.Errorf("%w: attempt already finished as %s", ErrConflict, a.State)
	}
	_ = s.store.Metadata().Audit(ctx, storage.AuditEvent{
		ExecutionID: a.ExecutionID,
		Time:        now,
		Kind:        "upgrade.cancel-requested",
		ActorID:     a.ActorUID,
		Detail:      map[string]string{"attemptID": a.AttemptID, "state": string(a.State)},
	})
	return s.Get(ctx, attemptID)
}

// Rollback admits a separate, explicit rollback of a failed attempt to its
// pinned predecessor payload. The attempt must have failed and the worker
// must have pinned the predecessor from the verified manifest; admission
// itself performs no guest effect.
func (s *Service) Rollback(ctx context.Context, attemptID string) (storage.AgentUpgradeAttempt, error) {
	if s.attempts == nil {
		return storage.AgentUpgradeAttempt{}, fmt.Errorf("%w: %w", ErrUnavailable, storage.ErrDisabled)
	}
	a, err := s.Get(ctx, attemptID)
	if err != nil {
		return storage.AgentUpgradeAttempt{}, err
	}
	if a.State != storage.AttemptFailed {
		return storage.AgentUpgradeAttempt{}, fmt.Errorf("%w: rollback requires a failed attempt, found %s", ErrConflict, a.State)
	}
	if a.Predecessor.TargetID == "" || !digestPattern.MatchString(a.Predecessor.ManifestSHA256) {
		return storage.AgentUpgradeAttempt{}, fmt.Errorf("%w: attempt has no pinned rollback predecessor", ErrInvalid)
	}
	now := s.now().UTC()
	if err := s.attempts.Transition(ctx, a.AttemptID, a.State, storage.AttemptTransition{
		To:  storage.AttemptRollbackPending,
		Now: now,
	}); err != nil {
		return storage.AgentUpgradeAttempt{}, mapStoreError(err)
	}
	_ = s.store.Metadata().Audit(ctx, storage.AuditEvent{
		ExecutionID: a.ExecutionID,
		Time:        now,
		Kind:        "upgrade.rollback-admitted",
		ActorID:     a.ActorUID,
		Detail: map[string]string{
			"attemptID":         a.AttemptID,
			"predecessorTarget": a.Predecessor.TargetID,
			"predecessorDigest": a.Predecessor.ManifestSHA256,
		},
	})
	return s.Get(ctx, attemptID)
}

// recordingOutcome maps attempt terminal states onto the linked execution
// record outcome. rolled_back is never success; uncertain outcomes are
// permanently unknown and must never be auto-rerun.
func recordingOutcome(state storage.AttemptState) (storage.ExecutionOutcome, bool) {
	switch state {
	case storage.AttemptSucceeded:
		return storage.ExecutionOutcome{State: storage.StateSucceeded}, true
	case storage.AttemptCancelled:
		return storage.ExecutionOutcome{State: storage.StateCancelled}, true
	case storage.AttemptRolledBack:
		return storage.ExecutionOutcome{State: storage.StateFailed, Termination: "rolled back to pinned predecessor"}, true
	case storage.AttemptManualRecoveryRequired:
		return storage.ExecutionOutcome{State: storage.StateUnknown, Termination: "manual recovery required; do not rerun"}, true
	case storage.AttemptUnknown:
		return storage.ExecutionOutcome{State: storage.StateUnknown, Termination: "outcome unknown; do not rerun"}, true
	case storage.AttemptRecordingLost:
		return storage.ExecutionOutcome{State: storage.StateRecordingLost, RecordingLost: true}, true
	default:
		return storage.ExecutionOutcome{}, false
	}
}

// finalize closes the attempt's evidence trail once its state is
// recording-final. Same-replica admissions hold the recording writer and
// finalize inline; after a replica restart the execution record still
// transitions and the deferred audit explains the missing inline finalize.
// outcomeState is the attempt state the recording outcome derives from, which
// may differ from the current state when an administrator clears a stuck
// uncertain attempt.
func (s *Service) finalize(ctx context.Context, attemptID, kind string, outcomeState storage.AttemptState) {
	a, err := s.attempts.Get(ctx, attemptID)
	if err != nil || !a.State.RecordingFinal() {
		return
	}
	outcome, ok := recordingOutcome(outcomeState)
	if !ok {
		return
	}
	s.mu.Lock()
	session := s.sessions[attemptID]
	delete(s.sessions, attemptID)
	s.mu.Unlock()
	now := s.now().UTC()
	if session != nil {
		_ = session.Audit(ctx, "upgrade."+kind, map[string]string{"attemptID": attemptID, "state": string(a.State)})
		_ = session.Finish(ctx, outcome)
		return
	}
	_ = s.store.Metadata().Transition(ctx, a.ExecutionID, outcome)
	_ = s.store.Metadata().Audit(ctx, storage.AuditEvent{
		ExecutionID: a.ExecutionID,
		Time:        now,
		Kind:        "upgrade.recording.finalize-deferred",
		ActorID:     a.ActorUID,
		Detail:      map[string]string{"attemptID": attemptID, "state": string(a.State)},
	})
}

func mapStoreError(err error) error {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, storage.ErrVMReserved), errors.Is(err, storage.ErrIdempotencyConflict), errors.Is(err, storage.ErrConflict), errors.Is(err, storage.ErrFenced), errors.Is(err, storage.ErrLeaseExpired):
		return fmt.Errorf("%w: %v", ErrConflict, err)
	case errors.Is(err, storage.ErrDisabled), errors.Is(err, storage.ErrNotReady), errors.Is(err, storage.ErrOverCapacity):
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	default:
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
}

func mintID(prefix string) (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(raw[:]), nil
}
