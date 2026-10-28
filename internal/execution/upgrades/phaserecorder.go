package upgrades

import (
	"context"

	"github.com/kube-workspaces/api/internal/execution"
	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/execution/updates"
)

var _ PhaseIntentRecorder = (*Service)(nil)

// RecordPhaseIntent uses ONLY the existing admission's live protected writer.
// It never calls Begin, adopts a sibling's writer or recreates recording state
// after restart. Missing ownership remains unavailable until a separately fenced
// recovery protocol exists. This adapter is not wired to production dispatch.
func (s *Service) RecordPhaseIntent(ctx context.Context, expected storage.AgentUpgradeAttempt, checkpoint []byte) (storage.PhaseRecordingReceipt, error) {
	if s.store == nil || s.store.Durability() != storage.DurabilityDurable || len(checkpoint) == 0 || len(checkpoint) > updates.MaxJournalBytes {
		return storage.PhaseRecordingReceipt{}, ErrUnavailable
	}
	session, err := s.phaseRecordingSession(ctx, expected)
	if err != nil {
		return storage.PhaseRecordingReceipt{}, err
	}
	receipt, err := session.AppendChunkReceipt(ctx, checkpoint)
	if err != nil {
		return storage.PhaseRecordingReceipt{}, ErrUnavailable
	}
	// The object may be committed even if authorization changed during its PUT.
	// Preserve that evidence but return no receipt to admit a phase under stale
	// ownership/cancellation. The ledger performs its own locked checks afterward.
	if err := s.checkPhaseRecording(ctx, expected, session); err != nil {
		return storage.PhaseRecordingReceipt{}, err
	}
	return receipt, nil
}

// CheckPhaseRecording is required both before phase claim and before returning
// its signature. A previously recorded intent cannot justify signing after the
// active writer is lost, finalized or poisoned, even with healthy metadata.
func (s *Service) CheckPhaseRecording(ctx context.Context, expected storage.AgentUpgradeAttempt) error {
	_, err := s.phaseRecordingSession(ctx, expected)
	return err
}

func (s *Service) phaseRecordingSession(ctx context.Context, expected storage.AgentUpgradeAttempt) (*execution.Session, error) {
	if s.store == nil || s.store.Durability() != storage.DurabilityDurable {
		return nil, ErrUnavailable
	}
	if err := s.Ready(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	session := s.sessions[expected.AttemptID]
	s.mu.Unlock()
	if session == nil {
		return nil, ErrUnavailable
	}
	if err := s.checkPhaseRecording(ctx, expected, session); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *Service) checkPhaseRecording(ctx context.Context, expected storage.AgentUpgradeAttempt, session *execution.Session) error {
	current, err := s.attempts.Get(ctx, expected.AttemptID)
	if err != nil {
		return mapStoreError(err)
	}
	if !samePhaseRecordingBinding(expected, current) || !current.State.Claimable() || current.CancelRequested ||
		current.LeaseOwner == "" || !s.now().Before(current.LeaseExpiresAt) {
		return ErrDenied
	}
	s.mu.Lock()
	owned := s.sessions[current.AttemptID] == session
	s.mu.Unlock()
	if !owned {
		return ErrUnavailable
	}
	if err := session.CheckRecording(); err != nil {
		return ErrUnavailable
	}
	rec, outcome, err := s.store.Metadata().Get(ctx, current.ExecutionID)
	if err != nil {
		return ErrUnavailable
	}
	admitted := session.Record()
	rec.AdmissionTime, admitted.AdmissionTime = rec.AdmissionTime.UTC(), admitted.AdmissionTime.UTC()
	if rec != admitted || !rec.Admitted || rec.Durability != storage.DurabilityDurable ||
		rec.Operation != storage.OperationUpgrade || !rec.Elevated || rec.OSIdentity != "SYSTEM" ||
		rec.RecordingID != current.RecordingID || rec.ActorID != current.ActorUID ||
		rec.Namespace != current.Namespace || rec.WorkspaceName != current.WorkspaceName || rec.WorkspaceUID != current.WorkspaceUID ||
		(outcome.State != storage.StateAdmitted && outcome.State != storage.StateRunning) || outcome.RecordingLost {
		return ErrDenied
	}
	return nil
}

func samePhaseRecordingBinding(a, b storage.AgentUpgradeAttempt) bool {
	return a.AttemptID == b.AttemptID && a.ExecutionID == b.ExecutionID && a.RecordingID == b.RecordingID &&
		a.ActorUID == b.ActorUID && a.Namespace == b.Namespace && a.WorkspaceName == b.WorkspaceName &&
		a.WorkspaceUID == b.WorkspaceUID && a.VMUID == b.VMUID && a.ExpectedRevocationEpoch == b.ExpectedRevocationEpoch &&
		a.TargetID == b.TargetID && a.TargetManifestSHA256 == b.TargetManifestSHA256 &&
		a.ExpectedInstalledInventorySHA256 == b.ExpectedInstalledInventorySHA256 && a.AllowReboot == b.AllowReboot &&
		a.Predecessor == b.Predecessor && a.LeaseOwner == b.LeaseOwner && a.LeaseFence == b.LeaseFence
}
