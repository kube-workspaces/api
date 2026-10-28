package upgrades

import (
	"context"

	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/execution/updates"
)

// ArtifactApprovalReader must obtain independently CURRENT operator key/allowlist
// policy on every call. No production reader, cached-success fallback or request-
// supplied policy is provided here.
type ArtifactApprovalReader func(context.Context) (ArtifactApproval, error)

// ArtifactPhaseAuthority adds immutable artifact/plan checks to a REQUIRED base
// implementing all remaining current authority/lineage/authenticated-exchange
// checks. It is not a standalone complete source and is not wired by the server.
type ArtifactPhaseAuthority struct {
	base      PhaseAuthoritySource
	artifacts *VerifiedPhaseArtifacts
	current   ArtifactApprovalReader
}

func NewArtifactPhaseAuthority(base PhaseAuthoritySource, artifacts *VerifiedPhaseArtifacts, current ArtifactApprovalReader) (*ArtifactPhaseAuthority, error) {
	if base == nil || artifacts == nil || current == nil {
		return nil, ErrUnavailable
	}
	return &ArtifactPhaseAuthority{base: base, artifacts: artifacts, current: current}, nil
}

func (s *ArtifactPhaseAuthority) check(ctx context.Context, a storage.AgentUpgradeAttempt, j *updates.Journal) error {
	if s == nil || s.base == nil || s.artifacts == nil || s.current == nil || j == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	approval, err := s.current(ctx)
	if err != nil {
		return ErrUnavailable
	}
	return s.artifacts.CheckPlan(ctx, a, j.Snapshot().Plan, approval)
}

func (s *ArtifactPhaseAuthority) CheckIntent(ctx context.Context, a storage.AgentUpgradeAttempt, j *updates.Journal) error {
	if s == nil || s.base == nil || s.artifacts == nil || s.current == nil || j == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	if err := s.base.CheckIntent(ctx, a, j); err != nil {
		return err
	}
	return s.check(ctx, a, j)
}

func (s *ArtifactPhaseAuthority) CurrentPhase(ctx context.Context, a storage.AgentUpgradeAttempt, j *updates.Journal) (PhaseContext, error) {
	if err := s.check(ctx, a, j); err != nil {
		return PhaseContext{}, err
	}
	current, err := s.base.CurrentPhase(ctx, a, j)
	if err != nil {
		return PhaseContext{}, err
	}
	// A slow exchange cannot preserve a key/allowlist approval that was revoked
	// while the base obtained fresh boot/peer/challenge authority.
	if err := s.check(ctx, a, j); err != nil {
		return PhaseContext{}, err
	}
	return current, nil
}
