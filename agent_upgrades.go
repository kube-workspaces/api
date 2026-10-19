package kubeworkspaces

import (
	"context"
	"errors"
	"fmt"
	"time"

	genagentupgrades "github.com/kube-workspaces/api/gen/agentupgrades"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution/qga"
	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/execution/upgrades"
	"github.com/kube-workspaces/api/internal/platform"
	"goa.design/clue/log"
)

// UpgradeEligibility resolves the current controller-owned identity of a
// workspace: the same fail-closed QGA resolver the execution pilot uses,
// which internally requires the platform execution policy to admit SYSTEM
// elevation for the workspace.
type UpgradeEligibility interface {
	Resolve(ctx context.Context, namespace, name string) (qga.Target, error)
}

// agentupgradessrvc implements the administrator-only agent-upgrade admission
// surface. It authorizes, computes fresh eligibility and delegates durable
// reservation/recording to the upgrades coordinator; it never dispatches to
// the guest or verifies artifacts itself.
type agentupgradessrvc struct {
	svc      *upgrades.Service
	plat     *platform.ConfigProvider
	resolver UpgradeEligibility
}

// NewAgentUpgrades returns the agent-upgrades service implementation. A nil
// coordinator, policy provider or resolver leaves every method unavailable;
// the surface never degrades to in-memory best-effort behavior.
func NewAgentUpgrades(svc *upgrades.Service, plat *platform.ConfigProvider, resolver UpgradeEligibility) genagentupgrades.Service {
	return &agentupgradessrvc{svc: svc, plat: plat, resolver: resolver}
}

func agentUpgradeError(name, message string) error {
	switch name {
	case "unauthorized":
		return genagentupgrades.Unauthorized(message)
	case "forbidden":
		return genagentupgrades.Forbidden(message)
	case "invalid":
		return genagentupgrades.Invalid(message)
	case "not_found":
		return genagentupgrades.NotFound(message)
	case "conflict":
		return genagentupgrades.Conflict(message)
	default:
		return genagentupgrades.Unavailable(message)
	}
}

func (s *agentupgradessrvc) requireService() error {
	if s.svc == nil {
		return agentUpgradeError("unavailable", "agent upgrade admission is not enabled")
	}
	return nil
}

// authorizeAdmin enforces the upgrade gate: a current UID-bound credential
// with administrator role. Legacy credentials and auth-disabled anonymous
// callers never admit an upgrade.
func (s *agentupgradessrvc) authorizeAdmin(ctx context.Context) (*auth.UserInfo, error) {
	user := auth.ExecutionPrincipal(ctx)
	if user == nil {
		return nil, agentUpgradeError("unauthorized", "sign in with a user-bound credential")
	}
	if user.Role != "admin" {
		return nil, agentUpgradeError("forbidden", "administrator access required for agent upgrades")
	}
	return user, nil
}

func (s *agentupgradessrvc) policyEnabled(ctx context.Context) (bool, error) {
	if s.plat == nil {
		return false, agentUpgradeError("unavailable", "agent upgrade policy unavailable")
	}
	policy, err := s.plat.GetAgentUpgradePolicy(ctx)
	if err != nil {
		return false, agentUpgradeError("unavailable", "agent upgrade policy unavailable")
	}
	return policy.Enabled, nil
}

// resolveWorkspace resolves the current controller-owned identity of the
// workspace. ErrDenied is a definitive not-eligible; other resolver failures
// are temporarily unavailable, never a silent "not eligible".
func (s *agentupgradessrvc) resolveWorkspace(ctx context.Context, ns, name string) (qga.Target, error) {
	if s.resolver == nil {
		return qga.Target{}, agentUpgradeError("unavailable", "workspace eligibility resolution is not enabled")
	}
	target, err := s.resolver.Resolve(ctx, ns, name)
	if err != nil {
		if errors.Is(err, qga.ErrDenied) {
			return qga.Target{}, agentUpgradeError("invalid", "not an eligible running Windows VM")
		}
		return qga.Target{}, agentUpgradeError("unavailable", "workspace eligibility is temporarily unavailable")
	}
	return target, nil
}

// Availability reports whether a start would be admissible right now. The
// inventory flag stays false until the guest-integration slice ships; start
// never depends on it as a silent shortcut.
func (s *agentupgradessrvc) Availability(ctx context.Context, p *genagentupgrades.AvailabilityPayload) (*genagentupgrades.AgentUpgradeAvailability, error) {
	if _, err := s.authorizeAdmin(ctx); err != nil {
		return nil, err
	}
	if p == nil || p.Name == "" {
		return nil, agentUpgradeError("invalid", "workspace name required")
	}
	ns := p.Namespace
	if ns == "" {
		ns = "workspaces"
	}
	out := &genagentupgrades.AgentUpgradeAvailability{
		PolicyEnabled:      false,
		StorageAvailable:   false,
		WorkspaceEligible:  false,
		InventoryAvailable: false,
		Admissible:         false,
		DenyReason:         "policy_disabled",
	}
	policyEnabled, err := s.policyEnabled(ctx)
	if err != nil {
		return nil, err
	}
	out.PolicyEnabled = policyEnabled
	if !policyEnabled {
		return out, nil
	}
	if s.svc == nil || s.svc.Ready(ctx) != nil {
		out.DenyReason = "storage_unavailable"
		return out, nil
	}
	out.StorageAvailable = true
	target, resolveErr := s.resolveWorkspace(ctx, ns, p.Name)
	if resolveErr != nil {
		out.DenyReason = "eligibility_unavailable"
		return out, nil
	}
	out.WorkspaceEligible = true
	vmUID := target.VMUID
	out.VMUID = &vmUID
	active, err := s.svc.ActiveAttempt(ctx, vmUID)
	switch {
	case err == nil:
		id := active.AttemptID
		out.ActiveAttemptID = &id
		out.DenyReason = "attempt_active"
		return out, nil
	case !errors.Is(err, upgrades.ErrNotFound):
		out.DenyReason = "storage_unavailable"
		return out, nil
	}
	// Fresh guest inventory is a mandatory install-time verification, not an
	// admission-time dependency; the flag stays false until the guest
	// integration slice lands.
	out.InventoryAvailable = false
	out.Admissible = true
	out.DenyReason = ""
	return out, nil
}

// Start admits one explicit upgrade attempt, durably recording the admission
// before any guest effect. An identical idempotent replay returns the original
// attempt; the reservation is exclusive per VM.
func (s *agentupgradessrvc) Start(ctx context.Context, p *genagentupgrades.AgentUpgradeStartPayload) (*genagentupgrades.AgentUpgradeAttempt, error) {
	user, err := s.authorizeAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if p == nil {
		return nil, agentUpgradeError("invalid", "upgrade request required")
	}
	ns := p.Namespace
	if ns == "" {
		ns = "workspaces"
	}
	policyEnabled, err := s.policyEnabled(ctx)
	if err != nil {
		return nil, err
	}
	if !policyEnabled {
		return nil, agentUpgradeError("forbidden", "agent upgrades are disabled by platform policy")
	}
	target, err := s.resolveWorkspace(ctx, ns, p.Name)
	if err != nil {
		return nil, err
	}
	if p.ExpectedVMUID != target.VMUID {
		return nil, agentUpgradeError("conflict", "workspace VM identity changed; retry availability first")
	}
	log.Printf(ctx, "agentupgrades.start namespace=%s workspace=%s target=%s", ns, p.Name, p.TargetID)
	attempt, replayed, err := s.svc.Admit(ctx, upgrades.AdmitRequest{
		Namespace:                        ns,
		WorkspaceName:                    p.Name,
		WorkspaceUID:                     target.WorkspaceUID,
		VMUID:                            target.VMUID,
		ActorUID:                         user.UID,
		TargetID:                         p.TargetID,
		TargetManifestSHA256:             p.TargetManifestSha256,
		ExpectedInstalledInventorySHA256: p.ExpectedInstalledInventorySha256,
		ExpectedRevocationEpoch:          p.ExpectedRevocationEpoch,
		IdempotencyKey:                   p.IdempotencyKey,
		AllowReboot:                      p.AllowReboot,
	})
	if err != nil {
		return nil, mapAgentUpgradeServiceError(err)
	}
	if replayed {
		log.Printf(ctx, "agentupgrades.start replayed attempt=%s", attempt.AttemptID)
	}
	return attemptToResult(attempt, p.Name), nil
}

func (s *agentupgradessrvc) Status(ctx context.Context, p *genagentupgrades.StatusPayload) (*genagentupgrades.AgentUpgradeAttempt, error) {
	if _, err := s.authorizeAdmin(ctx); err != nil {
		return nil, err
	}
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if p == nil || p.AttemptID == "" {
		return nil, agentUpgradeError("invalid", "attempt id required")
	}
	attempt, err := s.svc.Get(ctx, p.AttemptID)
	if err != nil {
		return nil, mapAgentUpgradeServiceError(err)
	}
	if err := matchAgentUpgradeScope(attempt, p.Namespace, p.Name); err != nil {
		return nil, err
	}
	return attemptToResult(attempt, p.Name), nil
}

// Cancel closes out or requests safe cancellation. Before any install phase
// the attempt is cancelled immediately; during mutation it only records the
// request. It never promises to kill an active MSI transaction.
func (s *agentupgradessrvc) Cancel(ctx context.Context, p *genagentupgrades.CancelPayload) (*genagentupgrades.AgentUpgradeAttempt, error) {
	if _, err := s.authorizeAdmin(ctx); err != nil {
		return nil, err
	}
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if p == nil || p.AttemptID == "" {
		return nil, agentUpgradeError("invalid", "attempt id required")
	}
	existing, err := s.svc.Get(ctx, p.AttemptID)
	if err != nil {
		return nil, mapAgentUpgradeServiceError(err)
	}
	if err := matchAgentUpgradeScope(existing, p.Namespace, p.Name); err != nil {
		return nil, err
	}
	attempt, err := s.svc.Cancel(ctx, p.AttemptID)
	if err != nil {
		return nil, mapAgentUpgradeServiceError(err)
	}
	return attemptToResult(attempt, p.Name), nil
}

// Rollback admits a separate, explicit rollback of a failed attempt to its
// pinned previous payload; admission itself performs no guest effect.
func (s *agentupgradessrvc) Rollback(ctx context.Context, p *genagentupgrades.RollbackPayload) (*genagentupgrades.AgentUpgradeAttempt, error) {
	if _, err := s.authorizeAdmin(ctx); err != nil {
		return nil, err
	}
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if p == nil || p.AttemptID == "" {
		return nil, agentUpgradeError("invalid", "attempt id required")
	}
	existing, err := s.svc.Get(ctx, p.AttemptID)
	if err != nil {
		return nil, mapAgentUpgradeServiceError(err)
	}
	if err := matchAgentUpgradeScope(existing, p.Namespace, p.Name); err != nil {
		return nil, err
	}
	attempt, err := s.svc.Rollback(ctx, p.AttemptID)
	if err != nil {
		return nil, mapAgentUpgradeServiceError(err)
	}
	return attemptToResult(attempt, p.Name), nil
}

// matchAgentUpgradeScope binds an attempt to the namespace/workspace in the
// URL: an attempt is only visible under the exact scope that admitted it.
func matchAgentUpgradeScope(a storage.AgentUpgradeAttempt, ns, name string) error {
	if ns == "" {
		ns = "workspaces"
	}
	if a.Namespace != ns || a.WorkspaceName != name {
		return agentUpgradeError("not_found", "upgrade attempt not found")
	}
	return nil
}

func mapAgentUpgradeServiceError(err error) error {
	switch {
	case errors.Is(err, upgrades.ErrInvalid):
		return agentUpgradeError("invalid", err.Error())
	case errors.Is(err, upgrades.ErrNotFound):
		return agentUpgradeError("not_found", "upgrade attempt not found")
	case errors.Is(err, upgrades.ErrDenied):
		return agentUpgradeError("forbidden", err.Error())
	case errors.Is(err, upgrades.ErrConflict):
		return agentUpgradeError("conflict", err.Error())
	default:
		return agentUpgradeError("unavailable", "agent upgrade admission unavailable")
	}
}

// attemptToResult renders the protected attempt metadata, including the
// independently authorized recording link and the canonical status URL.
func attemptToResult(a storage.AgentUpgradeAttempt, workspaceName string) *genagentupgrades.AgentUpgradeAttempt {
	recordingURL := fmt.Sprintf("/v1/executions/%s/recording", a.ExecutionID)
	statusURL := fmt.Sprintf("/v1/workspaces/%s/agent-upgrades/%s?namespace=%s", workspaceName, a.AttemptID, a.Namespace)
	res := &genagentupgrades.AgentUpgradeAttempt{
		AttemptID:                        a.AttemptID,
		Namespace:                        a.Namespace,
		WorkspaceName:                    a.WorkspaceName,
		WorkspaceUID:                     a.WorkspaceUID,
		VMUID:                            a.VMUID,
		ActorID:                          a.ActorUID,
		State:                            string(a.State),
		TargetID:                         a.TargetID,
		TargetManifestSha256:             a.TargetManifestSHA256,
		ExpectedInstalledInventorySha256: a.ExpectedInstalledInventorySHA256,
		AllowReboot:                      a.AllowReboot,
		CancelRequested:                  a.CancelRequested,
		ExecutionID:                      a.ExecutionID,
		RecordingID:                      a.RecordingID,
		RecordingURL:                     recordingURL,
		StatusURL:                        statusURL,
		JournalSequence:                  a.JournalSequence,
		AdmittedAt:                       a.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:                        a.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if a.Predecessor.TargetID != "" {
		target := a.Predecessor.TargetID
		res.PredecessorTargetID = &target
	}
	if a.Predecessor.ManifestSHA256 != "" {
		digest := a.Predecessor.ManifestSHA256
		res.PredecessorManifestSha256 = &digest
	}
	if a.ErrorCode != "" {
		code := a.ErrorCode
		res.ErrorCode = &code
	}
	if t, ok := a.PhaseTimes[storage.AttemptStaging]; ok {
		s := t.UTC().Format(time.RFC3339)
		res.StagingAt = &s
	}
	if t, ok := a.PhaseTimes[storage.AttemptPrepared]; ok {
		s := t.UTC().Format(time.RFC3339)
		res.PreparedAt = &s
	}
	if t, ok := a.PhaseTimes[storage.AttemptInstalling]; ok {
		s := t.UTC().Format(time.RFC3339)
		res.InstallingAt = &s
	}
	if t, ok := a.PhaseTimes[storage.AttemptAwaitingReboot]; ok {
		s := t.UTC().Format(time.RFC3339)
		res.AwaitingRebootAt = &s
	}
	if t, ok := a.PhaseTimes[storage.AttemptVerifying]; ok {
		s := t.UTC().Format(time.RFC3339)
		res.VerifyingAt = &s
	}
	if t, ok := a.PhaseTimes[storage.AttemptRollbackPending]; ok {
		s := t.UTC().Format(time.RFC3339)
		res.RollbackRequestedAt = &s
	}
	if t, ok := a.PhaseTimes[storage.AttemptRollingBack]; ok {
		s := t.UTC().Format(time.RFC3339)
		res.RollingBackAt = &s
	}
	if a.State.Terminal() {
		if t, ok := a.PhaseTimes[a.State]; ok {
			s := t.UTC().Format(time.RFC3339)
			res.TerminalAt = &s
		}
	}
	return res
}
