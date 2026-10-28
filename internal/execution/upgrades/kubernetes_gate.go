package upgrades

import (
	"context"
	"errors"
	"time"

	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution/enrollment"
	"github.com/kube-workspaces/api/internal/execution/pki"
	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/execution/updates"
	"github.com/kube-workspaces/api/internal/platform"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var phaseWorkspaceResource = schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "workspaces"}

// KubernetesPhaseGate implements ONLY the live credential/policy/controller-
// incarnation part of phase authority. It deliberately does not implement
// PhaseAuthoritySource: verified artifacts, trusted journal lineage and an
// authenticated guest exchange remain separate mandatory prerequisites.
type KubernetesPhaseGate struct {
	client dynamic.Interface
	now    func() time.Time
}

func NewKubernetesPhaseGate(client dynamic.Interface) (*KubernetesPhaseGate, error) {
	if client == nil {
		return nil, ErrUnavailable
	}
	return &KubernetesPhaseGate{client: client, now: time.Now}, nil
}

// Check requires a fresh signed, method/UID-bound credential for the admitted
// administrator. It never uses a caller-built UserInfo, auth-disabled principal,
// stored actor UID alone, desktop grant or QGA capability as authorization.
// Credentials stay call-local: no persistence, caching, logging or worker token
// minting is performed. Success is NOT permission to sign or install by itself.
func (g *KubernetesPhaseGate) Check(ctx context.Context, a storage.AgentUpgradeAttempt, j *updates.Journal, credential string) (pki.Identity, error) {
	if ctx.Err() != nil || g == nil || g.client == nil {
		return pki.Identity{}, ErrUnavailable
	}
	if credential == "" || len(credential) > 32*1024 || !phaseGateBinding(a, j, g.now()) {
		return pki.Identity{}, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	policy := platform.NewConfigProvider(g.client)
	authConfig, err := auth.NewConfigProvider(g.client).GetAuthConfig(ctx)
	if err != nil || !phaseObject(authConfig) || authConfig.GetName() != "default" || authConfig.GetNamespace() != "" {
		return pki.Identity{}, ErrUnavailable
	}
	enabled, found, err := unstructured.NestedBool(authConfig.Object, "spec", "enabled")
	if err != nil || !found || !enabled {
		return pki.Identity{}, ErrDenied
	}
	platformConfig, err := policy.GetPlatformConfig(ctx)
	if err != nil || !phaseObject(platformConfig) || platformConfig.GetName() != "default" || platformConfig.GetNamespace() != "" {
		return pki.Identity{}, ErrUnavailable
	}
	actor, expiry, err := g.actor(ctx, a, credential)
	if err != nil {
		return pki.Identity{}, err
	}
	if err := phaseEnabled(ctx, policy); err != nil {
		return pki.Identity{}, err
	}
	workspace, err := g.client.Resource(phaseWorkspaceResource).Namespace(a.Namespace).Get(ctx, a.WorkspaceName, metav1.GetOptions{})
	if err != nil {
		return pki.Identity{}, ErrUnavailable
	}
	// W3's current qualified control-plane scope is the sealed Windows profile.
	// Do not mistake enrollment of a Linux/generic VM for Windows MSI eligibility.
	if !phaseWindowsWorkspace(workspace, a) {
		return pki.Identity{}, ErrDenied
	}
	expected := pki.Identity{Role: pki.RoleGuest, Namespace: a.Namespace, WorkspaceName: a.WorkspaceName,
		WorkspaceUID: a.WorkspaceUID, Generation: a.VMUID, RevocationEpoch: a.ExpectedRevocationEpoch}
	resolver, err := enrollment.NewKubernetesResolver(g.client, policy)
	if err != nil {
		return pki.Identity{}, ErrUnavailable
	}
	if err := resolver.Authorize(ctx, expected); err != nil {
		if errors.Is(err, enrollment.ErrUnavailable) {
			return pki.Identity{}, ErrUnavailable
		}
		return pki.Identity{}, ErrDenied // no stale identity or transport fallback
	}
	// Fresh providers intentionally bypass the ordinary 30-second auth cache.
	// Rotation may conservatively require a fresh sign-in rather than relying on
	// a per-replica cached predecessor signing key for this privileged operation.
	latestActor, latestExpiry, err := g.actor(ctx, a, credential)
	if err != nil {
		return pki.Identity{}, err
	}
	if !samePhaseObject(actor, latestActor) {
		return pki.Identity{}, ErrDenied
	}
	if err := phaseEnabled(ctx, policy); err != nil {
		return pki.Identity{}, err
	}
	latestAuth, err := auth.NewConfigProvider(g.client).GetAuthConfig(ctx)
	if err != nil {
		return pki.Identity{}, ErrUnavailable
	}
	latestPolicy, err := policy.GetPlatformConfig(ctx)
	if err != nil {
		return pki.Identity{}, ErrUnavailable
	}
	latestWorkspace, err := g.client.Resource(phaseWorkspaceResource).Namespace(a.Namespace).Get(ctx, a.WorkspaceName, metav1.GetOptions{})
	if err != nil {
		return pki.Identity{}, ErrUnavailable
	}
	if !samePhaseObject(authConfig, latestAuth) || !samePhaseObject(platformConfig, latestPolicy) ||
		!samePhaseObject(workspace, latestWorkspace) || !phaseWindowsWorkspace(latestWorkspace, a) {
		return pki.Identity{}, ErrDenied
	}
	now := g.now()
	if ctx.Err() != nil {
		return pki.Identity{}, ErrUnavailable
	}
	if now.Unix() >= min(expiry, latestExpiry) || !phaseGateBinding(a, j, now) {
		return pki.Identity{}, ErrDenied
	}
	return expected, nil
}

func (g *KubernetesPhaseGate) actor(ctx context.Context, a storage.AgentUpgradeAttempt, credential string) (*unstructured.Unstructured, int64, error) {
	provider := auth.NewConfigProvider(g.client)
	user, err := provider.AuthorizeExecution(ctx, credential, a.Namespace, a.WorkspaceName, auth.PermissionExec, true, g.now())
	if err != nil || user == nil {
		return nil, 0, ErrUnavailable // verification failed; never infer permission
	}
	if user.UID != a.ActorUID || user.Role != "admin" {
		return nil, 0, ErrDenied
	}
	current, err := provider.GetUserByEmail(ctx, user.Email)
	if err != nil || !phaseObject(current) || current.GetNamespace() != "" || string(current.GetUID()) != a.ActorUID {
		return nil, 0, ErrUnavailable
	}
	cfg, err := provider.GetConfig(ctx)
	if err != nil {
		return nil, 0, ErrUnavailable
	}
	token, err := auth.ValidateSessionTokenWithKeys(credential, cfg.SessionSigningKeys())
	if err != nil {
		return nil, 0, ErrUnavailable
	}
	return current, token.ExpiresAt, nil
}

func phaseEnabled(ctx context.Context, policy *platform.ConfigProvider) error {
	upgrade, err := policy.GetAgentUpgradePolicy(ctx)
	if err != nil {
		return ErrUnavailable
	}
	execution, err := policy.GetVMExecutionPolicy(ctx)
	if err != nil {
		return ErrUnavailable
	}
	if !upgrade.Enabled || !execution.Enabled || !execution.AllowElevated {
		return ErrDenied
	}
	return nil
}

func phaseObject(obj *unstructured.Unstructured) bool {
	return obj != nil && obj.GetUID() != "" && obj.GetName() != "" && obj.GetResourceVersion() != "" && obj.GetDeletionTimestamp() == nil
}

func samePhaseObject(a, b *unstructured.Unstructured) bool {
	return phaseObject(a) && phaseObject(b) && a.GetUID() == b.GetUID() && a.GetResourceVersion() == b.GetResourceVersion() &&
		a.GetName() == b.GetName() && a.GetNamespace() == b.GetNamespace()
}

func phaseWindowsWorkspace(ws *unstructured.Unstructured, a storage.AgentUpgradeAttempt) bool {
	if !phaseObject(ws) || ws.GetNamespace() != a.Namespace || ws.GetName() != a.WorkspaceName || string(ws.GetUID()) != a.WorkspaceUID {
		return false
	}
	profile, found, err := unstructured.NestedString(ws.Object, "spec", "vmProfile", "id")
	return err == nil && found && profile == "windows11-amd64-v1"
}

func phaseGateBinding(a storage.AgentUpgradeAttempt, j *updates.Journal, now time.Time) bool {
	if j == nil || !a.State.Claimable() || a.CancelRequested || a.LeaseOwner == "" || !now.Before(a.LeaseExpiresAt) {
		return false
	}
	s := j.Snapshot()
	b := s.Plan.Binding
	return s.Active != nil && s.Active.Sequence == s.Sequence && (s.Phase == "active" || s.Phase == "awaiting_reboot") &&
		!s.CancelRequested && s.OwnerFence == a.LeaseFence && s.OwnerFence <= updates.MaxJournalSequence &&
		s.Sequence >= a.JournalSequence && now.Unix() >= s.UpdatedAt && now.Unix() < s.ExpiresAt &&
		b.AttemptID == a.AttemptID && b.Namespace == a.Namespace && b.WorkspaceName == a.WorkspaceName &&
		b.WorkspaceUID == a.WorkspaceUID && b.VMUID == a.VMUID && b.RevocationEpoch == a.ExpectedRevocationEpoch &&
		b.ActorUID == a.ActorUID && b.RecordingID == a.RecordingID && b.TargetSHA256 == a.TargetManifestSHA256 &&
		b.InventorySHA256 == a.ExpectedInstalledInventorySHA256 && a.Predecessor.TargetID != "" &&
		b.PreviousSHA256 == a.Predecessor.ManifestSHA256 && s.Plan.AllowReboot == a.AllowReboot &&
		(s.Active.Kind != "reboot" || a.AllowReboot)
}
