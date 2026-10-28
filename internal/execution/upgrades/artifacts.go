package upgrades

import (
	"context"
	"crypto/ed25519"
	"io"
	"strconv"
	"strings"

	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/execution/updates"
)

// ArtifactApproval is independently obtained CURRENT operator policy, never
// accepted from an upgrade request, manifest or artifact server. A complete live
// authority source must refresh it on every phase; this library loads no policy.
// The snapshot must not be concurrently mutated while a call is using it.
type ArtifactApproval struct {
	Targets       map[string]string // exact immutable target ID -> manifest SHA256
	PublisherKeys map[string]ed25519.PublicKey
}

type SignedUpdateManifest struct {
	Raw            []byte
	Signature      []byte
	PublisherKeyID string
}

// ArtifactOpener resolves only a verified manifest digest + signed basename.
// There are no request-controlled URLs/paths/redirects here. The trusted staging
// transport must honor ctx for both opening and reads; byte limits alone cannot
// interrupt a blocked reader. Every returned non-nil stream is closed.
type ArtifactOpener func(ctx context.Context, manifestSHA256, basename string) (io.ReadCloser, error)

// VerifiedPhaseArtifacts proves publisher authenticity and complete payload
// verification for one immutable target/predecessor pair. It is not install
// authority, a trusted journal head, current inventory or protected guest staging.
// No cached allowlist/keyring is retained: Plan/CheckPlan reverify current policy.
type VerifiedPhaseArtifacts struct {
	target, previous SignedUpdateManifest
}

// VerifyPhaseArtifacts streams BOTH pinned MSI/updater pairs before returning a
// proof. Driver-bearing releases deny until a separately qualified driver adapter
// exists; a publisher signature alone cannot qualify a driver. No download, guest
// transfer, Windows Installer execution or enabled dispatch is performed.
func VerifyPhaseArtifacts(ctx context.Context, a storage.AgentUpgradeAttempt, approval ArtifactApproval, target, previous SignedUpdateManifest, open ArtifactOpener) (*VerifiedPhaseArtifacts, error) {
	if ctx.Err() != nil || open == nil {
		return nil, ErrUnavailable
	}
	for _, envelope := range []SignedUpdateManifest{target, previous} {
		if len(envelope.Raw) == 0 || len(envelope.Raw) > updates.MaxManifestBytes || len(envelope.Signature) != ed25519.SignatureSize || len(envelope.PublisherKeyID) != 32 {
			return nil, ErrDenied
		}
	}
	set := &VerifiedPhaseArtifacts{target: copyUpdateManifest(target), previous: copyUpdateManifest(previous)}
	t, p, err := set.approved(a, approval)
	if err != nil {
		return nil, err
	}
	for _, manifest := range []*updates.VerifiedManifest{t, p} {
		m := manifest.Metadata()
		for _, artifact := range []updates.Artifact{m.MSI.Artifact, m.Updater.Artifact} {
			if ctx.Err() != nil {
				return nil, ErrUnavailable
			}
			reader, err := open(ctx, manifest.SHA256(), artifact.File)
			if err != nil || reader == nil {
				if reader != nil {
					_ = reader.Close()
				}
				return nil, ErrUnavailable
			}
			verified := manifest.VerifyArtifact(artifact.File, phaseArtifactReader{ctx: ctx, reader: reader})
			closed := reader.Close()
			if verified != nil || closed != nil || ctx.Err() != nil {
				return nil, ErrUnavailable
			}
		}
	}
	// Recheck the supplied policy after callbacks as well. The caller still must
	// obtain independently current policy again for each later Plan/CheckPlan.
	if _, _, err := set.approved(a, approval); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return set, nil
}

func copyUpdateManifest(m SignedUpdateManifest) SignedUpdateManifest {
	return SignedUpdateManifest{Raw: append([]byte(nil), m.Raw...), Signature: append([]byte(nil), m.Signature...), PublisherKeyID: m.PublisherKeyID}
}

type phaseArtifactReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r phaseArtifactReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(buffer)
	if canceled := r.ctx.Err(); canceled != nil {
		return n, canceled
	}
	return n, err
}

func (v *VerifiedPhaseArtifacts) approved(a storage.AgentUpgradeAttempt, approval ArtifactApproval) (*updates.VerifiedManifest, *updates.VerifiedManifest, error) {
	if v == nil || len(approval.Targets) == 0 || len(approval.Targets) > 64 || len(approval.PublisherKeys) == 0 || len(approval.PublisherKeys) > 16 {
		return nil, nil, ErrUnavailable
	}
	for id, digest := range approval.Targets {
		if !targetIDPattern.MatchString(id) || !digestPattern.MatchString(digest) {
			return nil, nil, ErrDenied
		}
	}
	if approval.Targets[a.TargetID] != a.TargetManifestSHA256 || !digestPattern.MatchString(a.TargetManifestSHA256) ||
		approval.Targets[a.Predecessor.TargetID] != a.Predecessor.ManifestSHA256 || !digestPattern.MatchString(a.Predecessor.ManifestSHA256) ||
		a.TargetID == a.Predecessor.TargetID || a.TargetManifestSHA256 == a.Predecessor.ManifestSHA256 {
		return nil, nil, ErrDenied
	}
	target, err := updates.Verify(v.target.Raw, v.target.Signature, v.target.PublisherKeyID, a.TargetManifestSHA256, approval.PublisherKeys)
	if err != nil {
		return nil, nil, ErrDenied
	}
	previous, err := updates.Verify(v.previous.Raw, v.previous.Signature, v.previous.PublisherKeyID, a.Predecessor.ManifestSHA256, approval.PublisherKeys)
	if err != nil {
		return nil, nil, ErrDenied
	}
	t, p := target.Metadata(), previous.Metadata()
	if t.TargetID != a.TargetID || p.TargetID != a.Predecessor.TargetID || t.Driver != nil || p.Driver != nil ||
		t.MSI.ProductCode == p.MSI.ProductCode || t.MSI.Artifact.SHA256 == p.MSI.Artifact.SHA256 ||
		compareArtifactVersions(t.AgentVersion, p.AgentVersion) <= 0 ||
		compareArtifactVersions(p.AgentVersion, t.Compatibility.MinimumAgentVersion) < 0 ||
		compareArtifactVersions(p.AgentVersion, t.Compatibility.MaximumAgentVersion) > 0 ||
		!phaseArtifactWire(t) || !phaseArtifactWire(p) ||
		(a.AllowReboot && (t.RebootPolicy != "may-require" || p.RebootPolicy != "may-require")) {
		return nil, nil, ErrDenied
	}
	for _, predecessor := range t.RollbackPredecessors {
		if predecessor.TargetID == p.TargetID && predecessor.ManifestSHA256 == previous.SHA256() {
			return target, previous, nil
		}
	}
	return nil, nil, ErrDenied
}

func phaseArtifactWire(m updates.Manifest) bool {
	return m.Updater.ProtocolVersion == 1 && m.Compatibility.ManagementMin <= 1 && m.Compatibility.ManagementMax >= 1 &&
		m.Compatibility.DesktopMin <= 1 && m.Compatibility.DesktopMax >= 1
}

// Inputs come only from the strict publisher parser's canonical MSI versions.
func compareArtifactVersions(a, b string) int {
	x, y := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		left, _ := strconv.Atoi(x[i])
		right, _ := strconv.Atoi(y[i])
		if left < right {
			return -1
		}
		if left > right {
			return 1
		}
	}
	return 0
}

// Plan constructs only exact immutable artifact bindings under CURRENT approval.
// The admitted inventory digest is pinned, not freshly authenticated here. Guest
// identity/inventory/boot, journal lineage, recording, consent and live authority
// still must be independently checked by the complete source and guest adapter.
func (v *VerifiedPhaseArtifacts) Plan(ctx context.Context, a storage.AgentUpgradeAttempt, current ArtifactApproval) (updates.JournalPlan, error) {
	if ctx.Err() != nil {
		return updates.JournalPlan{}, ErrUnavailable
	}
	t, p, err := v.approved(a, current)
	if err != nil {
		return updates.JournalPlan{}, err
	}
	plan := updates.JournalPlan{Binding: updates.JournalBinding{
		AttemptID: a.AttemptID, Namespace: a.Namespace, WorkspaceName: a.WorkspaceName, WorkspaceUID: a.WorkspaceUID,
		VMUID: a.VMUID, RevocationEpoch: a.ExpectedRevocationEpoch, ActorUID: a.ActorUID, RecordingID: a.RecordingID,
		TargetSHA256: t.SHA256(), PreviousSHA256: p.SHA256(), InventorySHA256: a.ExpectedInstalledInventorySHA256,
	}, TargetProductCode: t.Metadata().MSI.ProductCode, PreviousProductCode: p.Metadata().MSI.ProductCode, AllowReboot: a.AllowReboot}
	if plan.Validate() != nil {
		return updates.JournalPlan{}, ErrDenied
	}
	if ctx.Err() != nil {
		return updates.JournalPlan{}, ErrUnavailable
	}
	return plan, nil
}

func (v *VerifiedPhaseArtifacts) CheckPlan(ctx context.Context, a storage.AgentUpgradeAttempt, candidate updates.JournalPlan, current ArtifactApproval) error {
	expected, err := v.Plan(ctx, a, current)
	if err != nil {
		return err
	}
	if candidate != expected {
		return ErrDenied
	}
	return nil
}
