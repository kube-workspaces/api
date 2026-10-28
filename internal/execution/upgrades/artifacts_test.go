package upgrades

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/execution/updates"
)

type artifactFixture struct {
	attempt          storage.AgentUpgradeAttempt
	approval         ArtifactApproval
	target, previous updates.Manifest
	key              ed25519.PrivateKey
	payloads         map[string]map[string][]byte
}

func newArtifactFixture(t *testing.T) *artifactFixture {
	t.Helper()
	raw, err := os.ReadFile("../updates/testdata/manifest-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var target updates.Manifest
	if err := json.Unmarshal(raw, &target); err != nil {
		t.Fatal(err)
	}
	target.Driver = nil // software-only scope; shared signed fixtures stay unchanged
	previous := target
	previous.TargetID = "windows-agent-0.3.4"
	previous.AgentVersion = "0.3.4"
	previous.BuildSHA256 = updates.Digest([]byte("previous-build"))
	previous.MSI.ProductCode = "87654321-4321-4321-4321-cba987654321"
	previous.MSI.Artifact.SHA256 = updates.Digest([]byte("previous-msi-v1"))
	previous.MSI.Artifact.Size = uint64(len("previous-msi-v1"))
	previous.Updater.Artifact.SHA256 = updates.Digest([]byte("previous-helper-v1"))
	previous.Updater.Artifact.Size = uint64(len("previous-helper-v1"))
	previous.RollbackPredecessors = []updates.Predecessor{}
	f := &artifactFixture{target: target, previous: previous, key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, 32))}
	f.rebuild(t)
	return f
}

func (f *artifactFixture) signed(m updates.Manifest) SignedUpdateManifest {
	raw, _ := json.Marshal(m)
	return SignedUpdateManifest{Raw: raw, Signature: ed25519.Sign(f.key, append([]byte(updates.Domain), raw...)), PublisherKeyID: updates.KeyID(f.key.Public().(ed25519.PublicKey))}
}

func (f *artifactFixture) rebuild(t *testing.T) {
	t.Helper()
	p := f.signed(f.previous)
	f.target.RollbackPredecessors = []updates.Predecessor{{TargetID: f.previous.TargetID, ManifestSHA256: updates.Digest(p.Raw)}}
	target := f.signed(f.target)
	f.attempt = storage.AgentUpgradeAttempt{
		AttemptID: "upg_artifacts001", Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "workspace-uid", VMUID: "vm-uid", ActorUID: "actor-uid",
		RecordingID: "rec-artifacts", ExpectedRevocationEpoch: 7, TargetID: f.target.TargetID, TargetManifestSHA256: updates.Digest(target.Raw),
		ExpectedInstalledInventorySHA256: updates.Digest([]byte("admitted-inventory")),
		Predecessor:                      storage.AttemptPredecessor{TargetID: f.previous.TargetID, ManifestSHA256: updates.Digest(p.Raw)},
	}
	public := f.key.Public().(ed25519.PublicKey)
	f.approval = ArtifactApproval{Targets: map[string]string{f.target.TargetID: f.attempt.TargetManifestSHA256, f.previous.TargetID: f.attempt.Predecessor.ManifestSHA256},
		PublisherKeys: map[string]ed25519.PublicKey{updates.KeyID(public): public}}
	f.payloads = map[string]map[string][]byte{
		f.attempt.TargetManifestSHA256:       {f.target.MSI.Artifact.File: []byte("msi-v1"), f.target.Updater.Artifact.File: []byte("helper-v1")},
		f.attempt.Predecessor.ManifestSHA256: {f.previous.MSI.Artifact.File: []byte("previous-msi-v1"), f.previous.Updater.Artifact.File: []byte("previous-helper-v1")},
	}
}

func (f *artifactFixture) open(_ context.Context, digest, file string) (io.ReadCloser, error) {
	payload, ok := f.payloads[digest][file]
	if !ok {
		return nil, errors.New("unapproved artifact lookup")
	}
	return io.NopCloser(bytes.NewReader(payload)), nil
}

func (f *artifactFixture) verify() (*VerifiedPhaseArtifacts, error) {
	return VerifyPhaseArtifacts(context.Background(), f.attempt, f.approval, f.signed(f.target), f.signed(f.previous), f.open)
}

func TestPhaseArtifactsVerifyBothPairsAndConstructExactPlan(t *testing.T) {
	f := newArtifactFixture(t)
	opens, closes := 0, 0
	descriptors := map[string]bool{}
	set, err := VerifyPhaseArtifacts(context.Background(), f.attempt, f.approval, f.signed(f.target), f.signed(f.previous), func(ctx context.Context, digest, file string) (io.ReadCloser, error) {
		opens++
		descriptors[digest+"/"+file] = true
		stream, err := f.open(ctx, digest, file)
		return countedArtifactCloser{stream, &closes}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if opens != 4 || closes != 4 || len(descriptors) != 4 {
		t.Fatal("both digest-scoped MSI/updater pairs must be fully verified and closed")
	}
	plan, err := set.Plan(context.Background(), f.attempt, f.approval)
	if err != nil {
		t.Fatal(err)
	}
	if plan.TargetProductCode != f.target.MSI.ProductCode || plan.PreviousProductCode != f.previous.MSI.ProductCode ||
		plan.Binding.TargetSHA256 != f.attempt.TargetManifestSHA256 || plan.Binding.PreviousSHA256 != f.attempt.Predecessor.ManifestSHA256 ||
		plan.Binding.InventorySHA256 != f.attempt.ExpectedInstalledInventorySHA256 || plan.TargetDriverSHA256 != "" || plan.PreviousDriverSHA256 != "" {
		t.Fatalf("incorrect immutable plan: %+v", plan)
	}
	if err := set.CheckPlan(context.Background(), f.attempt, plan, f.approval); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*updates.JournalPlan){
		func(p *updates.JournalPlan) { p.TargetProductCode = "abcdef12-1234-1234-1234-123456789abc" },
		func(p *updates.JournalPlan) { p.PreviousProductCode = p.TargetProductCode },
		func(p *updates.JournalPlan) { p.Binding.TargetSHA256 = updates.Digest([]byte("other")) },
		func(p *updates.JournalPlan) { p.Binding.PreviousSHA256 = updates.Digest([]byte("other")) },
		func(p *updates.JournalPlan) { p.Binding.InventorySHA256 = updates.Digest([]byte("other")) },
		func(p *updates.JournalPlan) { p.Binding.ActorUID = "other" },
		func(p *updates.JournalPlan) { p.Binding.VMUID = "other" },
		func(p *updates.JournalPlan) { p.Binding.WorkspaceUID = "other" },
		func(p *updates.JournalPlan) { p.Binding.RevocationEpoch++ },
		func(p *updates.JournalPlan) { p.Binding.AttemptID = "other" },
		func(p *updates.JournalPlan) { p.Binding.RecordingID = "other" },
		func(p *updates.JournalPlan) { p.Binding.Namespace = "other" },
		func(p *updates.JournalPlan) { p.Binding.WorkspaceName = "other" },
		func(p *updates.JournalPlan) { p.TargetDriverSHA256 = updates.Digest([]byte("driver")) },
		func(p *updates.JournalPlan) { p.PreviousDriverSHA256 = updates.Digest([]byte("driver")) },
		func(p *updates.JournalPlan) { p.AllowReboot = true },
	}
	for n, mutate := range mutations {
		changed := plan
		mutate(&changed)
		if err := set.CheckPlan(context.Background(), f.attempt, changed, f.approval); err == nil {
			t.Fatalf("plan substitution %d accepted", n)
		}
	}
}

type countedArtifactCloser struct {
	io.ReadCloser
	closes *int
}

func (r countedArtifactCloser) Close() error { *r.closes++; return r.ReadCloser.Close() }

func TestPhaseArtifactsEveryTargetAndPredecessorPayloadIsRequired(t *testing.T) {
	for corrupt := 0; corrupt < 4; corrupt++ {
		f := newArtifactFixture(t)
		opens, closes := 0, 0
		set, err := VerifyPhaseArtifacts(context.Background(), f.attempt, f.approval, f.signed(f.target), f.signed(f.previous), func(_ context.Context, digest, file string) (io.ReadCloser, error) {
			payload := f.payloads[digest][file]
			if opens == corrupt {
				payload = []byte("substituted payload")
			}
			opens++
			return artifactReadCloser{bytes.NewReader(payload), &closes, nil}, nil
		})
		if err == nil || set != nil || opens != corrupt+1 || closes != opens {
			t.Fatalf("payload %d was skipped or leaked (opens=%d closes=%d)", corrupt, opens, closes)
		}
	}
}

func TestPhaseArtifactsCurrentApprovalAndOwnedManifestBytes(t *testing.T) {
	f := newArtifactFixture(t)
	target, previous := f.signed(f.target), f.signed(f.previous)
	set, err := VerifyPhaseArtifacts(context.Background(), f.attempt, f.approval, target, previous, f.open)
	if err != nil {
		t.Fatal(err)
	}
	target.Raw[0], previous.Raw[0] = 'x', 'x'
	target.Signature[0] ^= 1
	previous.Signature[0] ^= 1
	if _, err := set.Plan(context.Background(), f.attempt, f.approval); err != nil {
		t.Fatal("caller mutation changed verified bytes", err)
	}
	for _, revoke := range []string{"target", "previous", "publisher", "wildcard", "wrong-digest", "oversized-allowlist"} {
		t.Run(revoke, func(t *testing.T) {
			approval := ArtifactApproval{Targets: map[string]string{}, PublisherKeys: f.approval.PublisherKeys}
			for k, v := range f.approval.Targets {
				approval.Targets[k] = v
			}
			switch revoke {
			case "target":
				delete(approval.Targets, f.target.TargetID)
			case "previous":
				delete(approval.Targets, f.previous.TargetID)
			case "publisher":
				approval.PublisherKeys = map[string]ed25519.PublicKey{}
			case "wildcard":
				approval.Targets["*"] = f.attempt.TargetManifestSHA256
			case "wrong-digest":
				approval.Targets[f.target.TargetID] = updates.Digest([]byte("changed"))
			case "oversized-allowlist":
				for n := 0; n < 65; n++ {
					approval.Targets[strings.Repeat("a", n+1)] = f.attempt.TargetManifestSHA256
				}
			}
			if plan, err := set.Plan(context.Background(), f.attempt, approval); err == nil || plan != (updates.JournalPlan{}) {
				t.Fatal("cached proof bypassed current approval")
			}
		})
	}
	var empty *VerifiedPhaseArtifacts
	if _, err := empty.Plan(context.Background(), f.attempt, f.approval); err == nil {
		t.Fatal("nil proof accepted")
	}
	if _, err := new(VerifiedPhaseArtifacts).Plan(context.Background(), f.attempt, f.approval); err == nil {
		t.Fatal("zero-value forged proof accepted")
	}
}

func TestPhaseArtifactsRejectSignedIncompatibleOrUnqualifiedPairs(t *testing.T) {
	for _, mode := range []string{"target-driver", "previous-driver", "product-reuse", "payload-reuse", "downgrade", "same-version", "incompatible-installed", "incompatible-installed-max", "management-wire", "desktop-wire", "updater-wire", "rollback-id", "rollback-digest", "reboot-policy"} {
		t.Run(mode, func(t *testing.T) {
			f := newArtifactFixture(t)
			switch mode {
			case "target-driver", "previous-driver":
				driver := &updates.Driver{Artifact: updates.Artifact{File: "idd.zip", Size: 1, SHA256: updates.Digest([]byte("d"))}, Version: "1.0.0.0",
					SignerSHA256: updates.Digest([]byte("signer")), HardwareIDs: []string{`ROOT\ExampleIDD`}}
				if mode == "target-driver" {
					f.target.Driver = driver
				} else {
					f.previous.Driver = driver
				}
			case "product-reuse":
				f.previous.MSI.ProductCode = f.target.MSI.ProductCode
			case "payload-reuse":
				f.previous.MSI.Artifact = f.target.MSI.Artifact
			case "downgrade":
				f.target.AgentVersion = "0.3.3"
			case "same-version":
				f.target.AgentVersion = f.previous.AgentVersion
			case "incompatible-installed":
				f.target.Compatibility.MinimumAgentVersion = "0.3.5"
			case "incompatible-installed-max":
				f.target.Compatibility.MaximumAgentVersion = "0.3.3"
			case "management-wire":
				f.target.Compatibility.ManagementMin, f.target.Compatibility.ManagementMax = 2, 2
			case "desktop-wire":
				f.previous.Compatibility.DesktopMin, f.previous.Compatibility.DesktopMax = 2, 2
			case "updater-wire":
				f.target.Updater.ProtocolVersion = 2
			case "reboot-policy":
				f.previous.RebootPolicy = "never"
			}
			f.rebuild(t)
			if mode == "rollback-id" || mode == "rollback-digest" {
				if mode == "rollback-id" {
					f.target.RollbackPredecessors[0].TargetID = "another-target"
				} else {
					f.target.RollbackPredecessors[0].ManifestSHA256 = updates.Digest([]byte("another manifest"))
				}
				raw := f.signed(f.target).Raw
				f.attempt.TargetManifestSHA256 = updates.Digest(raw)
				f.approval.Targets[f.target.TargetID] = f.attempt.TargetManifestSHA256
			}
			if mode == "reboot-policy" {
				f.attempt.AllowReboot = true
			}
			opens := 0
			set, err := VerifyPhaseArtifacts(context.Background(), f.attempt, f.approval, f.signed(f.target), f.signed(f.previous), func(context.Context, string, string) (io.ReadCloser, error) {
				opens++
				return nil, errors.New("should not open")
			})
			if err == nil || set != nil || opens != 0 {
				t.Fatal("ineligible signed pair reached payload staging")
			}
		})
	}
	f := newArtifactFixture(t)
	f.target.AgentVersion, f.previous.AgentVersion = "0.3.10", "0.3.9"
	f.rebuild(t)
	if _, err := f.verify(); err != nil {
		t.Fatal("canonical numeric version comparison became lexical", err)
	}
}

type artifactReadCloser struct {
	io.Reader
	closes   *int
	closeErr error
}

func (r artifactReadCloser) Close() error { *r.closes++; return r.closeErr }

type endlessArtifact struct{ read *int }

func (r endlessArtifact) Read(p []byte) (int, error) { *r.read += len(p); clear(p); return len(p), nil }

func TestPhaseArtifactsBoundedStreamsOutagesAndCancellation(t *testing.T) {
	for _, mode := range []string{"wrong-bytes", "truncated", "oversized", "read-error", "close-error", "open-error", "nil-reader", "cancel-during-read", "policy-revoked-during-read"} {
		t.Run(mode, func(t *testing.T) {
			f := newArtifactFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			closes, bytesRead := 0, 0
			set, err := VerifyPhaseArtifacts(ctx, f.attempt, f.approval, f.signed(f.target), f.signed(f.previous), func(_ context.Context, digest, file string) (io.ReadCloser, error) {
				payload := f.payloads[digest][file]
				var reader io.Reader = bytes.NewReader(payload)
				var closeErr error
				switch mode {
				case "wrong-bytes":
					reader = strings.NewReader(strings.Repeat("x", len(payload)))
				case "truncated":
					reader = bytes.NewReader(payload[:len(payload)-1])
				case "oversized":
					reader = endlessArtifact{&bytesRead}
				case "read-error":
					reader = io.MultiReader(reader, artifactErrorReader{})
				case "close-error":
					closeErr = errors.New("close unavailable")
				case "open-error":
					return artifactReadCloser{reader, &closes, nil}, errors.New("open unavailable")
				case "nil-reader":
					return nil, nil
				case "cancel-during-read":
					reader = artifactCancelReader{reader, cancel}
				case "policy-revoked-during-read":
					delete(f.approval.Targets, f.previous.TargetID)
				}
				return artifactReadCloser{reader, &closes, closeErr}, nil
			})
			if err == nil || set != nil {
				t.Fatal("incomplete/uncertain payload produced proof")
			}
			if mode == "oversized" && bytesRead != int(f.target.MSI.Artifact.Size)+1 {
				t.Fatalf("unbounded payload read: %d", bytesRead)
			}
			if mode != "nil-reader" && closes == 0 {
				t.Fatal("opened stream not closed")
			}
		})
	}
}

type artifactErrorReader struct{}

func (artifactErrorReader) Read([]byte) (int, error) { return 0, errors.New("read unavailable") }

type artifactCancelReader struct {
	io.Reader
	cancel context.CancelFunc
}

func (r artifactCancelReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.cancel()
	return n, err
}

func TestPhaseArtifactsPublisherRotationStillRequiresPredecessorTrust(t *testing.T) {
	f := newArtifactFixture(t)
	oldID := updates.KeyID(f.key.Public().(ed25519.PublicKey))
	newKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x56}, 32))
	newPublic := newKey.Public().(ed25519.PublicKey)
	target := f.signed(f.target)
	target.PublisherKeyID = updates.KeyID(newPublic)
	target.Signature = ed25519.Sign(newKey, append([]byte(updates.Domain), target.Raw...))
	f.approval.PublisherKeys[target.PublisherKeyID] = newPublic
	set, err := VerifyPhaseArtifacts(context.Background(), f.attempt, f.approval, target, f.signed(f.previous), f.open)
	if err != nil {
		t.Fatal("explicit overlapping publisher rotation denied", err)
	}
	delete(f.approval.PublisherKeys, oldID)
	if plan, err := set.Plan(context.Background(), f.attempt, f.approval); err == nil || plan != (updates.JournalPlan{}) {
		t.Fatal("trusted target bypassed retired predecessor publisher")
	}
}

func TestPhaseArtifactsRejectTrustDomainOrEnvelopeSubstitution(t *testing.T) {
	for _, mode := range []string{"bad-signature", "wrong-domain", "wrong-publisher", "retired-publisher", "oversized-manifest", "oversized-signature"} {
		t.Run(mode, func(t *testing.T) {
			f := newArtifactFixture(t)
			target := f.signed(f.target)
			switch mode {
			case "bad-signature":
				target.Signature[0] ^= 1
			case "wrong-domain":
				target.Signature = ed25519.Sign(f.key, append([]byte(updates.PhaseDomain), target.Raw...))
			case "wrong-publisher":
				target.PublisherKeyID = strings.Repeat("f", 32)
			case "retired-publisher":
				f.approval.PublisherKeys = map[string]ed25519.PublicKey{}
			case "oversized-manifest":
				target.Raw = make([]byte, updates.MaxManifestBytes+1)
			case "oversized-signature":
				target.Signature = make([]byte, 65)
			}
			opened := false
			set, err := VerifyPhaseArtifacts(context.Background(), f.attempt, f.approval, target, f.signed(f.previous), func(context.Context, string, string) (io.ReadCloser, error) {
				opened = true
				return nil, errors.New("unexpected open")
			})
			if err == nil || set != nil || opened {
				t.Fatal("untrusted envelope reached payload staging")
			}
		})
	}
}
