package upgrades

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/execution/updates"
)

// Test-only dependencies; no permissive authority or recording source is wired
// into the API server. Real atomic fencing is tested against PostgreSQL.
type phaseSourceProbe struct {
	intentErr, currentErr error
	current               PhaseContext
	onCurrent             func()
}

func (p *phaseSourceProbe) CheckIntent(context.Context, storage.AgentUpgradeAttempt, *updates.Journal) error {
	return p.intentErr
}
func (p *phaseSourceProbe) CurrentPhase(context.Context, storage.AgentUpgradeAttempt, *updates.Journal) (PhaseContext, error) {
	if p.onCurrent != nil {
		p.onCurrent()
	}
	return p.current, p.currentErr
}

type phaseRecorderProbe struct {
	err     error
	badHash bool
	calls   int
	onAck   func()
}

func (p *phaseRecorderProbe) RecordPhaseIntent(_ context.Context, a storage.AgentUpgradeAttempt, raw []byte) (storage.PhaseRecordingReceipt, error) {
	p.calls++
	if p.onAck != nil {
		p.onAck()
	}
	digest := updates.Digest(raw)
	if p.badHash {
		digest = updates.Digest([]byte("different bytes"))
	}
	return storage.PhaseRecordingReceipt{RecordingID: a.RecordingID, ChunkIndex: 1, ChunkSHA256: digest}, p.err
}

type phaseLedgerProbe struct {
	storage.UpgradePhaseLedger
	durability storage.Durability
	intent     *storage.UpgradePhaseIntent
	spent      bool
	readyErr   error
	claimErr   error
	onClaim    func()
}

func (p *phaseLedgerProbe) Durability() storage.Durability { return p.durability }
func (p *phaseLedgerProbe) Ready(context.Context) error    { return p.readyErr }
func (p *phaseLedgerProbe) RecordIntent(_ context.Context, i storage.UpgradePhaseIntent) error {
	if _, err := i.Journal(); err != nil {
		return err
	}
	p.intent = &i
	return nil
}
func (p *phaseLedgerProbe) GetIntent(context.Context, string, uint64) (storage.UpgradePhaseIntent, error) {
	if p.intent == nil {
		return storage.UpgradePhaseIntent{}, storage.ErrNotFound
	}
	return *p.intent, nil
}
func (p *phaseLedgerProbe) ClaimPhase(context.Context, string, string, updates.PhasePermit, time.Time) error {
	if p.spent {
		return storage.ErrConflict
	}
	p.spent = true
	if p.onClaim != nil {
		p.onClaim()
	}
	return p.claimErr
}

func phaseIssuerFixture(t *testing.T) (*PhaseIssuer, *phaseLedgerProbe, *phaseSourceProbe, *phaseRecorderProbe, storage.UpgradePhaseIntent, ed25519.PublicKey) {
	t.Helper()
	ctx := context.Background()
	raw, err := os.ReadFile("../updates/testdata/journal-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot updates.JournalSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	snapshot.Plan.Binding.AttemptID = fmt.Sprintf("upg_%d", time.Now().UnixNano())
	snapshot.Plan.Binding.RecordingID = "rec_" + snapshot.Plan.Binding.AttemptID[4:]
	snapshot.Plan.Binding.VMUID = snapshot.Plan.Binding.AttemptID
	snapshot.StartedAt, snapshot.UpdatedAt, snapshot.ExpiresAt = now.Unix(), now.Unix(), now.Unix()+900
	raw, _ = json.Marshal(snapshot)
	b := snapshot.Plan.Binding
	attempts, _ := storage.NewMemoryAgentUpgrades(10)
	if err := attempts.Reserve(ctx, storage.AgentUpgradeAttempt{
		AttemptID: b.AttemptID, IdempotencyKey: "synthetic-" + b.AttemptID, Namespace: b.Namespace, WorkspaceName: b.WorkspaceName,
		WorkspaceUID: b.WorkspaceUID, VMUID: b.VMUID, ActorUID: b.ActorUID, TargetID: "approved-target",
		TargetManifestSHA256: b.TargetSHA256, ExpectedInstalledInventorySHA256: b.InventorySHA256,
		ExpectedRevocationEpoch: b.RevocationEpoch, ExecutionID: "exec_" + b.AttemptID[4:], RecordingID: b.RecordingID,
		State: storage.AttemptAdmitted, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := attempts.ClaimLease(ctx, b.AttemptID, "worker", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	ledger := &phaseLedgerProbe{durability: storage.DurabilityDurable}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	source := &phaseSourceProbe{current: PhaseContext{
		Challenge: base64.RawURLEncoding.EncodeToString(nonce[:]), PeerSHA256: updates.Digest([]byte("peer")), BootID: snapshot.Active.BootID,
	}}
	recorder := &phaseRecorderProbe{}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := append(ed25519.PublicKey(nil), key.Public().(ed25519.PublicKey)...)
	issuer, err := NewPhaseIssuer(attempts, ledger, source, recorder, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return now }
	// The constructor must retain a private copy, not mutable configuration bytes.
	clear(key)
	i := storage.UpgradePhaseIntent{AttemptID: b.AttemptID, Owner: "worker", Fence: 1,
		PlanSHA256: snapshot.Plan.SHA256(), CheckpointSHA256: updates.Digest(append([]byte("kw-agent-upgrade-journal/v1\x00"), raw...)),
		Checkpoint: raw, RecordedAt: now}
	return issuer, ledger, source, recorder, i, public
}

type phaseCommitAckLoss struct{ storage.UpgradePhaseLedger }

func (p phaseCommitAckLoss) ClaimPhase(ctx context.Context, id, owner string, permit updates.PhasePermit, now time.Time) error {
	if err := p.UpgradePhaseLedger.ClaimPhase(ctx, id, owner, permit, now); err != nil {
		return err
	}
	return errors.New("synthetic lost COMMIT acknowledgment")
}

func TestPostgresPhaseIssuerIntegration(t *testing.T) {
	dsn := os.Getenv("KW_EXECUTION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set KW_EXECUTION_TEST_DATABASE_URL for disposable PostgreSQL")
	}
	ctx := context.Background()
	attempts, err := storage.NewPostgresAgentUpgrades(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer attempts.Close()
	metadata, err := storage.NewPostgresMetadata(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Close()
	ledger, err := storage.NewPostgresUpgradePhases(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	for _, ackLoss := range []bool{false, true} {
		t.Run(fmt.Sprintf("ack-loss-%v", ackLoss), func(t *testing.T) {
			s, _, _, _, i, public := phaseIssuerFixture(t)
			a, err := s.attempts.Get(ctx, i.AttemptID)
			if err != nil {
				t.Fatal(err)
			}
			if err := attempts.Reserve(ctx, a); err != nil {
				t.Fatal(err)
			}
			fence, err := attempts.ClaimLease(ctx, a.AttemptID, "worker", s.now(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			var snapshot updates.JournalSnapshot
			if err := json.Unmarshal(i.Checkpoint, &snapshot); err != nil {
				t.Fatal(err)
			}
			if err := attempts.Transition(ctx, a.AttemptID, storage.AttemptAdmitted, storage.AttemptTransition{
				To: storage.AttemptStaging, Now: s.now(), Fence: &fence,
				Predecessor: &storage.AttemptPredecessor{TargetID: "previous", ManifestSHA256: snapshot.Plan.Binding.PreviousSHA256},
			}); err != nil {
				t.Fatal(err)
			}
			if err := metadata.Reserve(ctx, storage.ExecutionRecord{
				ExecutionID: a.ExecutionID, RecordingID: a.RecordingID, ActorID: a.ActorUID, Operation: storage.OperationUpgrade,
				Namespace: a.Namespace, WorkspaceName: a.WorkspaceName, WorkspaceUID: a.WorkspaceUID,
				OSIdentity: "SYSTEM", Elevated: true, Durability: storage.DurabilityDurable, Mode: "external", AdmissionTime: s.now(), Admitted: true,
			}); err != nil {
				t.Fatal(err)
			}
			s.attempts, s.ledger = attempts, ledger
			if err := s.RecordIntent(ctx, i.AttemptID, i.Owner, i.Checkpoint, i.PlanSHA256, i.CheckpointSHA256); err != nil {
				t.Fatal(err)
			}
			if ackLoss {
				s.ledger = phaseCommitAckLoss{ledger}
			}
			var wg sync.WaitGroup
			results := make(chan SignedPhase, 16)
			for n := 0; n < 16; n++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					result, _ := s.Issue(ctx, i.AttemptID, i.Owner, 3)
					results <- result
				}()
			}
			wg.Wait()
			close(results)
			signatures := 0
			for result := range results {
				if len(result.Signature) == 0 {
					continue
				}
				signatures++
				var permit updates.PhasePermit
				if err := json.Unmarshal(result.Permit, &permit); err != nil {
					t.Fatal(err)
				}
				if err := updates.VerifyPhase(result.Permit, result.Signature, result.KeyID,
					map[string]ed25519.PublicKey{updates.KeyID(public): public}, permit, s.now().Unix()); err != nil {
					t.Fatal(err)
				}
			}
			if (ackLoss && signatures != 0) || (!ackLoss && signatures != 1) {
				t.Fatalf("returned signatures: %d (ACK loss %v)", signatures, ackLoss)
			}
			reopened, err := storage.NewPostgresUpgradePhases(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			s.ledger = reopened
			if result, err := s.Issue(ctx, i.AttemptID, i.Owner, 3); err == nil || len(result.Signature) != 0 {
				t.Fatal("reopening reissued a committed/uncertain phase")
			}
		})
	}
}

func TestPhaseIssuerRecordsBeforeSigningAndDeniesReplay(t *testing.T) {
	s, ledger, source, recorder, i, public := phaseIssuerFixture(t)
	ctx := context.Background()
	if result, err := s.Issue(ctx, i.AttemptID, i.Owner, 3); err == nil || len(result.Signature) != 0 {
		t.Fatal("unrecorded intent returned signature")
	}
	if err := s.RecordIntent(ctx, i.AttemptID, i.Owner, i.Checkpoint, i.PlanSHA256, i.CheckpointSHA256); err != nil {
		t.Fatal(err)
	}
	if recorder.calls != 1 || ledger.intent == nil {
		t.Fatal("protected recording ACK did not precede intent")
	}
	result, err := s.Issue(ctx, i.AttemptID, i.Owner, 3)
	if err != nil {
		t.Fatal(err)
	}
	var permit updates.PhasePermit
	if err := json.Unmarshal(result.Permit, &permit); err != nil {
		t.Fatal(err)
	}
	if !ledger.spent || permit.PlanSHA256 != i.PlanSHA256 || permit.Challenge != source.current.Challenge || permit.Action.Sequence != 3 {
		t.Fatal("signature did not bind the recorded action and current exchange")
	}
	if err := updates.VerifyPhase(result.Permit, result.Signature, result.KeyID,
		map[string]ed25519.PublicKey{updates.KeyID(public): public}, permit, s.now().Unix()); err != nil {
		t.Fatal(err)
	}
	if result, err := s.Issue(ctx, i.AttemptID, i.Owner, 3); err == nil || len(result.Signature) != 0 {
		t.Fatal("replayed phase returned signature")
	}
}

func TestPhaseIssuerDeniesMissingTrustOrRecording(t *testing.T) {
	for _, mutation := range []string{"ephemeral", "key", "source", "recorder", "attempts", "ledger"} {
		t.Run(mutation, func(t *testing.T) {
			s, ledger, _, _, _, _ := phaseIssuerFixture(t)
			switch mutation {
			case "ephemeral":
				ledger.durability = storage.DurabilityNone
			case "key":
				s.key = nil
			case "source":
				s.source = nil
			case "recorder":
				s.recorder = nil
			case "attempts":
				s.attempts = nil
			case "ledger":
				s.ledger = nil
			}
			if _, err := NewPhaseIssuer(s.attempts, s.ledger, s.source, s.recorder, s.key); err == nil {
				t.Fatal("missing trust/durability dependency accepted")
			}
		})
	}
}

func TestPhaseIssuerFailuresReturnNoSignature(t *testing.T) {
	for _, mutation := range []string{"intent-denied", "recording-outage", "receipt-substitution", "storage-outage", "current-denied", "wrong-boot", "wrong-peer", "bad-nonce", "commit-ack-loss", "slow-commit", "slow-authority"} {
		t.Run(mutation, func(t *testing.T) {
			s, ledger, source, recorder, i, _ := phaseIssuerFixture(t)
			switch mutation {
			case "intent-denied":
				source.intentErr = ErrDenied
			case "recording-outage":
				recorder.err = errors.New("recording unavailable")
			case "receipt-substitution":
				recorder.badHash = true
			case "storage-outage":
				ledger.readyErr = storage.ErrNotReady
			}
			err := s.RecordIntent(context.Background(), i.AttemptID, i.Owner, i.Checkpoint, i.PlanSHA256, i.CheckpointSHA256)
			if mutation == "intent-denied" || mutation == "recording-outage" || mutation == "receipt-substitution" || mutation == "storage-outage" {
				if err == nil || ledger.intent != nil {
					t.Fatal("failed intent was recorded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			now := s.now()
			switch mutation {
			case "current-denied":
				source.currentErr = ErrDenied
			case "wrong-boot":
				source.current.BootID = "other-boot"
			case "wrong-peer":
				source.current.PeerSHA256 = "not-a-certificate-digest"
			case "bad-nonce":
				source.current.Challenge = "bad"
			case "commit-ack-loss":
				ledger.claimErr = errors.New("commit response lost")
			case "slow-commit":
				ledger.onClaim = func() { s.now = func() time.Time { return now.Add(16 * time.Second) } }
			case "slow-authority":
				source.onCurrent = func() { s.now = func() time.Time { return now.Add(time.Minute) } }
			}
			result, err := s.Issue(context.Background(), i.AttemptID, i.Owner, 3)
			if err == nil || len(result.Signature) != 0 || len(result.Permit) != 0 {
				t.Fatal("denied/uncertain authority returned signature")
			}
			if mutation == "commit-ack-loss" || mutation == "slow-commit" {
				ledger.claimErr = nil
				s.now = func() time.Time { return now }
				if result, err := s.Issue(context.Background(), i.AttemptID, i.Owner, 3); err == nil || len(result.Signature) != 0 {
					t.Fatal("uncertain committed claim allowed redispatch")
				}
			}
		})
	}
}
