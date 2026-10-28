package upgrades

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/execution/updates"
)

// PhaseAuthoritySource MUST independently verify current administrator/access/
// elevation policy, enrolled workspace/VM/epoch/boot, verified allowlisted target
// and predecessor, reboot consent, deadline and exact trusted journal lineage.
// No production source, mTLS listener or default-on issuer is supplied here.
type PhaseAuthoritySource interface {
	CheckIntent(context.Context, storage.AgentUpgradeAttempt, *updates.Journal) error
	// CurrentPhase repeats the live checks at issuance and obtains the challenge
	// and certificate digest from the authenticated guest exchange, never an
	// HTTP body/header or the proposed permit. Outages must deny.
	CurrentPhase(context.Context, storage.AgentUpgradeAttempt, *updates.Journal) (PhaseContext, error)
}

type PhaseContext struct {
	Challenge  string
	PeerSHA256 string
	BootID     string
}

// PhaseIntentRecorder returns only after independently committing these exact
// checkpoint bytes to the attempt's protected encrypted recording. It must
// reject missing/lost/finalized recordings and competing recording writers.
type PhaseIntentRecorder interface {
	RecordPhaseIntent(context.Context, storage.AgentUpgradeAttempt, []byte) (storage.PhaseRecordingReceipt, error)
}

// PhaseIssuer is an offline integration boundary. All live trust and recording
// dependencies are mandatory. It is deliberately not constructed by the server.
type PhaseIssuer struct {
	attempts storage.AgentUpgradeStore
	ledger   storage.UpgradePhaseLedger
	source   PhaseAuthoritySource
	recorder PhaseIntentRecorder
	key      ed25519.PrivateKey
	now      func() time.Time
}

func NewPhaseIssuer(attempts storage.AgentUpgradeStore, ledger storage.UpgradePhaseLedger, source PhaseAuthoritySource, recorder PhaseIntentRecorder, key ed25519.PrivateKey) (*PhaseIssuer, error) {
	if attempts == nil || ledger == nil || ledger.Durability() != storage.DurabilityDurable || source == nil || recorder == nil || len(key) != ed25519.PrivateKeySize {
		return nil, ErrUnavailable
	}
	// Do not retain a mutable key slice supplied by configuration code.
	return &PhaseIssuer{attempts: attempts, ledger: ledger, source: source, recorder: recorder,
		key: append(ed25519.PrivateKey(nil), key...), now: time.Now}, nil
}

// RecordIntent requires independently trusted plan/checkpoint digests. A guest's
// self-reported hash is not authority. The recorder ACK precedes the durable
// ledger row; a lost ACK/commit may leave orphan evidence, never permission to run.
func (s *PhaseIssuer) RecordIntent(ctx context.Context, attemptID, owner string, checkpoint []byte, planSHA256, checkpointSHA256 string) error {
	if err := s.ledger.Ready(ctx); err != nil {
		return ErrUnavailable
	}
	a, err := s.attempts.Get(ctx, attemptID)
	if err != nil {
		return mapStoreError(err)
	}
	i := storage.UpgradePhaseIntent{
		AttemptID: attemptID, Owner: owner, Fence: a.LeaseFence, PlanSHA256: planSHA256,
		CheckpointSHA256: checkpointSHA256, Checkpoint: append([]byte(nil), checkpoint...), RecordedAt: s.now().UTC(),
		Receipt: storage.PhaseRecordingReceipt{RecordingID: a.RecordingID, ChunkSHA256: updates.Digest(checkpoint)},
	}
	j, err := i.Journal()
	if err != nil {
		return ErrInvalid
	}
	if err := s.source.CheckIntent(ctx, a, j); err != nil {
		return err
	}
	// Give the recorder an isolated copy: a callback cannot mutate the bytes
	// whose digest and exact identity the ledger will persist.
	i.Receipt, err = s.recorder.RecordPhaseIntent(ctx, a, append([]byte(nil), i.Checkpoint...))
	if err != nil {
		return ErrUnavailable
	}
	// Re-read the trusted clock after callbacks: recording latency must not be
	// hidden from the final lease/deadline check in the transaction.
	i.RecordedAt = s.now().UTC()
	return mapPhaseError(s.ledger.RecordIntent(ctx, i))
}

type SignedPhase struct {
	Permit    []byte
	Signature []byte
	KeyID     string
}

// Issue never accepts client-chosen phase fields. It loads exact recorded intent
// and obtains challenge/peer/boot from the REQUIRED authenticated current source.
// Each action is claimed once, even if response delivery or COMMIT ACK is lost.
func (s *PhaseIssuer) Issue(ctx context.Context, attemptID, owner string, sequence uint64) (SignedPhase, error) {
	if err := s.ledger.Ready(ctx); err != nil {
		return SignedPhase{}, ErrUnavailable
	}
	a, err := s.attempts.Get(ctx, attemptID)
	if err != nil {
		return SignedPhase{}, mapStoreError(err)
	}
	i, err := s.ledger.GetIntent(ctx, attemptID, sequence)
	if err != nil {
		return SignedPhase{}, mapStoreError(err)
	}
	j, err := i.Journal()
	if err != nil {
		return SignedPhase{}, ErrInvalid
	}
	current, err := s.source.CurrentPhase(ctx, a, j)
	if err != nil {
		return SignedPhase{}, err
	}
	snapshot := j.Snapshot()
	if current.BootID != snapshot.Active.BootID {
		return SignedPhase{}, ErrDenied
	}
	now := s.now().UTC()
	expires := min(now.Unix()+updates.MaxPhaseSeconds, a.LeaseExpiresAt.Unix(), snapshot.ExpiresAt)
	permit := updates.PhasePermit{
		Version: 1, Audience: "agent-upgrade.phase.v1", PlanSHA256: i.PlanSHA256, Action: *snapshot.Active,
		OwnerFence: i.Fence, Challenge: current.Challenge, PeerSHA256: current.PeerSHA256,
		IssuedAt: now.Unix(), ExpiresAt: expires,
	}
	if permit.Validate() != nil {
		return SignedPhase{}, ErrDenied
	}
	if err := s.ledger.ClaimPhase(ctx, attemptID, owner, permit, now); err != nil {
		return SignedPhase{}, mapPhaseError(err)
	}
	if s.now().Unix() >= permit.ExpiresAt {
		return SignedPhase{}, ErrDenied // a slow commit still leaves the claim spent
	}
	// No signature is computed or returned before successful durable claim ACK.
	// Guest-side current-authority checks remain mandatory: an API permit cannot
	// guarantee policy/lifecycle stayed unchanged after the transaction committed.
	raw, signature, err := updates.SignPhase(permit, s.key)
	if err != nil {
		return SignedPhase{}, ErrUnavailable // claim stays spent
	}
	return SignedPhase{Permit: raw, Signature: signature, KeyID: updates.KeyID(s.key.Public().(ed25519.PublicKey))}, nil
}

func mapPhaseError(err error) error {
	if err == nil {
		return nil
	}
	return mapStoreError(err)
}
