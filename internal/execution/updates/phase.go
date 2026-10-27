package updates

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"unicode/utf8"
)

const (
	PhaseDomain           = "kw-agent-upgrade-phase/v1\x00"
	MaxPhaseBytes         = 4096
	MaxPhaseSeconds int64 = 15
)

var ErrPhase = errors.New("invalid, stale or mismatched upgrade phase permit")

// PhasePermit authorizes only the exact recorded action. PlanSHA256 includes
// actor, workspace/VM/epoch, attempt/recording, manifests, inventory and reboot
// consent. This offline contract does not authorize or dispatch an API job.
type PhasePermit struct {
	Version    uint32        `json:"version"`
	Audience   string        `json:"audience"`
	PlanSHA256 string        `json:"plan_sha256"`
	Action     JournalAction `json:"action"`
	OwnerFence uint64        `json:"owner_fence"`
	Challenge  string        `json:"challenge"`
	PeerSHA256 string        `json:"peer_sha256"`
	IssuedAt   int64         `json:"issued_at"`
	ExpiresAt  int64         `json:"expires_at"`
}

func (p PhasePermit) Encode() []byte {
	raw, err := json.Marshal(p)
	if err != nil {
		panic("phase schema serialization is infallible")
	}
	return raw
}

func (p PhasePermit) valid() bool {
	if p.Version != 1 || p.Audience != "agent-upgrade.phase.v1" || !validDigest(p.PlanSHA256) || !validDigest(p.PeerSHA256) || !validNonce(p.Challenge) || p.OwnerFence == 0 || p.OwnerFence > MaxJournalSequence || p.Action.Sequence == 0 || p.Action.Sequence > MaxJournalSequence || !identifier.MatchString(p.Action.BootID) || p.IssuedAt <= 0 || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > MaxPhaseSeconds {
		return false
	}
	switch p.Action.Kind {
	case "stop_agent", "start_agent", "install_target_msi", "uninstall_target_msi", "install_previous_msi", "install_target_driver", "restore_previous_driver", "verify_target", "verify_previous", "reboot":
		return true
	}
	return false
}

// SignPhase signs structurally valid exact bytes. Callers must FIRST recheck
// administrator/lifecycle/identity/policy, worker ownership and exact durable
// intent recording. No route or production issuer is enabled by this helper.
func SignPhase(p PhasePermit, key ed25519.PrivateKey) ([]byte, []byte, error) {
	if !p.valid() || len(key) != ed25519.PrivateKeySize {
		return nil, nil, ErrPhase
	}
	raw := p.Encode()
	return raw, ed25519.Sign(key, append([]byte(PhaseDomain), raw...)), nil
}

// VerifyPhase expects every non-time field from independent live authority,
// including a guest-minted single-use challenge and authenticated peer digest.
// It is a stateless verifier, not replay storage or current authorization.
func VerifyPhase(raw, signature []byte, keyID string, keys map[string]ed25519.PublicKey, expected PhasePermit, now int64) error {
	if len(raw) == 0 || len(raw) > MaxPhaseBytes || !utf8.Valid(raw) {
		return ErrPhase
	}
	if len(keys) == 0 || len(keys) > 16 {
		return ErrUntrusted
	}
	for id, public := range keys {
		if len(public) != ed25519.PublicKeySize || id != KeyID(public) {
			return ErrUntrusted
		}
	}
	public, ok := keys[keyID]
	if !ok {
		return ErrUntrusted
	}
	if !ed25519.Verify(public, append([]byte(PhaseDomain), raw...), signature) {
		return ErrSignature
	}
	var permit PhasePermit
	// Equality to canonical bytes rejects duplicate, missing, unknown and
	// case-insensitive field aliases as well as alternate encodings.
	if json.Unmarshal(raw, &permit) != nil || !permit.valid() || !bytes.Equal(permit.Encode(), raw) {
		return ErrPhase
	}
	expected.IssuedAt, expected.ExpiresAt = permit.IssuedAt, permit.ExpiresAt
	if permit != expected || now < permit.IssuedAt || now >= permit.ExpiresAt {
		return ErrPhase
	}
	return nil
}
