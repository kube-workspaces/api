package storage

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
)

const maxTerminalIntentBytes = 16 << 10

// TerminalIntent is protected evidence of the finalizing session's intended
// metadata commit, not a committed outcome or a lease/ownership grant. Recovery
// must separately compare Admission to the authoritative row and fence owners.
type TerminalIntent struct {
	Version   int              `json:"version"`
	Admission ExecutionRecord  `json:"admission"`
	Outcome   ExecutionOutcome `json:"outcome"`
}

// MatchesAdmission compares the complete original admission, not just IDs.
func (i TerminalIntent) MatchesAdmission(rec ExecutionRecord) bool {
	return sameRecord(i.Admission, rec)
}

func (i TerminalIntent) valid(recordingID string) bool {
	r := i.Admission
	if i.Version != 1 || !validCompletion(i.Outcome) || !r.Admitted ||
		r.RecordingID != recordingID || validateID("execution", r.ExecutionID) != nil ||
		validateID("recording", r.RecordingID) != nil || r.ActorID == "" ||
		r.Namespace == "" || r.WorkspaceName == "" || r.WorkspaceUID == "" ||
		r.OSIdentity == "" || r.AdmissionTime.IsZero() || i.Outcome.EndTime.Before(r.AdmissionTime) {
		return false
	}
	switch r.Operation {
	case OperationCommand, OperationScript, OperationShell, OperationUpgrade:
	default:
		return false
	}
	return (r.Mode == "ephemeral" && r.Durability == DurabilityNone) ||
		((r.Mode == "external" || r.Mode == "bundled") && r.Durability == DurabilityDurable)
}

func terminalGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, ErrTampered
	}
	// Independent key and AAD domain: chunk ciphertext can never stand in for
	// terminal intent, even if a nonce or attacker-selected identifier repeats.
	h := hmac.New(sha256.New, key)
	h.Write([]byte("kube-workspaces/execution/terminal-key/v1\x00"))
	return newGCM(h.Sum(nil))
}

func terminalAAD(recordingID, keyID string) []byte {
	raw, _ := json.Marshal([]string{"kube-workspaces/execution/terminal/v1", recordingID, keyID})
	return raw
}

func sealTerminalIntent(key []byte, keyID, recordingID string, intent TerminalIntent) ([]byte, error) {
	if !intent.valid(recordingID) {
		return nil, ErrConflict
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxTerminalIntentBytes {
		return nil, ErrChunkTooLarge
	}
	gcm, err := terminalGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, raw, terminalAAD(recordingID, keyID)), nil
}

func openTerminalIntent(key []byte, keyID, recordingID string, payload []byte) (*TerminalIntent, error) {
	gcm, err := terminalGCM(key)
	if err != nil {
		return nil, err
	}
	if len(payload) < nonceSize+gcm.Overhead() || len(payload) > maxTerminalIntentBytes+nonceSize+gcm.Overhead() {
		return nil, ErrTampered
	}
	raw, err := gcm.Open(nil, payload[:nonceSize], payload[nonceSize:], terminalAAD(recordingID, keyID))
	if err != nil {
		return nil, ErrTampered
	}
	var intent TerminalIntent
	if json.Unmarshal(raw, &intent) != nil || !intent.valid(recordingID) {
		return nil, ErrTampered
	}
	return &intent, nil
}

func protectTerminalIntent(m *Manifest, key []byte, meta FinalizeMeta) error {
	if meta.Terminal == nil {
		return nil // Keep the exact legacy v1 representation/signature.
	}
	if meta.ActorID != meta.Terminal.Admission.ActorID || !meta.EndTime.Equal(meta.Terminal.Outcome.EndTime) {
		return ErrConflict
	}
	sealed, err := sealTerminalIntent(key, m.KeyID, m.RecordingID, *meta.Terminal)
	if err != nil {
		return err
	}
	m.Version, m.Terminal = 2, sealed
	return nil
}

func cloneManifest(m Manifest) Manifest {
	m.Terminal = append([]byte(nil), m.Terminal...)
	return m
}
