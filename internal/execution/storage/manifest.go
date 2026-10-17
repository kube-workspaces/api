package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Domain-separated HMAC protects the terminal chunk count and chain against a
// storage attacker who truncates a recording and recomputes its public hashes.
func manifestAuthentication(key []byte, m Manifest) string {
	m.Authentication = ""
	raw, _ := json.Marshal(m) // Manifest contains only JSON-safe scalar values.
	h := hmac.New(sha256.New, key)
	h.Write([]byte("kube-workspaces/execution/manifest/v1\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

func verifyManifest(key []byte, keyID, recordingID string, m Manifest) error {
	if m.Version != 1 || m.KeyID != keyID || m.RecordingID != recordingID || m.PlaintextBytes < 0 ||
		!hmac.Equal([]byte(m.Authentication), []byte(manifestAuthentication(key, m))) {
		return ErrTampered
	}
	return nil
}
