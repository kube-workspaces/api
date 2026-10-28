package storage

import (
	"bytes"
	"crypto/cipher"
	"fmt"
)

// MaxPreviousRecordingKeys bounds the read-only overlap during coordinated
// rotation. New recordings always use the separately configured active key.
const MaxPreviousRecordingKeys = 8

type recordingReadKey struct {
	key []byte
	gcm cipher.AEAD
}

func recordingKeyring(active []byte, activeID string, previous [][]byte) (map[string]recordingReadKey, error) {
	if activeID == "" || len(previous) > MaxPreviousRecordingKeys {
		return nil, fmt.Errorf("invalid recording keyring")
	}
	keys := make(map[string]recordingReadKey, len(previous)+1)
	add := func(id string, raw []byte) error {
		if _, exists := keys[id]; exists {
			return fmt.Errorf("duplicate recording key")
		}
		gcm, err := newGCM(raw)
		if err != nil {
			return err
		}
		keys[id] = recordingReadKey{key: bytes.Clone(raw), gcm: gcm}
		return nil
	}
	if err := add(activeID, active); err != nil {
		return nil, err
	}
	for _, raw := range previous {
		if bytes.Equal(active, raw) {
			return nil, fmt.Errorf("active recording key repeated in read-only keys")
		}
		if err := add(DeriveKeyID(raw), raw); err != nil {
			return nil, err
		}
	}
	return keys, nil
}
