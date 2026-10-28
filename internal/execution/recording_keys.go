package execution

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/kube-workspaces/api/internal/execution/storage"
)

const maxRecordingKeyFileBytes = 16 * 1024

// parseRecordingKeys preserves the original base64 single-key file and adds a
// strict versioned keyring in the same Secret mount. All errors are deliberately
// generic: JSON decoder errors may include sensitive file content.
func parseRecordingKeys(raw []byte) ([]byte, [][]byte, error) {
	invalid := errors.New("invalid recording key file or keyring")
	if len(raw) > maxRecordingKeyFileBytes {
		return nil, nil, invalid
	}
	raw = bytes.TrimSpace(raw)
	decode := func(encoded string) ([]byte, error) {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != 32 {
			return nil, invalid
		}
		return key, nil
	}
	if !bytes.HasPrefix(raw, []byte("{")) {
		active, err := decode(string(raw))
		return active, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, nil, invalid
	}
	seen := map[string]bool{}
	var version int
	var active string
	var previous []string
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return nil, nil, invalid
		}
		seen[name] = true
		switch name {
		case "version":
			err = decoder.Decode(&version)
		case "active":
			err = decoder.Decode(&active)
		case "previous":
			err = decoder.Decode(&previous)
			if previous == nil {
				return nil, nil, invalid
			}
		default:
			return nil, nil, invalid
		}
		if err != nil {
			return nil, nil, invalid
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, nil, invalid
	}
	var tail any
	if err := decoder.Decode(&tail); err != io.EOF || version != 1 || !seen["active"] || len(previous) > storage.MaxPreviousRecordingKeys {
		return nil, nil, invalid
	}
	key, err := decode(active)
	if err != nil {
		return nil, nil, invalid
	}
	keys := make([][]byte, 0, len(previous))
	fingerprints := map[string]bool{storage.DeriveKeyID(key): true}
	for _, encoded := range previous {
		readKey, err := decode(encoded)
		if err != nil {
			return nil, nil, invalid
		}
		id := storage.DeriveKeyID(readKey)
		if fingerprints[id] {
			return nil, nil, invalid
		}
		fingerprints[id] = true
		keys = append(keys, readKey)
	}
	return key, keys, nil
}

// PreviousRecordingKeys returns independent copies of read-only secret keys.
// They permit replay/recovery only, never selection of a writer's active key.
func (c StorageConfig) PreviousRecordingKeys() [][]byte {
	keys := make([][]byte, len(c.previousRecordingKeys))
	for i, key := range c.previousRecordingKeys {
		keys[i] = bytes.Clone(key)
	}
	return keys
}
