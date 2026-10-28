package execution

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kube-workspaces/api/internal/execution/storage"
)

func TestRecordingKeyFileCompatibilityAndRotation(t *testing.T) {
	active := bytes.Repeat([]byte{1}, 32)
	previous := bytes.Repeat([]byte{2}, 32)
	a, p := base64.StdEncoding.EncodeToString(active), base64.StdEncoding.EncodeToString(previous)
	for _, raw := range []string{a + "\n", fmt.Sprintf(`{"version":1,"active":%q}`, a), fmt.Sprintf(`{"version":1,"active":%q,"previous":[%q]}`, a, p)} {
		env := persistentEnvironment("external")
		cfg, err := readStorageConfig(func(key string) string { return env[key] }, func(string) ([]byte, error) { return []byte(raw), nil })
		if err != nil || !bytes.Equal(cfg.RecordingKey(), active) || cfg.KeyID != storage.DeriveKeyID(active) {
			t.Fatalf("key configuration failed: %v", err)
		}
		opts := cfg.StorageOptions()
		if bytes.Contains([]byte(raw), []byte(p)) {
			if len(opts.PreviousRecordingKeys) != 1 || !bytes.Equal(opts.PreviousRecordingKeys[0], previous) {
				t.Fatal("storage options lost read-only key")
			}
			opts.PreviousRecordingKeys[0][0] ^= 1
			if !bytes.Equal(cfg.PreviousRecordingKeys()[0], previous) {
				t.Fatal("key accessor leaked mutable configuration")
			}
		}
		opts.RecordingKey[0] ^= 1
		if !bytes.Equal(cfg.RecordingKey(), active) {
			t.Fatal("active key accessor leaked mutable configuration")
		}
		for _, logged := range []string{fmt.Sprintf("%+v", cfg), fmt.Sprintf("%+v", opts)} {
			if strings.Contains(logged, a) || strings.Contains(logged, p) || strings.Contains(logged, "disposable") || strings.Contains(logged, "test-password") {
				t.Fatal("configuration logging disclosed keyring or credentials")
			}
		}
	}
}

func TestRecordingKeyFileRejectsAmbiguousOrUnsafeKeyrings(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	other := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	for _, raw := range []string{
		``, `null`, `[]`, `{`,
		fmt.Sprintf(`{"version":2,"active":%q}`, key),
		fmt.Sprintf(`{"active":%q}`, key),
		`{"version":1}`, `{"version":1,"active":null}`,
		fmt.Sprintf(`{"version":1,"active":%q,"previous":null}`, key),
		fmt.Sprintf(`{"version":1,"active":%q,"previous":[%q]}`, key, key),
		fmt.Sprintf(`{"version":1,"active":%q,"previous":[%q,%q]}`, key, other, other),
		fmt.Sprintf(`{"version":1,"active":%q,"previous":["private-invalid-key"]}`, key),
		fmt.Sprintf(`{"version":1,"active":%q,"unknown":"private-field"}`, key),
		fmt.Sprintf(`{"version":1,"active":%q,"active":%q}`, key, other),
		fmt.Sprintf(`{"version":1,"version":1,"active":%q}`, key),
		fmt.Sprintf(`{"version":1,"active":%q,"previous":[],"previous":[]}`, key),
		fmt.Sprintf(`{"version":1,"active":%q} {}`, key),
		fmt.Sprintf(`{"version":1,"active":%q} trailing`, key),
		strings.Repeat(" ", maxRecordingKeyFileBytes) + key,
	} {
		active, previous, err := parseRecordingKeys([]byte(raw))
		if err == nil || active != nil || previous != nil {
			t.Fatal("unsafe keyring accepted")
		}
		if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), other) || strings.Contains(err.Error(), "private-") {
			t.Fatal("configuration error disclosed key material")
		}
	}
	previous := make([]string, storage.MaxPreviousRecordingKeys)
	for i := range previous {
		previous[i] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 2)}, 32))
	}
	encode := func(keys []string) []byte {
		raw, _ := json.Marshal(map[string]any{"version": 1, "active": key, "previous": keys})
		return raw
	}
	if _, keys, err := parseRecordingKeys(encode(previous)); err != nil || len(keys) != len(previous) {
		t.Fatal("bounded complete keyring rejected")
	}
	previous = append(previous, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{99}, 32)))
	if _, _, err := parseRecordingKeys(encode(previous)); err == nil {
		t.Fatal("unbounded read keyring accepted")
	}
}
