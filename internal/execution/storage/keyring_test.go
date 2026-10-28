package storage

import (
	"bytes"
	"context"
	"testing"
)

func TestRecordingKeyringValidationAndCopy(t *testing.T) {
	active, old := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	a, b := DeriveKeyID(active), DeriveKeyID(old)
	keys, err := recordingKeyring(active, a, [][]byte{old})
	if err != nil || len(keys) != 2 {
		t.Fatalf("keyring construction: %v", err)
	}
	active[0] ^= 1
	old[0] ^= 1
	if keys[a].key[0] != 1 || keys[b].key[0] != 2 {
		t.Fatal("caller mutation changed retained key material")
	}
	active = bytes.Repeat([]byte{1}, 32)
	old = bytes.Repeat([]byte{2}, 32)
	for _, tt := range []struct {
		key      []byte
		id       string
		previous [][]byte
	}{
		{active, "", nil},
		{[]byte("short"), a, nil},
		{active, a, [][]byte{old, old}},
		{active, a, [][]byte{active}},
		{active, a, [][]byte{[]byte("short")}},
		{active, a, make([][]byte, MaxPreviousRecordingKeys+1)},
	} {
		if _, err := recordingKeyring(tt.key, tt.id, tt.previous); err == nil {
			t.Fatal("invalid recording keyring accepted")
		}
	}
	if _, err := Open(context.Background(), Options{Mode: "ephemeral", EphemeralDir: t.TempDir(), EphemeralMaxBytes: 1024, PreviousRecordingKeys: [][]byte{old}}); err == nil {
		t.Fatal("ephemeral mode accepted persistent read-only keys")
	}
}
