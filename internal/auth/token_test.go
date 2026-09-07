package auth

import (
	"testing"
	"time"
)

func TestValidateSessionTokenRotation(t *testing.T) {
	oldKey := []byte("old-signing-key-aaaaaaaaaaaaaaaa")
	newKey := []byte("new-signing-key-bbbbbbbbbbbbbbbb")
	expiry := time.Hour

	tokenMintedUnderOld, err := CreateSessionToken("a@example.com", "A", "user", nil, oldKey, expiry)
	if err != nil {
		t.Fatalf("CreateSessionToken() error = %v", err)
	}

	// After rotation the new key alone rejects the old token...
	if _, err := ValidateSessionToken(tokenMintedUnderOld, newKey); err == nil {
		t.Fatal("ValidateSessionToken() accepted token minted under the old key")
	}

	// ...but the dual-key path accepts it while switching keys.
	got, err := ValidateSessionTokenWithKeys(tokenMintedUnderOld, [][]byte{newKey, oldKey})
	if err != nil {
		t.Fatalf("ValidateSessionTokenWithKeys() error = %v", err)
	}
	if got.Email != "a@example.com" {
		t.Fatalf("ValidateSessionTokenWithKeys() email = %q, want a@example.com", got.Email)
	}

	// Tokens minted under the current key still validate first-class.
	tokenMintedUnderNew, err := CreateSessionToken("b@example.com", "B", "user", nil, newKey, expiry)
	if err != nil {
		t.Fatalf("CreateSessionToken() error = %v", err)
	}
	if _, err := ValidateSessionTokenWithKeys(tokenMintedUnderNew, [][]byte{newKey, oldKey}); err != nil {
		t.Fatalf("ValidateSessionTokenWithKeys() error = %v", err)
	}

	// Empty key list is rejected explicitly, not misreported as a bad signature.
	if _, err := ValidateSessionTokenWithKeys(tokenMintedUnderOld, [][]byte{}); err == nil {
		t.Fatal("ValidateSessionTokenWithKeys() accepted empty key list")
	}
}

func TestValidateSessionTokenEmptyKey(t *testing.T) {
	if _, err := CreateSessionToken("a@example.com", "A", "user", nil, nil, time.Hour); err == nil {
		t.Fatal("CreateSessionToken() signed with an empty key")
	}
	if _, err := ValidateSessionToken("token.value", nil); err == nil {
		t.Fatal("ValidateSessionToken() accepted an empty key")
	}
}

func TestApplyKeyRotation(t *testing.T) {
	keyA := []byte("key-a-aaaaaaaaaaaaaaaaaaaaaaaa")
	keyB := []byte("key-b-bbbbbbbbbbbbbbbbbbbbbbbb")
	keyC := []byte("key-c-cccccccccccccccccccccccc")
	expiry := 24 * time.Hour

	p := &ConfigProvider{}

	// First load: nothing to rotate from.
	p.applyKeyRotation(&Config{})
	p.config = &Config{SigningKey: keyA, TokenExpiry: expiry}
	if len(p.config.PreviousSigningKey) != 0 {
		t.Fatalf("expected no previous key on first load, got %q", p.config.PreviousSigningKey)
	}

	// Rotation: A -> B keeps A as the valid predecessor.
	next := &Config{SigningKey: keyB, TokenExpiry: expiry}
	p.applyKeyRotation(next)
	if !bytesEqual(next.PreviousSigningKey, keyA) {
		t.Fatalf("rotation A->B previous = %q, want %q", next.PreviousSigningKey, keyA)
	}
	if p.rotatedAt.IsZero() {
		t.Fatal("rotation did not record rotatedAt")
	}

	// No change: predecessor is carried forward.
	p.config = next
	stable := &Config{SigningKey: keyB, TokenExpiry: expiry}
	p.applyKeyRotation(stable)
	// Simulate time passing to stay within the expiry window.
	now := time.Now()
	p.rotatedAt = now.Add(-expiry / 2)
	if !bytesEqual(stable.PreviousSigningKey, keyA) {
		t.Fatalf("carried previous = %q, want %q", stable.PreviousSigningKey, keyA)
	}

	// Predecessor older than one token lifetime is dropped.
	p.config = stable
	stale := &Config{SigningKey: keyB, TokenExpiry: expiry}
	p.rotatedAt = now.Add(-expiry - time.Minute)
	p.applyKeyRotation(stale)
	if len(stale.PreviousSigningKey) != 0 {
		t.Fatalf("expected stale previous key to be dropped, got %q", stale.PreviousSigningKey)
	}

	// Another rotation while stale: B -> C carries B.
	p.config = stale
	rot := &Config{SigningKey: keyC, TokenExpiry: expiry}
	p.applyKeyRotation(rot)
	if !bytesEqual(rot.PreviousSigningKey, keyB) {
		t.Fatalf("rotation B->C previous = %q, want %q", rot.PreviousSigningKey, keyB)
	}
}

func TestSessionSigningKeys(t *testing.T) {
	cfg := &Config{SigningKey: []byte("primary")}
	got := cfg.SessionSigningKeys()
	if len(got) != 1 || !bytesEqual(got[0], []byte("primary")) {
		t.Fatalf("SessionSigningKeys() with no previous = %q", got)
	}
	cfg.PreviousSigningKey = []byte("previous")
	got = cfg.SessionSigningKeys()
	if len(got) != 2 || !bytesEqual(got[0], []byte("primary")) || !bytesEqual(got[1], []byte("previous")) {
		t.Fatalf("SessionSigningKeys() = %q", got)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
