package updates

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func phaseFixture(t *testing.T) (PhasePermit, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/phase-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.TrimSuffix(raw, []byte{'\n'})
	var p PhasePermit
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, p.Encode()) {
		t.Fatal("fixture encoding drift")
	}
	journal, err := os.ReadFile("testdata/journal-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var s JournalSnapshot
	if err := json.Unmarshal(journal, &s); err != nil {
		t.Fatal(err)
	}
	if p.PlanSHA256 != s.Plan.SHA256() || p.Action != *s.Active {
		t.Fatal("journal binding drift")
	}
	return p, raw
}

func TestPhaseSignedContract(t *testing.T) {
	p, raw := phaseFixture(t)
	key := inventoryKey()
	public := key.Public().(ed25519.PublicKey)
	id := KeyID(public)
	keys := map[string]ed25519.PublicKey{id: public}
	encoded, sig, err := SignPhase(p, key)
	if err != nil || !bytes.Equal(raw, encoded) {
		t.Fatal("signing drift", err)
	}
	// Shared deterministic Ed25519 vector asserted by Rust too.
	const signature = "06854609cf8e43cbcd10053a53c34b166ec9601630f81b39e074ac2b85a6b8e41954105929b945d7a975e467ebed0bdb443eeeaba9514c39a4bc3b86e1be7d00"
	if hex.EncodeToString(sig) != signature {
		t.Fatalf("signature: %x", sig)
	}
	for _, now := range []int64{p.IssuedAt, p.ExpiresAt - 1} {
		if err := VerifyPhase(raw, sig, id, keys, p, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, now := range []int64{-1, p.IssuedAt - 1, p.ExpiresAt, p.ExpiresAt + 1} {
		if VerifyPhase(raw, sig, id, keys, p, now) == nil {
			t.Fatal("accepted clock", now)
		}
	}
	mutations := []func(*PhasePermit){
		func(v *PhasePermit) { v.Version++ }, func(v *PhasePermit) { v.Audience = "command" },
		func(v *PhasePermit) { v.PlanSHA256 = strings.Repeat("5", 64) },
		func(v *PhasePermit) { v.Action.Sequence++ }, func(v *PhasePermit) { v.Action.Kind = "uninstall_target_msi" },
		func(v *PhasePermit) { v.Action.BootID = "boot-2" }, func(v *PhasePermit) { v.OwnerFence++ },
		func(v *PhasePermit) { v.Challenge = strings.Repeat("B", 43) },
		func(v *PhasePermit) { v.PeerSHA256 = strings.Repeat("5", 64) },
	}
	for i, mutate := range mutations {
		expected := p
		mutate(&expected)
		if VerifyPhase(raw, sig, id, keys, expected, p.IssuedAt) == nil {
			t.Fatal("binding accepted", i)
		}
	}
	bad := [][]byte{append([]byte(" "), raw...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"extra":true`), 1), bytes.Replace(raw, []byte(`"version":1,`), nil, 1), []byte(strings.Repeat("x", MaxPhaseBytes+1))}
	for i, b := range bad {
		s := ed25519.Sign(key, append([]byte(PhaseDomain), b...))
		if VerifyPhase(b, s, id, keys, p, p.IssuedAt) == nil {
			t.Fatal("invalid encoding", i)
		}
	}
	foreign := ed25519.Sign(key, append([]byte(InventoryDomain), raw...))
	if VerifyPhase(raw, foreign, id, keys, p, p.IssuedAt) == nil || VerifyPhase(raw, sig, "unknown", keys, p, p.IssuedAt) == nil || VerifyPhase(raw, sig, id, nil, p, p.IssuedAt) == nil {
		t.Fatal("trust/domain failure")
	}
	for _, mutate := range []func(*PhasePermit){
		func(v *PhasePermit) { v.ExpiresAt++ }, func(v *PhasePermit) { v.IssuedAt = 0 },
		func(v *PhasePermit) { v.OwnerFence = 0 }, func(v *PhasePermit) { v.Action.Sequence = 0 },
		func(v *PhasePermit) { v.Action.Kind = "shell" }, func(v *PhasePermit) { v.Challenge = "bad" },
	} {
		invalid := p
		mutate(&invalid)
		if _, _, err := SignPhase(invalid, key); err == nil {
			t.Fatal("invalid permit signed")
		}
	}
}

func FuzzVerifyPhase(f *testing.F) {
	raw, _ := os.ReadFile("testdata/phase-v1.json")
	f.Add(bytes.TrimSpace(raw))
	key := inventoryKey()
	public := key.Public().(ed25519.PublicKey)
	id := KeyID(public)
	keys := map[string]ed25519.PublicKey{id: public}
	var expected PhasePermit
	_ = json.Unmarshal(raw, &expected)
	f.Fuzz(func(t *testing.T, raw []byte) {
		sig := ed25519.Sign(key, append([]byte(PhaseDomain), raw...))
		if VerifyPhase(raw, sig, id, keys, expected, expected.IssuedAt) == nil {
			var got PhasePermit
			if json.Unmarshal(raw, &got) != nil || !bytes.Equal(raw, got.Encode()) || !got.valid() {
				t.Fatal("unexpected accepted encoding")
			}
			binding := expected
			binding.IssuedAt, binding.ExpiresAt = got.IssuedAt, got.ExpiresAt
			if got != binding {
				t.Fatal("unexpected accepted binding")
			}
		}
	})
}
