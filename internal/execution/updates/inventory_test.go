package updates

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
)

const inventoryFixtureNow int64 = 1700000060

type inventoryVector struct {
	KeyID           string `json:"key_id"`
	InventorySHA256 string `json:"inventory_sha256"`
	PublicKey       string `json:"public_key"`
	Signature       string `json:"signature"`
}

func inventoryKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5A}, 32))
}

func inventoryFixture(t *testing.T) ([]byte, inventoryVector) {
	t.Helper()
	raw, err := os.ReadFile("testdata/inventory-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	meta, err := os.ReadFile("testdata/inventory-v1-signature.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector inventoryVector
	if err := json.Unmarshal(meta, &vector); err != nil {
		t.Fatal(err)
	}
	return raw, vector
}

func inventoryKeys(t *testing.T, vector inventoryVector) map[string]ed25519.PublicKey {
	t.Helper()
	public, err := base64.RawURLEncoding.DecodeString(vector.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]ed25519.PublicKey{vector.KeyID: public}
}

func signInventory(t *testing.T, raw []byte) ([]byte, string, map[string]ed25519.PublicKey) {
	t.Helper()
	key := inventoryKey()
	public := key.Public().(ed25519.PublicKey)
	return ed25519.Sign(key, append([]byte(InventoryDomain), raw...)), KeyID(public), map[string]ed25519.PublicKey{KeyID(public): public}
}

func TestInventorySignedFixtureRoundTripAndFreshness(t *testing.T) {
	raw, vector := inventoryFixture(t)
	keys := inventoryKeys(t, vector)
	v, err := VerifyInventory(raw, mustDecode64(t, vector.Signature), vector.KeyID, nonceOf(t, raw), inventoryFixtureNow, keys)
	if err != nil {
		t.Fatal(err)
	}
	if v.SHA256() != vector.InventorySHA256 || v.SHA256() != Digest(raw) {
		t.Fatal("fixture digest drift")
	}
	metadata := v.Metadata()
	if !bytes.Equal(metadata.Encode(), raw) || metadata.Namespace != "team-a" || metadata.Attempt == nil || metadata.Attempt.Phase != "active" {
		t.Fatal("fixture identity drift")
	}
	metadata.MSI[0].ProductCode = "00000000-0000-0000-0000-000000000000"
	metadata.Attempt.Sequence = 99
	if v.Metadata().MSI[0].ProductCode == metadata.MSI[0].ProductCode || v.Metadata().Attempt.Sequence == 99 {
		t.Fatal("metadata aliased the verified report")
	}
	bare := v.Metadata()
	bare.Driver, bare.Attempt = nil, nil
	enc := bare.Encode()
	if !bytes.Contains(enc, []byte(`"driver":null`)) || !bytes.Contains(enc, []byte(`"attempt":null`)) {
		t.Fatal("optional inventory sections must encode as explicit null")
	}
	if _, err := VerifyInventory(raw, mustDecode64(t, vector.Signature), vector.KeyID, vector.KeyID, inventoryFixtureNow, keys); !errors.Is(err, ErrInventoryFresh) {
		t.Fatal("foreign nonce accepted", err)
	}
	for _, now := range []int64{inventoryFixtureNow + InventoryFreshSeconds, inventoryFixtureNow - 1, inventoryFixtureNow - InventoryFreshSeconds - 1} {
		if _, err := VerifyInventory(raw, mustDecode64(t, vector.Signature), vector.KeyID, nonceOf(t, raw), now, keys); (now == inventoryFixtureNow+InventoryFreshSeconds) != (err == nil) {
			t.Fatal("freshness window misclassified", now, err)
		}
	}
}

func TestInventoryRejectsUntrustedTamperedAndNonCanonicalBodies(t *testing.T) {
	raw, vector := inventoryFixture(t)
	keys := inventoryKeys(t, vector)
	signature := mustDecode64(t, vector.Signature)
	nonce := nonceOf(t, raw)

	flipped := append([]byte{}, signature...)
	flipped[0] ^= 1
	wrongKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5B}, 32))
	wrongPublic := wrongKey.Public().(ed25519.PublicKey)
	cases := []struct {
		name  string
		raw   []byte
		sig   []byte
		keyID string
		keys  map[string]ed25519.PublicKey
		want  error
	}{
		{"flipped signature", raw, flipped, vector.KeyID, keys, ErrSignature},
		{"signature from a different key", raw, ed25519.Sign(wrongKey, append([]byte(InventoryDomain), raw...)), vector.KeyID, keys, ErrSignature},
		{"manifest domain framing", raw, ed25519.Sign(inventoryKey(), append([]byte(Domain), raw...)), vector.KeyID, keys, ErrSignature},
		{"unknown key id", raw, signature, KeyID(wrongPublic), keys, ErrUntrusted},
		{"empty keyring", raw, signature, vector.KeyID, map[string]ed25519.PublicKey{}, ErrUntrusted},
		{"mismatched keyring entry", raw, signature, vector.KeyID, map[string]ed25519.PublicKey{KeyID(wrongPublic): append(ed25519.PublicKey{}, keys[vector.KeyID]...)}, ErrUntrusted},
		{"oversized body", bytes.Repeat([]byte{' '}, MaxInventoryBytes+1), signature, vector.KeyID, keys, ErrInventory},
		{"invalid utf-8", append(append([]byte{}, raw[:len(raw)-1]...), 0xff), signature, vector.KeyID, keys, ErrInventory},
		{"trailing json", append(append([]byte{}, raw...), []byte(`{}`)...), ed25519.Sign(inventoryKey(), append([]byte(InventoryDomain), append(append([]byte{}, raw...), []byte(`{}`)...)...)), vector.KeyID, keys, ErrInventory},
		{"trailing whitespace", append(append([]byte{}, raw...), ' '), ed25519.Sign(inventoryKey(), append([]byte(InventoryDomain), append(append([]byte{}, raw...), ' ')...)), vector.KeyID, keys, ErrInventory},
		{"unknown field", injectInventoryField(t, raw, `"bogus":1,`), signInventoryField(t, raw, `"bogus":1,`), vector.KeyID, keys, ErrInventory},
		{"duplicate field", injectInventoryField(t, raw, `"version":1,`), signInventoryField(t, raw, `"version":1,`), vector.KeyID, keys, ErrInventory},
		{"missing field", bytes.Replace(raw, []byte(`"timestamp":1700000060,`), nil, 1), signInventoryBytes(t, bytes.Replace(raw, []byte(`"timestamp":1700000060,`), nil, 1)), vector.KeyID, keys, ErrInventory},
		{"null scalar", bytes.Replace(raw, []byte(`"pending_reboot":false`), []byte(`"pending_reboot":null`), 1), signInventoryBytes(t, bytes.Replace(raw, []byte(`"pending_reboot":false`), []byte(`"pending_reboot":null`), 1)), vector.KeyID, keys, ErrInventory},
		{"case-variant field", bytes.Replace(raw, []byte(`"version":1`), []byte(`"Version":1`), 1), signInventoryBytes(t, bytes.Replace(raw, []byte(`"version":1`), []byte(`"Version":1`), 1)), vector.KeyID, keys, ErrInventory},
	}
	for _, tc := range cases {
		if _, err := VerifyInventory(tc.raw, tc.sig, tc.keyID, nonce, inventoryFixtureNow, tc.keys); !errors.Is(err, tc.want) {
			t.Fatalf("%s: got %v want %v", tc.name, err, tc.want)
		}
	}
}

func TestInventoryRejectsSchemaViolations(t *testing.T) {
	raw, _ := inventoryFixture(t)
	mutations := map[string]func(*Inventory){
		"unsupported schema":     func(i *Inventory) { i.Version = 2 },
		"foreign architecture":   func(i *Inventory) { i.Architecture = "arm64" },
		"short agent version":    func(i *Inventory) { i.AgentVersion = "0.3" },
		"leading-zero version":   func(i *Inventory) { i.AgentVersion = "01.3.5" },
		"uppercase build digest": func(i *Inventory) { i.BuildSHA256 = strings.ToUpper(i.BuildSHA256) },
		"management range":       func(i *Inventory) { i.ManagementMax = 65 },
		"inverted updater range": func(i *Inventory) { i.UpdaterMin = 2 },
		"epoch above int64":      func(i *Inventory) { i.RevocationEpoch = uint64(math.MaxInt64) + 1 },
		"empty msi list":         func(i *Inventory) { i.MSI = []InventoryMSI{} },
		"unbounded msi list": func(i *Inventory) {
			for len(i.MSI) < MaxInventoryMSIEntries+1 {
				i.MSI = append(i.MSI, i.MSI[0])
			}
		},
		"two agent registrations":   func(i *Inventory) { i.MSI[1].UpgradeCode = AgentUpgradeCode },
		"duplicate product code":    func(i *Inventory) { i.MSI[1].ProductCode = i.MSI[0].ProductCode },
		"nil product code":          func(i *Inventory) { i.MSI[0].ProductCode = "00000000-0000-0000-0000-000000000000" },
		"product equals upgrade":    func(i *Inventory) { i.MSI[1].ProductCode = i.MSI[1].UpgradeCode },
		"bad msi version":           func(i *Inventory) { i.MSI[1].Version = "1.4" },
		"empty install directory":   func(i *Inventory) { i.MSI[0].InstallDirectory = "" },
		"control byte in path":      func(i *Inventory) { i.MSI[0].InstallDirectory = "C:\\Apps\x01Bad" },
		"non-ascii path":            func(i *Inventory) { i.MSI[0].InstallDirectory = "C:\\Apps\\café" },
		"bad package identity":      func(i *Inventory) { i.Driver.PackageIdentity = "bad identity" },
		"bad package digest":        func(i *Inventory) { i.Driver.PackageSHA256 = "xyz" },
		"non-inf published name":    func(i *Inventory) { i.Driver.InfName = "idd.dll" },
		"device without separator":  func(i *Inventory) { i.Driver.DeviceInstance = "ROOT-IDD-0000" },
		"three-part driver version": func(i *Inventory) { i.Driver.DriverVersion = "25.7.23" },
		"unknown attempt phase":     func(i *Inventory) { i.Attempt.Phase = "installing" },
		"attempt sequence bound":    func(i *Inventory) { i.Attempt.Sequence = MaxJournalSequence + 1 },
		"uppercase attempt id":      func(i *Inventory) { i.Attempt.AttemptID = "UPD-1" },
		"malformed nonce":           func(i *Inventory) { i.Nonce = "short" },
		"zero timestamp":            func(i *Inventory) { i.Timestamp = 0 },
		"uppercase namespace":       func(i *Inventory) { i.Namespace = "Team" },
	}
	for name, mutate := range mutations {
		var inventory Inventory
		if err := json.Unmarshal(raw, &inventory); err != nil {
			t.Fatal(err)
		}
		mutate(&inventory)
		raw := inventory.Encode()
		signature, keyID, keys := signInventory(t, raw)
		if _, err := VerifyInventory(raw, signature, keyID, inventory.Nonce, inventory.Timestamp, keys); !errors.Is(err, ErrInventory) {
			t.Fatalf("%s: got %v want %v", name, err, ErrInventory)
		}
	}
}

func nonceOf(t *testing.T, raw []byte) string {
	t.Helper()
	var inventory Inventory
	if err := json.Unmarshal(raw, &inventory); err != nil {
		t.Fatal(err)
	}
	return inventory.Nonce
}

func mustDecode64(t *testing.T, value string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func injectInventoryField(t *testing.T, raw []byte, field string) []byte {
	t.Helper()
	return bytes.Replace(raw, []byte(`{`), []byte(`{`+field), 1)
}

func signInventoryField(t *testing.T, raw []byte, field string) []byte {
	t.Helper()
	return signInventoryBytes(t, injectInventoryField(t, raw, field))
}

func signInventoryBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	key := inventoryKey()
	return ed25519.Sign(key, append([]byte(InventoryDomain), raw...))
}

func FuzzVerifyInventory(f *testing.F) {
	raw, err := os.ReadFile("testdata/inventory-v1.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"version":1,"Version":1}`))
	f.Add([]byte(`null`))
	key := inventoryKey()
	public := key.Public().(ed25519.PublicKey)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxInventoryBytes {
			return
		}
		expected := ""
		var probe struct {
			Nonce string `json:"nonce"`
		}
		if json.Unmarshal(raw, &probe) == nil {
			expected = probe.Nonce
		}
		v, err := VerifyInventory(raw, ed25519.Sign(key, append([]byte(InventoryDomain), raw...)), KeyID(public), expected, inventoryFixtureNow, map[string]ed25519.PublicKey{KeyID(public): public})
		if err == nil && (v == nil || v.Metadata().Version != 1 || v.SHA256() != Digest(raw) || !bytes.Equal(v.Metadata().Encode(), raw)) {
			t.Fatal("verified inventory violated identity invariants")
		}
	})
}
