package updates

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	raw, err := os.ReadFile("testdata/manifest-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, 32))
}

func verifySigned(raw []byte, private ed25519.PrivateKey) (*VerifiedManifest, error) {
	public := private.Public().(ed25519.PublicKey)
	return Verify(raw, ed25519.Sign(private, append([]byte(Domain), raw...)), KeyID(public), Digest(raw), map[string]ed25519.PublicKey{KeyID(public): public})
}

func TestManifestPublisherFixtureAndBoundedArtifactStreams(t *testing.T) {
	raw, _ := fixture(t)
	var vector struct {
		KeyID          string `json:"key_id"`
		ManifestSHA256 string `json:"manifest_sha256"`
		PublicKey      string `json:"public_key"`
		Signature      string `json:"signature"`
	}
	metadata, err := os.ReadFile("testdata/manifest-v1-signature.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(metadata, &vector); err != nil {
		t.Fatal(err)
	}
	public, err := base64.RawURLEncoding.DecodeString(vector.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(vector.Signature)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(raw, signature, vector.KeyID, vector.ManifestSHA256, map[string]ed25519.PublicKey{vector.KeyID: public})
	if err != nil {
		t.Fatal(err)
	}
	if v.SHA256() != vector.ManifestSHA256 || v.Metadata().TargetID != "windows-agent-0.3.5" {
		t.Fatal("fixture identity drift")
	}
	for name, payload := range map[string]string{"agent.msi": "msi-v1", "updater.exe": "helper-v1", "idd.zip": "idd-v1"} {
		if err := v.VerifyArtifact(name, strings.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{payload[:len(payload)-1], payload + "x", strings.Repeat("x", len(payload))} {
			if err := v.VerifyArtifact(name, strings.NewReader(bad)); !errors.Is(err, ErrPayload) {
				t.Fatal("corrupt payload accepted", err)
			}
		}
	}
	if err := v.VerifyArtifact("other.msi", strings.NewReader("msi-v1")); !errors.Is(err, ErrPayload) {
		t.Fatal("unsigned payload name accepted")
	}
	r := &countingReader{}
	if err := v.VerifyArtifact("agent.msi", r); !errors.Is(err, ErrPayload) || r.bytes != 7 {
		t.Fatalf("unbounded payload read: bytes=%d err=%v", r.bytes, err)
	}
	if err := v.VerifyArtifact("agent.msi", io.MultiReader(strings.NewReader("msi-v1"), errorReader{})); !errors.Is(err, ErrPayload) {
		t.Fatal("I/O error reported success")
	}
	// Availability callers receive copies, not mutable verified authority.
	m := v.Metadata()
	m.MSI.Artifact.SHA256 = Digest([]byte("evil"))
	m.Driver.HardwareIDs[0] = "ROOT\\Other"
	m.RollbackPredecessors[0].TargetID = "changed"
	if err := v.VerifyArtifact("agent.msi", strings.NewReader("msi-v1")); err != nil || v.Metadata().Driver.HardwareIDs[0] != "ROOT\\ExampleIDD" || v.Metadata().RollbackPredecessors[0].TargetID == "changed" {
		t.Fatal("metadata copy altered verified state")
	}
}

type countingReader struct{ bytes int }

func (r *countingReader) Read(p []byte) (int, error) { r.bytes += len(p); return len(p), nil }

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("synthetic storage outage") }

func TestManifestRejectsPublisherAndByteSubstitution(t *testing.T) {
	raw, private := fixture(t)
	public := private.Public().(ed25519.PublicKey)
	id := KeyID(public)
	sig := ed25519.Sign(private, append([]byte(Domain), raw...))
	keys := map[string]ed25519.PublicKey{id: public}
	for _, test := range []struct {
		name       string
		raw, sig   []byte
		id, digest string
		keys       map[string]ed25519.PublicKey
		want       error
	}{
		{"unknown-key", raw, sig, "unknown", Digest(raw), keys, ErrUntrusted},
		{"retired-key", raw, sig, id, Digest(raw), map[string]ed25519.PublicKey{}, ErrUntrusted},
		{"wrong-fingerprint", raw, sig, id, Digest(raw), map[string]ed25519.PublicKey{id: make([]byte, 32)}, ErrUntrusted},
		{"digest-substitution", raw, sig, id, strings.Repeat("1", 64), keys, ErrDigest},
		{"signature-substitution", raw, make([]byte, 64), id, Digest(raw), keys, ErrSignature},
		{"domain-confusion", raw, ed25519.Sign(private, raw), id, Digest(raw), keys, ErrSignature},
		{"whitespace-substitution", append(append([]byte{}, raw...), ' '), sig, id, Digest(append(append([]byte{}, raw...), ' ')), keys, ErrSignature},
		{"oversize", bytes.Repeat([]byte{' '}, MaxManifestBytes+1), sig, id, Digest(raw), keys, ErrInvalid},
		{"non-utf8", []byte{0xff}, sig, id, Digest([]byte{0xff}), keys, ErrInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Verify(test.raw, test.sig, test.id, test.digest, test.keys); !errors.Is(err, test.want) {
				t.Fatalf("got %v want %v", err, test.want)
			}
		})
	}
}

func TestManifestPublisherRotationRequiresExplicitOverlap(t *testing.T) {
	raw, old := fixture(t)
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x56}, 32))
	oldPublic, nextPublic := old.Public().(ed25519.PublicKey), next.Public().(ed25519.PublicKey)
	keys := map[string]ed25519.PublicKey{KeyID(oldPublic): oldPublic, KeyID(nextPublic): nextPublic}
	for _, key := range []ed25519.PrivateKey{old, next} {
		id := KeyID(key.Public().(ed25519.PublicKey))
		if _, err := Verify(raw, ed25519.Sign(key, append([]byte(Domain), raw...)), id, Digest(raw), keys); err != nil {
			t.Fatal(err)
		}
	}
	delete(keys, KeyID(oldPublic))
	if _, err := Verify(raw, ed25519.Sign(old, append([]byte(Domain), raw...)), KeyID(oldPublic), Digest(raw), keys); !errors.Is(err, ErrUntrusted) {
		t.Fatal("retired publisher remained trusted", err)
	}
}

func TestManifestRejectsMalformedSignedSchema(t *testing.T) {
	raw, private := fixture(t)
	for _, test := range []struct{ from, to string }{
		{`"version": 1`, `"version": 2`},
		{`"version": 1`, `"version": 1, "version": 1`},
		{`"version": 1`, `"version": 1, "ver\u0073ion": 1`},
		{`"version": 1`, `"version": 1, "unknown": true`},
		{`"version": 1`, `"version": 1, "Version": 1`},
		{`"file": "agent.msi"`, `"File": "agent.msi"`},
		{`"file": "agent.msi"`, `"file": "agent.msi", "file": "other.msi"`},
		{`"file": "agent.msi"`, `"file": "agent.msi", "fi\u006ce": "other.msi"`},
		{`"file": "agent.msi"`, `"file": "../agent.msi"`},
		{`"file": "agent.msi"`, `"file": "c:agent.msi"`},
		{`"file": "agent.msi"`, `"file": "con.msi"`},
		{`"file": "agent.msi"`, `"file": "com1.msi"`},
		{`"file": "agent.msi"`, `"file": "agent.msi."`},
		{`"file": "agent.msi"`, `"file": "agent.msi", "url": "https://example.test/payload"`},
		{`"size": 6`, `"size": 0`},
		{`"size": 6`, `"size": 2147483649`},
		{`"size": 6`, `"size": 6.0`},
		{`"size": 6`, `"size": null`},
		{`"architecture": "amd64"`, `"architecture": "arm64"`},
		{`"os": "windows"`, `"os": "linux"`},
		{`"agent_version": "0.3.5"`, `"agent_version": "0.03.5"`},
		{`"agent_version": "0.3.5"`, `"agent_version": "256.3.5"`},
		{`"protocol_version": 1`, `"protocol_version": 2`},
		{`"management_max": 1`, `"management_max": 0`},
		{`"minimum_agent_version": "0.3.0"`, `"minimum_agent_version": "0.4.0"`},
		{`"upgrade_code": "f72bb43e-dba8-4dbb-a963-b201e6c0d885"`, `"upgrade_code": "12345678-1234-1234-1234-123456789abc"`},
		{`"ROOT\\ExampleIDD"`, `"ROOT\\*"`},
		{`"ROOT\\ExampleIDD"`, `"ROOT\\ExampleIDD", "root\\exampleidd"`},
		{`"target_id": "windows-agent-0.3.4"`, `"target_id": "windows-agent-0.3.5"`},
		{`"reboot_policy": "may-require"`, `"reboot_policy": "always"`},
	} {
		t.Run(test.to, func(t *testing.T) {
			changed := bytes.Replace(raw, []byte(test.from), []byte(test.to), 1)
			if bytes.Equal(changed, raw) {
				t.Fatal("test mutation did not apply")
			}
			if _, err := verifySigned(changed, private); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid publisher-signed schema accepted", err)
			}
		})
	}
	for _, suffix := range []string{`{}`, `null`, `[]`} {
		if _, err := verifySigned(append(append([]byte{}, raw...), []byte(suffix)...), private); !errors.Is(err, ErrInvalid) {
			t.Fatal("trailing value accepted")
		}
	}
}

func TestManifestOptionalDriverAndRequiredPredecessorArray(t *testing.T) {
	raw, private := fixture(t)
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m.Driver = nil
	m.RollbackPredecessors = []Predecessor{}
	b, _ := json.Marshal(m)
	if _, err := verifySigned(b, private); err != nil {
		t.Fatal(err)
	}
	m.RollbackPredecessors = nil
	b, _ = json.Marshal(m)
	if _, err := verifySigned(b, private); !errors.Is(err, ErrInvalid) {
		t.Fatal("null predecessor array accepted")
	}
	duplicatedDriver := bytes.Replace(raw, []byte(`"driver": {`), []byte(`"driver": null, "driver": {`), 1)
	if _, err := verifySigned(duplicatedDriver, private); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate optional driver accepted")
	}
}

func TestManifestRejectsDuplicateRollbackTargetsAndDigests(t *testing.T) {
	raw, private := fixture(t)
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	p := m.RollbackPredecessors[0]
	m.RollbackPredecessors = append(m.RollbackPredecessors, p)
	for _, sameTarget := range []bool{true, false} {
		if sameTarget {
			m.RollbackPredecessors[1].ManifestSHA256 = strings.Repeat("2", 64)
		} else {
			m.RollbackPredecessors[1] = p
			m.RollbackPredecessors[1].TargetID = "another-target"
		}
		b, _ := json.Marshal(m)
		if _, err := verifySigned(b, private); !errors.Is(err, ErrInvalid) {
			t.Fatal("ambiguous predecessor accepted")
		}
	}
}

func FuzzSignedManifest(f *testing.F) {
	raw, err := os.ReadFile("testdata/manifest-v1.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"version":1,"Version":1}`))
	f.Add([]byte(`null`))
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, 32))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxManifestBytes {
			return
		}
		v, err := verifySigned(raw, key)
		if err == nil && (v == nil || v.Metadata().Version != 1 || v.Metadata().OS != "windows" || v.SHA256() != Digest(raw)) {
			t.Fatal("verified manifest violated identity invariants")
		}
	})
}
