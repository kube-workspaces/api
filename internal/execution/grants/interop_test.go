package grants

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

//go:embed testdata/management-v1.json
var interoperabilityVector []byte

func TestInteropVector(t *testing.T) {
	// Public test-only seed. Never load this key in a running installation.
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	b := Binding{ActorUID: "actor", Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "uid", ProvisioningGeneration: "1", ExecutionID: "exec", RecordingID: "rec", Operation: "shell", OSIdentity: "workspace", PolicyVersion: "1", RevocationEpoch: 4, Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), PeerCertificateSHA256: Digest([]byte("peer")), RequestSHA256: Digest([]byte("request"))}
	c := Claims{Version: 1, Issuer: Issuer, Audience: Audience, ID: b.Challenge, IssuedAt: 1800000000, ExpiresAt: 1800000030, Binding: b}
	h, _ := json.Marshal(header{Algorithm: "EdDSA", Type: grantType, KeyID: KeyID(key.Public().(ed25519.PublicKey))})
	p, _ := json.Marshal(c)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	token := input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(input)))
	vector, _ := json.Marshal(map[string]interface{}{"public_key": base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), "now": c.IssuedAt, "binding": b, "token": token})
	if !bytes.Equal(bytes.TrimSpace(interoperabilityVector), vector) {
		t.Fatal("management-v1 interoperability vector drift")
	}
	v, err := NewVerifier(map[string]ed25519.PublicKey{KeyID(key.Public().(ed25519.PublicKey)): key.Public().(ed25519.PublicKey)}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Consume(token, b, time.Unix(c.IssuedAt, 0)); err != nil {
		t.Fatal(err)
	}
}
