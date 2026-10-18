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

//go:embed testdata/management-qga-v1.json
var qgaInteroperabilityVector []byte

// QGATestVector regenerates the pinned Go→Rust interoperability fixture. The
// same public seed and request bytes are pinned in workspace-agent's
// kw-management fixtures; both sides must accept this exact grant.
func qgaVector(t *testing.T) map[string]interface{} {
	t.Helper()
	// Public test-only seed. Never load this key in a running installation.
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	target := "namespace/VM-UID/POD-UID"
	request := []byte(`{"version":1,"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","transport_target_sha256":"` + Digest([]byte(target)) + `","actor_uid":"user-1","namespace":"team-a","workspace_name":"vm-1","workspace_uid":"11111111-1111-4111-8111-111111111111","provisioning_generation":"22222222-2222-4222-8222-222222222222","execution_id":"exec-1","recording_id":"rec-1","operation":"command","os_identity":"SYSTEM","elevated":true,"policy_version":"1","revocation_epoch":0,"executable":"C:\\\\Windows\\\\System32\\\\cmd.exe","args":["/c","echo hi"],"cwd":null,"deadline_seconds":20}`)
	b := BindingQGA{
		ActorUID:               "user-1",
		Namespace:              "team-a",
		WorkspaceName:          "vm-1",
		WorkspaceUID:           "11111111-1111-4111-8111-111111111111",
		ProvisioningGeneration: "22222222-2222-4222-8222-222222222222",
		ExecutionID:            "exec-1",
		RecordingID:            "rec-1",
		Operation:              "command",
		OSIdentity:             "SYSTEM",
		Elevated:               true,
		PolicyVersion:          "1",
		RevocationEpoch:        0,
		Challenge:              base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Transport:              TransportQGAPodExec,
		TransportTargetSHA256:  Digest([]byte(target)),
		RequestSHA256:          Digest(request),
	}
	c := ClaimsQGA{Version: 1, Issuer: QGAIssuer, Audience: QGAAudience, ID: b.Challenge, IssuedAt: 1800000000, ExpiresAt: 1800000030, Binding: b}
	h, _ := json.Marshal(header{Algorithm: "EdDSA", Type: qgaGrantType, KeyID: KeyID(key.Public().(ed25519.PublicKey))})
	p, _ := json.Marshal(c)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	token := input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(input)))
	requestB64 := base64.RawURLEncoding.EncodeToString(request)
	return map[string]interface{}{
		"public_key":       base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		"now":              c.IssuedAt,
		"request_b64url":   requestB64,
		"transport_target": target,
		"binding":          b,
		"token":            token,
	}
}

func TestQGAInteropVector(t *testing.T) {
	vector := qgaVector(t)
	raw, _ := json.Marshal(vector)
	if !bytes.Equal(bytes.TrimSpace(qgaInteroperabilityVector), raw) {
		t.Fatal("management-qga-v1 interoperability vector drift")
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	v, err := NewVerifier(map[string]ed25519.PublicKey{KeyID(key.Public().(ed25519.PublicKey)): key.Public().(ed25519.PublicKey)}, 1)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := v.ConsumeQGA(vector["token"].(string), vector["binding"].(BindingQGA), time.Unix(1800000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Binding.Operation != "command" || claims.Binding.Transport != TransportQGAPodExec {
		t.Fatalf("unexpected claims: %+v", claims.Binding)
	}
	if _, err := v.ConsumeQGA(vector["token"].(string), vector["binding"].(BindingQGA), time.Unix(1800000000, 0)); err != ErrReplay {
		t.Fatalf("expected replay denial, got %v", err)
	}
}
