package grants

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func qgaTestBinding() BindingQGA {
	return BindingQGA{
		ActorUID:               "actor",
		Namespace:              "team",
		WorkspaceName:          "vm",
		WorkspaceUID:           "uid",
		ProvisioningGeneration: "gen",
		ExecutionID:            "exec",
		RecordingID:            "rec",
		Operation:              "command",
		OSIdentity:             "SYSTEM",
		Elevated:               true,
		PolicyVersion:          "1",
		Challenge:              base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Transport:              TransportQGAPodExec,
		TransportTargetSHA256:  Digest([]byte("target")),
		RequestSHA256:          Digest([]byte("request")),
	}
}

func qgaSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner(ed25519.NewKeyFromSeed(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestQGABindingValidation(t *testing.T) {
	base := qgaTestBinding()
	if err := base.validate(); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}
	cases := map[string]func(*BindingQGA){
		"unknown operation":       func(b *BindingQGA) { b.Operation = "unknown" },
		"shell operation":         func(b *BindingQGA) { b.Operation = "shell" },
		"foreign transport":       func(b *BindingQGA) { b.Transport = "mtls/v1" },
		"ordinary os identity":    func(b *BindingQGA) { b.OSIdentity = "workspace" },
		"root without elevated":   func(b *BindingQGA) { b.OSIdentity = "root"; b.Elevated = false },
		"system without elevated": func(b *BindingQGA) { b.Elevated = false },
		"bad target digest":       func(b *BindingQGA) { b.TransportTargetSHA256 = "xyz" },
		"bad challenge":           func(b *BindingQGA) { b.Challenge = "short" },
	}
	for name, mutate := range cases {
		b := base
		mutate(&b)
		if err := b.validate(); err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
}

func TestQGAIssueAndConsumeLifecycle(t *testing.T) {
	signer := qgaSigner(t)
	binding := qgaTestBinding()
	now := time.Unix(1800000000, 0)
	token, err := signer.IssueQGA(binding, now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	key := signer.private.Public().(ed25519.PublicKey)
	verifier, err := NewVerifier(map[string]ed25519.PublicKey{KeyID(key): key}, 2)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.ConsumeQGA(token, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Audience != QGAAudience || claims.Issuer != QGAIssuer {
		t.Fatalf("unexpected claims envelope: %+v", claims)
	}
	if _, err := verifier.ConsumeQGA(token, binding, now); err != ErrReplay {
		t.Fatalf("expected replay denial, got %v", err)
	}
	// A mTLS-grant verifier must not accept a QGA token type.
	var mtlsBinding Binding
	mtlsBinding.ActorUID = "actor"
	mtlsBinding.Namespace = "team"
	mtlsBinding.WorkspaceName = "vm"
	mtlsBinding.WorkspaceUID = "uid"
	mtlsBinding.ProvisioningGeneration = "gen"
	mtlsBinding.ExecutionID = "exec"
	mtlsBinding.RecordingID = "rec"
	mtlsBinding.Operation = "command"
	mtlsBinding.OSIdentity = "workspace"
	mtlsBinding.PolicyVersion = "1"
	mtlsBinding.Challenge = binding.Challenge
	mtlsBinding.PeerCertificateSHA256 = Digest([]byte("peer"))
	mtlsBinding.RequestSHA256 = Digest([]byte("request"))
	if _, err := verifier.Consume(token, mtlsBinding, now); err == nil {
		t.Fatal("mTLS verifier accepted a QGA grant")
	}
}

func TestQGADenies(t *testing.T) {
	signer := qgaSigner(t)
	binding := qgaTestBinding()
	now := time.Unix(1800000000, 0)
	token, err := signer.IssueQGA(binding, now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	key := signer.private.Public().(ed25519.PublicKey)
	verifier, _ := NewVerifier(map[string]ed25519.PublicKey{KeyID(key): key}, 2)

	other := binding
	other.RequestSHA256 = Digest([]byte("other request"))
	if _, err := verifier.ConsumeQGA(token, other, now); err != ErrBinding {
		t.Fatalf("expected binding denial, got %v", err)
	}
	other = binding
	other.TransportTargetSHA256 = Digest([]byte("other target"))
	if _, err := verifier.ConsumeQGA(token, other, now); err != ErrBinding {
		t.Fatalf("expected target denial, got %v", err)
	}
	other = binding
	other.WorkspaceUID = "other-uid"
	if _, err := verifier.ConsumeQGA(token, other, now); err != ErrBinding {
		t.Fatalf("expected workspace denial, got %v", err)
	}
	if _, err := verifier.ConsumeQGA(token, binding, now.Add(-time.Second)); err != ErrExpired {
		t.Fatalf("expected future-issuance denial, got %v", err)
	}
	if _, err := verifier.ConsumeQGA(token, binding, now.Add(30*time.Second)); err != ErrExpired {
		t.Fatalf("expected expiry denial, got %v", err)
	}
	if _, err := signer.IssueQGA(binding, now, 61*time.Second); err == nil {
		t.Fatal("expected over-long lifetime rejection")
	}
	// A foreign-signer token must fail signature verification.
	var seed [32]byte
	for i := range seed {
		seed[i] = 1
	}
	foreign, err := NewSigner(ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	foreignToken, err := foreign.IssueQGA(binding, now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.ConsumeQGA(foreignToken, binding, now); err == nil {
		t.Fatal("expected foreign-signer denial")
	}
}
