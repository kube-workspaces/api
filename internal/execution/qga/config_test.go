package qga

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/kube-workspaces/api/internal/execution/grants"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(EnvEnabled, "")
	t.Setenv(EnvKeyFile, "")
	cfg, err := ConfigFromEnv()
	if err != nil || cfg.Enabled || cfg.KeyFile != "" {
		t.Fatalf("expected a disabled config by default, got %+v, %v", cfg, err)
	}
	t.Setenv(EnvEnabled, "true")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("expected an error when enabled without a key file")
	}
	t.Setenv(EnvKeyFile, "/keys/grant.pem")
	cfg, err = ConfigFromEnv()
	if err != nil || !cfg.Enabled || cfg.KeyFile != "/keys/grant.pem" {
		t.Fatalf("expected an enabled config, got %+v, %v", cfg, err)
	}
	t.Setenv(EnvEnabled, "sometimes")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("expected an error for a non-boolean opt-in value")
	}
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSignerAcceptsPKCS8PEMAndRawDER(t *testing.T) {
	seed := make([]byte, 32)
	key := ed25519.NewKeyFromSeed(seed)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemPath := writeFile(t, "key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	signer, err := LoadSigner(pemPath)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.PublicKey().Equal(key.Public().(ed25519.PublicKey)) || signer.KeyID() != grants.KeyID(key.Public().(ed25519.PublicKey)) {
		t.Fatal("loaded signer does not match the source key")
	}
	rawPath := writeFile(t, "key.der", key)
	signer, err = LoadSigner(rawPath)
	if err != nil || !signer.PublicKey().Equal(key.Public().(ed25519.PublicKey)) {
		t.Fatalf("raw DER key was not accepted: %v", err)
	}
}

func TestLoadSignerRejectsUnusableKeys(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"two-pem-blocks":    append(append([]byte{}, pemBlock...), pemBlock...),
		"encrypted-pem":     pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}),
		"non-ed25519":       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}),
		"raw-short":         key[:63],
		"raw-oversized":     append(append([]byte{}, key...), 0),
		"empty":             {},
		"encrypted-headers": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: der}),
	} {
		if _, err := LoadSigner(writeFile(t, "key", data)); err == nil {
			t.Fatalf("%s: expected a configuration error", name)
		}
	}
	if _, err := LoadSigner(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected an error for a missing key file")
	}
	if _, err := LoadSigner(""); err == nil {
		t.Fatal("expected an error for an empty path")
	}
}
