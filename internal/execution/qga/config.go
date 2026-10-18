// Package qga implements the server side of the approved QGA pod-exec pilot
// transport (`qga-pod-exec/v1`): a Kubernetes-authenticated pod exec into the
// current KubeVirt virt-launcher, driving the fixed installed runner through
// the QEMU guest agent. It is an explicit opt-in backend for the Windows
// command-only pilot and is never a fallback from a failed mTLS management
// connection; the dedicated mTLS management transport remains the follow-up.
//
// Trust shape: the API signs one short-lived, single-use Ed25519 grant bound to
// the fresh request bytes, actor/workspace/provisioning-generation identity and
// a digest of the server-resolved launcher target. Sensitive grant and request
// bytes travel only over pod-exec stdin through a fixed wrapper, never as
// pod-exec URL arguments. The guest independently verifies the grant, its own
// enrolled workspace UID and the request bounds before creating any process,
// and reports one bounded JSON result the API treats as authoritative; loss of
// that result is an unknown outcome, never success.
package qga

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kube-workspaces/api/internal/execution/grants"
)

// Environment configuration for the opt-in pilot transport.
const (
	EnvEnabled  = "KW_EXECUTION_QGA_ENABLED"
	EnvKeyFile  = "KW_MANAGEMENT_GRANT_KEY_FILE"
	maxKeyBytes = 16 * 1024
)

// ErrConfiguration reports unusable opt-in pilot configuration. It is never
// logged with private material.
var ErrConfiguration = errors.New("QGA pilot transport configuration is invalid")

// Config is the validated opt-in pilot configuration.
type Config struct {
	Enabled bool
	KeyFile string
}

// ConfigFromEnv reads the explicit opt-in flag and signing-key location. The
// transport is disabled unless explicitly enabled, and enabling without a
// key file is a startup error rather than a silent downgrade.
func ConfigFromEnv() (Config, error) {
	cfg := Config{KeyFile: strings.TrimSpace(os.Getenv(EnvKeyFile))}
	switch strings.TrimSpace(os.Getenv(EnvEnabled)) {
	case "", "0", "false", "no":
	case "1", "true", "yes":
		cfg.Enabled = true
	default:
		return Config{}, fmt.Errorf("%w: %s must be a boolean", ErrConfiguration, EnvEnabled)
	}
	if cfg.Enabled && cfg.KeyFile == "" {
		return Config{}, fmt.Errorf("%w: %s is required when %s is enabled", ErrConfiguration, EnvKeyFile, EnvEnabled)
	}
	return cfg, nil
}

// LoadSigner reads exactly one unencrypted PKCS#8 Ed25519 private key, either
// PEM ("BEGIN PRIVATE KEY") or raw 64-byte DER, from a bounded regular file.
// No inline/environment key or automatic generation is available.
func LoadSigner(path string) (*grants.Signer, error) {
	data, err := readBoundedFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	var der []byte
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		block, rest := pem.Decode(trimmed)
		if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("%w: %s is not a single unencrypted PKCS#8 PEM block", ErrConfiguration, EnvKeyFile)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: PKCS#8 key is unreadable", ErrConfiguration)
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: only Ed25519 keys are supported", ErrConfiguration)
		}
		der = key
	} else {
		if len(trimmed) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: raw key must be exactly %d bytes", ErrConfiguration, ed25519.PrivateKeySize)
		}
		der = trimmed
	}
	signer, err := grants.NewSigner(ed25519.PrivateKey(der))
	if err != nil {
		return nil, fmt.Errorf("%w: Ed25519 key is invalid", ErrConfiguration)
	}
	return signer, nil
}

func readBoundedFile(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrConfiguration, EnvKeyFile)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: key file is unreadable", ErrConfiguration)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxKeyBytes {
		return nil, fmt.Errorf("%w: key file must be a regular file of at most %d bytes", ErrConfiguration, maxKeyBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxKeyBytes+1))
	if err != nil || len(data) > maxKeyBytes || len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("%w: key file is empty or oversized", ErrConfiguration)
	}
	return data, nil
}
