package enrollment

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/execution/pki"
	"github.com/kube-workspaces/api/internal/execution/storage"
)

// Opt-in Linux file-key ↔ Go one-use enrollment proof. No live identity, token or
// credentials are loaded. The Rust helper returns only a public CSR, never a key.
func TestRustMachineKeyEnrollmentInterop(t *testing.T) {
	probe := os.Getenv("KW_MANAGEMENT_RUST_KEY_PROBE")
	if probe == "" {
		t.Skip("set KW_MANAGEMENT_RUST_KEY_PROBE to the built Rust key_probe test executable")
	}
	if runtime.GOOS != "linux" {
		t.Skip("protected machine-key storage currently supports Linux only")
	}
	if !filepath.IsAbs(probe) {
		t.Fatal("select an absolute trusted Rust key-probe executable")
	}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	_, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic enrollment root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := pki.NewAuthority(rootDER, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := storage.NewMemoryEnrollment(16)
	if err != nil {
		t.Fatal(err)
	}
	expected := pki.Identity{Role: pki.RoleGuest, Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "uid", Generation: "gen-1", RevocationEpoch: 4}
	current := expected
	service, err := New(ledger, issuer, func(_ context.Context, i pki.Identity) error {
		if i != current {
			return ErrDenied
		}
		return nil
	}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := service.Mint(ctx, expected, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		Event    string `json:"event"`
		OK       bool   `json:"ok"`
		CSR      []byte `json:"csr"`
		TLSReady bool   `json:"tls_ready"`
	}
	invoke := func(path string, identity pki.Identity, create bool, certificates [][]byte) result {
		t.Helper()
		if certificates == nil {
			certificates = [][]byte{}
		}
		uri, err := identity.URI()
		if err != nil {
			t.Fatal(err)
		}
		input, err := json.Marshal(struct {
			Root         string   `json:"root"`
			Identity     string   `json:"identity"`
			Create       bool     `json:"create"`
			Roots        [][]byte `json:"roots"`
			Certificates [][]byte `json:"certificates"`
		}{path, uri.String(), create, [][]byte{rootDER}, certificates})
		if err != nil {
			t.Fatal(err)
		}
		deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(deadline, probe, "--exact", "rust_key_probe_child", "--ignored", "--nocapture", "--format", "terse")
		cmd.Env = append(os.Environ(), "KW_MANAGEMENT_KEY_PROBE=1")
		cmd.Stdin = bytes.NewReader(input)
		cmd.Stderr = io.Discard
		output, err := cmd.Output()
		if err != nil {
			t.Fatal("Rust key probe failed; private diagnostics withheld")
		}
		scanner := bufio.NewScanner(bytes.NewReader(output))
		count := 0
		var response result
		for scanner.Scan() {
			line := scanner.Text()
			start := strings.IndexByte(line, '{')
			if start < 0 {
				continue
			}
			decoder := json.NewDecoder(strings.NewReader(line[start:]))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&response) != nil || response.Event != "result" {
				t.Fatal("Rust key probe returned unexpected fields")
			}
			count++
		}
		if scanner.Err() != nil || count != 1 {
			t.Fatal("missing or duplicate public key-probe result")
		}
		return response
	}
	path := filepath.Join(t.TempDir(), "machine-key")
	first := invoke(path, expected, true, nil)
	if !first.OK || len(first.CSR) == 0 || first.TLSReady {
		t.Fatal("Rust key was not durably initialized")
	}
	request, err := x509.ParseCertificateRequest(first.CSR)
	if err != nil || request.CheckSignature() != nil || request.PublicKeyAlgorithm != x509.Ed25519 || len(request.Subject.Names) != 0 || len(request.Attributes) != 0 || len(request.Extensions) != 0 || len(request.URIs) != 0 {
		t.Fatal("Rust CSR contains invalid proof or requested identity/extensions")
	}
	certificate, err := service.EnrollBound(ctx, expected, token, first.CSR)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := pki.CertificateIdentity(leaf)
	if err != nil || identity != expected {
		t.Fatal("issued certificate did not use authoritative scope")
	}
	// A new process loads the opaque private key directly into TLS state. Exact
	// CSR retries return the committed certificate, not another key or issuance.
	reopened := invoke(path, expected, false, [][]byte{certificate})
	if !reopened.OK || !reopened.TLSReady || !bytes.Equal(reopened.CSR, first.CSR) {
		t.Fatal("reopen rotated the key/CSR or TLS rejected its matching certificate")
	}
	retry, err := service.EnrollBound(ctx, expected, token, reopened.CSR)
	if err != nil || !bytes.Equal(retry, certificate) {
		t.Fatal("same-CSR enrollment retry did not preserve the certificate")
	}
	competitor := invoke(filepath.Join(t.TempDir(), "other-key"), expected, true, nil)
	if !competitor.OK || bytes.Equal(competitor.CSR, first.CSR) {
		t.Fatal("independent guest key was not distinct")
	}
	if _, err := service.EnrollBound(ctx, expected, token, competitor.CSR); !errors.Is(err, ErrDenied) {
		t.Fatal("used bootstrap token accepted another guest key")
	}
	otherCertificate, err := issuer.Issue(competitor.CSR, expected, now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if response := invoke(path, expected, false, [][]byte{otherCertificate}); response.OK || len(response.CSR) != 0 {
		t.Fatal("machine key accepted a certificate for a different private key")
	}
	// Failed public certificate input does not rotate or damage the immutable key.
	if response := invoke(path, expected, false, [][]byte{certificate}); !response.OK || !response.TLSReady || !bytes.Equal(response.CSR, first.CSR) {
		t.Fatal("bad certificate input changed the stored key")
	}
	changed := expected
	changed.Generation = "gen-2"
	if response := invoke(path, changed, false, nil); response.OK || len(response.CSR) != 0 {
		t.Fatal("old guest key was rebound to a new provisioning identity")
	}
	current = changed
	if _, err := service.EnrollBound(ctx, expected, token, first.CSR); !errors.Is(err, ErrDenied) {
		t.Fatal("current-identity change did not fence enrollment retry")
	}
}
