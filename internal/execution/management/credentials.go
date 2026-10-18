package management

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"time"

	"github.com/kube-workspaces/api/internal/execution/pki"
)

type credentials struct {
	authority     *pki.Authority
	issuer        *x509.Certificate
	roots         *x509.CertPool
	intermediates *x509.CertPool
	chainPEM      []byte
	rootsPEM      []byte
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, ErrConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, ErrConfiguration
	}
	return data, nil
}

func parseCAChain(data []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for len(bytes.TrimSpace(data)) != 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrConfiguration
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrConfiguration
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, ErrConfiguration
		}
		chain = append(chain, cert)
		if len(chain) > 8 {
			return nil, ErrConfiguration
		}
		data = rest
	}
	if len(chain) == 0 {
		return nil, ErrConfiguration
	}
	return chain, nil
}

func loadCredentials(c Config, now time.Time) (*credentials, error) {
	chainPEM, err := readBoundedFile(c.caCertFile, 128*1024)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readBoundedFile(c.caKeyFile, 16*1024)
	if err != nil {
		return nil, err
	}
	rootsPEM, err := readBoundedFile(c.trustRootsFile, 128*1024)
	if err != nil {
		return nil, err
	}
	chain, err := parseCAChain(chainPEM)
	if err != nil {
		return nil, err
	}
	// Only one unencrypted PKCS#8 key is accepted. No inline/environment key,
	// legacy PEM fallback or automatic CA generation is available.
	trimmed := bytes.TrimSpace(keyPEM)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN PRIVATE KEY-----")) {
		return nil, ErrConfiguration
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrConfiguration
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrConfiguration
	}
	var signer crypto.Signer
	switch key := key.(type) {
	case ed25519.PrivateKey:
		signer = key
	case *ecdsa.PrivateKey:
		if key.Curve != elliptic.P256() {
			return nil, ErrConfiguration
		}
		signer = key
	default:
		return nil, ErrConfiguration
	}
	authority, err := pki.NewAuthority(chain[0].Raw, signer)
	if err != nil {
		return nil, ErrConfiguration
	}
	roots, err := pki.TrustRoots(rootsPEM)
	if err != nil {
		return nil, ErrConfiguration
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	result := &credentials{authority: authority, issuer: chain[0], roots: roots, intermediates: intermediates, chainPEM: append([]byte(nil), chainPEM...), rootsPEM: append([]byte(nil), rootsPEM...)}
	if result.validAt(now, c.LeafLifetime) != nil {
		return nil, ErrConfiguration
	}
	return result, nil
}

func (c *credentials) validAt(now time.Time, lifetime time.Duration) error {
	// Verify current and leaf-expiry time, including all intermediate/root
	// validity and CA constraints. A loaded root must not silently expire while
	// its issuer continues signing longer-lived leaves.
	for _, when := range []time.Time{now, now.Add(lifetime)} {
		for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
			if _, err := c.issuer.Verify(x509.VerifyOptions{Roots: c.roots, Intermediates: c.intermediates, CurrentTime: when, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
				return ErrUnavailable
			}
		}
	}
	return nil
}

func (c *credentials) verifyIssued(der, csrDER []byte, expected pki.Identity, now time.Time) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ErrUnavailable
	}
	i, err := pki.CertificateIdentity(cert)
	if err != nil || i != expected {
		return ErrDenied
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		return ErrDenied
	}
	requested, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return ErrDenied
	}
	issued, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil || !bytes.Equal(requested, issued) {
		return ErrDenied
	}
	intermediates := c.intermediates.Clone()
	intermediates.AddCert(c.issuer)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: c.roots, Intermediates: intermediates, CurrentTime: now, DNSName: pki.ServerName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return ErrDenied
	}
	return nil
}

func (c *credentials) String() string   { return "management CA credentials (private material redacted)" }
func (c *credentials) GoString() string { return c.String() }
