package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/url"
	"time"
)

const (
	MaxLeafLifetime  = time.Hour
	issuanceBackdate = 30 * time.Second
)

// Authority uses a separately provisioned management CA; it never auto-generates
// production roots and never accepts desktop/session secrets as CA credentials.
type Authority struct {
	certificate *x509.Certificate
	signer      crypto.Signer
}

func (a *Authority) String() string   { return "management CA authority (private signer redacted)" }
func (a *Authority) GoString() string { return a.String() }

func NewAuthority(caDER []byte, signer crypto.Signer) (*Authority, error) {
	cert, err := x509.ParseCertificate(caDER)
	if err != nil || signer == nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, ErrCertificate
	}
	a, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, ErrCertificate
	}
	b, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(a, b) {
		return nil, ErrCertificate
	}
	return &Authority{certificate: cert, signer: signer}, nil
}

// Issue signs an independently authorized identity after CSR proof of possession.
// The caller must validate/reserve a one-use enrollment credential and current
// workspace incarnation before calling, and persist the issued result for retry.
// No private guest key is received or generated here. CSR identity/extensions
// are rejected rather than copied into the certificate.
func (a *Authority) Issue(csrDER []byte, identity Identity, now time.Time, lifetime time.Duration) ([]byte, error) {
	uri, err := identity.URI()
	if err != nil {
		return nil, err
	}
	if len(csrDER) == 0 || len(csrDER) > 16*1024 || lifetime < time.Minute || lifetime > MaxLeafLifetime {
		return nil, ErrCertificate
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil || len(csr.Subject.Names) != 0 || len(csr.Extensions) != 0 || len(csr.DNSNames) != 0 || len(csr.URIs) != 0 || len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 {
		return nil, ErrCertificate
	}
	switch key := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return nil, ErrCertificate
		}
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return nil, ErrCertificate
		}
	default:
		return nil, ErrCertificate
	}
	// A leaf must not reuse the CA key, even if that CSR proves possession.
	leafKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, ErrCertificate
	}
	caKey, _ := x509.MarshalPKIXPublicKey(a.certificate.PublicKey)
	if bytes.Equal(leafKey, caKey) {
		return nil, ErrCertificate
	}
	if now.Before(a.certificate.NotBefore) || !now.Before(a.certificate.NotAfter) || now.Add(lifetime).After(a.certificate.NotAfter) {
		return nil, ErrCertificate
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, ErrCertificate
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	start := now.Add(-issuanceBackdate)
	if start.Before(a.certificate.NotBefore) {
		start = a.certificate.NotBefore
	}
	leaf := &x509.Certificate{SerialNumber: serial, NotBefore: start, NotAfter: now.Add(lifetime), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, URIs: []*url.URL{uri}}
	if identity.Role == RoleGuest {
		leaf.DNSNames = []string{ServerName}
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, a.certificate, csr.PublicKey, a.signer)
	if err != nil {
		return nil, ErrCertificate
	}
	return der, nil
}

// TrustRoots accepts only an explicit, bounded management CA bundle. It never
// falls back to machine/web PKI roots. Both old and new roots may overlap during
// an operator-coordinated trust rotation.
func TrustRoots(bundle []byte) (*x509.CertPool, error) {
	if len(bundle) == 0 || len(bundle) > 128*1024 {
		return nil, ErrTrust
	}
	roots := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(bundle)) != 0 {
		bundle = bytes.TrimSpace(bundle)
		if !bytes.HasPrefix(bundle, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrTrust
		}
		block, rest := pem.Decode(bundle)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrTrust
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, ErrTrust
		}
		count++
		if count > 16 {
			return nil, ErrTrust
		}
		roots.AddCert(cert)
		bundle = rest
	}
	if count == 0 {
		return nil, ErrTrust
	}
	return roots, nil
}
