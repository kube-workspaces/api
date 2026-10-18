package pki

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
)

// AuthorizePeer must read current authoritative identity/revocation state. A CA
// signature alone does not authorize a reset/deleted workspace or retired API
// replica. The callback must fail on lookup outages and bound its own deadline.
type AuthorizePeer func(Identity) error

// APIClientFingerprint supplies the local certificate digest bound into an
// issued management grant. The guest derives the same digest from its verified
// TLS peer, rather than trusting a fingerprint supplied in an operation request.
func APIClientFingerprint(cert tls.Certificate) (string, error) {
	i, err := localIdentity(cert)
	if err != nil || i.Role != RoleAPI {
		return "", ErrCertificate
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:]), nil
}

// VerifiedAPIFingerprint is valid only after a successful management handshake.
// It refuses unverified chains, foreign protocols and server-purpose identities.
func VerifiedAPIFingerprint(state tls.ConnectionState) (string, error) {
	if _, err := verifiedPeer(state, RoleAPI); err != nil {
		return "", err
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

func CertificateIdentity(cert *x509.Certificate) (Identity, error) {
	if cert == nil || cert.IsCA || len(cert.URIs) != 1 || len(cert.ExtKeyUsage) != 1 || len(cert.UnknownExtKeyUsage) != 0 || cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 {
		return Identity{}, ErrCertificate
	}
	if !cert.NotAfter.After(cert.NotBefore) || cert.NotAfter.Sub(cert.NotBefore) > MaxLeafLifetime+issuanceBackdate {
		return Identity{}, ErrCertificate
	}
	i, err := parseIdentity(cert.URIs[0])
	if err != nil {
		return Identity{}, err
	}
	if i.Role == RoleGuest {
		if cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(cert.DNSNames) != 1 || cert.DNSNames[0] != ServerName {
			return Identity{}, ErrCertificate
		}
	} else if cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.DNSNames) != 0 {
		return Identity{}, ErrCertificate
	}
	return i, nil
}

func localIdentity(cert tls.Certificate) (Identity, error) {
	if len(cert.Certificate) == 0 || len(cert.Certificate) > 8 {
		return Identity{}, ErrCertificate
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return Identity{}, ErrCertificate
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return Identity{}, ErrCertificate
	}
	a, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return Identity{}, ErrCertificate
	}
	b, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(a, b) {
		return Identity{}, ErrCertificate
	}
	return CertificateIdentity(leaf)
}

func verifiedPeer(state tls.ConnectionState, role string) (Identity, error) {
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != ALPN || state.DidResume || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return Identity{}, ErrCertificate
	}
	i, err := CertificateIdentity(state.PeerCertificates[0])
	if err != nil || i.Role != role {
		return Identity{}, ErrCertificate
	}
	return i, nil
}

// ClientTLS verifies both the CA/DNS chain through Go's built-in TLS verifier
// and the exact enrolled guest URI identity, including provisioning and epoch.
// No InsecureSkipVerify/custom-chain bypass or session-resumption path exists.
func ClientTLS(cert tls.Certificate, roots *x509.CertPool, expected Identity, authorize AuthorizePeer) (*tls.Config, error) {
	local, err := localIdentity(cert)
	if err != nil || local.Role != RoleAPI || expected.validate() != nil || expected.Role != RoleGuest {
		return nil, ErrCertificate
	}
	if roots == nil || len(roots.Subjects()) == 0 {
		return nil, ErrTrust
	}
	if authorize == nil {
		return nil, ErrAuthorization
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: ServerName,
		NextProtos: []string{ALPN},
		RootCAs:    roots.Clone(), Certificates: []tls.Certificate{cert},
		SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			i, err := verifiedPeer(state, RoleGuest)
			if err != nil {
				return err
			}
			if i != expected {
				return ErrIdentity
			}
			if authorize(i) != nil {
				return ErrAuthorization
			}
			return nil
		},
	}, nil
}

// ServerTLS requires a trusted API client certificate and current replica
// authorization. It validates the local certificate against enrolled identity.
func ServerTLS(cert tls.Certificate, roots *x509.CertPool, enrolled Identity, authorize AuthorizePeer) (*tls.Config, error) {
	local, err := localIdentity(cert)
	if err != nil || local.Role != RoleGuest || local != enrolled {
		return nil, ErrCertificate
	}
	if roots == nil || len(roots.Subjects()) == 0 {
		return nil, ErrTrust
	}
	if authorize == nil {
		return nil, ErrAuthorization
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{ALPN},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots.Clone(),
		Certificates: []tls.Certificate{cert}, SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			i, err := verifiedPeer(state, RoleAPI)
			if err != nil {
				return err
			}
			if authorize(i) != nil {
				return ErrAuthorization
			}
			return nil
		},
	}, nil
}
