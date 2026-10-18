// Package enrollment implements one-use, CSR-bound management bootstrap issuance.
// It is not wired to an HTTP route or controller staging yet.
package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/kube-workspaces/api/internal/execution/pki"
	"github.com/kube-workspaces/api/internal/execution/storage"
)

const MaxBootstrapLifetime = 15 * time.Minute

var (
	ErrDenied      = errors.New("management enrollment denied")
	ErrUnavailable = errors.New("management enrollment unavailable")
)

// CurrentIdentity must fetch authoritative workspace existence/UID/provisioning
// generation/epoch and policy. It must reject any mismatch or lookup outage.
type CurrentIdentity func(context.Context, pki.Identity) error

type Service struct {
	store        storage.EnrollmentStore
	issuer       *pki.Authority
	current      CurrentIdentity
	leafLifetime time.Duration
	now          func() time.Time
}

func New(store storage.EnrollmentStore, issuer *pki.Authority, current CurrentIdentity, leafLifetime time.Duration) (*Service, error) {
	if store == nil || issuer == nil || current == nil || leafLifetime < time.Minute || leafLifetime > pki.MaxLeafLifetime {
		return nil, ErrUnavailable
	}
	return &Service{store: store, issuer: issuer, current: current, leafLifetime: leafLifetime, now: time.Now}, nil
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Mint is an internal provisioning operation, not end-user delegation. Only the
// returned token is staged through a trusted per-clone channel; the database
// keeps its hash. The caller must never log the raw return value.
func (s *Service) Mint(ctx context.Context, identity pki.Identity, lifetime time.Duration) (string, error) {
	if identity.Role != pki.RoleGuest || lifetime < time.Second || lifetime > MaxBootstrapLifetime {
		return "", ErrDenied
	}
	if _, err := identity.URI(); err != nil {
		return "", ErrDenied
	}
	if err := s.current(ctx, identity); err != nil {
		return "", ErrDenied
	}
	if err := s.store.Ready(ctx); err != nil {
		return "", ErrUnavailable
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrUnavailable
	}
	c := storage.EnrollmentCredential{TokenHash: digest(raw[:]), Namespace: identity.Namespace, WorkspaceName: identity.WorkspaceName, WorkspaceUID: identity.WorkspaceUID, Generation: identity.Generation, RevocationEpoch: identity.RevocationEpoch, ExpiresAt: s.now().Add(lifetime)}
	if err := s.store.Create(ctx, c); err != nil {
		return "", ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func identity(c storage.EnrollmentCredential) pki.Identity {
	return pki.Identity{Role: pki.RoleGuest, Namespace: c.Namespace, WorkspaceName: c.WorkspaceName, WorkspaceUID: c.WorkspaceUID, Generation: c.Generation, RevocationEpoch: c.RevocationEpoch}
}

// Enroll returns only the single persisted certificate for the exact same CSR.
// Another key/CSR cannot redeem the token, including from another API replica.
// Both initial issuance and retries require unexpired bootstrap and current
// workspace identity; a reset while issuance commits is checked again before
// returning, and subsequent TLS authorization independently fences stale leaves.
func (s *Service) Enroll(ctx context.Context, token string, csrDER []byte) ([]byte, error) {
	if len(token) != 43 || len(csrDER) == 0 || len(csrDER) > 16*1024 {
		return nil, ErrDenied
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return nil, ErrDenied
	}
	if err := s.store.Ready(ctx); err != nil {
		return nil, ErrUnavailable
	}
	c, err := s.store.Get(ctx, digest(raw))
	if errors.Is(err, storage.ErrNotFound) {
		return nil, ErrDenied
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	if !s.now().Before(c.ExpiresAt) {
		return nil, ErrDenied
	}
	i := identity(c)
	if err := s.current(ctx, i); err != nil {
		return nil, ErrDenied
	}
	csrHash := digest(csrDER)
	if c.CSRHash != "" && c.CSRHash != csrHash {
		return nil, ErrDenied
	}
	candidate := c.CertificateDER
	if c.CSRHash == "" {
		candidate, err = s.issuer.Issue(csrDER, i, s.now(), s.leafLifetime)
		if err != nil {
			return nil, ErrDenied
		}
	}
	result, err := s.store.Redeem(ctx, c.TokenHash, csrHash, candidate, s.now())
	if errors.Is(err, storage.ErrConflict) || errors.Is(err, storage.ErrNotFound) {
		return nil, ErrDenied
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	if err := s.current(ctx, i); err != nil {
		return nil, ErrDenied
	}
	cert, err := x509.ParseCertificate(result)
	if err != nil {
		return nil, ErrUnavailable
	}
	actual, err := pki.CertificateIdentity(cert)
	if err != nil || actual != i {
		return nil, ErrUnavailable
	}
	now := s.now()
	if !now.Before(c.ExpiresAt) || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, ErrDenied
	}
	return result, nil
}
