package storage

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// EnrollmentCredential stores no raw bootstrap token or guest private key.
// CertificateDER is the single committed result of redeeming this credential.
type EnrollmentCredential struct {
	TokenHash       string
	Namespace       string
	WorkspaceName   string
	WorkspaceUID    string
	Generation      string
	RevocationEpoch uint64
	ExpiresAt       time.Time
	CSRHash         string
	CertificateDER  []byte
}

// EnrollmentStore atomically binds a bootstrap token to its first CSR. A retry
// for that exact CSR returns the original certificate bytes; a different CSR
// cannot claim another identity. Time must come from the trusted service clock.
type EnrollmentStore interface {
	Create(ctx context.Context, credential EnrollmentCredential) error
	Get(ctx context.Context, tokenHash string) (EnrollmentCredential, error)
	Redeem(ctx context.Context, tokenHash, csrHash string, certificateDER []byte, now time.Time) ([]byte, error)
	Ready(ctx context.Context) error
	Close() error
}

func validHash(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == value
}

func validCredential(c EnrollmentCredential) bool {
	return validHash(c.TokenHash) && c.Namespace != "" && c.WorkspaceName != "" && c.WorkspaceUID != "" && c.Generation != "" && !c.ExpiresAt.IsZero() && c.CSRHash == "" && len(c.CertificateDER) == 0
}

// NewMemoryEnrollment is explicitly process-local and bounded. It is useful for
// tests/ephemeral control state only; persistent or multi-replica issuance must
// use a shared ledger. It never evicts a live credential to admit another.
func NewMemoryEnrollment(capacity int) (EnrollmentStore, error) {
	if capacity < 1 || capacity > 65536 {
		return nil, ErrOverCapacity
	}
	return &memoryEnrollment{records: make(map[string]EnrollmentCredential), capacity: capacity}, nil
}

type memoryEnrollment struct {
	mu       sync.Mutex
	records  map[string]EnrollmentCredential
	capacity int
}

func (m *memoryEnrollment) Create(ctx context.Context, c EnrollmentCredential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validCredential(c) {
		return ErrConflict
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.records[c.TokenHash]; exists {
		return ErrConflict
	}
	if len(m.records) >= m.capacity {
		return ErrOverCapacity
	}
	m.records[c.TokenHash] = c
	return nil
}

func (m *memoryEnrollment) Get(ctx context.Context, hash string) (EnrollmentCredential, error) {
	if err := ctx.Err(); err != nil {
		return EnrollmentCredential{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, exists := m.records[hash]
	if !exists {
		return EnrollmentCredential{}, ErrNotFound
	}
	c.CertificateDER = append([]byte(nil), c.CertificateDER...)
	return c, nil
}

func (m *memoryEnrollment) Redeem(ctx context.Context, hash, csrHash string, cert []byte, now time.Time) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validHash(csrHash) || len(cert) == 0 || len(cert) > 16*1024 {
		return nil, ErrConflict
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, exists := m.records[hash]
	if !exists {
		return nil, ErrNotFound
	}
	if !now.Before(c.ExpiresAt) {
		return nil, ErrConflict
	}
	if c.CSRHash != "" && c.CSRHash != csrHash {
		return nil, ErrConflict
	}
	if c.CSRHash == "" {
		c.CSRHash = csrHash
		c.CertificateDER = append([]byte(nil), cert...)
		m.records[hash] = c
	}
	return append([]byte(nil), c.CertificateDER...), nil
}

func (m *memoryEnrollment) Ready(ctx context.Context) error { return ctx.Err() }
func (m *memoryEnrollment) Close() error                    { return nil }

type postgresEnrollment struct{ metadata *postgresMetadata }

// NewPostgresEnrollment opens the shared issuance ledger and applies the same
// embedded schema migrations as execution storage. It never falls back to RAM.
func NewPostgresEnrollment(ctx context.Context, databaseURL string) (EnrollmentStore, error) {
	m, err := NewPostgresMetadata(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	return &postgresEnrollment{metadata: m.(*postgresMetadata)}, nil
}

func (p *postgresEnrollment) Create(ctx context.Context, c EnrollmentCredential) error {
	if !validCredential(c) {
		return ErrConflict
	}
	tag, err := p.metadata.pool.Exec(ctx, `INSERT INTO execution_enrollment
		(token_hash, namespace, workspace_name, workspace_uid, generation, revocation_epoch, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6::text::numeric,$7) ON CONFLICT (token_hash) DO NOTHING`, c.TokenHash, c.Namespace, c.WorkspaceName, c.WorkspaceUID, c.Generation, strconv.FormatUint(c.RevocationEpoch, 10), c.ExpiresAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func (p *postgresEnrollment) Get(ctx context.Context, hash string) (EnrollmentCredential, error) {
	var c EnrollmentCredential
	var epoch string
	err := p.metadata.pool.QueryRow(ctx, `SELECT token_hash, namespace, workspace_name, workspace_uid, generation, revocation_epoch::text, expires_at, COALESCE(csr_hash,''), certificate_der FROM execution_enrollment WHERE token_hash=$1`, hash).Scan(&c.TokenHash, &c.Namespace, &c.WorkspaceName, &c.WorkspaceUID, &c.Generation, &epoch, &c.ExpiresAt, &c.CSRHash, &c.CertificateDER)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	if err == nil {
		c.RevocationEpoch, err = strconv.ParseUint(epoch, 10, 64)
	}
	return c, err
}

func (p *postgresEnrollment) Redeem(ctx context.Context, hash, csrHash string, cert []byte, now time.Time) ([]byte, error) {
	if !validHash(csrHash) || len(cert) == 0 || len(cert) > 16*1024 {
		return nil, ErrConflict
	}
	var result []byte
	err := p.metadata.pool.QueryRow(ctx, `UPDATE execution_enrollment SET csr_hash=$2, certificate_der=$3
		WHERE token_hash=$1 AND expires_at>$4 AND csr_hash IS NULL RETURNING certificate_der`, hash, csrHash, cert, now).Scan(&result)
	if err == nil {
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	// A competing replica may have committed the same CSR. Return that exact
	// result, never this caller's newly generated candidate certificate.
	c, err := p.Get(ctx, hash)
	if err != nil {
		return nil, err
	}
	if !now.Before(c.ExpiresAt) || c.CSRHash != csrHash || len(c.CertificateDER) == 0 {
		return nil, ErrConflict
	}
	return c.CertificateDER, nil
}

func (p *postgresEnrollment) Ready(ctx context.Context) error { return p.metadata.Ready(ctx) }
func (p *postgresEnrollment) Close() error                    { return p.metadata.Close() }
