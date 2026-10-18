package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/execution/pki"
	"github.com/kube-workspaces/api/internal/execution/storage"
)

func fixture(t *testing.T, current CurrentIdentity) (*Service, storage.EnrollmentStore, pki.Identity) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := pki.NewAuthority(der, key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewMemoryEnrollment(128)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(store, issuer, current, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now }
	i := pki.Identity{Role: pki.RoleGuest, Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "uid", Generation: "gen-1", RevocationEpoch: 4}
	return s, store, i
}

func csr(t *testing.T) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestBootstrapSingleCSRAndRetry(t *testing.T) {
	ctx := context.Background()
	s, store, i := fixture(t, func(context.Context, pki.Identity) error { return nil })
	token, err := s.Mint(ctx, i, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(token)
	credential, err := store.Get(ctx, digest(raw))
	if err != nil || credential.TokenHash == token || credential.CSRHash != "" {
		t.Fatalf("unsafe bootstrap storage: %+v %v", credential, err)
	}
	request := csr(t)
	cert, err := s.Enroll(ctx, token, request)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := s.Enroll(ctx, token, request)
	if err != nil || !bytes.Equal(cert, retry) {
		t.Fatal("retry reissued identity", err)
	}
	leaf, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := pki.CertificateIdentity(leaf)
	if err != nil || actual != i {
		t.Fatal("certificate not bound to reserved identity", err)
	}
	if _, err := s.Enroll(ctx, token, csr(t)); !errors.Is(err, ErrDenied) {
		t.Fatal("another key redeemed token", err)
	}
}

func TestConcurrentDifferentCSRHasOneWinner(t *testing.T) {
	ctx := context.Background()
	s, _, i := fixture(t, func(context.Context, pki.Identity) error { return nil })
	token, err := s.Mint(ctx, i, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	requests := make([][]byte, 16)
	for j := range requests {
		requests[j] = csr(t)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for _, request := range requests {
		wg.Add(1)
		go func(request []byte) {
			defer wg.Done()
			_, err := s.Enroll(ctx, token, request)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrDenied) {
				t.Error(err)
			}
		}(request)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("got %d distinct enrolled identities", wins.Load())
	}
}

func TestResetExpiryAndOutageFenceIssuedRetries(t *testing.T) {
	ctx := context.Background()
	var revoked atomic.Bool
	s, _, i := fixture(t, func(context.Context, pki.Identity) error {
		if revoked.Load() {
			return errors.New("workspace reset/deleted or lookup unavailable")
		}
		return nil
	})
	token, err := s.Mint(ctx, i, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request := csr(t)
	if _, err := s.Enroll(ctx, token, request); err != nil {
		t.Fatal(err)
	}
	revoked.Store(true)
	if _, err := s.Enroll(ctx, token, request); !errors.Is(err, ErrDenied) {
		t.Fatal("stale issued retry authorized", err)
	}
	if _, err := s.Mint(ctx, i, time.Minute); !errors.Is(err, ErrDenied) {
		t.Fatal("stale bootstrap minted", err)
	}
	revoked.Store(false)
	later := s.now().Add(time.Minute)
	s.now = func() time.Time { return later }
	if _, err := s.Enroll(ctx, token, request); !errors.Is(err, ErrDenied) {
		t.Fatal("expired bootstrap retry accepted", err)
	}
}

func TestInvalidProofDoesNotSpendBootstrap(t *testing.T) {
	ctx := context.Background()
	s, _, i := fixture(t, func(context.Context, pki.Identity) error { return nil })
	token, err := s.Mint(ctx, i, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(ctx, token, []byte("not a CSR")); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if _, err := s.Enroll(ctx, token, csr(t)); err != nil {
		t.Fatal("bad proof spent bootstrap", err)
	}
	for _, lifetime := range []time.Duration{0, MaxBootstrapLifetime + time.Second} {
		if _, err := s.Mint(ctx, i, lifetime); !errors.Is(err, ErrDenied) {
			t.Fatal("invalid bootstrap lifetime", err)
		}
	}
	i.Role = pki.RoleAPI
	if _, err := s.Mint(ctx, i, time.Minute); !errors.Is(err, ErrDenied) {
		t.Fatal("guest bootstrap minted API authority", err)
	}
}

type hookStore struct {
	storage.EnrollmentStore
	after func()
}

func (h *hookStore) Redeem(ctx context.Context, hash, csrHash string, cert []byte, now time.Time) ([]byte, error) {
	result, err := h.EnrollmentStore.Redeem(ctx, hash, csrHash, cert, now)
	h.after()
	return result, err
}

func TestResetOrExpiryDuringCommitWithholdsCertificate(t *testing.T) {
	for _, test := range []string{"reset", "expiry"} {
		t.Run(test, func(t *testing.T) {
			ctx := context.Background()
			var revoked atomic.Bool
			s, store, i := fixture(t, func(context.Context, pki.Identity) error {
				if revoked.Load() {
					return errors.New("reset")
				}
				return nil
			})
			token, err := s.Mint(ctx, i, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			now := s.now()
			s.store = &hookStore{EnrollmentStore: store, after: func() {
				if test == "reset" {
					revoked.Store(true)
				} else {
					s.now = func() time.Time { return now.Add(time.Minute) }
				}
			}}
			if _, err := s.Enroll(ctx, token, csr(t)); !errors.Is(err, ErrDenied) {
				t.Fatalf("certificate returned after %s: %v", test, err)
			}
		})
	}
}

func TestExpiredCertificateIsNotReissuedOnBootstrapRetry(t *testing.T) {
	ctx := context.Background()
	s, _, i := fixture(t, func(context.Context, pki.Identity) error { return nil })
	s.leafLifetime = time.Minute
	token, err := s.Mint(ctx, i, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request := csr(t)
	if _, err := s.Enroll(ctx, token, request); err != nil {
		t.Fatal(err)
	}
	later := s.now().Add(2 * time.Minute)
	s.now = func() time.Time { return later }
	if _, err := s.Enroll(ctx, token, request); !errors.Is(err, ErrDenied) {
		t.Fatal("bootstrap became a renewal credential", err)
	}
}
