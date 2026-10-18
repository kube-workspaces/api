package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func enrollmentHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func exerciseEnrollmentStore(t *testing.T, first, second EnrollmentStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	hash := enrollmentHash(fmt.Sprintf("bootstrap-%d", now.UnixNano()))
	c := EnrollmentCredential{TokenHash: hash, Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "uid", Generation: "gen", RevocationEpoch: ^uint64(0), ExpiresAt: now.Add(time.Minute)}
	if err := first.Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := first.Create(ctx, c); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate credential: %v", err)
	}
	got, err := second.Get(ctx, hash)
	if err != nil || got.RevocationEpoch != c.RevocationEpoch {
		t.Fatalf("credential: %+v, %v", got, err)
	}
	// Two replicas redeem different candidates for the same CSR. Every caller
	// must receive one identical committed certificate, not its own candidate.
	var wg sync.WaitGroup
	results := make(chan []byte, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := first
			if i%2 != 0 {
				store = second
			}
			der, err := store.Redeem(ctx, hash, enrollmentHash("same-csr"), []byte(fmt.Sprintf("candidate-%d", i)), now)
			if err != nil {
				t.Error(err)
				return
			}
			results <- der
		}(i)
	}
	wg.Wait()
	close(results)
	var committed []byte
	for result := range results {
		if committed == nil {
			committed = result
		}
		if !bytes.Equal(committed, result) {
			t.Fatal("different identities issued for one CSR")
		}
	}
	if committed == nil {
		t.Fatal("no issuance winner")
	}
	if _, err := second.Redeem(ctx, hash, enrollmentHash("foreign-csr"), []byte("foreign-cert"), now); !errors.Is(err, ErrConflict) {
		t.Fatalf("another CSR claimed token: %v", err)
	}
	if _, err := second.Redeem(ctx, hash, enrollmentHash("same-csr"), []byte("retry"), c.ExpiresAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired retry accepted: %v", err)
	}
	// Different CSRs racing through independent replica pools have one winning
	// identity group. The losing group must never receive a certificate.
	c.TokenHash = enrollmentHash(hash + "-competing")
	if err := first.Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	winners := make(chan string, 16)
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			group := fmt.Sprintf("csr-group-%d", n%2)
			store := first
			if n%2 != 0 {
				store = second
			}
			_, err := store.Redeem(ctx, c.TokenHash, enrollmentHash(group), []byte(group), now)
			if err == nil {
				winners <- group
			} else if !errors.Is(err, ErrConflict) {
				t.Error(err)
			}
		}(n)
	}
	wg.Wait()
	close(winners)
	winningGroup := ""
	for group := range winners {
		if winningGroup == "" {
			winningGroup = group
		}
		if group != winningGroup {
			t.Fatal("different CSR groups both enrolled")
		}
	}
	if winningGroup == "" {
		t.Fatal("no competing CSR winner")
	}
}

func TestMemoryEnrollmentSingleCSR(t *testing.T) {
	m, err := NewMemoryEnrollment(32)
	if err != nil {
		t.Fatal(err)
	}
	exerciseEnrollmentStore(t, m, m)
}

func TestPostgresEnrollmentIntegration(t *testing.T) {
	dsn := os.Getenv("KW_EXECUTION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set KW_EXECUTION_TEST_DATABASE_URL for disposable PostgreSQL")
	}
	first, err := NewPostgresEnrollment(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewPostgresEnrollment(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	exerciseEnrollmentStore(t, first, second)
}
