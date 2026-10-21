package auth

import (
	"sync"
	"testing"
	"time"
)

func TestK8sCodeStoreConcurrentRedeemHasOneWinner(t *testing.T) {
	dyn := newFakeDynamicClient(t)
	stores := []CodeStore{NewK8sCodeStore(dyn), NewK8sCodeStore(dyn)}
	for _, store := range stores {
		t.Cleanup(store.Close)
	}
	if err := stores[0].Issue("concurrent-code", nativeAuthCode{token: "token.signature"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 20)
	for i := range 20 {
		wg.Go(func() { _, ok := stores[i%2].Redeem("concurrent-code"); results <- ok })
	}
	wg.Wait()
	close(results)
	winners := 0
	for ok := range results {
		if ok {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("got %d redemption winners", winners)
	}
}

func TestK8sCodeStoreCrossReplica(t *testing.T) {
	dyn := newFakeDynamicClient(t)
	issuer := newK8sCodeStore(dyn, nativeCodeTTL, nativeCodeMaxEntries)
	redeemer := newK8sCodeStore(dyn, nativeCodeTTL, nativeCodeMaxEntries)
	t.Cleanup(issuer.Close)
	t.Cleanup(redeemer.Close)

	code := "test-code-cross-replica-0123456789"
	entry := nativeAuthCode{
		token:          "tok.sig",
		codeChallenge:  "challenge",
		email:          "ada@example.com",
		role:           "editor",
		tokenExpiresAt: time.Now().Add(time.Hour).Unix(),
		redirect:       "/proxy/ns/ws/",
	}
	if err := issuer.Issue(code, entry); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, ok := redeemer.Redeem(code)
	if !ok {
		t.Fatal("Redeem on second store: not found, want cross-replica success")
	}
	if got.token != entry.token || got.email != entry.email || got.codeChallenge != entry.codeChallenge || got.redirect != entry.redirect {
		t.Fatalf("Redeem = %+v, want %+v", got, entry)
	}
	// Single-use: second redeem fails on both stores.
	if _, ok := redeemer.Redeem(code); ok {
		t.Fatal("second Redeem succeeded, want single-use failure")
	}
	if _, ok := issuer.Redeem(code); ok {
		t.Fatal("Redeem on issuing store after remote redeem succeeded, want failure")
	}
}

func TestK8sCodeStoreExpiry(t *testing.T) {
	dyn := newFakeDynamicClient(t)
	s := newK8sCodeStore(dyn, 50*time.Millisecond, nativeCodeMaxEntries)
	t.Cleanup(s.Close)
	code := "test-code-expiry-0123456789"
	if err := s.Issue(code, nativeAuthCode{token: "t", email: "e"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, ok := s.Redeem(code); ok {
		t.Fatal("Redeem of expired code succeeded, want failure")
	}
}

func TestK8sCodeStoreNilDynFallsBackToMemory(t *testing.T) {
	s := NewK8sCodeStore(nil)
	t.Cleanup(s.Close)
	if err := s.Issue("c1", nativeAuthCode{token: "t"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, ok := s.Redeem("c1"); !ok {
		t.Fatal("Redeem on memory fallback failed")
	}
}
