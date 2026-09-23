package auth

import (
	"testing"
	"time"
)

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
