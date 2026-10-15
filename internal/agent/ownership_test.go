package agent

import "testing"

func TestIssuerRoutingAndBoundLifecycle(t *testing.T) {
	s := NewOwnedStore("api-one")
	id, _, err := s.Mint("uid-one", "generation-one", "viewer", 1, testKeys())
	if err != nil {
		t.Fatal(err)
	}
	if SessionOwner(id, testKeys()) != "api-one" || SessionOwner(id+"x", testKeys()) != "" || SessionOwner(id, [][]byte{[]byte("wrong")}) != "" {
		t.Fatal("issuer signature not enforced")
	}
	if SessionOwner(id, append([][]byte{[]byte("new")}, testKeys()...)) != "api-one" {
		t.Fatal("rotation lost issuer")
	}
	if s.RenewBound(id, "other", "generation-one") || s.ReleaseBound(id, "other", "generation-one") {
		t.Fatal("cross-workspace mutation")
	}
	if s.RenewBound(id, "uid-one", "generation-two") || s.ReleaseBound(id, "uid-one", "generation-two") {
		t.Fatal("reset generation mutation")
	}
	if !s.RenewBound(id, "uid-one", "generation-one") || !s.ReleaseBound(id, "uid-one", "generation-one") {
		t.Fatal("correct binding refused")
	}
	if s.RenewBound(id, "uid-one", "generation-one") {
		t.Fatal("released grant resurrected")
	}
	if NewOwnedStore("api-one").RenewBound(id, "uid-one", "generation-one") {
		t.Fatal("restart resurrected grant")
	}
}
