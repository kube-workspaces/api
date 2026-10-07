package agent

import (
	"strings"
	"testing"
	"time"
)

func testKeys() [][]byte { return [][]byte{[]byte("test-key-0123456789abcdef")} }

func TestMintParseRoundTrip(t *testing.T) {
	store := NewStore()
	id, signed, err := store.Mint("ws-1", "gen-1", "tester", 3, testKeys())
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("empty session id")
	}
	if parts := strings.SplitN(signed, ".", 3); len(parts) != 3 || parts[0] != id {
		t.Fatalf("ticket must carry its session id first: %q", signed)
	}
	ticket, err := store.Parse(signed, testKeys())
	if err != nil {
		t.Fatal(err)
	}
	if ticket.WorkspaceUID != "ws-1" || ticket.WorkspaceGeneration != "gen-1" {
		t.Fatalf("binding lost: %+v", ticket)
	}
	if ticket.Role != "controller" || ticket.Audience != "workspace-agent" {
		t.Fatalf("scope lost: %+v", ticket)
	}
	if ticket.ControlEpoch != 3 {
		t.Fatalf("epoch lost: %+v", ticket)
	}
	if ticket.SessionID != "" {
		t.Fatalf("minted ticket must bind the live claim, got session %q", ticket.SessionID)
	}
	if _, ok := store.Lookup(id); !ok {
		t.Fatal("fresh session must be renewable")
	}
}

func TestParseRejectsTampering(t *testing.T) {
	store := NewStore()
	_, signed, err := store.Mint("ws-1", "gen-1", "tester", 1, testKeys())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Parse(signed+"x", testKeys()); err == nil {
		t.Fatal("tampered signature must fail")
	}
	if _, err := store.Parse("nonsense", testKeys()); err == nil {
		t.Fatal("malformed ticket must fail")
	}
	other := [][]byte{[]byte("different-key")}
	if _, err := store.Parse(signed, other); err == nil {
		t.Fatal("wrong key must fail")
	}
}

func TestParseRejectsExpiry(t *testing.T) {
	store := NewStore()
	store.ttl = -time.Second
	_, signed, err := store.Mint("ws-1", "gen-1", "tester", 1, testKeys())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Parse(signed, testKeys()); err == nil {
		t.Fatal("expired ticket must fail")
	}
}

func TestRenewReleaseLifecycle(t *testing.T) {
	store := NewStore()
	id, _, err := store.Mint("ws-1", "gen-1", "tester", 1, testKeys())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Renew(id); !ok {
		t.Fatal("live session must renew")
	}
	store.Release(id)
	if _, ok := store.Lookup(id); ok {
		t.Fatal("released session must be gone")
	}
	if _, ok := store.Renew(id); ok {
		t.Fatal("released session must not renew")
	}
	// Best-effort release of unknown ids never errors.
	store.Release("does-not-exist")
	if _, ok := store.Renew("does-not-exist"); ok {
		t.Fatal("unknown session must not renew")
	}
}

func TestActiveCountsLiveSessionsPerWorkspace(t *testing.T) {
	store := NewStore()
	if got := store.Active("ws-1"); got != 0 {
		t.Fatalf("empty store must report 0, got %d", got)
	}
	id, _, err := store.Mint("ws-1", "gen-1", "tester", 1, testKeys())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Mint("ws-2", "gen-1", "tester", 1, testKeys()); err != nil {
		t.Fatal(err)
	}
	if got := store.Active("ws-1"); got != 1 {
		t.Fatalf("ws-1 must report 1, got %d", got)
	}
	if got := store.Active("ws-2"); got != 1 {
		t.Fatalf("ws-2 must report 1, got %d", got)
	}
	store.Release(id)
	if got := store.Active("ws-1"); got != 0 {
		t.Fatalf("released workspace must report 0, got %d", got)
	}
}

func TestKeyRotationVerifiesPredecessors(t *testing.T) {
	store := NewStore()
	_, signed, err := store.Mint("ws-1", "gen-1", "tester", 1, [][]byte{[]byte("old-key")})
	if err != nil {
		t.Fatal(err)
	}
	keys := [][]byte{[]byte("new-key"), []byte("old-key")}
	if _, err := store.Parse(signed, keys); err != nil {
		t.Fatalf("predecessor key must still verify: %v", err)
	}
	if _, _, err := store.Mint("ws-1", "gen-1", "tester", 1, [][]byte{}); err == nil {
		t.Fatal("mint without keys must fail")
	}
}
