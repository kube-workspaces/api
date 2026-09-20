package display

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// The coordinator claims the membership lease when the first join creates a
// session, renews it while members exist, and releases it when the session
// empties.
func TestMembershipClaimRenewReleaseCycle(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	store := NewStoreWithOwner(cs, "replica-a")
	sessions := NewSessions()
	m := NewMembership(store, sessions)
	sessions.SetMembershipClaimer(m)

	if _, err := sessions.Join("alice", "desktop", RoleObserver); err != nil {
		t.Fatalf("join: %v", err)
	}
	if got, _ := store.MembershipOwner(ctx, "alice", "desktop"); got != "replica-a" {
		t.Fatalf("owner after first join: %q", got)
	}

	// The sweeper renews a live claim and keeps it.
	m.sweep(ctx)
	if got, _ := store.MembershipOwner(ctx, "alice", "desktop"); got != "replica-a" {
		t.Fatalf("owner after renew sweep: %q", got)
	}

	// Leave the only member: the next sweep releases the marker.
	p := sessions.mustStatus(t, "alice", "desktop").Observers[0]
	if err := sessions.Leave("alice", "desktop", p.ID); err != nil {
		t.Fatalf("leave: %v", err)
	}
	m.sweep(ctx)
	if got, _ := store.MembershipOwner(ctx, "alice", "desktop"); got != "" {
		t.Fatalf("owner after release sweep: %q", got)
	}

	// A fresh join reclaims.
	if _, err := sessions.Join("alice", "desktop", RoleObserver); err != nil {
		t.Fatalf("rejoin: %v", err)
	}
	if got, _ := store.MembershipOwner(ctx, "alice", "desktop"); got != "replica-a" {
		t.Fatalf("owner after rejoin: %q", got)
	}
}

// A join on replica B for a membership owned by replica A unwinds: B's
// registry holds nothing and B learns where to route.
func TestMembershipJoinOwnedElsewhere(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	storeA := NewStoreWithOwner(cs, "replica-a")
	storeB := NewStoreWithOwner(cs, "replica-b")
	sessionsA, sessionsB := NewSessions(), NewSessions()
	mA := NewMembership(storeA, sessionsA)
	sessionsA.SetMembershipClaimer(mA)
	sessionsB.SetMembershipClaimer(NewMembership(storeB, sessionsB))

	if _, err := sessionsA.Join("alice", "desktop", RoleObserver); err != nil {
		t.Fatalf("A join: %v", err)
	}
	if _, err := sessionsB.Join("alice", "desktop", RoleObserver); err == nil {
		t.Fatal("B join must fail while A owns the membership")
	} else {
		var oe *OwnershipError
		if !errors.As(err, &oe) || oe.Owner != "replica-a" {
			t.Fatalf("B join error: %v", err)
		}
	}
	if st, ok := sessionsB.Status("alice", "desktop"); ok {
		t.Fatalf("B registry polluted by an owned join: %+v", st)
	}
	// After A's membership empties and its sweeper releases the marker, B can
	// claim.
	p := sessionsA.mustStatus(t, "alice", "desktop").Observers[0]
	if err := sessionsA.Leave("alice", "desktop", p.ID); err != nil {
		t.Fatalf("A leave: %v", err)
	}
	mA.sweep(ctx)
	if _, err := sessionsB.Join("alice", "desktop", RoleObserver); err != nil {
		t.Fatalf("B join after A released: %v", err)
	}
	if got, _ := storeB.MembershipOwner(ctx, "alice", "desktop"); got != "replica-b" {
		t.Fatalf("owner after B claim: %q", got)
	}
}

// Losing the marker (deleted, then claimed by a sibling) drops the local
// claim; the sweeper stops renewing instead of fighting the new owner, and
// the re-claim attempt respects the sibling's OwnershipError.
func TestMembershipSweepDropsLostClaim(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	store := NewStoreWithOwner(cs, "replica-a")
	sessions := NewSessions()
	m := NewMembership(store, sessions)
	sessions.SetMembershipClaimer(m)

	if _, err := sessions.Join("alice", "desktop", RoleObserver); err != nil {
		t.Fatalf("join: %v", err)
	}
	// Delete/recreate: the marker vanishes and a sibling claims it fresh.
	if err := cs.CoordinationV1().Leases("alice").Delete(ctx, membershipLeaseName("desktop"), metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete marker: %v", err)
	}
	if _, err := NewStoreWithOwner(cs, "replica-b").ClaimMembership(ctx, "alice", "desktop"); err != nil {
		t.Fatalf("takeover claim: %v", err)
	}
	// First sweep renews against the vanished marker and drops the claim.
	m.sweep(ctx)
	m.mu.Lock()
	remaining := len(m.claims)
	m.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("lost claim still tracked: %d", remaining)
	}
	// Second sweep's re-claim hits the sibling's OwnershipError and stays out.
	m.sweep(ctx)
	m.mu.Lock()
	remaining = len(m.claims)
	m.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("re-claimed under a sibling owner: %d", remaining)
	}
	if got, _ := store.MembershipOwner(ctx, "alice", "desktop"); got != "replica-b" {
		t.Fatalf("owner after takeover: %q", got)
	}
	// The live session itself is untouched (media leases guard it).
	if st := sessions.mustStatus(t, "alice", "desktop"); len(st.Observers) != 1 {
		t.Fatalf("session disturbed by a lost marker: %+v", st)
	}
}

// When the marker vanishes and NO sibling takes it, the sweeper re-claims it
// for the still-live session (delete/recreate recovery).
func TestMembershipSweepReclaimsVanishedMarker(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	store := NewStoreWithOwner(cs, "replica-a")
	sessions := NewSessions()
	m := NewMembership(store, sessions)
	sessions.SetMembershipClaimer(m)

	if _, err := sessions.Join("alice", "desktop", RoleObserver); err != nil {
		t.Fatalf("join: %v", err)
	}
	if err := cs.CoordinationV1().Leases("alice").Delete(ctx, membershipLeaseName("desktop"), metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete marker: %v", err)
	}
	m.sweep(ctx) // drops the dead claim
	m.sweep(ctx) // re-claims for the live session
	if got, _ := store.MembershipOwner(ctx, "alice", "desktop"); got != "replica-a" {
		t.Fatalf("owner after re-claim: %q", got)
	}
}

// Run drives the sweeper until ctx ends.
func TestMembershipRunStopsWithContext(t *testing.T) {
	cs := fake.NewClientset()
	store := NewStoreWithOwner(cs, "replica-a")
	sessions := NewSessions()
	m := NewMembership(store, sessions)
	sessions.SetMembershipClaimer(m)
	if _, err := sessions.Join("alice", "desktop", RoleObserver); err != nil {
		t.Fatalf("join: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop with context")
	}
}
