package display

import (
	"context"
	"errors"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// Membership coordinates the cross-replica routing marker for the in-memory
// session registry. The registry lives per replica, but clients reach any
// replica: before a broker generation exists (and its seat/capture leases
// record the owner), the first REST join must record WHICH replica holds the
// workspace's membership so sibling replicas can forward stream attaches and
// membership/control calls there.
//
// The marker is the kw-display-membership-* coordination lease, claimed on
// first join, renewed while local members exist, and released when the last
// member leaves. It gates nothing media-side; the seat/capture/control
// leases keep their own invariants.
type Membership struct {
	store    *Store
	sessions *Sessions

	mu     sync.Mutex
	claims map[string]string // ns/name -> claim id
	now    func() time.Time
}

// NewMembership wires the registry to the lease store. The returned
// coordinator must be installed on the Sessions (SetMembershipClaimer) and
// driven with Run.
func NewMembership(store *Store, sessions *Sessions) *Membership {
	return &Membership{store: store, sessions: sessions, claims: make(map[string]string), now: time.Now}
}

// membershipClaimTimeout bounds one lease write against the API server.
const membershipClaimTimeout = 5 * time.Second

// membershipRenewInterval is how often live claims are renewed. Renewals must
// land well inside ClientTTL so a contender never observes a quiet lease
// while the owner is healthy.
const membershipRenewInterval = 2 * time.Second

// ClaimForJoin implements Sessions.MembershipClaimer: it is called when a
// join creates a fresh local session for a workspace and records this replica
// as the membership owner. A claim by another live replica fails with an
// *OwnershipError naming it; the caller unwinds the join so the client's next
// attempt is forwarded to the owner.
func (m *Membership) ClaimForJoin(ns, name string) error {
	key := ns + "/" + name
	m.mu.Lock()
	if _, ok := m.claims[key]; ok {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), membershipClaimTimeout)
	id, err := m.store.ClaimMembership(ctx, ns, name)
	cancel()
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.claims[key] = id
	m.mu.Unlock()
	return nil
}

// Run renews live claims while their local session exists and releases claims
// whose session emptied (last leave or idle TTL). It exits with ctx.
func (m *Membership) Run(ctx context.Context) {
	tick := time.NewTicker(membershipRenewInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			m.sweep(ctx)
		}
	}
}

// Owner returns the recorded membership owner for ns/name, or "".
func (m *Membership) Owner(ctx context.Context, ns, name string) (string, error) {
	return m.store.MembershipOwner(ctx, ns, name)
}

func (m *Membership) sweep(ctx context.Context) {
	live := m.sessions.Keys()

	m.mu.Lock()
	claims := make(map[string]string, len(m.claims))
	for k, id := range m.claims {
		claims[k] = id
	}
	m.mu.Unlock()

	liveSet := make(map[string]bool, len(live))
	for _, key := range live {
		liveSet[key] = true
		if _, ok := claims[key]; ok {
			continue
		}
		// A live session without a tracked claim: the marker vanished
		// (delete/recreate) or a takeover was dropped earlier. Re-claim it;
		// a sibling legitimately owning it answers OwnershipError, which
		// simply leaves the marker alone.
		ns, name := splitKey(key)
		rctx, cancel := context.WithTimeout(ctx, membershipClaimTimeout)
		id, err := m.store.ClaimMembership(rctx, ns, name)
		cancel()
		if err == nil {
			m.mu.Lock()
			m.claims[key] = id
			m.mu.Unlock()
		}
	}

	for key, id := range claims {
		ns, name := splitKey(key)
		if !liveSet[key] {
			// The session emptied (last leave or idle TTL): drop the routing
			// marker so a fresh join anywhere can claim it. A lost marker
			// (ErrRevoked) needs no action either way.
			rctx, cancel := context.WithTimeout(ctx, membershipClaimTimeout)
			_ = m.store.ReleaseMembership(rctx, ns, name, id)
			cancel()
			m.mu.Lock()
			delete(m.claims, key)
			m.mu.Unlock()
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, membershipClaimTimeout)
		err := m.store.RenewMembership(rctx, ns, name, id)
		cancel()
		if errors.Is(err, ErrRevoked) || apierrors.IsNotFound(err) {
			// The marker was taken over, revoked or deleted: drop the claim.
			// While the session stays live the next sweep re-claims it; the
			// generation's own leases keep their invariants independently.
			m.mu.Lock()
			delete(m.claims, key)
			m.mu.Unlock()
		}
	}
}

func splitKey(key string) (ns, name string) {
	for i := 0; i < len(key); i++ {
		if key[i] == '/' {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}
