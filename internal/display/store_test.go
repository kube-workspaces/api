package display

import (
	"context"
	"errors"
	"testing"
	"time"

	coordination "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestClaimRenewReleaseLifecycle(t *testing.T) {
	s := NewStore(fake.NewClientset())
	ctx := context.Background()
	id, err := s.Claim(ctx, "alice", "desktop", "vnc")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(id) != 64 {
		t.Fatalf("claim id length %d", len(id))
	}
	// Cross-tier exclusion: the tier1 probe must not open a second density.
	if _, err := s.Claim(ctx, "alice", "desktop", "tier1"); !errors.Is(err, ErrBusy) {
		t.Fatalf("cross-tier claim must be busy, got: %v", err)
	}
	if inUse, _ := s.InUse(ctx, "alice", "desktop"); !inUse {
		t.Fatal("status missed a held display")
	}
	if err := s.Renew(ctx, "alice", "desktop", id); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if err := s.Renew(ctx, "alice", "desktop", "wrong"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("renew with stale id: %v", err)
	}
	if err := s.Release(ctx, "alice", "desktop", "wrong"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("stale release must not free the slot: %v", err)
	}
	if inUse, _ := s.InUse(ctx, "alice", "desktop"); !inUse {
		t.Fatal("stale release freed the slot")
	}
	if err := s.Release(ctx, "alice", "desktop", id); err != nil {
		t.Fatalf("release: %v", err)
	}
	if inUse, _ := s.InUse(ctx, "alice", "desktop"); inUse {
		t.Fatal("release left the slot held")
	}
	// A released slot is immediately claimable: the owner only releases after
	// its media sockets are down (API bridge) or torn down (proxy close()).
	if _, err := s.Claim(ctx, "alice", "desktop", "tier1"); err != nil {
		t.Fatalf("reclaim after release: %v", err)
	}
}

func TestRevokeBlocksRenewalButNotRelease(t *testing.T) {
	s := NewStore(fake.NewClientset())
	ctx := context.Background()
	id, err := s.Claim(ctx, "alice", "desktop", "vnc")
	if err != nil {
		t.Fatal(err)
	}
	wasHeld, err := s.Revoke(ctx, "alice", "desktop")
	if err != nil || !wasHeld {
		t.Fatalf("revoke: held=%v err=%v", wasHeld, err)
	}
	if err := s.Renew(ctx, "alice", "desktop", id); !errors.Is(err, ErrRevoked) {
		t.Fatalf("renew after revoke must fail: %v", err)
	}
	// Revocation alone must not free the slot: the old owner may still write
	// to its media sockets until it observes the revoke or its local deadline
	// passes. A contender must either wait for the release or the fence.
	if _, err := s.Claim(ctx, "alice", "desktop", "tier1"); !errors.Is(err, ErrBusy) {
		t.Fatalf("claim while old owner still holds: %v", err)
	}
	if err := s.Release(ctx, "alice", "desktop", id); err != nil {
		t.Fatalf("old owner release after revoke: %v", err)
	}
	if _, err := s.Claim(ctx, "alice", "desktop", "tier1"); err != nil {
		t.Fatalf("claim after old owner released: %v", err)
	}
}

// TestFencingTakeover simulates a partition victim that stops renewing. A
// contender may take over only after observing the same resourceVersion for
// the full fence interval — by which time the victim's local input deadline
// (ClientTTL from its last successful renewal) has long passed.
func TestFencingTakeover(t *testing.T) {
	cs := fake.NewClientset()
	now := time.Now()
	s := NewStore(cs)
	s.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := s.Claim(ctx, "alice", "desktop", "vnc"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx, "alice", "desktop", "tier1"); !errors.Is(err, ErrBusy) {
		t.Fatalf("immediate takeover: %v", err)
	}
	now = now.Add(FenceInterval - time.Second)
	if _, err := s.Claim(ctx, "alice", "desktop", "tier1"); !errors.Is(err, ErrBusy) {
		t.Fatalf("takeover before the fence interval: %v", err)
	}
	now = now.Add(2 * time.Second)
	id2, err := s.Claim(ctx, "alice", "desktop", "tier1")
	if err != nil {
		t.Fatalf("takeover after the fence interval: %v", err)
	}
	if err := s.Renew(ctx, "alice", "desktop", id2); err != nil {
		t.Fatalf("new owner renew: %v", err)
	}
	if err := s.Renew(ctx, "alice", "desktop", "old-stale-id"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("partition victim renew must be fenced: %v", err)
	}
}

// The real API server rejects a stale Update with 409 Conflict (resourceVersion
// CAS). The fake does not enforce this, so the conflict path is exercised with
// a reactor: a loser's claim must surface as ErrBusy, not a success.
func TestClaimUpdateCASConflictIsBusy(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	if _, err := cs.CoordinationV1().Leases("alice").Create(ctx, &coordination.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: leaseName("desktop"), Namespace: "alice"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	cs.PrependReactor("update", "leases", func(action ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(leaseGR, leaseName("desktop"), errors.New("conflict"))
	})
	s := NewStore(cs)
	if _, err := s.Claim(ctx, "alice", "desktop", "vnc"); !errors.Is(err, ErrBusy) {
		t.Fatalf("lost CAS race must report busy, got: %v", err)
	}
}

// Renew/release share the same CAS; a conflict there must surface as ErrRevoked
// so the guard stops writing input rather than extending its deadline.
func TestModifyCASConflictWrapsErrRevoked(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	held := "some-id"
	now := metav1.NewMicroTime(time.Now())
	if _, err := cs.CoordinationV1().Leases("alice").Create(ctx, &coordination.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: leaseName("desktop"), Namespace: "alice"},
		Spec:       coordination.LeaseSpec{HolderIdentity: &held, RenewTime: &now},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	cs.PrependReactor("update", "leases", func(action ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(leaseGR, leaseName("desktop"), errors.New("conflict"))
	})
	s := NewStore(cs)
	if err := s.Renew(ctx, "alice", "desktop", "some-id"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("CAS conflict on renew must wrap ErrRevoked, got: %v", err)
	}
}

func TestInvalidTierRejected(t *testing.T) {
	s := NewStore(fake.NewClientset())
	if _, err := s.Claim(context.Background(), "alice", "desktop", "bogus"); err == nil {
		t.Fatal("invalid display tier accepted")
	}
}

var leaseGR = schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}
