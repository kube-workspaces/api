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

// The capture/seat lease and the control lease are independent coordination
// objects: a broker can hold capture while a controller's input claim is held
// by a different participant, and one can die without the other.
func TestControlLeaseSplitFromSeat(t *testing.T) {
	s := NewStore(fake.NewClientset())
	ctx := context.Background()
	seat, err := s.Claim(ctx, "alice", "desktop", "vnc")
	if err != nil {
		t.Fatalf("seat claim: %v", err)
	}
	ctrl, err := s.ClaimControl(ctx, "alice", "desktop", "p1")
	if err != nil {
		t.Fatalf("control claim: %v", err)
	}
	if inUse, _ := s.ControlInUse(ctx, "alice", "desktop"); !inUse {
		t.Fatal("control lease missing")
	}
	if p, held, _ := s.ControlHolder(ctx, "alice", "desktop"); !held || p != "p1" {
		t.Fatalf("control holder: participant=%q held=%v", p, held)
	}
	if _, err := s.ClaimControl(ctx, "alice", "desktop", "p2"); !errors.Is(err, ErrBusy) {
		t.Fatalf("second control claim: %v", err)
	}
	if inUse, _ := s.InUse(ctx, "alice", "desktop"); !inUse {
		t.Fatal("seat claim lost while control held")
	}
	if err := s.Renew(ctx, "alice", "desktop", seat); err != nil {
		t.Fatalf("seat renew while control held: %v", err)
	}
	if err := s.RenewControl(ctx, "alice", "desktop", ctrl); err != nil {
		t.Fatalf("control renew: %v", err)
	}
	if err := s.ReleaseControl(ctx, "alice", "desktop", ctrl); err != nil {
		t.Fatalf("control release: %v", err)
	}
	if inUse, _ := s.ControlInUse(ctx, "alice", "desktop"); inUse {
		t.Fatal("control release left the slot held")
	}
	if p, held, _ := s.ControlHolder(ctx, "alice", "desktop"); held || p != "" {
		t.Fatalf("released control slot: participant=%q held=%v", p, held)
	}
	// The seat must be untouched by control operations throughout.
	if inUse, _ := s.InUse(ctx, "alice", "desktop"); !inUse {
		t.Fatal("seat claim should be independent of control lifecycle")
	}
}

func TestControlLeaseTokenFencing(t *testing.T) {
	s := NewStore(fake.NewClientset())
	ctx := context.Background()
	ctrl, err := s.ClaimControl(ctx, "alice", "desktop", "p1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RenewControl(ctx, "alice", "desktop", "stale"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("stale token renew: %v", err)
	}
	wasHeld, err := s.RevokeControl(ctx, "alice", "desktop")
	if err != nil || !wasHeld {
		t.Fatalf("revoke control: held=%v err=%v", wasHeld, err)
	}
	if err := s.RenewControl(ctx, "alice", "desktop", ctrl); !errors.Is(err, ErrRevoked) {
		t.Fatalf("renew after revoke must fail: %v", err)
	}
	// Revocation alone leaves the slot held until release or the fence elapses.
	if _, err := s.ClaimControl(ctx, "alice", "desktop", "p2"); !errors.Is(err, ErrBusy) {
		t.Fatalf("claim while old holder remains: %v", err)
	}
	if p, held, _ := s.ControlHolder(ctx, "alice", "desktop"); !held || p != "p1" {
		t.Fatalf("revoked holder: participant=%q held=%v", p, held)
	}
	if err := s.ReleaseControl(ctx, "alice", "desktop", ctrl); err != nil {
		t.Fatalf("old holder release after revoke: %v", err)
	}
	if _, err := s.ClaimControl(ctx, "alice", "desktop", "p2"); err != nil {
		t.Fatalf("claim after old holder released: %v", err)
	}
}

// A partitioned controller stops renewing, so a contender may take over the
// control lease only after observing the same resourceVersion for the full
// fence interval, by which time the victim's local input deadline has passed.
func TestControlFencingTakeover(t *testing.T) {
	cs := fake.NewClientset()
	now := time.Now()
	s := NewStore(cs)
	s.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := s.ClaimControl(ctx, "alice", "desktop", "p1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimControl(ctx, "alice", "desktop", "p2"); !errors.Is(err, ErrBusy) {
		t.Fatalf("immediate control takeover: %v", err)
	}
	now = now.Add(FenceInterval - time.Second)
	if _, err := s.ClaimControl(ctx, "alice", "desktop", "p2"); !errors.Is(err, ErrBusy) {
		t.Fatalf("takeover before control fence interval: %v", err)
	}
	now = now.Add(2 * time.Second)
	token, err := s.ClaimControl(ctx, "alice", "desktop", "p2")
	if err != nil {
		t.Fatalf("takeover after control fence interval: %v", err)
	}
	if p, held, _ := s.ControlHolder(ctx, "alice", "desktop"); !held || p != "p2" {
		t.Fatalf("takeover holder: participant=%q held=%v", p, held)
	}
	if err := s.RenewControl(ctx, "alice", "desktop", token); err != nil {
		t.Fatalf("new controller renew: %v", err)
	}
	if err := s.RenewControl(ctx, "alice", "desktop", "old-stale-token"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("partition victim renew must be fenced: %v", err)
	}
}

// Two API replicas share one cluster: the replica that wins the seat lease must
// record its identity on it, and the loser must learn who owns the display via
// an OwnershipError carrying the owner — never by dialing a second console.
func TestCrossReplicaOwnershipRouting(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	replicaA := NewStoreWithOwner(cs, "replica-a")
	replicaB := NewStoreWithOwner(cs, "replica-b")

	seatA, err := replicaA.Claim(ctx, "alice", "desktop", "vnc")
	if err != nil {
		t.Fatalf("replica A seat claim: %v", err)
	}
	l, err := cs.CoordinationV1().Leases("alice").Get(ctx, leaseName("desktop"), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := l.Annotations[ownerKey]; got != "replica-a" {
		t.Fatalf("seat lease owner annotation: %q", got)
	}
	if got, err := replicaA.SeatOwner(ctx, "alice", "desktop"); err != nil || got != "replica-a" {
		t.Fatalf("SeatOwner from A: %q err=%v", got, err)
	}
	if got, err := replicaB.SeatOwner(ctx, "alice", "desktop"); err != nil || got != "replica-a" {
		t.Fatalf("SeatOwner from B: %q err=%v", got, err)
	}

	// B must not steal the seat from A: fencing, a busy response, and a routing
	// hint all in one typed error.
	_, err = replicaB.Claim(ctx, "alice", "desktop", "vnc")
	var oe *OwnershipError
	if !errors.As(err, &oe) {
		t.Fatalf("B's claim must be an OwnershipError, got: %v", err)
	}
	if oe.Owner != "replica-a" || oe.Kind != "display-ownership" {
		t.Fatalf("ownership error: owner=%q kind=%q", oe.Owner, oe.Kind)
	}
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("ownership error must unwrap to busy: %v", err)
	}

	// A is stripped (crash), so after the fence the seat must be claimable by B.
	if err := replicaA.Release(ctx, "alice", "desktop", seatA); err != nil {
		t.Fatalf("replica A release: %v", err)
	}
	seatB, err := replicaB.Claim(ctx, "alice", "desktop", "vnc")
	if err != nil {
		t.Fatalf("replica B reclaim after release: %v", err)
	}
	if got, _ := replicaB.SeatOwner(ctx, "alice", "desktop"); got != "replica-b" {
		t.Fatalf("SeatOwner after B takeover: %q", got)
	}

	// The control lease carries an owner too: a controller served by B cannot
	// mint a control claim that says A owns it.
	ctrlA, err := replicaA.ClaimControl(ctx, "alice", "desktop", "p1")
	if err != nil {
		t.Fatalf("A control claim: %v", err)
	}
	_, err = replicaB.ClaimControl(ctx, "alice", "desktop", "p2")
	if !errors.As(err, &oe) || oe.Owner != "replica-a" {
		t.Fatalf("B's control claim: owner=%q err=%v", oe.Owner, err)
	}
	if got, _ := replicaB.ControlOwner(ctx, "alice", "desktop"); got != "replica-a" {
		t.Fatalf("ControlOwner from B: %q", got)
	}
	if err := replicaA.ReleaseControl(ctx, "alice", "desktop", ctrlA); err != nil {
		t.Fatalf("A control release: %v", err)
	}
	if _, err := replicaB.ClaimControl(ctx, "alice", "desktop", "p2"); err != nil {
		t.Fatalf("B control claim after release: %v", err)
	}
	_ = seatB
}

var leaseGR = schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}
