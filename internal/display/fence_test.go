package display

import (
	"context"
	"errors"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newFencedFixture(t *testing.T, role string) (*Store, *Sessions, *Participant) {
	t.Helper()
	clock := &fakeClock{t: time.Now()}
	s := NewStore(fake.NewClientset())
	s.now = clock.now
	sess := NewSessions()
	sess.now = clock.now
	p, err := sess.Join("alice", "desktop", role)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	return s, sess, p
}

func TestFenceAdmitsInputOnlyWhileController(t *testing.T) {
	s, sess, ctrl := newFencedFixture(t, RoleController)
	ctx := context.Background()
	f, err := AcquireControl(ctx, s, sess, "alice", "desktop", ctrl.ID, false)
	if err != nil {
		t.Fatalf("acquire control: %v", err)
	}
	defer f.Close()
	if inUse, _ := s.ControlInUse(ctx, "alice", "desktop"); !inUse {
		t.Fatal("control lease not held")
	}
	called := 0
	if err := f.DispatchInput(func() { called++ }); err != nil {
		t.Fatalf("dispatch while controller: %v", err)
	}
	if called != 1 {
		t.Fatalf("input not dispatched: %d", called)
	}
	// A non-controller participant never gets the fence in the first place.
	if _, err := AcquireControl(ctx, s, sess, "alice", "desktop", "unknown", false); !errors.Is(err, ErrNotController) {
		t.Fatalf("unknown participant fence: %v", err)
	}
	f.Close()
	if inUse, _ := s.ControlInUse(ctx, "alice", "desktop"); inUse {
		t.Fatal("close left the control lease held")
	}
}

func TestFenceDropsInputOnRegistryDemotion(t *testing.T) {
	s, sess, ctrl := newFencedFixture(t, RoleController)
	ctx := context.Background()
	f, err := AcquireControl(ctx, s, sess, "alice", "desktop", ctrl.ID, false)
	if err != nil {
		t.Fatalf("acquire control: %v", err)
	}
	defer f.Close()
	obs, err := sess.Join("alice", "desktop", RoleObserver)
	if err != nil {
		t.Fatal(err)
	}
	// Registry-level takeover demotes the old controller to observer.
	if _, _, err := sess.Acquire("alice", "desktop", obs.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := f.DispatchInput(func() {}); !errors.Is(err, ErrNotController) {
		t.Fatalf("demoted controller input: %v", err)
	}
	// Once the demoted fence stops renewing (revoked elsewhere) its deadline
	// lapses and writes become hard-fenced.
	if wasHeld, err := s.RevokeControl(ctx, "alice", "desktop"); err != nil || !wasHeld {
		t.Fatalf("revoke control: held=%v err=%v", wasHeld, err)
	}
	select {
	case <-f.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("fence kept renewing after revoke")
	}
	if err := f.DispatchInput(func() {}); !errors.Is(err, ErrInputFenced) {
		t.Fatalf("hard fence after revoke+deadline: %v", err)
	}
}

func TestFenceDeadlineBoundsWrites(t *testing.T) {
	s, sess, ctrl := newFencedFixture(t, RoleController)
	// Purposely stop the renew loop so only the panic? deadline is tested:
	// construct the fence directly to drive the pure deadline gate.
	ctx := context.Background()
	started := s.now()
	token, err := s.ClaimControl(ctx, "alice", "desktop", ctrl.ID)
	if err != nil {
		t.Fatal(err)
	}
	f := &Fence{deadline: started.Add(ClientTTL), store: s, sessions: sess,
		ns: "alice", name: "desktop", participant: ctrl.ID, token: token, now: s.now}
	if err := f.DispatchInput(func() {}); err != nil {
		t.Fatalf("dispatch inside deadline: %v", err)
	}
	// Advance past the local monotonic deadline: input must be dropped even
	// though the registry still lists the participant as controller.
	f.now = func() time.Time { return started.Add(ClientTTL + time.Millisecond) }
	if err := f.DispatchInput(func() {}); !errors.Is(err, ErrInputFenced) {
		t.Fatalf("dispatch past deadline: %v", err)
	}
}

func TestFenceForceAcquireRevokesOldHolder(t *testing.T) {
	s, sess, ctrl := newFencedFixture(t, RoleController)
	ctx := context.Background()
	f1, err := AcquireControl(ctx, s, sess, "alice", "desktop", ctrl.ID, false)
	if err != nil {
		t.Fatalf("first control: %v", err)
	}
	obs, err := sess.Join("alice", "desktop", RoleObserver)
	if err != nil {
		t.Fatal(err)
	}
	// Force takeover revokes the old holder's renewal immediately, but the
	// slot stays occupied until the old fence releases its token.
	if _, err := AcquireControl(ctx, s, sess, "alice", "desktop", obs.ID, true); !errors.Is(err, ErrBusy) {
		t.Fatalf("force takeover before release: %v", err)
	}
	select {
	case <-f1.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("old fence kept renewing after force revoke")
	}
	f1.Close()
	// The old participant is no longer the local controller, so without force
	// this must fail; with force the fresh claim now lands.
	if p, held, _ := s.ControlHolder(ctx, "alice", "desktop"); held && p != ctrl.ID {
		t.Fatalf("unexpected holder: %q held=%v", p, held)
	}
	if _, _, err := sess.Acquire("alice", "desktop", obs.ID, true); err != nil {
		// Promote the observer in the local registry first, as the service
		// does before granting a new fence.
		t.Fatal(err)
	}
	f2, err := AcquireControl(ctx, s, sess, "alice", "desktop", obs.ID, true)
	if err != nil {
		t.Fatalf("force takeover after release: %v", err)
	}
	f2.Close()
	if p, held, _ := s.ControlHolder(ctx, "alice", "desktop"); held || p != "" {
		t.Fatalf("final release left holder: %q held=%v", p, held)
	}
}
