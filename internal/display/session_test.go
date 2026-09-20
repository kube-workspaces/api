package display

import (
	"errors"
	"testing"
	"time"
)

func fixedClock() (time.Time, func(*Sessions, time.Time)) {
	base := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	return base, func(s *Sessions, t time.Time) { s.now = func() time.Time { return t } }
}

func TestJoinObserverCapacityAndEpoch(t *testing.T) {
	base, setNow := fixedClock()
	s := NewSessions()
	setNow(s, base)

	first, err := s.Join("workspaces", "vm-a", RoleObserver)
	if err != nil {
		t.Fatalf("join observer: %v", err)
	}
	if first.Role != RoleObserver {
		t.Fatalf("role = %q, want observer", first.Role)
	}

	epoch := s.mustStatus(t, "workspaces", "vm-a").Epoch
	for i := 1; i < MaxParticipants; i++ {
		if _, err := s.Join("workspaces", "vm-a", RoleObserver); err != nil {
			t.Fatalf("join %d: %v", i, err)
		}
	}
	if _, err := s.Join("workspaces", "vm-a", RoleObserver); !errors.Is(err, ErrCapacity) {
		t.Fatalf("expected ErrCapacity, got %v", err)
	}

	// A different workspace is independent.
	if _, err := s.Join("workspaces", "vm-b", RoleController); err != nil {
		t.Fatalf("join other workspace controller: %v", err)
	}
	if got := s.mustStatus(t, "workspaces", "vm-b").Epoch; got == epoch {
		t.Fatalf("epoch %q should differ across workspaces", got)
	}
}

func TestJoinControllerConflict(t *testing.T) {
	s := NewSessions()
	ctrl, err := s.Join("workspaces", "vm-a", RoleController)
	if err != nil {
		t.Fatalf("join controller: %v", err)
	}
	if ctrl.Role != RoleController {
		t.Fatalf("role = %q, want controller", ctrl.Role)
	}
	if _, err := s.Join("workspaces", "vm-a", RoleController); !errors.Is(err, ErrControllerPresent) {
		t.Fatalf("expected ErrControllerPresent, got %v", err)
	}
	// Observers can still join an occupied display.
	if _, err := s.Join("workspaces", "vm-a", RoleObserver); err != nil {
		t.Fatalf("join observer while controlled: %v", err)
	}
	if _, err := s.Join("workspaces", "vm-a", "superuser"); err == nil {
		t.Fatal("expected unknown role to fail")
	}
}

// While a Tier 1 session holds the interactive seat, the registry must refuse
// controller joins and acquires (the shared display is observer-only), and
// accept them again once the lock clears.
func TestControlLockedRefusesControllerPaths(t *testing.T) {
	s := NewSessions()
	obs, err := s.Join("workspaces", "vm-a", RoleObserver)
	if err != nil {
		t.Fatalf("join observer: %v", err)
	}

	s.SetControlLocked("workspaces", "vm-a", true)
	if _, err := s.Join("workspaces", "vm-a", RoleController); !errors.Is(err, ErrControllerPresent) {
		t.Fatalf("controller join while locked: %v", err)
	}
	if _, _, err := s.Acquire("workspaces", "vm-a", obs.ID, true); !errors.Is(err, ErrControllerPresent) {
		t.Fatalf("force acquire while locked: %v", err)
	}
	// Observing is unaffected.
	if _, err := s.Join("workspaces", "vm-a", RoleObserver); err != nil {
		t.Fatalf("observer join while locked: %v", err)
	}

	s.SetControlLocked("workspaces", "vm-a", false)
	if _, _, err := s.Acquire("workspaces", "vm-a", obs.ID, false); err != nil {
		t.Fatalf("acquire after unlock: %v", err)
	}
	if got := s.mustParticipant(t, "workspaces", "vm-a", obs.ID); got.Role != RoleController {
		t.Fatalf("role after unlock = %q, want controller", got.Role)
	}

	// The lock lives apart from membership: it also gates the first
	// participant of a workspace that has no session entry yet.
	s.SetControlLocked("workspaces", "vm-b", true)
	if _, err := s.Join("workspaces", "vm-b", RoleController); !errors.Is(err, ErrControllerPresent) {
		t.Fatalf("controller join on a locked workspace with no members: %v", err)
	}
	s.SetControlLocked("workspaces", "vm-b", false)
	if _, err := s.Join("workspaces", "vm-b", RoleController); err != nil {
		t.Fatalf("controller join after unlock: %v", err)
	}
}

func TestAcquireReleaseTransfer(t *testing.T) {
	base, setNow := fixedClock()
	s := NewSessions()
	setNow(s, base)

	obs, err := s.Join("workspaces", "vm-a", RoleObserver)
	if err != nil {
		t.Fatalf("join observer: %v", err)
	}
	ctrl, err := s.Join("workspaces", "vm-a", RoleController)
	if err != nil {
		t.Fatalf("join controller: %v", err)
	}
	obs2, err := s.Join("workspaces", "vm-a", RoleObserver)
	if err != nil {
		t.Fatalf("join observer 2: %v", err)
	}

	// Observer tries acquire without force: occupied -> ErrControllerPresent.
	if _, _, err := s.Acquire("workspaces", "vm-a", obs.ID, false); !errors.Is(err, ErrControllerPresent) {
		t.Fatalf("acquire no force: expected ErrControllerPresent, got %v", err)
	}
	// With force: demotes current controller.
	if newCtrl, wasHeld, err := s.Acquire("workspaces", "vm-a", obs.ID, true); err != nil {
		t.Fatalf("acquire force: %v", err)
	} else if !wasHeld || newCtrl.ID != obs.ID {
		t.Fatalf("acquire force: wasHeld=%v new=%s want held + obs", wasHeld, newCtrl.ID)
	}
	// Old controller was demoted.
	if got := s.mustParticipant(t, "workspaces", "vm-a", ctrl.ID).Role; got != RoleObserver {
		t.Fatalf("demoted role = %q, want observer", got)
	}

	// Observer release (not controller) -> ErrNotController.
	if _, _, err := s.Release("workspaces", "vm-a", obs2.ID); !errors.Is(err, ErrNotController) {
		t.Fatalf("release by observer: expected ErrNotController, got %v", err)
	}
	// Controller release succeeds; observers stay attached.
	if _, wasHeld, err := s.Release("workspaces", "vm-a", obs.ID); err != nil {
		t.Fatalf("release: %v", err)
	} else if !wasHeld {
		t.Fatal("release should report wasHeld")
	}
	if st := s.mustStatus(t, "workspaces", "vm-a"); st.Controller != nil || len(st.Observers) != 3 {
		t.Fatalf("after release: controller=%v observers=%d want nil + 3 (obs, demoted ctrl, obs2)", st.Controller, len(st.Observers))
	}

	// Re-acquire then transfer to obs2.
	if _, _, err := s.Acquire("workspaces", "vm-a", obs.ID, false); err != nil {
		t.Fatalf("reacquire: %v", err)
	}
	if _, _, err := s.Transfer("workspaces", "vm-a", obs.ID, obs2.ID); err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if c := s.mustStatus(t, "workspaces", "vm-a").Controller; c == nil || c.ID != obs2.ID {
		t.Fatalf("controller after transfer = %+v, want obs2", c)
	}
	// Transfer by a non-controller -> ErrNotController.
	if _, _, err := s.Transfer("workspaces", "vm-a", ctrl.ID, obs.ID); !errors.Is(err, ErrNotController) {
		t.Fatalf("transfer by non-controller: expected ErrNotController, got %v", err)
	}
	// Transfer to a missing target -> ErrParticipantNotFound.
	if _, _, err := s.Transfer("workspaces", "vm-a", obs2.ID, "nope"); !errors.Is(err, ErrParticipantNotFound) {
		t.Fatalf("transfer to unknown: expected ErrParticipantNotFound, got %v", err)
	}
}

func TestLookupParticipant(t *testing.T) {
	s := NewSessions()
	p, err := s.Join("workspaces", "vm-a", RoleObserver)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if _, err := s.Lookup("workspaces", "vm-a", p.ID); err != nil {
		t.Fatalf("lookup known participant: %v", err)
	}
	if _, err := s.Lookup("workspaces", "vm-a", "nope"); !errors.Is(err, ErrParticipantNotFound) {
		t.Fatalf("lookup unknown: expected ErrParticipantNotFound, got %v", err)
	}
	// Lookup refreshes the idle deadline and must not mark the member connected.
	if err := s.SetConnected("workspaces", "vm-a", p.ID, true); err != nil {
		t.Fatalf("set connected: %v", err)
	}
	if st := s.mustStatus(t, "workspaces", "vm-a"); len(st.Observers) != 1 || !st.Observers[0].Connected {
		t.Fatalf("connected flag not recorded: %+v", st)
	}
}

func TestLeaveAndIdleEviction(t *testing.T) {
	base, setNow := fixedClock()
	s := NewSessions()
	setNow(s, base)

	ctrl, err := s.Join("workspaces", "vm-a", RoleController)
	if err != nil {
		t.Fatalf("join controller: %v", err)
	}
	obs, err := s.Join("workspaces", "vm-a", RoleObserver)
	if err != nil {
		t.Fatalf("join observer: %v", err)
	}

	// Leaving the controller clears control, observers stay.
	if err := s.Leave("workspaces", "vm-a", ctrl.ID); err != nil {
		t.Fatalf("leave controller: %v", err)
	}
	if st := s.mustStatus(t, "workspaces", "vm-a"); st.Controller != nil || len(st.Observers) != 1 {
		t.Fatalf("after leave: controller=%v observers=%d", st.Controller, len(st.Observers))
	}
	if err := s.Leave("workspaces", "vm-a", "ghost"); !errors.Is(err, ErrParticipantNotFound) {
		t.Fatalf("leave unknown: expected ErrParticipantNotFound, got %v", err)
	}

	// Idle expiry drops the observer; an exhausted session disappears.
	setNow(s, base.Add(IdleMembershipTTL))
	if st, ok := s.Status("workspaces", "vm-a"); ok {
		t.Fatalf("session should have been purged, got %+v", st)
	}
	if _, _, err := s.Acquire("workspaces", "vm-a", obs.ID, false); !errors.Is(err, ErrParticipantNotFound) {
		t.Fatalf("acquire purged participant: expected ErrParticipantNotFound, got %v", err)
	}

	// A fresh Join after full drain starts a new epoch and is free to control.
	once, err := s.Join("workspaces", "vm-a", RoleController)
	if err != nil {
		t.Fatalf("rejoin: %v", err)
	}
	if st := s.mustStatus(t, "workspaces", "vm-a"); st.Epoch == "" || len(st.Observers) != 0 {
		t.Fatalf("epoch=%q observers=%d", st.Epoch, len(st.Observers))
	}
	_ = once
}

func TestTouchKeepsParticipantAlive(t *testing.T) {
	base, setNow := fixedClock()
	s := NewSessions()
	setNow(s, base)

	obs, err := s.Join("workspaces", "vm-a", RoleObserver)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	setNow(s, base.Add(IdleMembershipTTL-time.Minute))
	if err := s.Touch("workspaces", "vm-a", obs.ID); err != nil {
		t.Fatalf("touch: %v", err)
	}
	setNow(s, base.Add(IdleMembershipTTL+time.Second))
	if st, ok := s.Status("workspaces", "vm-a"); !ok || len(st.Observers) != 1 {
		t.Fatalf("participant should survive with touch: ok=%v status=%+v", ok, st)
	}
}

func TestSetConnected(t *testing.T) {
	s := NewSessions()
	obs, err := s.Join("workspaces", "vm-a", RoleObserver)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if err := s.SetConnected("workspaces", "vm-a", obs.ID, true); err != nil {
		t.Fatalf("set connected: %v", err)
	}
	if st := s.mustStatus(t, "workspaces", "vm-a"); st.Observers[0].Connected != true {
		t.Fatalf("connected = %v, want true", st.Observers[0].Connected)
	}
	if err := s.SetConnected("workspaces", "vm-a", "ghost", true); !errors.Is(err, ErrParticipantNotFound) {
		t.Fatalf("set connected unknown: expected ErrParticipantNotFound, got %v", err)
	}
}

// The membership claimer runs exactly when a join creates a fresh session:
// the first join claims, later joins to the same live session do not, and a
// join after full drain claims again.
func TestJoinClaimsMembershipOnFreshSession(t *testing.T) {
	s := NewSessions()
	var claims []string
	s.SetMembershipClaimer(claimerFunc(func(ns, name string) error {
		claims = append(claims, ns+"/"+name)
		return nil
	}))

	if _, err := s.Join("workspaces", "vm-a", RoleObserver); err != nil {
		t.Fatalf("first join: %v", err)
	}
	if _, err := s.Join("workspaces", "vm-a", RoleObserver); err != nil {
		t.Fatalf("second join: %v", err)
	}
	if len(claims) != 1 || claims[0] != "workspaces/vm-a" {
		t.Fatalf("claims: %v", claims)
	}
	// A different workspace's first join claims independently.
	if _, err := s.Join("workspaces", "vm-b", RoleObserver); err != nil {
		t.Fatalf("vm-b join: %v", err)
	}
	if len(claims) != 2 {
		t.Fatalf("claims after vm-b: %v", claims)
	}
}

// A claim owned by another replica unwinds the fresh member: the join fails
// with the typed OwnershipError, the registry holds nothing, and the next
// join (e.g. after forwarding) can claim again.
func TestJoinUnwindsWhenMembershipOwnedElsewhere(t *testing.T) {
	s := NewSessions()
	s.SetMembershipClaimer(claimerFunc(func(ns, name string) error {
		return &OwnershipError{Owner: "replica-b", Kind: "display-membership"}
	}))
	if _, err := s.Join("workspaces", "vm-a", RoleObserver); err == nil {
		t.Fatal("join must fail when the claim is owned elsewhere")
	} else {
		var oe *OwnershipError
		if !errors.As(err, &oe) || oe.Owner != "replica-b" {
			t.Fatalf("join error: %v", err)
		}
	}
	if st, ok := s.Status("workspaces", "vm-a"); ok {
		t.Fatalf("member stranded on an unwound join: %+v", st)
	}
	// Same for a controller join (control must not linger either).
	if _, err := s.Join("workspaces", "vm-a", RoleController); err == nil {
		t.Fatal("controller join must fail when the claim is owned elsewhere")
	}
	if st, ok := s.Status("workspaces", "vm-a"); ok {
		t.Fatalf("controller stranded on an unwound join: %+v", st)
	}
	// Ownership resolves: a later join succeeds.
	s.SetMembershipClaimer(claimerFunc(func(ns, name string) error { return nil }))
	if _, err := s.Join("workspaces", "vm-a", RoleObserver); err != nil {
		t.Fatalf("rejoin after ownership resolved: %v", err)
	}
	if st := s.mustStatus(t, "workspaces", "vm-a"); len(st.Observers) != 1 {
		t.Fatalf("observers after rejoin: %d", len(st.Observers))
	}
}

// Keys drives the membership sweeper: it purges idle sessions first, so a
// workspace with no live members does not keep its routing marker.
func TestKeysPurgesBeforeListing(t *testing.T) {
	base, setNow := fixedClock()
	s := NewSessions()
	setNow(s, base)
	if _, err := s.Join("workspaces", "vm-a", RoleObserver); err != nil {
		t.Fatalf("join: %v", err)
	}
	if _, err := s.Join("workspaces", "vm-b", RoleObserver); err != nil {
		t.Fatalf("join: %v", err)
	}
	setNow(s, base.Add(IdleMembershipTTL+time.Second))
	// vm-c joined "now" stays live; the other two must purge.
	fresh, err := s.Join("workspaces", "vm-c", RoleObserver)
	if err != nil {
		t.Fatalf("fresh join: %v", err)
	}
	_ = fresh
	keys := s.Keys()
	if len(keys) != 1 || keys[0] != "workspaces/vm-c" {
		t.Fatalf("keys: %v", keys)
	}
}

type claimerFunc func(ns, name string) error

func (f claimerFunc) ClaimForJoin(ns, name string) error { return f(ns, name) }

func (s *Sessions) mustStatus(t *testing.T, ns, name string) Status {
	t.Helper()
	st, ok := s.Status(ns, name)
	if !ok {
		t.Fatalf("no session for %s/%s", ns, name)
	}
	return st
}

func (s *Sessions) mustParticipant(t *testing.T, ns, name, id string) Participant {
	t.Helper()
	st := s.mustStatus(t, ns, name)
	if c := st.Controller; c != nil && c.ID == id {
		return *c
	}
	for _, o := range st.Observers {
		if o.ID == id {
			return *o
		}
	}
	t.Fatalf("participant %s not found", id)
	return Participant{}
}
