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
