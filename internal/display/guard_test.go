package display

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGuardRenewsAndStopsOnRevoke(t *testing.T) {
	s := NewStore(fake.NewClientset())
	g, err := Acquire(context.Background(), s, "alice", "desktop")
	if err != nil {
		t.Fatal(err)
	}
	// While the API is reachable the guard renews and stays valid.
	select {
	case <-g.Done():
		t.Fatal("guard expired while renewals succeed")
	case <-time.After(2500 * time.Millisecond):
	}
	if _, valid := g.Deadline(); !valid {
		t.Fatal("guard should be valid with renewals succeeding")
	}
	if _, err := s.Revoke(context.Background(), "alice", "desktop"); err != nil {
		t.Fatal(err)
	}
	// The guard must stop renewing and close within one tick of observing the
	// revoke (the takeover path), so it stops relaying input to the guest.
	select {
	case <-g.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("guard did not stop after revoke")
	}
	if inUse, _ := s.InUse(context.Background(), "alice", "desktop"); !inUse {
		t.Fatal("revoked owner slot freed before its release")
	}
	g.Close()
	if inUse, _ := s.InUse(context.Background(), "alice", "desktop"); inUse {
		t.Fatal("slot still held after guard close")
	}
}

func TestGuardDiesWhenStoreUnavailable(t *testing.T) {
	s := NewStore(fake.NewClientset())
	g, err := Acquire(context.Background(), s, "alice", "desktop")
	if err != nil {
		t.Fatal(err)
	}
	// Partition simulation: the lease disappears from the owner's view, so its
	// renewals fail. The guard must stop (fencing the victim's input) without
	// being told explicitly. It must not Release a lease it can no longer see.
	if err := s.client.CoordinationV1().Leases("alice").Delete(context.Background(), leaseName("desktop"), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("guard kept renewing against a vanished lease")
	}
}

// Guard expiry is measured on the local monotonic clock from request start. A
// renewal that arrives after the deadline must not resurrect an expired owner.
func TestGuardDeadlineIsLocal(t *testing.T) {
	s := NewStore(fake.NewClientset())
	g, err := Acquire(context.Background(), s, "alice", "desktop")
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.mu.Lock()
	g.deadline = time.Now().Add(10 * time.Millisecond)
	g.mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	if _, valid := g.Deadline(); valid {
		t.Fatal("deadline stayed valid past expiry")
	}
}
