package exec

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestSessionRegistryAcquireAndRelease(t *testing.T) {
	r := newSessionRegistry()
	key := "chris-at-fordham-id-au/cf-debian-gnome-vm-0"

	h1 := &sessionHandle{cancel: func() {}}
	if _, ok := r.acquire(key, h1); !ok {
		t.Fatal("first acquire should succeed")
	}
	if !r.held(key) {
		t.Fatal("registry should report session active after acquire")
	}

	var existing *sessionHandle
	existing, ok := r.acquire(key, &sessionHandle{cancel: func() {}})
	if ok {
		t.Fatal("second acquire should fail while a session is active")
	}
	if existing != h1 {
		t.Fatal("failed acquire should return the existing session")
	}

	if !r.stillCurrent(key, h1) {
		t.Fatal("h1 should still own the slot")
	}

	// A session that never acquired must not be able to release the slot.
	r.release(key, &sessionHandle{id: h1.id + 1})
	if !r.held(key) {
		t.Fatal("release by a non-owner must not evict the active session")
	}

	r.release(key, h1)
	if r.held(key) {
		t.Fatal("release by the owner should clear the slot")
	}
}

func TestSessionRegistryForceRelease(t *testing.T) {
	r := newSessionRegistry()
	key := "ns/test"

	var closed atomic.Bool
	h1 := &sessionHandle{
		cancel: func() {},
		close:  func() { closed.Store(true) },
	}
	if _, ok := r.acquire(key, h1); !ok {
		t.Fatal("acquire should succeed")
	}

	if !r.forceRelease(key) {
		t.Fatal("forceRelease should report an active session")
	}
	if r.forceRelease(key) {
		t.Fatal("forceRelease on a free slot should report no session")
	}
	if r.held(key) {
		t.Fatal("slot should be free after forceRelease")
	}
	if !closed.Load() {
		t.Fatal("forceRelease should tear down the evicted session")
	}

	// The evicted session must not unregister its successor on unwind.
	if _, ok := r.acquire(key, &sessionHandle{cancel: func() {}}); !ok {
		t.Fatal("a successor should be able to acquire the slot")
	}
	r.release(key, h1) // late unwind of the evicted session
	if !r.held(key) {
		t.Fatal("late release by an evicted session must not clear the successor")
	}
}

func TestSessionRegistryConcurrentAcquire(t *testing.T) {
	r := newSessionRegistry()
	key := "ns/race"
	const workers = 64

	var wg sync.WaitGroup
	var winners atomic.Int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := r.acquire(key, &sessionHandle{cancel: func() {}}); ok {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()

	if winners.Load() != 1 {
		t.Fatalf("exactly one concurrent acquire should win, got %d", winners.Load())
	}
	if !r.held(key) {
		t.Fatal("a winner should hold the slot")
	}
}
