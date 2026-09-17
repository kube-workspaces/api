package exec

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestDisplayCrossTierExclusion(t *testing.T) {
	ns, name := "test", t.Name()
	var revoked atomic.Bool
	release, ok := ClaimTier1Session(ns, name, func() { revoked.Store(true) })
	if !ok {
		t.Fatal("claim failed")
	}
	defer release()
	if !VNCInUse(ns, name) {
		t.Fatal("VNC status missed Tier 1 owner")
	}
	if _, ok := vncSessions.acquire(consoleKey(ns, name), &sessionHandle{}); ok {
		t.Fatal("VNC acquired a Tier 1-owned display")
	}
	if !TakeOverVNC(ns, name) || !revoked.Load() {
		t.Fatal("VNC takeover did not revoke Tier 1")
	}
	next := &sessionHandle{}
	if _, ok := vncSessions.acquire(consoleKey(ns, name), next); !ok {
		t.Fatal("successor claim failed")
	}
	defer vncSessions.release(consoleKey(ns, name), next)
	release()
	if !Tier1InUse(ns, name) {
		t.Fatal("stale release removed successor")
	}
	if _, ok := ClaimTier1Session(ns, name, func() {}); ok {
		t.Fatal("Tier 1 acquired a VNC-owned display")
	}
}

func TestDisplaySimultaneousClaims(t *testing.T) {
	key := consoleKey("test", t.Name())
	var winners atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Go(func() {
			<-start
			if _, ok := tier1Sessions.acquire(key, &sessionHandle{}); ok {
				winners.Add(1)
			}
		})
		wg.Go(func() {
			<-start
			if _, ok := vncSessions.acquire(key, &sessionHandle{}); ok {
				winners.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	defer vncSessions.forceRelease(key)
	if got := winners.Load(); got != 1 {
		t.Fatalf("got %d owners", got)
	}
}

func TestDisplaySlotHeldDuringRevocation(t *testing.T) {
	registry := newSessionRegistry()
	started, finish := make(chan struct{}), make(chan struct{})
	handle := &sessionHandle{cancel: func() { close(started); <-finish }}
	registry.acquire("display", handle)
	done := make(chan struct{})
	go func() { registry.forceRelease("display"); close(done) }()
	<-started
	if _, ok := registry.acquire("display", &sessionHandle{}); ok {
		close(finish)
		<-done
		t.Fatal("new input owner admitted before old owner teardown completed")
	}
	close(finish)
	<-done
	if registry.held("display") {
		t.Fatal("revoked slot still held")
	}
}

func TestRevocationDuringSocketSetup(t *testing.T) {
	for range 100 {
		var closed atomic.Int32
		h := &sessionHandle{}
		var wg sync.WaitGroup
		wg.Go(func() { h.setClose(func() { closed.Add(1) }) })
		wg.Go(h.closeAndCancel)
		wg.Wait()
		h.closeAndCancel()
		if closed.Load() != 1 {
			t.Fatalf("socket closed %d times", closed.Load())
		}
	}
}
