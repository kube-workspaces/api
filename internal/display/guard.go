package display

import (
	"context"
	"sync"
	"time"
)

// Guard bounds validity using request-start times on this process's monotonic
// clock. A delayed renewal must not resurrect an expired owner.
//
// One guard owns the claims behind one VNC-console session: the capture lease
// always (the console is single-connection) and, when the caller also owns
// the interactive display, the seat lease. An observer-only broker generation
// holds the capture alone while a Tier 1 session holds the seat; it upgrades
// with EnsureSeat once the seat frees. Losing any held claim stops the guard,
// because a session that lost the seat was taken over and a session that lost
// the capture must not keep a console someone else is about to dial.
type Guard struct {
	mu        sync.Mutex
	deadline  time.Time
	closed    bool
	store     *Store
	ns, name  string
	seatID    string // empty while the seat claim is not held
	captureID string
	cancel    context.CancelFunc
	done      chan struct{}
}

// Acquire claims the interactive seat (tier "vnc") and the VNC-console
// capture for ns/name, so exactly one session can drive the console and the
// console is reserved before it is dialled. A capture failure releases the
// freshly claimed seat: the pair is atomic from the caller's point of view.
func Acquire(ctx context.Context, store *Store, ns, name string) (*Guard, error) {
	claimCtx, claimCancel := context.WithTimeout(ctx, 2*time.Second)
	seatID, err := store.Claim(claimCtx, ns, name, "vnc")
	claimCancel()
	if err != nil {
		return nil, err
	}
	g, err := acquireCapture(ctx, store, ns, name, seatID)
	if err != nil {
		relCtx, relCancel := context.WithTimeout(context.Background(), time.Second)
		defer relCancel()
		_ = store.Release(relCtx, ns, name, seatID)
		return nil, err
	}
	return g, nil
}

// AcquireCapture claims only the VNC-console capture. It is the observer-only
// mode of a shared display: the desktop is driven elsewhere (a Tier 1 session
// holds the seat), but observers still need the one console connection
// coordinated so no second dialer races them to it.
func AcquireCapture(ctx context.Context, store *Store, ns, name string) (*Guard, error) {
	return acquireCapture(ctx, store, ns, name, "")
}

func acquireCapture(ctx context.Context, store *Store, ns, name, seatID string) (*Guard, error) {
	started := time.Now()
	claimCtx, claimCancel := context.WithTimeout(ctx, 2*time.Second)
	captureID, err := store.ClaimCapture(claimCtx, ns, name)
	claimCancel()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	g := &Guard{deadline: started.Add(ClientTTL), store: store, ns: ns, name: name,
		seatID: seatID, captureID: captureID, cancel: cancel, done: make(chan struct{})}
	go g.run(ctx)
	return g, nil
}

// EnsureSeat claims the interactive seat (tier "vnc") for a guard that
// started capture-only, upgrading an observer-only generation to a full
// shared display once the previous seat holder (a Tier 1 session) let go. It
// is idempotent and fails with the claim's busy/ownership error when another
// session won the seat first.
func (g *Guard) EnsureSeat(ctx context.Context) error {
	g.mu.Lock()
	closed, has := g.closed, g.seatID != ""
	g.mu.Unlock()
	if closed {
		return ErrRevoked
	}
	if has {
		return nil
	}

	claimCtx, claimCancel := context.WithTimeout(ctx, 2*time.Second)
	id, err := g.store.Claim(claimCtx, g.ns, g.name, "vnc")
	claimCancel()
	if err != nil {
		return err
	}

	g.mu.Lock()
	if g.closed {
		// The guard died while the claim was in flight: release at once or the
		// seat sits held by a generation that no longer exists until fencing.
		g.mu.Unlock()
		relCtx, relCancel := context.WithTimeout(context.Background(), time.Second)
		defer relCancel()
		_ = g.store.Release(relCtx, g.ns, g.name, id)
		return ErrRevoked
	}
	g.seatID = id
	g.mu.Unlock()
	return nil
}

// HasSeat reports whether the guard currently holds the interactive seat —
// the condition under which shared-display participants may drive, not just
// watch.
func (g *Guard) HasSeat() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.seatID != "" && !g.closed
}

func (g *Guard) Deadline() (time.Time, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.deadline, !g.closed && time.Now().Before(g.deadline)
}

func (g *Guard) Done() <-chan struct{} { return g.done }

func (g *Guard) run(ctx context.Context) {
	defer close(g.done)
	defer func() { g.mu.Lock(); g.closed = true; g.mu.Unlock() }()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			deadline, valid := g.Deadline()
			if !valid {
				return
			}
			started := time.Now()
			renewCtx, cancel := context.WithDeadline(ctx, minTime(deadline, started.Add(time.Second)))
			err := g.renew(renewCtx)
			cancel()
			g.mu.Lock()
			if err != nil || !time.Now().Before(g.deadline) {
				g.closed = true
				g.mu.Unlock()
				return
			}
			g.deadline = started.Add(ClientTTL)
			g.mu.Unlock()
		}
	}
}

// renew keeps every held claim alive. Losing either one fails the guard: a
// revoked seat means the display was taken over, and a lost capture means the
// console this guard dialed belongs to someone else's session now.
func (g *Guard) renew(ctx context.Context) error {
	g.mu.Lock()
	seatID, captureID := g.seatID, g.captureID
	g.mu.Unlock()
	if seatID != "" {
		if err := g.store.Renew(ctx, g.ns, g.name, seatID); err != nil {
			return err
		}
	}
	return g.store.RenewCapture(ctx, g.ns, g.name, captureID)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Close must be invoked after the caller has closed its media sockets. It
// releases every claim the guard held; stale ids can never release a
// successor.
func (g *Guard) Close() {
	g.cancel()
	<-g.done
	g.mu.Lock()
	seatID, captureID := g.seatID, g.captureID
	g.seatID = ""
	g.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if seatID != "" {
		_ = g.store.Release(ctx, g.ns, g.name, seatID)
	}
	_ = g.store.ReleaseCapture(ctx, g.ns, g.name, captureID)
}
