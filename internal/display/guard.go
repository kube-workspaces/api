package display

import (
	"context"
	"sync"
	"time"
)

// Guard bounds validity using request-start times on this process's monotonic
// clock. A delayed renewal must not resurrect an expired owner.
type Guard struct {
	mu           sync.Mutex
	deadline     time.Time
	closed       bool
	store        *Store
	ns, name, id string
	cancel       context.CancelFunc
	done         chan struct{}
}

func Acquire(ctx context.Context, store *Store, ns, name string) (*Guard, error) {
	started := time.Now()
	claimCtx, claimCancel := context.WithTimeout(ctx, 2*time.Second)
	id, err := store.Claim(claimCtx, ns, name, "vnc")
	claimCancel()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	g := &Guard{deadline: started.Add(ClientTTL), store: store, ns: ns, name: name, id: id, cancel: cancel, done: make(chan struct{})}
	go g.run(ctx)
	return g, nil
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
			err := g.store.Renew(renewCtx, g.ns, g.name, g.id)
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

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Close must be invoked after the caller has closed its media sockets.
func (g *Guard) Close() {
	g.cancel()
	<-g.done
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = g.store.Release(ctx, g.ns, g.name, g.id)
}
