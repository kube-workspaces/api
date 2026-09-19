package display

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrInputFenced means the controller's input lease is no longer renewable, so
// its writes must stop within the fencing bound (ClientTTL).
var ErrInputFenced = errors.New("controller input fencing lost")

// Fence is the input boundary for one controller participant. Admitting a
// controller to the registry is not enough to write: the control lease must be
// renewable and the local Registry must still list the participant as
// controller. A Fence therefore gates input dispatch, dropping writes at the
// fencing bound when either leg is lost, mirroring the legacy Guard semantics.
type Fence struct {
	mu          sync.Mutex
	deadline    time.Time
	closed      bool
	store       *Store
	sessions    *Sessions
	ns, name    string
	participant string
	token       string
	now         func() time.Time
	cancel      context.CancelFunc
	done        chan struct{}
}

// AcquireControl grants participant the input fence on ns/name. With force, an
// existing control holder is revoked first (its renewal dies at once, its input
// no later than ClientTTL) and this call claims the slot as soon as it is free;
// without force the local Registry must already list participant as controller.
// The returned Fence renews the lease in the background until Close.
func AcquireControl(ctx context.Context, store *Store, sessions *Sessions, ns, name, participant string, force bool) (*Fence, error) {
	if !force {
		st, ok := sessions.Status(ns, name)
		if !ok || st.Controller == nil || st.Controller.ID != participant || st.Controller.Role != RoleController {
			return nil, ErrNotController
		}
	}
	started := store.now()
	claimCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	if force {
		if _, err := store.RevokeControl(claimCtx, ns, name); err != nil {
			cancel()
			return nil, err
		}
	}
	token, err := store.ClaimControl(claimCtx, ns, name, participant)
	cancel()
	if err != nil {
		return nil, err
	}
	ctx, cancel = context.WithCancel(ctx)
	f := &Fence{deadline: started.Add(ClientTTL), store: store, sessions: sessions,
		ns: ns, name: name, participant: participant, token: token,
		now: store.now, cancel: cancel, done: make(chan struct{})}
	go f.run(ctx)
	return f, nil
}

func (f *Fence) Deadline() (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deadline, !f.closed && f.now().Before(f.deadline)
}

func (f *Fence) Done() <-chan struct{} { return f.done }

func (f *Fence) run(ctx context.Context) {
	defer close(f.done)
	defer func() { f.mu.Lock(); f.closed = true; f.mu.Unlock() }()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			deadline, valid := f.Deadline()
			if !valid {
				return
			}
			started := f.now()
			renewCtx, cancel := context.WithDeadline(ctx, minTime(deadline, started.Add(time.Second)))
			err := f.store.RenewControl(renewCtx, f.ns, f.name, f.token)
			cancel()
			f.mu.Lock()
			if err != nil || !f.now().Before(f.deadline) {
				f.closed = true
				f.mu.Unlock()
				return
			}
			f.deadline = started.Add(ClientTTL)
			f.mu.Unlock()
		}
	}
}

// DispatchInput runs fn only while participant still holds the registry
// controller role and the control lease has not passed its fencing bound;
// otherwise the write is dropped with the appropriate error.
func (f *Fence) DispatchInput(fn func()) error {
	f.mu.Lock()
	if f.closed || !f.now().Before(f.deadline) {
		f.mu.Unlock()
		return ErrInputFenced
	}
	f.mu.Unlock()
	st, ok := f.sessions.Status(f.ns, f.name)
	if !ok || st.Controller == nil || st.Controller.ID != f.participant || st.Controller.Role != RoleController {
		return ErrNotController
	}
	fn()
	return nil
}

// Close stops renewing and releases the control lease. Like Guard.Close it must
// be called after the associated input path has been closed; a stale token
// cannot release a successor.
func (f *Fence) Close() {
	f.cancel()
	<-f.done
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = f.store.ReleaseControl(ctx, f.ns, f.name, f.token)
}
