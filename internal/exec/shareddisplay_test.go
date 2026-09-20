package exec

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/broker"
	"github.com/kube-workspaces/api/internal/display"
	"k8s.io/client-go/kubernetes/fake"
)

// TestSharedDisplayAttachDetachLifecycle exercises generation lifetime: many
// participants share one broker/upstream, the seat lease survives until the
// last detach, and a new generation can claim it afterwards.
func TestSharedDisplayAttachDetachLifecycle(t *testing.T) {
	store := display.NewStore(fake.NewClientset())
	sd := &SharedDisplay{
		opts: &Options{Display: store},
		live: make(map[string]*sharedRuntime),
		dial: func(context.Context, string, string) (broker.Stream, error) {
			// A dead upstream is fine: broker.Run fails the handshake at once
			// and the teardown wait only needs that to settle.
			client, server := net.Pipe()
			_ = client.Close()
			return server, nil
		},
	}
	ctx := context.Background()

	a, err := sd.attach(ctx, "ws", "vm-a")
	if err != nil {
		t.Fatalf("first attach: %v", err)
	}
	b, err := sd.attach(ctx, "ws", "vm-a")
	if err != nil {
		t.Fatalf("second attach: %v", err)
	}
	if a != b {
		t.Fatal("participants do not share one generation")
	}
	if inUse, _ := store.InUse(ctx, "ws", "vm-a"); !inUse {
		t.Fatal("seat lease not held for the generation")
	}

	// Mid-session churn: a participant leaves and another joins the same
	// generation without touching the seat lease.
	sd.detach("ws", "vm-a", b)
	c, err := sd.attach(ctx, "ws", "vm-a")
	if err != nil {
		t.Fatalf("attach while generation live: %v", err)
	}
	if c != a {
		t.Fatal("churn created a new generation")
	}
	sd.detach("ws", "vm-a", c)
	if inUse, _ := store.InUse(ctx, "ws", "vm-a"); !inUse {
		t.Fatal("seat released while a participant still holds the generation")
	}

	// Final detach tears down the generation and releases the seat lease.
	sd.detach("ws", "vm-a", a)
	if inUse, _ := store.InUse(ctx, "ws", "vm-a"); inUse {
		t.Fatal("seat lease still held after the last detach")
	}
	if _, ok := sd.live["ws/vm-a"]; ok {
		t.Fatal("generation not removed from the registry")
	}
	select {
	case <-a.done:
	case <-time.After(time.Second):
		t.Fatal("old generation did not stop")
	}

	// A fresh generation can claim the released seat lease.
	d, err := sd.attach(ctx, "ws", "vm-a")
	if err != nil {
		t.Fatalf("reattach after teardown: %v", err)
	}
	sd.detach("ws", "vm-a", d)
}

// TestSharedDisplayHandleCrossReplicaOwner proves the two-owner guarantee at
// the route: when replica A has generated the display, replica B's stream route
// must answer 409 with A's identity and must never dial the VM console.
func TestSharedDisplayHandleCrossReplicaOwner(t *testing.T) {
	cs := fake.NewClientset()
	storeA := display.NewStoreWithOwner(cs, "replica-a")
	storeB := display.NewStoreWithOwner(cs, "replica-b")
	ctx := context.Background()

	sdA := &SharedDisplay{
		opts: &Options{Display: storeA},
		live: make(map[string]*sharedRuntime),
		dial: func(context.Context, string, string) (broker.Stream, error) {
			client, server := net.Pipe()
			_ = client.Close()
			return server, nil
		},
	}
	rt, err := sdA.attach(ctx, "workspaces", "vm-a")
	if err != nil {
		t.Fatalf("replica A attach: %v", err)
	}
	defer sdA.detach("workspaces", "vm-a", rt)

	sdB := &SharedDisplay{
		opts: &Options{Display: storeB, Sessions: display.NewSessions()},
		live: make(map[string]*sharedRuntime),
		dial: func(context.Context, string, string) (broker.Stream, error) {
			t.Fatal("replica B must not dial a second VNC console")
			return nil, errors.New("unreachable")
		},
	}

	req := httptest.NewRequest("GET", "/v1/workspaces/vm-a/display/ws", nil)
	req.SetPathValue("name", "vm-a")
	rec := httptest.NewRecorder()
	sdB.Handle(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("non-owner replica status: got %d want %d", rec.Code, http.StatusConflict)
	}
	var body struct {
		Error string `json:"error"`
		Owner string `json:"owner"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("non-owner response is not JSON: %v (body %q)", err, rec.Body.String())
	}
	if body.Owner != "replica-a" {
		t.Fatalf("non-owner response identifies owner %q, want %q", body.Owner, "replica-a")
	}
}

// TestSharedDisplayHandleBindsParticipant proves a stream can attach to a
// participant registered through the REST membership API (?participant=): the
// route validates the participant, its role and attachment state before any
// WebSocket conversation.
func TestSharedDisplayHandleBindsParticipant(t *testing.T) {
	store := display.NewStore(fake.NewClientset())
	sessions := display.NewSessions()
	sd := &SharedDisplay{
		opts: &Options{Display: store, Sessions: sessions},
		live: make(map[string]*sharedRuntime),
		dial: func(context.Context, string, string) (broker.Stream, error) {
			t.Fatal("bind validation must fail before dialing")
			return nil, errors.New("unreachable")
		},
	}

	participant, err := sessions.Join("workspaces", "vm-a", display.RoleObserver)
	if err != nil {
		t.Fatalf("REST join: %v", err)
	}

	// Unknown participant id.
	req := httptest.NewRequest("GET", "/v1/workspaces/vm-a/display/ws?participant=nope", nil)
	req.SetPathValue("name", "vm-a")
	rec := httptest.NewRecorder()
	sd.Handle(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown participant: got %d want %d", rec.Code, http.StatusNotFound)
	}

	// Role mismatch: participant is an observer, stream requests controller.
	req = httptest.NewRequest("GET", "/v1/workspaces/vm-a/display/ws?participant="+participant.ID+"&role=controller", nil)
	req.SetPathValue("name", "vm-a")
	rec = httptest.NewRecorder()
	sd.Handle(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("role mismatch: got %d want %d", rec.Code, http.StatusConflict)
	}

	// Already attached elsewhere.
	if err := sessions.SetConnected("workspaces", "vm-a", participant.ID, true); err != nil {
		t.Fatalf("mark connected: %v", err)
	}
	req = httptest.NewRequest("GET", "/v1/workspaces/vm-a/display/ws?participant="+participant.ID+"&role=observer", nil)
	req.SetPathValue("name", "vm-a")
	rec = httptest.NewRecorder()
	sd.Handle(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("already-attached bind: got %d want %d", rec.Code, http.StatusConflict)
	}

	// Membership is untouched by rejected binds.
	if st, _ := sessions.Status("workspaces", "vm-a"); len(st.Observers) != 1 || !st.Observers[0].Connected {
		t.Fatalf("rejected binds altered the registry: %+v", st)
	}
}

// tier1Seat claims the interactive seat the way the Tier 1 path does.
func tier1Seat(t *testing.T, store *display.Store, ns, name string) string {
	t.Helper()
	id, err := store.Claim(context.Background(), ns, name, "tier1")
	if err != nil {
		t.Fatalf("tier1 seat claim: %v", err)
	}
	return id
}

// deadUpstream returns a dial fake whose broker fails the upstream handshake
// immediately; generation lifetime never depends on the stream surviving.
func deadUpstream() func(context.Context, string, string) (broker.Stream, error) {
	return func(context.Context, string, string) (broker.Stream, error) {
		client, server := net.Pipe()
		_ = client.Close()
		return server, nil
	}
}

// While a Tier 1 session holds the interactive seat, the shared display
// generates observer-only: the console capture is claimed, the seat is left
// to the Tier 1 session, and controller joins/acquires are refused.
func TestSharedDisplayObserverOnlyWhileTier1HoldsSeat(t *testing.T) {
	store := display.NewStore(fake.NewClientset())
	sessions := display.NewSessions()
	ctx := context.Background()
	tier1 := tier1Seat(t, store, "ws", "vm-a")

	sd := &SharedDisplay{
		opts: &Options{Display: store, Sessions: sessions},
		live: make(map[string]*sharedRuntime),
		dial: deadUpstream(),
	}
	rt, err := sd.attach(ctx, "ws", "vm-a")
	if err != nil {
		t.Fatalf("observer-only attach: %v", err)
	}
	if rt.full.Load() {
		t.Fatal("generation is full while a Tier 1 session holds the seat")
	}
	if tier, held, _ := store.SeatTier(ctx, "ws", "vm-a"); !held || tier != "tier1" {
		t.Fatalf("the broker disturbed the Tier 1 seat: tier=%q held=%v", tier, held)
	}
	if _, err := store.ClaimCapture(ctx, "ws", "vm-a"); !errors.Is(err, display.ErrBusy) {
		t.Fatalf("console capture not held by the generation: %v", err)
	}
	// The registry refuses controller paths while the generation is
	// observer-only, and accepts observers.
	if _, err := sessions.Join("ws", "vm-a", display.RoleController); !errors.Is(err, display.ErrControllerPresent) {
		t.Fatalf("controller join while Tier 1 drives: %v", err)
	}
	if _, err := sessions.Join("ws", "vm-a", display.RoleObserver); err != nil {
		t.Fatalf("observer join while Tier 1 drives: %v", err)
	}

	// Teardown releases the console and the lock, and leaves the Tier 1 seat
	// exactly as it was found.
	sd.detach("ws", "vm-a", rt)
	if _, err := store.ClaimCapture(ctx, "ws", "vm-a"); err != nil {
		t.Fatalf("console capture not released at teardown: %v", err)
	}
	if _, err := sessions.Join("ws", "vm-a", display.RoleController); err != nil {
		t.Fatalf("control lock leaked past the generation: %v", err)
	}
	if tier, held, _ := store.SeatTier(ctx, "ws", "vm-a"); !held || tier != "tier1" {
		t.Fatalf("Tier 1 seat after teardown: tier=%q held=%v", tier, held)
	}
	if err := store.Release(ctx, "ws", "vm-a", tier1); err != nil {
		t.Fatalf("tier1 release: %v", err)
	}
}

// The stream route refuses a controller attach on an observer-only generation
// before any upgrade, with a conflict, never dialing a second console.
func TestSharedDisplayControllerRefusedWhileTier1HoldsSeat(t *testing.T) {
	store := display.NewStore(fake.NewClientset())
	sessions := display.NewSessions()
	tier1 := tier1Seat(t, store, "workspaces", "vm-a")
	defer func() { _ = store.Release(context.Background(), "workspaces", "vm-a", tier1) }()

	sd := &SharedDisplay{
		opts: &Options{Display: store, Sessions: sessions},
		live: make(map[string]*sharedRuntime),
		dial: func(context.Context, string, string) (broker.Stream, error) {
			t.Fatal("a refused controller must not dial the console")
			return nil, errors.New("unreachable")
		},
	}

	// A REST-joined controller is refused even with a takeover force flag.
	p, err := sessions.Join("workspaces", "vm-a", display.RoleObserver)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	req := httptest.NewRequest("GET", "/v1/workspaces/vm-a/display/ws?participant="+p.ID+"&role=controller&force=1", nil)
	req.SetPathValue("name", "vm-a")
	rec := httptest.NewRecorder()
	sd.Handle(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("controller attach while Tier 1 drives: got %d want %d", rec.Code, http.StatusConflict)
	}
}

// When the Tier 1 session ends, the observer-only generation claims the freed
// seat and becomes the full shared display: control unlocks, the seat reads
// vnc, and observers may start driving.
func TestSharedDisplaySeatUpgradeAfterTier1Release(t *testing.T) {
	store := display.NewStore(fake.NewClientset())
	sessions := display.NewSessions()
	ctx := context.Background()
	tier1 := tier1Seat(t, store, "ws", "vm-a")

	sd := &SharedDisplay{
		opts: &Options{Display: store, Sessions: sessions},
		live: make(map[string]*sharedRuntime),
		dial: deadUpstream(),
	}
	rt, err := sd.attach(ctx, "ws", "vm-a")
	if err != nil {
		t.Fatalf("observer-only attach: %v", err)
	}
	defer sd.detach("ws", "vm-a", rt)

	if err := store.Release(ctx, "ws", "vm-a", tier1); err != nil {
		t.Fatalf("tier1 release: %v", err)
	}
	deadline := time.Now().Add(6 * time.Second)
	for !rt.full.Load() && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if !rt.full.Load() {
		t.Fatal("generation never upgraded after the Tier 1 session ended")
	}
	if tier, held, _ := store.SeatTier(ctx, "ws", "vm-a"); !held || tier != "vnc" {
		t.Fatalf("upgraded seat: tier=%q held=%v", tier, held)
	}
	if _, err := sessions.Join("ws", "vm-a", display.RoleController); err != nil {
		t.Fatalf("control still locked after the upgrade: %v", err)
	}
}

// Cross-replica observer-only generations coordinate through the capture
// lease: the loser learns the owner's identity instead of dialing.
func TestSharedDisplayCrossReplicaObserverOnlyOwner(t *testing.T) {
	cs := fake.NewClientset()
	storeA := display.NewStoreWithOwner(cs, "replica-a")
	storeB := display.NewStoreWithOwner(cs, "replica-b")
	ctx := context.Background()
	tier1 := tier1Seat(t, storeA, "workspaces", "vm-a")
	defer func() { _ = storeA.Release(ctx, "workspaces", "vm-a", tier1) }()

	sdB := &SharedDisplay{
		opts: &Options{Display: storeB, Sessions: display.NewSessions()},
		live: make(map[string]*sharedRuntime),
		dial: deadUpstream(),
	}
	rtB, err := sdB.attach(ctx, "workspaces", "vm-a")
	if err != nil {
		t.Fatalf("replica B observer-only attach: %v", err)
	}
	defer sdB.detach("workspaces", "vm-a", rtB)
	if rtB.full.Load() {
		t.Fatal("replica B generation is full while Tier 1 holds the seat")
	}

	sdA := &SharedDisplay{
		opts: &Options{Display: storeA, Sessions: display.NewSessions()},
		live: make(map[string]*sharedRuntime),
		dial: func(context.Context, string, string) (broker.Stream, error) {
			t.Fatal("replica A must not dial a second console")
			return nil, errors.New("unreachable")
		},
	}
	req := httptest.NewRequest("GET", "/v1/workspaces/vm-a/display/ws", nil)
	req.SetPathValue("name", "vm-a")
	rec := httptest.NewRecorder()
	sdA.Handle(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("replica A status: got %d want %d", rec.Code, http.StatusConflict)
	}
	var body struct {
		Owner string `json:"owner"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("replica A response is not JSON: %v (body %q)", err, rec.Body.String())
	}
	if body.Owner != "replica-b" {
		t.Fatalf("replica A routes to owner %q, want %q", body.Owner, "replica-b")
	}
}

// A generation whose claims die (takeover revokes the seat) must end: nobody
// may keep a console they can no longer renew.
func TestSharedDisplayGenerationEndsWhenGuardDies(t *testing.T) {
	store := display.NewStore(fake.NewClientset())
	ctx := context.Background()

	sd := &SharedDisplay{
		opts: &Options{Display: store},
		live: make(map[string]*sharedRuntime),
		dial: func(context.Context, string, string) (broker.Stream, error) {
			// A live but silent upstream: the broker waits on it, so the
			// generation ends only when the guard dies.
			client, server := net.Pipe()
			_ = client
			return server, nil
		},
	}
	rt, err := sd.attach(ctx, "ws", "vm-a")
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	if _, err := store.Revoke(ctx, "ws", "vm-a"); err != nil {
		t.Fatalf("takeover revoke: %v", err)
	}
	select {
	case <-rt.done:
	case <-time.After(5 * time.Second):
		t.Fatal("generation kept running after its seat was revoked")
	}

	// After the fenced takeover the console and the seat are claimable again.
	sd.detach("ws", "vm-a", rt)
	if _, err := store.ClaimCapture(ctx, "ws", "vm-a"); err != nil {
		t.Fatalf("console capture not released with the generation: %v", err)
	}
}

// While the pilot gate is off the stream route answers 404 before anything
// else: no join, no lease, no dial.
func TestSharedDisplayDisabledByPilotGate(t *testing.T) {
	store := display.NewStore(fake.NewClientset())
	sd := &SharedDisplay{
		opts: &Options{Display: store, Sessions: display.NewSessions(), SharedDisplayDisabled: true},
		live: make(map[string]*sharedRuntime),
		dial: func(context.Context, string, string) (broker.Stream, error) {
			t.Fatal("a gated route must not dial")
			return nil, errors.New("unreachable")
		},
	}
	req := httptest.NewRequest("GET", "/v1/workspaces/vm-a/display/ws", nil)
	req.SetPathValue("name", "vm-a")
	rec := httptest.NewRecorder()
	sd.Handle(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("pilot-gated stream route: got %d want %d", rec.Code, http.StatusNotFound)
	}
	if inUse, _ := store.InUse(context.Background(), "workspaces", "vm-a"); inUse {
		t.Fatal("a gated route claimed the seat")
	}
}
