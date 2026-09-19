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
