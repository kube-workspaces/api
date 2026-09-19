package exec

import (
	"context"
	"net"
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
