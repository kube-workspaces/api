package display

import (
	"context"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

func TestAgentTransportOwnerFencedBySeat(t *testing.T) {
	s := NewStore(fake.NewClientset())
	ctx := context.Background()
	id, err := s.ClaimAgent(ctx, "ns", "ws", "proxy-a")
	if err != nil {
		t.Fatal(err)
	}
	if info, err := s.SeatInfo(ctx, "ns", "ws"); err != nil || info.ProxyOwner != "proxy-a" || info.Transport != "agent" || !info.InUse {
		t.Fatalf("info=%+v err=%v", info, err)
	}
	if _, err := s.Revoke(ctx, "ns", "ws"); err != nil {
		t.Fatal(err)
	}
	if info, _ := s.SeatInfo(ctx, "ns", "ws"); info.ProxyOwner != "" || info.Transport != "" {
		t.Fatal("revoked transport/owner still advertised")
	}
	if err := s.Renew(ctx, "ns", "ws", id); err == nil {
		t.Fatal("revoked controller renewed")
	}
}
