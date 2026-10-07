package kubeworkspaces

import (
	"context"
	"testing"

	genagent "github.com/kube-workspaces/api/gen/agent"
	"github.com/kube-workspaces/api/internal/agent"
	"github.com/kube-workspaces/api/internal/k8s"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func newAgentSvc(t *testing.T) genagent.Service {
	t.Helper()
	fake := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(),
		workspaceCR("workspaces", "vm-a", "vm"),
		workspaceCR("workspaces", "wordpress", "container"),
	)
	keys := func(ctx context.Context) ([][]byte, error) {
		return [][]byte{[]byte("test-key-0123456789abcdef")}, nil
	}
	return NewAgent(k8s.NewWorkspaceClientFor(fake), agent.NewStore(), keys)
}

func TestAgentAttachMintsBoundTicket(t *testing.T) {
	svc := newAgentSvc(t)
	ctx := context.Background()

	result, err := svc.Attach(ctx, &genagent.AgentAttachPayload{Namespace: "workspaces", Name: "vm-a"})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if result.ID == "" || result.Ticket == "" {
		t.Fatalf("attach must return id and ticket: %+v", result)
	}
	if result.Protocol != 1 || result.TTLMs <= 0 {
		t.Fatalf("attach must report protocol and ttl: %+v", result)
	}

	if _, err := svc.Attach(ctx, &genagent.AgentAttachPayload{Namespace: "workspaces", Name: "ghost"}); !asGoaError[genagent.NotFound](t, err) {
		t.Fatalf("unknown workspace should be not_found, got %v", err)
	}
	if _, err := svc.Attach(ctx, &genagent.AgentAttachPayload{Namespace: "workspaces", Name: "wordpress"}); !asGoaError[genagent.Invalid](t, err) {
		t.Fatalf("container workspace should be invalid, got %v", err)
	}
}

func TestAgentRenewReleaseLifecycle(t *testing.T) {
	svc := newAgentSvc(t)
	ctx := context.Background()

	attached, err := svc.Attach(ctx, &genagent.AgentAttachPayload{Namespace: "workspaces", Name: "vm-a"})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	renewed, err := svc.Renew(ctx, &genagent.RenewPayload{Namespace: "workspaces", Name: "vm-a", SessionID: attached.ID})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewed.Protocol != 1 || renewed.TTLMs <= 0 {
		t.Fatalf("renew must report protocol and ttl: %+v", renewed)
	}
	released, err := svc.Release(ctx, &genagent.ReleasePayload{Namespace: "workspaces", Name: "vm-a", SessionID: attached.ID})
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if !released.OK {
		t.Fatal("release must report ok")
	}
	if _, err := svc.Renew(ctx, &genagent.RenewPayload{Namespace: "workspaces", Name: "vm-a", SessionID: attached.ID}); !asGoaError[genagent.NotFound](t, err) {
		t.Fatalf("released session must not renew, got %v", err)
	}
	// Best-effort release of unknown ids reports ok, never an error.
	again, err := svc.Release(ctx, &genagent.ReleasePayload{Namespace: "workspaces", Name: "vm-a", SessionID: "nope"})
	if err != nil || !again.OK {
		t.Fatalf("unknown release must report ok, got %v %+v", err, again)
	}
}
