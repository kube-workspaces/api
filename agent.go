package kubeworkspaces

import (
	"context"
	"fmt"

	genagent "github.com/kube-workspaces/api/gen/agent"
	"github.com/kube-workspaces/api/internal/agent"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/k8s"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// agent service implementation. Handwritten behavior lives here, outside the
// generated gen/ packages. Tickets are minted by this API and validated at
// the proxy edge (see internal/agent for the trust model); the guest checks
// binding and freshness only.
type agentsrvc struct {
	wsClient *k8s.WorkspaceClient
	sessions *agent.Store
	// keys returns the HMAC signing keys (rotation-safe: current first).
	keys func(ctx context.Context) ([][]byte, error)
}

// NewAgent returns the agent service implementation.
func NewAgent(wsClient *k8s.WorkspaceClient, sessions *agent.Store, keys func(ctx context.Context) ([][]byte, error)) genagent.Service {
	if sessions == nil {
		sessions = agent.NewStore()
	}
	return &agentsrvc{wsClient: wsClient, sessions: sessions, keys: keys}
}

// authorizeEditor enforces the console gate: an authenticated editor/admin with
// access to the requested namespace (mirrors the display service).
func (s *agentsrvc) authorizeEditor(ctx context.Context, requested string) (string, error) {
	ns := requested
	if ns == "" {
		ns = "workspaces"
	}
	if auth.AuthEnabled(ctx) {
		user := auth.UserFromContext(ctx)
		if user == nil {
			return "", genagent.Unauthorized("authentication required")
		}
		if !auth.HasMinimumRole(user.Role, "editor") {
			return "", genagent.Forbidden("editor or admin role required for agent access")
		}
		if !auth.UserHasNamespaceAccess(user, ns) {
			return "", genagent.Forbidden("no access to workspace namespace")
		}
	}
	return ns, nil
}

// agentWorkspace resolves the workspace and its stable binding. Only VM
// workspaces can host a guest agent; anything else is an invalid attach, not
// a silent success. Generation is the controller's stable provisioning
// generation when present (never the volatile object generation).
func (s *agentsrvc) agentWorkspace(ctx context.Context, ns, name string) (uid, generation string, err error) {
	obj, err := s.wsClient.GetWorkspace(ctx, ns, name)
	if err != nil {
		return "", "", genagent.NotFound(fmt.Sprintf("workspace \"%s\" not found", name))
	}
	wsType, _, _ := unstructured.NestedString(obj.Object, "spec", "type")
	if wsType == "" {
		wsType = "container"
	}
	if wsType != "vm" {
		return "", "", genagent.Invalid("agent sessions are only available for VM workspaces")
	}
	uid = string(obj.GetUID())
	annotations := obj.GetAnnotations()
	generation = annotations["kubeworkspaces.io/windows-provisioned-generation"]
	return uid, generation, nil
}

// Attach mints a short-lived ticket bound to the workspace. The participant
// label defaults to the authenticated user (or "viewer" when auth is off);
// it is echoed in records, never an authorization boundary.
func (s *agentsrvc) Attach(ctx context.Context, payload *genagent.AgentAttachPayload) (*genagent.AgentTicket, error) {
	ns, err := s.authorizeEditor(ctx, payload.Namespace)
	if err != nil {
		return nil, err
	}
	uid, generation, err := s.agentWorkspace(ctx, ns, payload.Name)
	if err != nil {
		return nil, err
	}
	keys, err := s.keys(ctx)
	if err != nil {
		return nil, genagent.Invalid(fmt.Sprintf("ticket service unavailable: %v", err))
	}
	participant := "viewer"
	if payload.Participant != nil && *payload.Participant != "" {
		participant = *payload.Participant
	} else if auth.AuthEnabled(ctx) {
		if user := auth.UserFromContext(ctx); user != nil && user.Email != "" {
			participant = user.Email
		}
	}
	id, ticket, err := s.sessions.Mint(uid, generation, participant, 1, keys)
	if err != nil {
		return nil, genagent.Invalid(fmt.Sprintf("ticket service unavailable: %v", err))
	}
	return &genagent.AgentTicket{
		ID:       id,
		Ticket:   ticket,
		TTLMs:    int(agent.DefaultTTL.Milliseconds()),
		Protocol: agent.Protocol,
	}, nil
}

// Renew extends a live session. Unknown or expired ids are not_found: the
// proxy drops the bridge and the viewer re-attaches (no silent resurrection).
func (s *agentsrvc) Renew(ctx context.Context, payload *genagent.RenewPayload) (*genagent.AgentRenew, error) {
	ns, err := s.authorizeEditor(ctx, payload.Namespace)
	if err != nil {
		return nil, err
	}
	if _, _, err := s.agentWorkspace(ctx, ns, payload.Name); err != nil {
		return nil, err
	}
	if _, ok := s.sessions.Renew(payload.SessionID); !ok {
		return nil, genagent.NotFound(fmt.Sprintf("agent session for workspace \"%s\" not found", payload.Name))
	}
	return &genagent.AgentRenew{
		TTLMs:    int(agent.DefaultTTL.Milliseconds()),
		Protocol: agent.Protocol,
	}, nil
}

// Status reports live agent session state: whether any unexpired session
// is bound to the workspace. This is the API leg of the indicator contract:
// clients combine it with proxy counters and guest telemetry, never alone.
func (s *agentsrvc) Status(ctx context.Context, payload *genagent.StatusPayload) (*genagent.AgentStatus, error) {
	ns, err := s.authorizeEditor(ctx, payload.Namespace)
	if err != nil {
		return nil, err
	}
	uid, _, err := s.agentWorkspace(ctx, ns, payload.Name)
	if err != nil {
		return nil, err
	}
	count := s.sessions.Active(uid)
	return &genagent.AgentStatus{
		Active:   count > 0,
		Sessions: count,
		Protocol: agent.Protocol,
	}, nil
}

// Release revokes a session id immediately. Unknown ids report ok:
// releases are best-effort (lost releases expire via TTL).
func (s *agentsrvc) Release(ctx context.Context, payload *genagent.ReleasePayload) (*genagent.AgentRelease, error) {
	ns, err := s.authorizeEditor(ctx, payload.Namespace)
	if err != nil {
		return nil, err
	}
	if _, _, err := s.agentWorkspace(ctx, ns, payload.Name); err != nil {
		return nil, err
	}
	s.sessions.Release(payload.SessionID)
	return &genagent.AgentRelease{OK: true}, nil
}
