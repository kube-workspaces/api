package kubeworkspaces

import (
	"context"
	"errors"
	"fmt"
	"time"

	gendisplay "github.com/kube-workspaces/api/gen/display"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/display"
	"github.com/kube-workspaces/api/internal/k8s"
	"goa.design/clue/log"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const displayRoleObserver = "observer"

// display service implementation. Handwritten behavior lives here, outside the
// generated gen/ packages. Membership/control is enforced by the in-memory
// display.Sessions registry; authorization replicates the console-gate policy
// from the handwritten exec/vnc routes (editor/admin plus namespace access).
type displaysrvc struct {
	wsClient *k8s.WorkspaceClient
	sessions *display.Sessions
}

// NewDisplay returns the display service implementation.
func NewDisplay(wsClient *k8s.WorkspaceClient, sessions *display.Sessions) gendisplay.Service {
	return &displaysrvc{wsClient: wsClient, sessions: sessions}
}

// authorizeEditor enforces the console gate: an authenticated editor/admin with
// access to the requested namespace. It returns the effective namespace and a
// generated unauthorized/forbidden error on failure.
func (s *displaysrvc) authorizeEditor(ctx context.Context, requested string) (string, error) {
	ns := requested
	if ns == "" {
		ns = "workspaces"
	}
	if auth.AuthEnabled(ctx) {
		user := auth.UserFromContext(ctx)
		if user == nil {
			return "", gendisplay.Unauthorized("authentication required")
		}
		if !auth.HasMinimumRole(user.Role, "editor") {
			return "", gendisplay.Forbidden("editor or admin role required for display access")
		}
		if !auth.UserHasNamespaceAccess(user, ns) {
			return "", gendisplay.Forbidden("no access to workspace namespace")
		}
	}
	return ns, nil
}

// displayWorkspace resolves the workspace and reports whether it participates in
// shared display sessions. mutating controls whether a non-VM workspace is an
// error (mutations) or an enabled=false advert (capability/status reads).
func (s *displaysrvc) displayWorkspace(ctx context.Context, ns, name string, mutating bool) (bool, error) {
	obj, err := s.wsClient.GetWorkspace(ctx, ns, name)
	if err != nil {
		return false, gendisplay.NotFound(fmt.Sprintf("workspace \"%s\" not found", name))
	}
	wsType, _, _ := unstructured.NestedString(obj.Object, "spec", "type")
	if wsType == "" {
		wsType = "container"
	}
	if wsType != "vm" {
		if mutating {
			return false, gendisplay.Invalid("shared display sessions are only available for VM workspaces")
		}
		return false, nil
	}
	return true, nil
}

func mapParticipant(p *display.Participant) *gendisplay.Participant {
	if p == nil {
		return nil
	}
	return &gendisplay.Participant{
		ID:        p.ID,
		Role:      p.Role,
		Connected: p.Connected,
		JoinedAt:  p.JoinedAt.UTC().Format(time.RFC3339),
	}
}

func mapCapability(c display.Capability) *gendisplay.DisplayCapability {
	return &gendisplay.DisplayCapability{
		Enabled:            true,
		Protocol:           c.Protocol,
		Transports:         c.Transports,
		MaxParticipants:    intPtr(c.MaxParticipants),
		MaxWidth:           intPtr(c.MaxWidth),
		MaxHeight:          intPtr(c.MaxHeight),
		HandshakeTimeoutMs: intPtr(int(c.HandshakeTimeout / time.Millisecond)),
		ParticipantTTLMs:   intPtr(int(c.IdleMembershipTTL / time.Millisecond)),
		Participants:       intPtr(c.Participants),
		ControllerPresent:  boolPtr(c.ControllerPresent),
	}
}

// Capability advertises whether a workspace participates in shared display
// sessions and with which limits.
func (s *displaysrvc) Capability(ctx context.Context, p *gendisplay.CapabilityPayload) (res *gendisplay.DisplayCapability, err error) {
	log.Printf(ctx, "display.capability name=%s namespace=%s", p.Name, p.Namespace)
	ns, err := s.authorizeEditor(ctx, p.Namespace)
	if err != nil {
		return nil, err
	}
	isVM, err := s.displayWorkspace(ctx, ns, p.Name, false)
	if err != nil {
		return nil, err
	}
	if !isVM {
		// Back-compat: absence of the capability means legacy exclusive mode.
		return &gendisplay.DisplayCapability{Enabled: false, Protocol: 1}, nil
	}
	c := s.sessions.Capability(ns, p.Name)
	return mapCapability(c), nil
}

// Status reports live membership and control state.
func (s *displaysrvc) Status(ctx context.Context, p *gendisplay.StatusPayload) (res *gendisplay.DisplayStatus, err error) {
	log.Printf(ctx, "display.status name=%s namespace=%s", p.Name, p.Namespace)
	ns, err := s.authorizeEditor(ctx, p.Namespace)
	if err != nil {
		return nil, err
	}
	isVM, err := s.displayWorkspace(ctx, ns, p.Name, false)
	if err != nil {
		return nil, err
	}
	if !isVM {
		return &gendisplay.DisplayStatus{Enabled: false, Protocol: 1, Epoch: "", Participants: 0}, nil
	}
	st, _ := s.sessions.Status(ns, p.Name)
	res = &gendisplay.DisplayStatus{
		Enabled:      true,
		Protocol:     1,
		Epoch:        st.Epoch,
		Controller:   mapParticipant(st.Controller),
		Observers:    make([]*gendisplay.Participant, 0, len(st.Observers)),
		Participants: st.Participants,
	}
	for _, o := range st.Observers {
		res.Observers = append(res.Observers, mapParticipant(o))
	}
	return res, nil
}

// Join adds an authenticated participant as an observer or, when free, the
// controller.
func (s *displaysrvc) Join(ctx context.Context, p *gendisplay.JoinDisplayPayload) (res *gendisplay.DisplayJoin, err error) {
	log.Printf(ctx, "display.join name=%s namespace=%s role=%s", p.Name, p.Namespace, p.Role)
	ns, err := s.authorizeEditor(ctx, p.Namespace)
	if err != nil {
		return nil, err
	}
	if _, err := s.displayWorkspace(ctx, ns, p.Name, true); err != nil {
		return nil, err
	}
	role := p.Role
	if role == "" {
		role = displayRoleObserver
	}
	member, err := s.sessions.Join(ns, p.Name, role)
	if err != nil {
		return nil, mapSessionError(err)
	}
	c := s.sessions.Capability(ns, p.Name)
	return &gendisplay.DisplayJoin{Participant: mapParticipant(member), Capability: mapCapability(c)}, nil
}

// Leave removes a participant, releasing control first when it held it.
func (s *displaysrvc) Leave(ctx context.Context, p *gendisplay.LeaveDisplayPayload) (res *gendisplay.LeaveResult, err error) {
	log.Printf(ctx, "display.leave name=%s namespace=%s", p.Name, p.Namespace)
	ns, err := s.authorizeEditor(ctx, p.Namespace)
	if err != nil {
		return nil, err
	}
	if _, err := s.displayWorkspace(ctx, ns, p.Name, true); err != nil {
		return nil, err
	}
	if err := s.sessions.Leave(ns, p.Name, p.ParticipantID); err != nil {
		return nil, mapSessionError(err)
	}
	return &gendisplay.LeaveResult{OK: true}, nil
}

// Acquire grants control, demoting the current controller to observer when
// force consent is given.
func (s *displaysrvc) Acquire(ctx context.Context, p *gendisplay.DisplayControlPayload) (res *gendisplay.DisplayControl, err error) {
	log.Printf(ctx, "display.acquire name=%s namespace=%s", p.Name, p.Namespace)
	return s.control(ctx, p, "acquire")
}

// Release clears control held by the acting participant, leaving observers.
func (s *displaysrvc) Release(ctx context.Context, p *gendisplay.DisplayControlPayload) (res *gendisplay.DisplayControl, err error) {
	log.Printf(ctx, "display.release name=%s namespace=%s", p.Name, p.Namespace)
	return s.control(ctx, p, "release")
}

// Transfer moves control from the current controller to a named observer.
func (s *displaysrvc) Transfer(ctx context.Context, p *gendisplay.DisplayControlPayload) (res *gendisplay.DisplayControl, err error) {
	log.Printf(ctx, "display.transfer name=%s namespace=%s", p.Name, p.Namespace)
	return s.control(ctx, p, "transfer")
}

func (s *displaysrvc) control(ctx context.Context, p *gendisplay.DisplayControlPayload, op string) (*gendisplay.DisplayControl, error) {
	ns, err := s.authorizeEditor(ctx, p.Namespace)
	if err != nil {
		return nil, err
	}
	if _, err := s.displayWorkspace(ctx, ns, p.Name, true); err != nil {
		return nil, err
	}
	var (
		controller *display.Participant
		wasHeld    bool
		released   bool
	)
	switch op {
	case "acquire":
		var m *display.Participant
		m, wasHeld, err = s.sessions.Acquire(ns, p.Name, p.ParticipantID, p.Force)
		controller = m
	case "release":
		var m *display.Participant
		m, wasHeld, err = s.sessions.Release(ns, p.Name, p.ParticipantID)
		controller = m
		released = err == nil
	case "transfer":
		if p.To == nil || *p.To == "" {
			return nil, gendisplay.Invalid("transfer requires a target participant")
		}
		var m *display.Participant
		m, wasHeld, err = s.sessions.Transfer(ns, p.Name, p.ParticipantID, *p.To)
		controller = m
	}
	if err != nil {
		return nil, mapSessionError(err)
	}
	return &gendisplay.DisplayControl{
		Controller: mapParticipant(controller),
		WasHeld:    wasHeld,
		Released:   released,
	}, nil
}

// mapSessionError translates registry sentinels to the Goa error surface while
// preserving 401/403/404, capacity (429) and occupied-control (409) semantics.
func mapSessionError(err error) error {
	switch {
	case errors.Is(err, display.ErrParticipantNotFound):
		return gendisplay.NotFound(err.Error())
	case errors.Is(err, display.ErrCapacity):
		return gendisplay.Capacity(err.Error())
	case errors.Is(err, display.ErrControllerPresent),
		errors.Is(err, display.ErrNotController):
		return gendisplay.Conflict(err.Error())
	case errors.Is(err, display.ErrAlreadyController),
		errors.Is(err, display.ErrBadTarget),
		errors.Is(err, display.ErrInvalidRole):
		return gendisplay.Invalid(err.Error())
	default:
		return err
	}
}

func intPtr(i int) *int { return &i }
