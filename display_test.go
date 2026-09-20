package kubeworkspaces

import (
	"context"
	"errors"
	"testing"

	gendisplay "github.com/kube-workspaces/api/gen/display"
	"github.com/kube-workspaces/api/internal/display"
	"github.com/kube-workspaces/api/internal/k8s"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func workspaceCR(ns, name, wsType string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1",
		"kind":       "Workspace",
		"metadata":   map[string]interface{}{"namespace": ns, "name": name},
		"spec":       map[string]interface{}{"type": wsType},
	}}
}

func newDisplaySvc(t *testing.T) (gendisplay.Service, *display.Sessions) {
	t.Helper()
	return newDisplaySvcEnabled(t, true)
}

func newDisplaySvcEnabled(t *testing.T, enabled bool) (gendisplay.Service, *display.Sessions) {
	t.Helper()
	fake := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(),
		workspaceCR("workspaces", "vm-a", "vm"),
		workspaceCR("workspaces", "wordpress", "container"),
	)
	return NewDisplay(k8s.NewWorkspaceClientFor(fake), display.NewSessions(), enabled), display.NewSessions()
}

func TestDisplayCapabilityGatesByWorkspaceType(t *testing.T) {
	svc, _ := newDisplaySvc(t)
	ctx := context.Background()

	vm, err := svc.Capability(ctx, &gendisplay.CapabilityPayload{Namespace: "workspaces", Name: "vm-a"})
	if err != nil {
		t.Fatalf("capability vm: %v", err)
	}
	if !vm.Enabled || vm.Protocol != 1 {
		t.Fatalf("vm capability: enabled=%v protocol=%d", vm.Enabled, vm.Protocol)
	}
	if vm.MaxParticipants == nil || *vm.MaxParticipants != display.MaxParticipants {
		t.Fatalf("max participants = %v, want %d", vm.MaxParticipants, display.MaxParticipants)
	}
	if vm.Participants == nil || *vm.Participants != 0 || *vm.ControllerPresent {
		t.Fatalf("live counts should be 0/absent, got %v", vm)
	}

	container, err := svc.Capability(ctx, &gendisplay.CapabilityPayload{Namespace: "workspaces", Name: "wordpress"})
	if err != nil {
		t.Fatalf("capability container: %v", err)
	}
	// Back-compat: absence of the capability means legacy exclusive mode.
	if container.Enabled {
		t.Fatalf("container capability should be disabled")
	}

	if _, err := svc.Capability(ctx, &gendisplay.CapabilityPayload{Namespace: "workspaces", Name: "ghost"}); !asGoaError[gendisplay.NotFound](t, err) {
		t.Fatalf("unknown workspace should be not_found, got %v", err)
	}
}

func TestDisplayJoinEnforcesRolesAndCapacity(t *testing.T) {
	svc, _ := newDisplaySvc(t)
	ctx := context.Background()

	ctrl, err := svc.Join(ctx, &gendisplay.JoinDisplayPayload{Namespace: "workspaces", Name: "vm-a", Role: "controller"})
	if err != nil {
		t.Fatalf("join controller: %v", err)
	}
	if ctrl.Participant.Role != "controller" {
		t.Fatalf("role = %q, want controller", ctrl.Participant.Role)
	}
	if ctrl.Capability == nil || *ctrl.Capability.ControllerPresent != true {
		t.Fatalf("capability should show controller present, got %+v", ctrl.Capability)
	}

	// A second controller cannot join silently.
	if _, err := svc.Join(ctx, &gendisplay.JoinDisplayPayload{Namespace: "workspaces", Name: "vm-a", Role: "controller"}); !asGoaError[gendisplay.Conflict](t, err) {
		t.Fatalf("second controller should be conflict, got %v", err)
	}

	// Observers can always join while occupied.
	if _, err := svc.Join(ctx, &gendisplay.JoinDisplayPayload{Namespace: "workspaces", Name: "vm-a", Role: "observer"}); err != nil {
		t.Fatalf("join observer: %v", err)
	}

	// Non-VM and non-existent workspaces cannot be joined.
	if _, err := svc.Join(ctx, &gendisplay.JoinDisplayPayload{Namespace: "workspaces", Name: "wordpress"}); !asGoaError[gendisplay.Invalid](t, err) {
		t.Fatalf("join container should be invalid, got %v", err)
	}
	if _, err := svc.Join(ctx, &gendisplay.JoinDisplayPayload{Namespace: "workspaces", Name: "ghost"}); !asGoaError[gendisplay.NotFound](t, err) {
		t.Fatalf("join unknown should be not_found, got %v", err)
	}
}

func TestDisplayControlTransitions(t *testing.T) {
	svc, _ := newDisplaySvc(t)
	ctx := context.Background()

	ctrl, err := svc.Join(ctx, &gendisplay.JoinDisplayPayload{Namespace: "workspaces", Name: "vm-a", Role: "controller"})
	if err != nil {
		t.Fatalf("join controller: %v", err)
	}
	obs, err := svc.Join(ctx, &gendisplay.JoinDisplayPayload{Namespace: "workspaces", Name: "vm-a", Role: "observer"})
	if err != nil {
		t.Fatalf("join observer: %v", err)
	}
	obs2, err := svc.Join(ctx, &gendisplay.JoinDisplayPayload{Namespace: "workspaces", Name: "vm-a", Role: "observer"})
	if err != nil {
		t.Fatalf("join observer 2: %v", err)
	}

	// Acquire without consent on an occupied display -> conflict.
	if _, err := svc.Acquire(ctx, &gendisplay.DisplayControlPayload{Namespace: "workspaces", Name: "vm-a", ParticipantID: obs.Participant.ID, Force: false}); !asGoaError[gendisplay.Conflict](t, err) {
		t.Fatalf("acquire no-force should be conflict, got %v", err)
	}

	// Acquire with consent demotes the current controller.
	acq, err := svc.Acquire(ctx, &gendisplay.DisplayControlPayload{Namespace: "workspaces", Name: "vm-a", ParticipantID: obs.Participant.ID, Force: true})
	if err != nil {
		t.Fatalf("acquire force: %v", err)
	}
	if !acq.WasHeld || acq.Controller == nil || acq.Controller.ID != obs.Participant.ID {
		t.Fatalf("acquire force: wasHeld=%v controller=%+v", acq.WasHeld, acq.Controller)
	}

	// Demoted controller is now an observer in status.
	st, err := svc.Status(ctx, &gendisplay.StatusPayload{Namespace: "workspaces", Name: "vm-a"})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(st.Observers) != 2 {
		t.Fatalf("observers = %d, want 2 (incl. demoted controller)", len(st.Observers))
	}

	// Observer release -> conflict.
	if _, err := svc.Release(ctx, &gendisplay.DisplayControlPayload{Namespace: "workspaces", Name: "vm-a", ParticipantID: obs2.Participant.ID}); !asGoaError[gendisplay.Conflict](t, err) {
		t.Fatalf("observer release should be conflict, got %v", err)
	}

	// Controller transfer to observer keeps everyone attached.
	if _, err := svc.Transfer(ctx, &gendisplay.DisplayControlPayload{Namespace: "workspaces", Name: "vm-a", ParticipantID: obs.Participant.ID, To: strPtr(obs2.Participant.ID)}); err != nil {
		t.Fatalf("transfer: %v", err)
	}
	st, err = svc.Status(ctx, &gendisplay.StatusPayload{Namespace: "workspaces", Name: "vm-a"})
	if err != nil {
		t.Fatalf("status after transfer: %v", err)
	}
	if st.Controller == nil || st.Controller.ID != obs2.Participant.ID {
		t.Fatalf("controller after transfer = %+v, want obs2", st.Controller)
	}
	if len(st.Observers) != 2 || st.Participants != 3 {
		t.Fatalf("membership after transfer: observers=%d participants=%d", len(st.Observers), st.Participants)
	}

	// Transfer by a non-controller -> conflict.
	if _, err := svc.Transfer(ctx, &gendisplay.DisplayControlPayload{Namespace: "workspaces", Name: "vm-a", ParticipantID: obs.Participant.ID, To: strPtr(ctrl.Participant.ID)}); !asGoaError[gendisplay.Conflict](t, err) {
		t.Fatalf("transfer by non-controller should be conflict, got %v", err)
	}
}

func TestDisplayLeaveReleasesControl(t *testing.T) {
	svc, _ := newDisplaySvc(t)
	ctx := context.Background()

	ctrl, err := svc.Join(ctx, &gendisplay.JoinDisplayPayload{Namespace: "workspaces", Name: "vm-a", Role: "controller"})
	if err != nil {
		t.Fatalf("join controller: %v", err)
	}
	if _, err := svc.Join(ctx, &gendisplay.JoinDisplayPayload{Namespace: "workspaces", Name: "vm-a", Role: "observer"}); err != nil {
		t.Fatalf("join observer: %v", err)
	}

	if _, err := svc.Leave(ctx, &gendisplay.LeaveDisplayPayload{Namespace: "workspaces", Name: "vm-a", ParticipantID: ctrl.Participant.ID}); err != nil {
		t.Fatalf("leave controller: %v", err)
	}
	st, err := svc.Status(ctx, &gendisplay.StatusPayload{Namespace: "workspaces", Name: "vm-a"})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Controller != nil || len(st.Observers) != 1 {
		t.Fatalf("after controller leave: controller=%+v observers=%d", st.Controller, len(st.Observers))
	}

	if _, err := svc.Leave(ctx, &gendisplay.LeaveDisplayPayload{Namespace: "workspaces", Name: "vm-a", ParticipantID: "ghost"}); !asGoaError[gendisplay.NotFound](t, err) {
		t.Fatalf("leave unknown should be not_found, got %v", err)
	}
}

func asGoaError[T any](t *testing.T, err error) bool {
	t.Helper()
	var e T
	return errors.As(err, &e)
}

// A membership claim owned by another replica surfaces as the 409 conflict
// contract (not a bare 500): the middleware forwards the retry to the owner.
// The owner identity itself rides on the lease and on the ws route's 409
// JSON; the Goa conflict body carries the fixed design description.
func TestMapSessionErrorOwnershipConflict(t *testing.T) {
	err := mapSessionError(&display.OwnershipError{Owner: "replica-b", Kind: "display-membership"})
	if err == nil {
		t.Fatal("nil error for an owned membership")
	}
	if !asGoaError[gendisplay.Conflict](t, err) {
		t.Fatalf("OwnershipError should map to conflict, got %T %v", err, err)
	}
	// Untyped errors keep falling through unchanged.
	plain := errors.New("boom")
	if mapSessionError(plain) != plain {
		t.Fatal("untyped error was wrapped")
	}
}

// While the pilot gate is off, the shared display advertises disabled and
// refuses every mutation path with a clear error — the rollback posture.
func TestDisplayPilotGateDisabled(t *testing.T) {
	svc, _ := newDisplaySvcEnabled(t, false)
	ctx := context.Background()

	cap, err := svc.Capability(ctx, &gendisplay.CapabilityPayload{Namespace: "workspaces", Name: "vm-a"})
	if err != nil {
		t.Fatalf("capability: %v", err)
	}
	if cap.Enabled {
		t.Fatal("capability advertises enabled with the pilot gate off")
	}
	st, err := svc.Status(ctx, &gendisplay.StatusPayload{Namespace: "workspaces", Name: "vm-a"})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Enabled {
		t.Fatal("status advertises enabled with the pilot gate off")
	}
	if _, err := svc.Join(ctx, &gendisplay.JoinDisplayPayload{Namespace: "workspaces", Name: "vm-a", Role: "observer"}); !asGoaError[gendisplay.Invalid](t, err) {
		t.Fatalf("join while disabled should be invalid, got %v", err)
	}
	if _, err := svc.Acquire(ctx, &gendisplay.DisplayControlPayload{Namespace: "workspaces", Name: "vm-a", ParticipantID: "p1"}); !asGoaError[gendisplay.Invalid](t, err) {
		t.Fatalf("acquire while disabled should be invalid, got %v", err)
	}
	if _, err := svc.Leave(ctx, &gendisplay.LeaveDisplayPayload{Namespace: "workspaces", Name: "vm-a", ParticipantID: "p1"}); !asGoaError[gendisplay.Invalid](t, err) {
		t.Fatalf("leave while disabled should be invalid, got %v", err)
	}
}

func TestSharedDisplayEnabledFromEnv(t *testing.T) {
	t.Setenv("KW_DISPLAY_SHARED", "")
	if SharedDisplayEnabledFromEnv() {
		t.Fatal("unset KW_DISPLAY_SHARED enables the pilot gate")
	}
	for _, v := range []string{"on", "ON", "true", "1"} {
		t.Setenv("KW_DISPLAY_SHARED", v)
		if !SharedDisplayEnabledFromEnv() {
			t.Fatalf("KW_DISPLAY_SHARED=%q does not enable the pilot gate", v)
		}
	}
	t.Setenv("KW_DISPLAY_SHARED", "off")
	if SharedDisplayEnabledFromEnv() {
		t.Fatal("KW_DISPLAY_SHARED=off enables the pilot gate")
	}
}
