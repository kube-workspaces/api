package qga

import (
	"context"
	"errors"
	"testing"

	"github.com/kube-workspaces/api/internal/platform"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
)

type policyStub struct {
	enabled  bool
	elevated bool
	err      error
}

func (p policyStub) GetVMExecutionPolicy(context.Context) (platform.VMExecutionPolicy, error) {
	return platform.VMExecutionPolicy{Enabled: p.enabled, AllowElevated: p.elevated}, p.err
}

const (
	testGeneration = "gen-1"
	testPodName    = "virt-launcher-vm-abc"
	testPodUID     = "pod-uid"
)

func windowsFixtures() (*unstructured.Unstructured, *unstructured.Unstructured, *unstructured.Unstructured, *unstructured.Unstructured) {
	ws := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Workspace",
		"metadata": map[string]interface{}{
			"name": "vm", "namespace": "team", "uid": "workspace-uid", "resourceVersion": "1",
			"annotations": map[string]interface{}{"kubeworkspaces.io/windows-provisioned-generation": testGeneration},
		},
		"spec": map[string]interface{}{"type": "vm", "vmProfile": map[string]interface{}{"id": windowsProfileID, "generation": testGeneration}},
	}}
	vm := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine",
		"metadata": map[string]interface{}{
			"name": "vm", "namespace": "team", "uid": "vm-uid", "resourceVersion": "1",
			"annotations":     map[string]interface{}{"kubeworkspaces.io/windows-generation": testGeneration},
			"ownerReferences": []interface{}{map[string]interface{}{"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Workspace", "name": "vm", "uid": "workspace-uid", "controller": true}},
		},
		"spec": map[string]interface{}{"running": true},
	}}
	vmi := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachineInstance",
		"metadata": map[string]interface{}{"name": "vm", "namespace": "team", "uid": "vmi-uid", "resourceVersion": "1"},
		"status":   map[string]interface{}{"phase": "Running", "activePods": map[string]interface{}{testPodUID: testPodName}},
	}}
	pod := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]interface{}{
			"name": testPodName, "namespace": "team", "uid": testPodUID, "resourceVersion": "1",
			"labels": map[string]interface{}{"vm.kubevirt.io/name": "vm"},
		},
		"status": map[string]interface{}{"phase": "Running"},
	}}
	return ws, vm, vmi, pod
}

func newTestResolver(t *testing.T, mutate func(ws, vm, vmi, pod *unstructured.Unstructured), policy PolicyReader) *Resolver {
	t.Helper()
	ws, vm, vmi, pod := windowsFixtures()
	if mutate != nil {
		mutate(ws, vm, vmi, pod)
	}
	client := fake.NewSimpleDynamicClient(runtime.NewScheme(), ws, vm, vmi, pod)
	r, err := NewResolver(client, policy)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResolveReturnsFreshLauncherTarget(t *testing.T) {
	r := newTestResolver(t, nil, policyStub{enabled: true, elevated: true})
	target, err := r.Resolve(context.Background(), "team", "vm")
	if err != nil {
		t.Fatal(err)
	}
	expected := Target{
		Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "workspace-uid",
		VMUID: "vm-uid", PodName: testPodName, PodUID: testPodUID, Domain: "team_vm",
	}
	if target != expected {
		t.Fatalf("unexpected target: %+v", target)
	}
	if target.identity() != "team/vm-uid/"+testPodUID {
		t.Fatalf("unexpected identity preimage: %s", target.identity())
	}
}

func TestResolveDeniesIneligibleTargets(t *testing.T) {
	annotations := func(object *unstructured.Unstructured, key string) {
		merged := object.GetAnnotations()
		if merged == nil {
			merged = map[string]string{}
		}
		merged[key] = testGeneration
		object.SetAnnotations(merged)
	}
	cases := map[string]func(ws, vm, vmi, pod *unstructured.Unstructured){
		"container-workspace": func(ws, _, _, _ *unstructured.Unstructured) {
			unstructured.SetNestedField(ws.Object, "container", "spec", "type")
		},
		"no-profile": func(ws, _, _, _ *unstructured.Unstructured) {
			unstructured.RemoveNestedField(ws.Object, "spec", "vmProfile")
		},
		"wrong-profile": func(ws, _, _, _ *unstructured.Unstructured) {
			unstructured.SetNestedField(ws.Object, "ubuntu", "spec", "vmProfile", "id")
		},
		"empty-generation": func(ws, _, _, _ *unstructured.Unstructured) {
			unstructured.SetNestedField(ws.Object, "", "spec", "vmProfile", "generation")
		},
		"unprovisioned": func(ws, _, _, _ *unstructured.Unstructured) {
			unstructured.RemoveNestedField(ws.Object, "metadata", "annotations")
		},
		"reset-annotation":   func(ws, _, _, _ *unstructured.Unstructured) { annotations(ws, "kubeworkspaces.io/reset") },
		"stopped-annotation": func(ws, _, _, _ *unstructured.Unstructured) { annotations(ws, "kubeworkspaces.io/stopped") },
		"reboot-annotation":  func(ws, _, _, _ *unstructured.Unstructured) { annotations(ws, "kubeworkspaces.io/reboot") },
		"detaching-annotation": func(ws, _, _, _ *unstructured.Unstructured) {
			annotations(ws, "kubeworkspaces.io/windows-detaching-generation")
		},
		"vm-not-running": func(_, vm, _, _ *unstructured.Unstructured) {
			unstructured.SetNestedField(vm.Object, false, "spec", "running")
		},
		"stale-vm-generation": func(_, vm, _, _ *unstructured.Unstructured) {
			unstructured.SetNestedField(vm.Object, "gen-0", "metadata", "annotations", "kubeworkspaces.io/windows-generation")
		},
		"foreign-owner": func(_, vm, _, _ *unstructured.Unstructured) {
			refs := vm.GetOwnerReferences()
			refs[0].UID = "other"
			vm.SetOwnerReferences(refs)
		},
		"no-owner": func(_, vm, _, _ *unstructured.Unstructured) { vm.SetOwnerReferences(nil) },
		"vmi-not-running": func(_, _, vmi, _ *unstructured.Unstructured) {
			unstructured.SetNestedField(vmi.Object, "Pending", "status", "phase")
		},
		"pod-not-active": func(_, _, vmi, _ *unstructured.Unstructured) {
			unstructured.SetNestedField(vmi.Object, map[string]interface{}{"other-uid": testPodName}, "status", "activePods")
		},
		"pod-terminating": func(_, _, _, pod *unstructured.Unstructured) { now := metav1.Now(); pod.SetDeletionTimestamp(&now) },
		"pod-not-running": func(_, _, _, pod *unstructured.Unstructured) {
			unstructured.SetNestedField(pod.Object, "Pending", "status", "phase")
		},
		"pod-label-mismatch": func(_, _, _, pod *unstructured.Unstructured) {
			pod.SetLabels(map[string]string{"vm.kubevirt.io/name": "other"})
		},
		"workspace-deleting": func(ws, _, _, _ *unstructured.Unstructured) { now := metav1.Now(); ws.SetDeletionTimestamp(&now) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := newTestResolver(t, mutate, policyStub{enabled: true, elevated: true})
			if _, err := r.Resolve(context.Background(), "team", "vm"); !errors.Is(err, ErrDenied) && !errors.Is(err, ErrUnavailable) {
				t.Fatalf("expected a fail-closed error, got %v", err)
			}
		})
	}
}

func TestResolveRejectsAmbiguousLaunchers(t *testing.T) {
	ws, vm, vmi, pod := windowsFixtures()
	twin := pod.DeepCopy()
	twin.SetName("virt-launcher-vm-def")
	twin.SetUID("other-uid")
	unstructured.SetNestedField(vmi.Object, map[string]interface{}{testPodUID: testPodName, "other-uid": "virt-launcher-vm-def"}, "status", "activePods")
	r, err := NewResolver(fake.NewSimpleDynamicClient(runtime.NewScheme(), ws, vm, vmi, pod, twin), policyStub{enabled: true, elevated: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(context.Background(), "team", "vm"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("multiple active launchers must be unavailable, got %v", err)
	}
}

func TestResolveHonoursPolicyAndAvailability(t *testing.T) {
	r := newTestResolver(t, nil, policyStub{enabled: false, elevated: true})
	if _, err := r.Resolve(context.Background(), "team", "vm"); !errors.Is(err, ErrDenied) {
		t.Fatalf("disabled policy must deny, got %v", err)
	}
	r = newTestResolver(t, nil, policyStub{enabled: true, elevated: false})
	if _, err := r.Resolve(context.Background(), "team", "vm"); !errors.Is(err, ErrDenied) {
		t.Fatalf("missing elevation grant must deny, got %v", err)
	}
	r = newTestResolver(t, nil, policyStub{enabled: true, elevated: true, err: errors.New("read failed")})
	if _, err := r.Resolve(context.Background(), "team", "vm"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("policy read failures must be unavailable, got %v", err)
	}
}

func TestResolveFailsClosedOnInvalidNames(t *testing.T) {
	r := newTestResolver(t, nil, policyStub{enabled: true, elevated: true})
	for _, names := range [][2]string{{"TEAM", "vm"}, {"team", "VM"}, {"team", ""}, {"", ""}} {
		if _, err := r.Resolve(context.Background(), names[0], names[1]); !errors.Is(err, ErrDenied) {
			t.Fatalf("invalid names %q/%q must deny, got %v", names[0], names[1], err)
		}
	}
}

func TestResolveDeniesMissingObjects(t *testing.T) {
	ws, vm, vmi, _ := windowsFixtures()
	policy := policyStub{enabled: true, elevated: true}
	cases := map[string][]runtime.Object{
		"missing-workspace": {vm, vmi},
		"missing-vm":        {ws, vmi},
		"missing-vmi":       {ws, vm},
	}
	for name, objects := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := NewResolver(fake.NewSimpleDynamicClient(runtime.NewScheme(), objects...), policy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Resolve(context.Background(), "team", "vm"); !errors.Is(err, ErrDenied) {
				t.Fatalf("missing objects must deny, got %v", err)
			}
		})
	}
}
