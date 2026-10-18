package enrollment

import (
	"context"
	"errors"
	"testing"

	"github.com/kube-workspaces/api/internal/execution/pki"
	"github.com/kube-workspaces/api/internal/platform"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func platformResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "platformconfigs"}
}

func kubernetesFixture() (*unstructured.Unstructured, *unstructured.Unstructured) {
	ws := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Workspace",
		"metadata": map[string]interface{}{"name": "vm", "namespace": "team", "uid": "workspace-uid", "resourceVersion": "1"},
		"spec":     map[string]interface{}{"type": "vm"},
	}}
	vm := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine",
		"metadata": map[string]interface{}{"name": "vm", "namespace": "team", "uid": "vm-uid", "resourceVersion": "1", "ownerReferences": []interface{}{map[string]interface{}{"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Workspace", "name": "vm", "uid": "workspace-uid", "controller": true}}},
		"spec":     map[string]interface{}{"running": true},
	}}
	return ws, vm
}

type policyStub struct {
	read func(context.Context) (platform.VMExecutionPolicy, error)
}

func (p policyStub) GetVMExecutionPolicy(ctx context.Context) (platform.VMExecutionPolicy, error) {
	return p.read(ctx)
}
func enabledPolicy() policyStub {
	return policyStub{read: func(context.Context) (platform.VMExecutionPolicy, error) {
		return platform.VMExecutionPolicy{Enabled: true}, nil
	}}
}

func TestKubernetesResolverFreshIncarnationAndPolicy(t *testing.T) {
	ctx := context.Background()
	ws, vm := kubernetesFixture()
	client := fake.NewSimpleDynamicClient(runtime.NewScheme(), ws, vm)
	config := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "PlatformConfig", "metadata": map[string]interface{}{"name": "default"}, "spec": map[string]interface{}{"vmExecution": map[string]interface{}{"enabled": true, "allowElevated": false}}}}
	if _, err := client.Resource(platformResource()).Create(ctx, config, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	r, err := NewKubernetesResolver(client, platform.NewConfigProvider(client))
	if err != nil {
		t.Fatal(err)
	}
	expected := pki.Identity{Role: pki.RoleGuest, Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "workspace-uid", Generation: "vm-uid", RevocationEpoch: 0}
	if err := r.Authorize(ctx, expected); err != nil {
		t.Fatal(err)
	}
	// Volatile VM metadata generation changes do not manufacture a new root identity.
	vm.SetGeneration(99)
	vm.SetResourceVersion("2")
	if _, err := client.Resource(vmResource).Namespace("team").Update(ctx, vm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := r.Authorize(ctx, expected); err != nil {
		t.Fatal("ordinary VM update invalidated identity", err)
	}
	vm.SetUID("reset-vm-uid")
	if _, err := client.Resource(vmResource).Namespace("team").Update(ctx, vm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := r.Authorize(ctx, expected); !errors.Is(err, ErrDenied) {
		t.Fatal("reset identity reused", err)
	}
	expected.Generation = "reset-vm-uid"
	if err := r.Authorize(ctx, expected); err != nil {
		t.Fatal(err)
	}
	unstructured.SetNestedField(config.Object, false, "spec", "vmExecution", "enabled")
	if _, err := client.Resource(platformResource()).Update(ctx, config, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := r.Authorize(ctx, expected); !errors.Is(err, ErrDenied) {
		t.Fatal("cached enabled policy authorized", err)
	}
}

func TestKubernetesResolverRejectsLifecycleOwnershipAndMalformedState(t *testing.T) {
	mutations := map[string]func(*unstructured.Unstructured, *unstructured.Unstructured){
		"workspace-deletion": func(ws, vm *unstructured.Unstructured) { now := metav1.Now(); ws.SetDeletionTimestamp(&now) },
		"vm-deletion":        func(ws, vm *unstructured.Unstructured) { now := metav1.Now(); vm.SetDeletionTimestamp(&now) },
		"foreign-owner": func(ws, vm *unstructured.Unstructured) {
			refs := vm.GetOwnerReferences()
			refs[0].UID = "other"
			vm.SetOwnerReferences(refs)
		},
		"owner-name": func(ws, vm *unstructured.Unstructured) {
			refs := vm.GetOwnerReferences()
			refs[0].Name = "other"
			vm.SetOwnerReferences(refs)
		},
		"no-owner": func(ws, vm *unstructured.Unstructured) { vm.SetOwnerReferences(nil) },
		"not-controller": func(ws, vm *unstructured.Unstructured) {
			refs := vm.GetOwnerReferences()
			no := false
			refs[0].Controller = &no
			vm.SetOwnerReferences(refs)
		},
		"container": func(ws, vm *unstructured.Unstructured) {
			unstructured.SetNestedField(ws.Object, "container", "spec", "type")
		},
		"malformed-type": func(ws, vm *unstructured.Unstructured) { unstructured.SetNestedField(ws.Object, true, "spec", "type") },
		"stopped-vm": func(ws, vm *unstructured.Unstructured) {
			unstructured.SetNestedField(vm.Object, false, "spec", "running")
		},
		"malformed-running": func(ws, vm *unstructured.Unstructured) {
			unstructured.SetNestedField(vm.Object, "true", "spec", "running")
		},
	}
	for _, marker := range []string{"kubeworkspaces.io/reset", "kubeworkspaces.io/stopped", "kubeworkspaces.io/reboot", "kubeworkspaces.io/windows-detaching-generation"} {
		marker := marker
		mutations[marker] = func(ws, vm *unstructured.Unstructured) { ws.SetAnnotations(map[string]string{marker: ""}) }
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			ws, vm := kubernetesFixture()
			mutate(ws, vm)
			r, _ := NewKubernetesResolver(fake.NewSimpleDynamicClient(runtime.NewScheme(), ws, vm), enabledPolicy())
			if _, err := r.Resolve(context.Background(), "team", "vm"); !errors.Is(err, ErrDenied) {
				t.Fatal("invalid state authorized", err)
			}
		})
	}
}

func TestKubernetesResolverWindowsAndEpochContract(t *testing.T) {
	ws, vm := kubernetesFixture()
	unstructured.SetNestedMap(ws.Object, map[string]interface{}{"id": "windows11-amd64-v1", "generation": "windows-generation"}, "spec", "vmProfile")
	ws.SetAnnotations(map[string]string{"kubeworkspaces.io/windows-provisioned-generation": "windows-generation"})
	vm.SetAnnotations(map[string]string{"kubeworkspaces.io/windows-generation": "windows-generation"})
	client := fake.NewSimpleDynamicClient(runtime.NewScheme(), ws, vm)
	r, _ := NewKubernetesResolver(client, enabledPolicy())
	i, err := r.Resolve(context.Background(), "team", "vm")
	if err != nil || i.Generation != "vm-uid" {
		t.Fatal("desktop generation used as management identity", i, err)
	}
	i.RevocationEpoch = 1
	if err := r.Authorize(context.Background(), i); !errors.Is(err, ErrDenied) {
		t.Fatal("unsupported epoch silently authorized", err)
	}
	ws.SetAnnotations(nil)
	if _, err := client.Resource(workspaceResource).Namespace("team").Update(context.Background(), ws, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(context.Background(), "team", "vm"); !errors.Is(err, ErrDenied) {
		t.Fatal("unprovisioned Windows guest authorized", err)
	}
}

func TestKubernetesResolverFencesMixedReadsAndLookupOutages(t *testing.T) {
	for _, which := range []string{"workspace-race", "vm-race", "lookup-outage", "policy-outage", "policy-change"} {
		t.Run(which, func(t *testing.T) {
			ws, vm := kubernetesFixture()
			client := fake.NewSimpleDynamicClient(runtime.NewScheme(), ws, vm)
			gets := 0
			client.PrependReactor("get", "*", func(a ktesting.Action) (bool, runtime.Object, error) {
				if which == "lookup-outage" {
					return true, nil, errors.New("unavailable")
				}
				resource := a.GetResource()
				if (which == "workspace-race" && resource == workspaceResource) || (which == "vm-race" && resource == vmResource) {
					gets++
					if gets == 2 {
						object := ws.DeepCopy()
						if resource == vmResource {
							object = vm.DeepCopy()
						}
						object.SetResourceVersion("changed")
						return true, object, nil
					}
				}
				return false, nil, nil
			})
			reads := 0
			policy := policyStub{read: func(ctx context.Context) (platform.VMExecutionPolicy, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Error("unbounded lookup context")
				}
				reads++
				if which == "policy-outage" {
					return platform.VMExecutionPolicy{}, errors.New("unavailable")
				}
				return platform.VMExecutionPolicy{Enabled: which != "policy-change" || reads == 1}, nil
			}}
			r, _ := NewKubernetesResolver(client, policy)
			if _, err := r.Resolve(context.Background(), "team", "vm"); err == nil {
				t.Fatal("mixed/outage state authorized")
			}
		})
	}
}
