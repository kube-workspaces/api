package kubeworkspaces

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/kube-workspaces/api/gen/workspaces"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/k8s"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func gpuAPITestFixture() (*unstructured.Unstructured, *unstructured.Unstructured, []*unstructured.Unstructured) {
	ws := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Workspace",
		"metadata": map[string]interface{}{"name": "desktop", "namespace": "test", "uid": "workspace-uid", "resourceVersion": "17", "annotations": map[string]interface{}{"kubeworkspaces.io/stopped": "true", "kubeworkspaces.io/windows-provisioned-generation": "one"}},
		"spec":     map[string]interface{}{"type": "vm", "vmProfile": map[string]interface{}{"id": windowsVMProfile, "generation": "one", "image": "registry.example/windows@sha256:" + strings.Repeat("a", 64), "cpuCores": int64(4), "guestMemory": "8Gi", "rootDiskSize": "80Gi"}, "template": map[string]interface{}{"spec": map[string]interface{}{"nodeSelector": map[string]interface{}{"kubernetes.io/hostname": "worker"}}}},
	}}
	vm := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine",
		"metadata": map[string]interface{}{"name": "desktop", "namespace": "test", "annotations": map[string]interface{}{"kubeworkspaces.io/windows-generation": "one"}, "ownerReferences": []interface{}{map[string]interface{}{"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Workspace", "name": "desktop", "uid": "workspace-uid", "controller": true}}},
		"spec":     map[string]interface{}{"running": false},
	}}
	profile := map[string]interface{}{"id": "intel-sriov-v1", "displayName": "Experimental Intel VF", "resourceName": "intel.com/render-vf", "kind": "pci", "count": int64(1), "nodeSelector": map[string]interface{}{"example.com/vm-gpu": "qualified"}, "guestDriverVersion": "32.0.101.6452", "experimental": true}
	platform := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "PlatformConfig", "metadata": map[string]interface{}{"name": "default"}, "spec": map[string]interface{}{"vmGPUProfiles": []interface{}{profile}}}}
	node := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "Node", "metadata": map[string]interface{}{"name": "worker-node", "labels": map[string]interface{}{"kubernetes.io/hostname": "worker", "kubernetes.io/arch": "amd64", "kubeworkspaces.io/windows11-amd64-eligible": "true", "example.com/vm-gpu": "qualified"}}, "status": map[string]interface{}{"allocatable": map[string]interface{}{"intel.com/render-vf": "1"}, "conditions": []interface{}{map[string]interface{}{"type": "Ready", "status": "True"}}}}}
	kv := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "kubevirt.io/v1", "kind": "KubeVirt", "metadata": map[string]interface{}{"name": "kubevirt", "namespace": "kubevirt"}, "spec": map[string]interface{}{"configuration": map[string]interface{}{"permittedHostDevices": map[string]interface{}{"pciHostDevices": []interface{}{map[string]interface{}{"resourceName": "intel.com/render-vf"}}}}}}}
	return ws, vm, []*unstructured.Unstructured{platform, node, kv}
}

func gpuAPITestService(objects ...*unstructured.Unstructured) (*workspacessrvc, *fake.FakeDynamicClient) {
	runtimeObjects := make([]runtime.Object, len(objects))
	for i := range objects {
		runtimeObjects[i] = objects[i]
	}
	dyn := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		{Version: "v1", Resource: "nodes"}:                                    "NodeList",
		{Group: "kubevirt.io", Version: "v1", Resource: "kubevirts"}:          "KubeVirtList",
		{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "images"}: "ImageList",
	}, runtimeObjects...)
	return &workspacessrvc{client: k8s.NewWorkspaceClientFor(dyn), imageClient: k8s.NewImageClientFor(dyn)}, dyn
}

func TestVMGPUSetProfilePreservesWindowsIdentityAndAllowsSoftwareRollback(t *testing.T) {
	ws, vm, prerequisites := gpuAPITestFixture()
	service, dyn := gpuAPITestService(append([]*unstructured.Unstructured{ws, vm}, prerequisites...)...)
	ctx := auth.ContextWithUser(context.Background(), &auth.UserInfo{Role: "editor", PersonalNamespace: "test", Email: "editor@example.com"})
	result, err := service.SetGpuProfile(ctx, &workspaces.SetGpuProfilePayload{Name: "desktop", Namespace: "test", ProfileID: "intel-sriov-v1"})
	if err != nil || result.VMGpuProfile == nil || result.VMGpuProfile.ResourceName != "intel.com/render-vf" || !result.Stopped {
		t.Fatalf("GPU selection failed: %+v %v", result, err)
	}
	stored, err := service.client.GetWorkspace(ctx, "test", "desktop")
	if err != nil {
		t.Fatal(err)
	}
	unchanged := stored.DeepCopy()
	unstructured.RemoveNestedField(unchanged.Object, "spec", "vmProfile", "gpu")
	if !reflect.DeepEqual(unchanged.Object["spec"], ws.Object["spec"]) || stored.GetUID() != ws.GetUID() || stored.GetAnnotations()["kubeworkspaces.io/windows-provisioned-generation"] != "one" {
		t.Fatal("GPU selection changed root, firmware generation, provisioning or placement")
	}
	// Removal is a recovery path even if the registry/device disappears.
	if err := dyn.Resource(schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "platformconfigs"}).Delete(ctx, "default", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	result, err = service.SetGpuProfile(ctx, &workspaces.SetGpuProfilePayload{Name: "desktop", Namespace: "test", ProfileID: ""})
	if err != nil || result.VMGpuProfile != nil || !result.Stopped {
		t.Fatalf("software rollback failed: %+v %v", result, err)
	}
}

func TestVMGPUSetProfileDeniesUnsafeLifecycleAndUnauthorizedChanges(t *testing.T) {
	for _, scenario := range []string{"running intent", "running VM", "VMI remains", "foreign VM", "different generation", "reset", "viewer", "other namespace", "concurrent Start"} {
		t.Run(scenario, func(t *testing.T) {
			ws, vm, prerequisites := gpuAPITestFixture()
			user := &auth.UserInfo{Role: "editor", PersonalNamespace: "test"}
			objects := append([]*unstructured.Unstructured{ws, vm}, prerequisites...)
			switch scenario {
			case "running intent":
				ws.SetAnnotations(nil)
			case "running VM":
				_ = unstructured.SetNestedField(vm.Object, true, "spec", "running")
			case "VMI remains":
				objects = append(objects, &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachineInstance", "metadata": map[string]interface{}{"name": "desktop", "namespace": "test"}}})
			case "foreign VM":
				owners := vm.GetOwnerReferences()
				owners[0].UID = "foreign"
				vm.SetOwnerReferences(owners)
			case "different generation":
				vm.SetAnnotations(map[string]string{"kubeworkspaces.io/windows-generation": "other"})
			case "reset":
				annotations := ws.GetAnnotations()
				annotations["kubeworkspaces.io/reset"] = "true"
				ws.SetAnnotations(annotations)
			case "viewer":
				user.Role = "viewer"
			case "other namespace":
				user.PersonalNamespace = "other"
			}
			service, dyn := gpuAPITestService(objects...)
			if scenario == "concurrent Start" {
				dyn.PrependReactor("update", "workspaces", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "kubeworkspaces.io", Resource: "workspaces"}, "desktop", errors.New("resourceVersion changed"))
				})
			}
			ctx := auth.ContextWithUser(context.Background(), user)
			if _, err := service.SetGpuProfile(ctx, &workspaces.SetGpuProfilePayload{Name: "desktop", Namespace: "test", ProfileID: "intel-sriov-v1"}); err == nil {
				t.Fatal("unsafe or unauthorized GPU mutation accepted")
			}
			stored, err := service.client.GetWorkspace(ctx, "test", "desktop")
			if err != nil {
				t.Fatal(err)
			}
			if _, found, _ := unstructured.NestedMap(stored.Object, "spec", "vmProfile", "gpu"); found {
				t.Fatal("rejected GPU request still mutated Workspace")
			}
		})
	}
}

func TestVMGPUCreateResolvesTypedProfileWithoutGenericGPUQuantities(t *testing.T) {
	ws, _, prerequisites := gpuAPITestFixture()
	ref, _, _ := unstructured.NestedString(ws.Object, "spec", "vmProfile", "image")
	image := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Image", "metadata": map[string]interface{}{"name": "windows"}, "spec": map[string]interface{}{"image": ref, "vmProfile": windowsVMProfile, "persistentRootDisk": true}}}
	service, _ := gpuAPITestService(append(prerequisites, image)...)
	profileID := "intel-sriov-v1"
	payload := &workspaces.CreateWorkspacePayload{Name: "fresh", Namespace: "test", Type: "vm", NodeSelector: map[string]string{"kubernetes.io/hostname": "worker"}, VMOptions: &workspaces.VMOptions{GpuProfile: &profileID}, Container: &workspaces.WorkspaceContainer{Name: "fresh", Image: ref, CPULimit: "4", MemoryLimit: "8Gi"}}
	result, err := service.Create(context.Background(), payload)
	if err != nil || result.VMGpuProfile == nil || result.VMGpuProfile.ID != profileID {
		t.Fatalf("typed GPU creation failed: %+v %v", result, err)
	}
	stored, err := service.client.GetWorkspace(context.Background(), "test", "fresh")
	if err != nil {
		t.Fatal(err)
	}
	containers, _, _ := unstructured.NestedSlice(stored.Object, "spec", "template", "spec", "containers")
	limits, _, _ := unstructured.NestedMap(containers[0].(map[string]interface{}), "resources", "limits")
	if _, found := limits["intel.com/render-vf"]; found {
		t.Fatal("typed VM GPU leaked into container GPU heuristics")
	}
}
