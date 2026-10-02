package kubeworkspaces

import (
	"context"
	"testing"

	"github.com/kube-workspaces/api/gen/volumes"
	"github.com/kube-workspaces/api/gen/workspaces"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func testVolumeService(objects ...runtime.Object) *volumessrvc {
	objects = append(objects, &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
		"metadata": map[string]interface{}{"name": "datavolumes.cdi.kubevirt.io"},
	}})
	return &volumessrvc{clientset: kubernetesfake.NewSimpleClientset(),
		dynamicClient: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
			vmDataVolumeGVR: "DataVolumeList", vmWorkspaceGVR: "WorkspaceList",
			{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstances"}: "VirtualMachineInstanceList",
		}, objects...),
	}
}

func TestVolumesWithoutCDI(t *testing.T) {
	ctx := context.Background()
	s := testVolumeService()
	crds := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	if err := s.dynamicClient.Resource(crds).Delete(ctx, "datavolumes.cdi.kubevirt.io", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	s.dynamicClient.(*dynamicfake.FakeDynamicClient).PrependReactor("*", "datavolumes", func(action clienttesting.Action) (bool, runtime.Object, error) {
		t.Fatal("container-only clusters must not query the unauthorized CDI API")
		return false, nil, nil
	})
	payload := &volumes.CreateVolumePayload{Name: "container-data", Namespace: "test", Size: "1Gi", Type: "pvc"}
	if _, err := s.Create(ctx, payload); err != nil {
		t.Fatal(err)
	}
	if items, err := s.List(ctx, &volumes.ListPayload{Namespace: "test"}); err != nil || len(items) != 1 {
		t.Fatalf("container PVC list must work without CDI: %v %v", items, err)
	}
	if _, err := s.Get(ctx, &volumes.GetPayload{Name: payload.Name, Namespace: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, &volumes.DeletePayload{Name: payload.Name, Namespace: "test"}); err != nil {
		t.Fatal(err)
	}
	payload.Type = "vm-disk"
	if _, err := s.Create(ctx, payload); err == nil {
		t.Fatal("VM disk creation must report the missing prerequisite")
	}
}

func TestReusableVMVolumeLifecycle(t *testing.T) {
	ctx := context.Background()
	s := testVolumeService()
	p := &volumes.CreateVolumePayload{Name: "data", Namespace: "test", Size: "1Gi", Type: "vm-disk", AccessMode: "ReadWriteOnce"}
	v, err := s.Create(ctx, p)
	if err != nil || v.Type != "vm-disk" || v.Phase != "Pending" {
		t.Fatalf("create pending disk: %v %v", v, err)
	}
	disk, err := s.getVMDataVolume(ctx, p.Namespace, p.Name)
	if err != nil || len(disk.GetOwnerReferences()) != 0 {
		t.Fatalf("reusable disk must not be garbage collected with a workspace: %v", err)
	}
	if _, found, _ := unstructured.NestedMap(disk.Object, "spec", "source", "blank"); !found {
		t.Fatal("expected CDI blank source")
	}
	if _, err := s.Create(ctx, p); err != nil {
		t.Fatalf("idempotent create: %v", err)
	}
	_, err = s.clientset.CoreV1().PersistentVolumeClaims("test").Create(ctx, &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "test"}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	items, err := s.List(ctx, &volumes.ListPayload{Namespace: "test"})
	if err != nil || len(items) != 1 || items[0].Type != "vm-disk" {
		t.Fatalf("CDI PVC and DV must be one disk in list: %v %v", items, err)
	}
	p.Type = "pvc"
	if _, err := s.Create(ctx, p); err == nil {
		t.Fatal("must not convert a disk into a container PVC")
	}
	if err := s.Delete(ctx, &volumes.DeletePayload{Namespace: "test", Name: "data"}); err != nil {
		t.Fatal(err)
	}
}

func TestVMVolumeValidationAndDeletionProtection(t *testing.T) {
	ctx := context.Background()
	s := testVolumeService()
	_, err := s.Create(ctx, &volumes.CreateVolumePayload{Name: "data", Namespace: "test", Size: "1Gi", Type: "vm-disk"})
	if err != nil {
		t.Fatal(err)
	}
	payload := &workspaces.CreateWorkspacePayload{Namespace: "test", VolumeMounts: []*workspaces.VolumeMount{{Name: "data", MountPath: "/data"}}}
	if err := validateVMVolumeMounts(ctx, s.dynamicClient, payload); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"/", "/etc", "/etc/subdir", "/data/../etc", "relative", "/data\ncommand"} {
		payload.VolumeMounts[0].MountPath = invalid
		if err := validateVMVolumeMounts(ctx, s.dynamicClient, payload); err == nil {
			t.Fatalf("accepted unsafe mount path %q", invalid)
		}
	}
	ws := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Workspace", "metadata": map[string]interface{}{"name": "vm", "namespace": "test"},
		"spec": map[string]interface{}{"type": "vm", "template": map[string]interface{}{"spec": map[string]interface{}{"containers": []interface{}{
			map[string]interface{}{"volumeMounts": []interface{}{map[string]interface{}{"name": "data", "mountPath": "/data"}}},
		}}}},
	}}
	if _, err := s.dynamicClient.Resource(vmWorkspaceGVR).Namespace("test").Create(ctx, ws, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, &volumes.DeletePayload{Namespace: "test", Name: "data"}); err == nil {
		t.Fatal("must not delete a disk configured on an existing workspace")
	}
}
