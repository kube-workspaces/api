package kubeworkspaces

import (
	"context"
	"testing"

	"github.com/kube-workspaces/api/gen/images"
	"github.com/kube-workspaces/api/gen/workspaces"
	"github.com/kube-workspaces/api/internal/k8s"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

func TestCloudImageCreateAndClone(t *testing.T) {
	const ref = "https://images.example.org/arch/cloud.qcow2"
	dyn := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "images"}: "ImageList",
	})
	imageClient := k8s.NewImageClientFor(dyn)
	persistent, cloudInit := true, true
	userData := "#cloud-config\npackages: [gnome]\n"
	img, err := NewImages(imageClient).Create(context.Background(), &images.CreateImagePayload{
		Name: "Arch GNOME", Image: ref, DefaultPort: 22, WorkspaceTypes: []string{"vm"},
		PersistentRootDisk: &persistent, DefaultCloudInit: &cloudInit, DefaultUserData: &userData,
	})
	if err != nil || img.Image != ref {
		t.Fatalf("cloud catalog creation failed: %v, %v", img, err)
	}
	svc := NewWorkspaces(k8s.NewWorkspaceClientFor(dyn), imageClient, nil, nil, nil)
	payload := &workspaces.CreateWorkspacePayload{Name: "arch", Namespace: "test", Type: "vm",
		Container: &workspaces.WorkspaceContainer{Name: "arch", Image: ref, Port: 22, CPULimit: "2", MemoryLimit: "4Gi"}}
	created, err := svc.Create(context.Background(), payload)
	if err != nil || created.Image != ref {
		t.Fatalf("workspace URL not preserved: %v, %v", created, err)
	}
	cloned, err := svc.Clone(context.Background(), &workspaces.ClonePayload{Name: "arch", Namespace: "test", NewName: "arch-clone"})
	if err != nil || cloned.Image != ref {
		t.Fatalf("clone URL not preserved: %v, %v", cloned, err)
	}
	payload.Type = "container"
	if _, err := svc.Create(context.Background(), payload); err == nil {
		t.Fatal("cloud image accepted for container workspace")
	}
	payload.Type = "vm"
	payload.Container.Image = "https://images.example.org/unregistered.qcow2"
	if _, err := svc.Create(context.Background(), payload); err == nil {
		t.Fatal("uncatalogued cloud image accepted")
	}
}

func TestCloudImageRejectsInvalidCatalogContract(t *testing.T) {
	for _, tt := range []struct {
		name, ref  string
		persistent bool
		types      []string
	}{
		{"ephemeral", "https://images.example.org/cloud.qcow2", false, []string{"vm"}},
		{"container", "https://images.example.org/cloud.qcow2", true, []string{"container"}},
		{"mixed types", "https://images.example.org/cloud.qcow2", true, []string{"vm", "container"}},
		{"credentials", "https://user:password@images.example.org/cloud.qcow2", true, []string{"vm"}},
		{"missing host", "https:///cloud.qcow2", true, []string{"vm"}},
		{"fragment", "https://images.example.org/cloud.qcow2#fragment", true, []string{"vm"}},
		{"unsupported scheme", "ftp://images.example.org/cloud.qcow2", true, []string{"vm"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dyn := fake.NewSimpleDynamicClient(runtime.NewScheme())
			_, err := NewImages(k8s.NewImageClientFor(dyn)).Create(context.Background(), &images.CreateImagePayload{
				Name: "Arch", Image: tt.ref, DefaultPort: 22, WorkspaceTypes: tt.types, PersistentRootDisk: &tt.persistent,
			})
			if err == nil {
				t.Fatal("invalid cloud image catalog declaration accepted")
			}
			for _, action := range dyn.Actions() {
				if action.GetVerb() == "create" {
					t.Fatal("invalid declaration was written to the Kubernetes API")
				}
			}
		})
	}
}
