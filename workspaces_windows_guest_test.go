package kubeworkspaces

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/kube-workspaces/api/gen/workspaces"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/k8s"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

func TestWindowsProfileRejectsLinuxOptionsAndPinsSource(t *testing.T) {
	image := &k8s.Image{Image: "registry.example.com/private/windows@sha256:" + strings.Repeat("a", 64), VMProfile: windowsVMProfile, PersistentRootDisk: true}
	payload := &workspaces.CreateWorkspacePayload{Name: "desktop", Namespace: "test", Type: "vm", NodeSelector: map[string]string{"kubernetes.io/hostname": "worker"}, Container: &workspaces.WorkspaceContainer{Name: "desktop", Image: image.Image, CPULimit: "2", MemoryLimit: "4Gi"}}
	profile, err := buildWindowsProfile(payload, image)
	if err != nil || profile["image"] != image.Image || profile["rootDiskSize"] != "80Gi" {
		t.Fatalf("wrong resolved Windows profile: %v", err)
	}
	payload.VolumeMounts = []*workspaces.VolumeMount{{Name: "linux", MountPath: "/home"}}
	if _, err := buildWindowsProfile(payload, image); err == nil {
		t.Fatal("Linux disk mounting accepted")
	}
	payload.VolumeMounts = nil
	payload.Container.MemoryLimit = "2Gi"
	if _, err := buildWindowsProfile(payload, image); err == nil {
		t.Fatal("undersized Windows memory accepted")
	}
}

func TestWindowsCredentialAuthorizationOwnershipAndNoStore(t *testing.T) {
	ws := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Workspace", "metadata": map[string]interface{}{"name": "desktop", "namespace": "test", "uid": "workspace-uid"},
		"spec": map[string]interface{}{"vmProfile": map[string]interface{}{"id": windowsVMProfile, "generation": "one"}},
	}}
	sum := sha256.Sum256([]byte("desktop/one"))
	secret := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Secret", "metadata": map[string]interface{}{"name": fmt.Sprintf("desktop-win-%x", sum[:6]), "namespace": "test", "labels": map[string]interface{}{"kubeworkspaces.io/windows-generation": "one"}, "ownerReferences": []interface{}{map[string]interface{}{"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Workspace", "name": "desktop", "uid": "workspace-uid", "controller": true}}},
		"data": map[string]interface{}{"username": base64.StdEncoding.EncodeToString([]byte("workspace")), "password": base64.StdEncoding.EncodeToString([]byte("test-only-password"))},
	}}
	dynamic := fake.NewSimpleDynamicClient(runtime.NewScheme(), ws, secret)
	service := &workspacessrvc{client: k8s.NewWorkspaceClientFor(dynamic)}
	for _, user := range []*auth.UserInfo{{Role: "viewer", PersonalNamespace: "test"}, {Role: "editor", PersonalNamespace: "other"}} {
		ctx := auth.ContextWithUser(context.Background(), user)
		if _, err := service.Credentials(ctx, &workspaces.CredentialsPayload{Name: "desktop", Namespace: "test"}); err == nil {
			t.Fatal("unauthorized credential retrieval accepted")
		}
	}
	ctx := auth.ContextWithUser(context.Background(), &auth.UserInfo{Role: "editor", PersonalNamespace: "test"})
	result, err := service.Credentials(ctx, &workspaces.CredentialsPayload{Name: "desktop", Namespace: "test"})
	if err != nil || result.Password != "test-only-password" || result.CacheControl != "no-store" {
		t.Fatalf("authorized credential contract failed: %v", err)
	}
	owners := secret.GetOwnerReferences()
	owners[0].UID = "other-workspace"
	secret.SetOwnerReferences(owners)
	if err := dynamic.Tracker().Update(schema.GroupVersionResource{Version: "v1", Resource: "secrets"}, secret, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Credentials(ctx, &workspaces.CredentialsPayload{Name: "desktop", Namespace: "test"}); err == nil {
		t.Fatal("foreign Secret ownership accepted")
	}
}
