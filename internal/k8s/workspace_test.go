package k8s

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func newFakeWorkspaceClient() *WorkspaceClient {
	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			workspaceGVR: "WorkspaceList",
		})
	return NewWorkspaceClientFor(dyn)
}

func TestWatchWorkspacesReceivesAdded(t *testing.T) {
	c := newFakeWorkspaceClient()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher, err := c.WatchWorkspaces(ctx, "workspaces", metav1.ListOptions{})
	if err != nil {
		t.Fatalf("WatchWorkspaces: %v", err)
	}
	defer watcher.Stop()

	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1",
		"kind":       "Workspace",
		"metadata":   map[string]interface{}{"name": "ws-1", "namespace": "workspaces"},
	}}
	if _, err := c.CreateWorkspace(ctx, obj); err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}

	select {
	case ev, ok := <-watcher.ResultChan():
		if !ok {
			t.Fatal("watch channel closed")
		}
		if ev.Type != watch.Added {
			t.Fatalf("event type = %v, want Added", ev.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Added event")
	}
}
