package k8s

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"path/filepath"
)

var workspaceGVR = schema.GroupVersionResource{
	Group:    "kubeworkspaces.io",
	Version:  "v1alpha1",
	Resource: "workspaces",
}

// WorkspaceClient provides operations on Workspace custom resources.
type WorkspaceClient struct {
	dynamic dynamic.Interface
}

// NewWorkspaceClient creates a new WorkspaceClient.
func NewWorkspaceClient() (*WorkspaceClient, error) {
	config, err := getConfig()
	if err != nil {
		return nil, err
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create dynamic client: %w", err)
	}

	return &WorkspaceClient{dynamic: dynClient}, nil
}

func getConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("unable to determine home directory: %w", err)
			}
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("unable to build kubeconfig: %w", err)
		}
	}
	return config, nil
}

// ListWorkspaces lists all workspace CRs in a namespace.
func (c *WorkspaceClient) ListWorkspaces(ctx context.Context, namespace string) (*unstructured.UnstructuredList, error) {
	return c.dynamic.Resource(workspaceGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
}

// GetWorkspace gets a workspace CR by name.
func (c *WorkspaceClient) GetWorkspace(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	return c.dynamic.Resource(workspaceGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
}

// CreateWorkspace creates a new workspace CR.
func (c *WorkspaceClient) CreateWorkspace(ctx context.Context, workspace *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	namespace := workspace.GetNamespace()
	return c.dynamic.Resource(workspaceGVR).Namespace(namespace).Create(ctx, workspace, metav1.CreateOptions{})
}

// DeleteWorkspace deletes a workspace CR.
func (c *WorkspaceClient) DeleteWorkspace(ctx context.Context, namespace, name string) error {
	return c.dynamic.Resource(workspaceGVR).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
}

// UpdateWorkspace updates an existing workspace CR.
func (c *WorkspaceClient) UpdateWorkspace(ctx context.Context, workspace *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	namespace := workspace.GetNamespace()
	return c.dynamic.Resource(workspaceGVR).Namespace(namespace).Update(ctx, workspace, metav1.UpdateOptions{})
}
