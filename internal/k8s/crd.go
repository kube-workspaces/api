package k8s

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var crdGVR = schema.GroupVersionResource{
	Group:    "apiextensions.k8s.io",
	Version:  "v1",
	Resource: "customresourcedefinitions",
}

// CRDClient provides operations on CustomResourceDefinition resources.
type CRDClient struct {
	dynamic dynamic.Interface
}

// NewCRDClient creates a new CRDClient using the same config as other clients.
func NewCRDClient() (*CRDClient, error) {
	config, err := getConfig()
	if err != nil {
		return nil, err
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create dynamic client: %w", err)
	}

	return &CRDClient{dynamic: dynClient}, nil
}

// ListCRDs lists all CustomResourceDefinitions in the cluster.
func (c *CRDClient) ListCRDs(ctx context.Context) (*unstructured.UnstructuredList, error) {
	return c.dynamic.Resource(crdGVR).List(ctx, metav1.ListOptions{})
}

// ListCRDsByGroup lists CustomResourceDefinitions filtered by spec.group.
func (c *CRDClient) ListCRDsByGroup(ctx context.Context, group string) (*unstructured.UnstructuredList, error) {
	list, err := c.dynamic.Resource(crdGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var filtered unstructured.UnstructuredList
	filtered.SetGroupVersionKind(list.GroupVersionKind())
	for i := range list.Items {
		g, _, _ := unstructured.NestedString(list.Items[i].Object, "spec", "group")
		if g == group {
			filtered.Items = append(filtered.Items, list.Items[i])
		}
	}
	return &filtered, nil
}

// GetCRD gets a CustomResourceDefinition by name.
func (c *CRDClient) GetCRD(ctx context.Context, name string) (*unstructured.Unstructured, error) {
	return c.dynamic.Resource(crdGVR).Get(ctx, name, metav1.GetOptions{})
}

// ListCRDInstances lists all instances of a CRD identified by group/version/resource.
// For namespaced CRDs, pass namespace; for cluster-scoped, pass "".
func (c *CRDClient) ListCRDInstances(ctx context.Context, group, version, resource, namespace string) (*unstructured.UnstructuredList, error) {
	gvr := schema.GroupVersionResource{
		Group:    group,
		Version:  version,
		Resource: resource,
	}
	if namespace != "" {
		return c.dynamic.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	}
	return c.dynamic.Resource(gvr).List(ctx, metav1.ListOptions{})
}
