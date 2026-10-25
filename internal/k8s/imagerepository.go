package k8s

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

var imageRepositoryGVR = schema.GroupVersionResource{
	Group:    "kubeworkspaces.io",
	Version:  "v1alpha1",
	Resource: "imagerepositories",
}

// ImageRepositoryClient provides operations on ImageRepository custom resources.
type ImageRepositoryClient struct {
	dynamic dynamic.Interface
}

// NewImageRepositoryClient creates a new ImageRepositoryClient.
func NewImageRepositoryClient() (*ImageRepositoryClient, error) {
	config, err := getConfig()
	if err != nil {
		return nil, err
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create dynamic client: %w", err)
	}

	return &ImageRepositoryClient{dynamic: dynClient}, nil
}

func NewImageRepositoryClientFor(client dynamic.Interface) *ImageRepositoryClient {
	return &ImageRepositoryClient{dynamic: client}
}

// ListImageRepositories lists all ImageRepository CRs (cluster-scoped).
func (c *ImageRepositoryClient) ListImageRepositories(ctx context.Context) (*unstructured.UnstructuredList, error) {
	return c.dynamic.Resource(imageRepositoryGVR).List(ctx, metav1.ListOptions{})
}

// GetImageRepositoryRaw returns the raw unstructured ImageRepository CR object.
func (c *ImageRepositoryClient) GetImageRepositoryRaw(ctx context.Context, name string) (*unstructured.Unstructured, error) {
	return c.dynamic.Resource(imageRepositoryGVR).Get(ctx, name, metav1.GetOptions{})
}

// CreateImageRepository creates a new ImageRepository CR.
func (c *ImageRepositoryClient) CreateImageRepository(ctx context.Context, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	return c.dynamic.Resource(imageRepositoryGVR).Create(ctx, obj, metav1.CreateOptions{})
}

// UpdateImageRepository updates an existing ImageRepository CR.
func (c *ImageRepositoryClient) UpdateImageRepository(ctx context.Context, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	return c.dynamic.Resource(imageRepositoryGVR).Update(ctx, obj, metav1.UpdateOptions{})
}

// DeleteImageRepository deletes an ImageRepository CR.
func (c *ImageRepositoryClient) DeleteImageRepository(ctx context.Context, name string) error {
	return c.dynamic.Resource(imageRepositoryGVR).Delete(ctx, name, metav1.DeleteOptions{})
}

// PatchImageRepository patches an ImageRepository CR.
func (c *ImageRepositoryClient) PatchImageRepository(ctx context.Context, name string, pt types.PatchType, data []byte) (*unstructured.Unstructured, error) {
	return c.dynamic.Resource(imageRepositoryGVR).Patch(ctx, name, pt, data, metav1.PatchOptions{})
}
