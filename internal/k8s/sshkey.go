package k8s

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var sshKeyGVR = schema.GroupVersionResource{
	Group:    "kubeworkspaces.io",
	Version:  "v1alpha1",
	Resource: "sshkeys",
}

// SSHKeyClient provides operations on SshKey custom resources (users' SSH
// public keys stored in their personal namespace).
type SSHKeyClient struct {
	dynamic dynamic.Interface
}

// NewSSHKeyClient creates a new SSHKeyClient.
func NewSSHKeyClient() (*SSHKeyClient, error) {
	config, err := getConfig()
	if err != nil {
		return nil, err
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create dynamic client: %w", err)
	}

	return &SSHKeyClient{dynamic: dynClient}, nil
}

// ListSSHKeys lists all SshKey CRs in a namespace.
func (c *SSHKeyClient) ListSSHKeys(ctx context.Context, namespace string) (*unstructured.UnstructuredList, error) {
	return c.dynamic.Resource(sshKeyGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
}

// GetSSHKey gets an SshKey CR by name.
func (c *SSHKeyClient) GetSSHKey(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	return c.dynamic.Resource(sshKeyGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
}

// CreateSSHKey creates a new SshKey CR.
func (c *SSHKeyClient) CreateSSHKey(ctx context.Context, sshKey *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	namespace := sshKey.GetNamespace()
	return c.dynamic.Resource(sshKeyGVR).Namespace(namespace).Create(ctx, sshKey, metav1.CreateOptions{})
}

// DeleteSSHKey deletes an SshKey CR.
func (c *SSHKeyClient) DeleteSSHKey(ctx context.Context, namespace, name string) error {
	return c.dynamic.Resource(sshKeyGVR).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
}
