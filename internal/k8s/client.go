package k8s

import (
	"context"
	"fmt"
	"io"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// NewClient creates a Kubernetes clientset (used by volumes and namespaces services).
func NewClient() (*kubernetes.Clientset, error) {
	config, err := getConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

// NewDynamicClient creates a dynamic Kubernetes client for working with CRDs.
func NewDynamicClient() (dynamic.Interface, error) {
	config, err := getConfig()
	if err != nil {
		return nil, err
	}
	return dynamic.NewForConfig(config)
}

// CoreClient provides operations on core Kubernetes resources (pods, events).
type CoreClient struct {
	clientset kubernetes.Interface
}

// NewCoreClient creates a new CoreClient using in-cluster config or kubeconfig.
func NewCoreClient() (*CoreClient, error) {
	config, err := getConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes clientset: %w", err)
	}

	return &CoreClient{clientset: clientset}, nil
}

// GetPod returns a pod by name and namespace.
func (c *CoreClient) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	return c.clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
}

// ListPods returns pods matching label selector in a namespace.
func (c *CoreClient) ListPods(ctx context.Context, namespace, labelSelector string) (*corev1.PodList, error) {
	return c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
}

// GetPodLogs returns the logs of a pod's container as a string.
func (c *CoreClient) GetPodLogs(ctx context.Context, namespace, name, container string, tailLines int64) (string, error) {
	opts := &corev1.PodLogOptions{}
	if container != "" {
		opts.Container = container
	}
	if tailLines > 0 {
		opts.TailLines = &tailLines
	}

	req := c.clientset.CoreV1().Pods(namespace).GetLogs(name, opts)
	stream, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get pod logs: %w", err)
	}
	defer stream.Close()

	bytes, err := io.ReadAll(stream)
	if err != nil {
		return "", fmt.Errorf("failed to read pod logs: %w", err)
	}

	return string(bytes), nil
}

// ListEvents returns events for a specific object (by field selector).
func (c *CoreClient) ListEvents(ctx context.Context, namespace, fieldSelector string) (*corev1.EventList, error) {
	return c.clientset.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fieldSelector,
	})
}

// ListNamespaceEvents returns all events in a namespace, optionally filtered.
func (c *CoreClient) ListNamespaceEvents(ctx context.Context, namespace string) (*corev1.EventList, error) {
	return c.clientset.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{})
}

// GetStatefulSet returns a StatefulSet by name and namespace.
func (c *CoreClient) GetStatefulSet(ctx context.Context, namespace, name string) (interface{}, error) {
	return c.clientset.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
}

// GetRESTConfig returns a Kubernetes REST config for use by the exec handler.
func GetRESTConfig() (*rest.Config, error) {
	return getConfig()
}

// GetClientset returns a Kubernetes clientset for use by the exec handler.
func GetClientset() (kubernetes.Interface, error) {
	config, err := getConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

// ListNamespaces returns all namespaces in the cluster.
func (c *CoreClient) ListNamespaces(ctx context.Context) (*corev1.NamespaceList, error) {
	return c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
}

// AnnotateNamespace sets or removes an annotation on a namespace.
// If value is empty, the annotation is removed.
func (c *CoreClient) AnnotateNamespace(ctx context.Context, name, key, value string) error {
	ns, err := c.clientset.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get namespace %s: %w", name, err)
	}

	if ns.Annotations == nil {
		ns.Annotations = make(map[string]string)
	}

	if value == "" {
		delete(ns.Annotations, key)
	} else {
		ns.Annotations[key] = value
	}

	_, err = c.clientset.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update namespace %s: %w", name, err)
	}
	return nil
}

// CreateWorkspaceEvent creates a Kubernetes Event associated with a Workspace CR.
func (c *CoreClient) CreateWorkspaceEvent(ctx context.Context, namespace, workspaceName, action, actor, message string) error {
	now := metav1.Now()
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: workspaceName + "-",
			Namespace:    namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: "kubeworkspaces.io/v1alpha1",
			Kind:       "Workspace",
			Name:       workspaceName,
			Namespace:  namespace,
		},
		Reason:              action,
		Message:             message,
		Type:                "Normal",
		Source:              corev1.EventSource{Component: "kube-workspaces-api"},
		FirstTimestamp:      now,
		LastTimestamp:       now,
		EventTime:           metav1.NewMicroTime(time.Now()),
		ReportingController: "kube-workspaces-api",
		ReportingInstance:   "kube-workspaces-api",
		Action:              action,
	}

	_, err := c.clientset.CoreV1().Events(namespace).Create(ctx, event, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create event: %w", err)
	}
	return nil
}

// ListWorkspaceEvents returns events related to a specific workspace.
func (c *CoreClient) ListWorkspaceEvents(ctx context.Context, namespace, workspaceName string) (*corev1.EventList, error) {
	return c.clientset.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("involvedObject.name=%s,involvedObject.kind=Workspace", workspaceName),
	})
}
