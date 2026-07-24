package kubeworkspaces

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	namespaces "github.com/kube-workspaces/api/gen/namespaces"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/k8s"
	"goa.design/clue/log"
	"k8s.io/client-go/kubernetes"
)

// namespaces service implementation.
type namespacessrvc struct {
	clientset    *kubernetes.Clientset
	authProvider *auth.ConfigProvider
}

// NewNamespaces returns the namespaces service implementation.
func NewNamespaces(authProvider *auth.ConfigProvider) namespaces.Service {
	clientset, err := k8s.NewClient()
	if err != nil {
		panic(fmt.Sprintf("failed to create kubernetes client: %v", err))
	}
	return &namespacessrvc{clientset: clientset, authProvider: authProvider}
}

// List available namespaces
func (s *namespacessrvc) List(ctx context.Context) (res []*namespaces.Namespace, err error) {
	log.Printf(ctx, "namespaces.list")

	nsList, err := s.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	// Check if any namespace has the enabled annotation set — this activates filtering
	hasEnabledAnnotation := false
	for i := range nsList.Items {
		if _, ok := nsList.Items[i].Annotations["kubeworkspaces.io/namespace-enabled"]; ok {
			hasEnabledAnnotation = true
			break
		}
	}

	res = make([]*namespaces.Namespace, 0, len(nsList.Items))
	for i := range nsList.Items {
		ns := &nsList.Items[i]

		// If any namespace uses the enabled annotation, only include those explicitly enabled
		if hasEnabledAnnotation {
			if ns.Annotations["kubeworkspaces.io/namespace-enabled"] != "true" {
				continue
			}
		}

		createdAt := ns.CreationTimestamp.Format("2006-01-02T15:04:05Z")
		res = append(res, &namespaces.Namespace{
			Name:      ns.Name,
			Phase:     string(ns.Status.Phase),
			CreatedAt: &createdAt,
		})
	}

	// Filter namespaces if restriction is enabled
	if s.isNamespaceRestricted(ctx) {
		res = s.filterNamespacesByAccess(ctx, res)
	}

	return res, nil
}

func (s *namespacessrvc) filterNamespacesByAccess(ctx context.Context, items []*namespaces.Namespace) []*namespaces.Namespace {
	user := auth.UserFromContext(ctx)
	if user == nil || user.Role == "admin" {
		return items
	}
	var filtered []*namespaces.Namespace
	for _, ns := range items {
		if auth.UserHasNamespaceAccess(user, ns.Name) {
			filtered = append(filtered, ns)
		}
	}
	if filtered == nil {
		filtered = []*namespaces.Namespace{}
	}
	return filtered
}

func (s *namespacessrvc) isNamespaceRestricted(ctx context.Context) bool {
	if s.authProvider == nil {
		return false
	}
	cfg, err := s.authProvider.GetConfig(ctx)
	if err != nil || cfg == nil {
		return false
	}
	return cfg.Enabled && cfg.RestrictNamespaceAccess
}
