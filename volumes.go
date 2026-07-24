package kubeworkspaces

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	volumes "github.com/kube-workspaces/api/gen/volumes"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/k8s"
	"goa.design/clue/log"
	"k8s.io/client-go/kubernetes"
)

// volumes service implementation.
type volumessrvc struct {
	clientset    *kubernetes.Clientset
	authProvider *auth.ConfigProvider
}

// NewVolumes returns the volumes service implementation.
func NewVolumes(authProvider *auth.ConfigProvider) volumes.Service {
	clientset, err := k8s.NewClient()
	if err != nil {
		panic(fmt.Sprintf("failed to create kubernetes client: %v", err))
	}
	return &volumessrvc{clientset: clientset, authProvider: authProvider}
}

// List all volumes
func (s *volumessrvc) List(ctx context.Context, p *volumes.ListPayload) (res []*volumes.Volume, err error) {
	ns := p.Namespace
	if ns == "_all" {
		ns = ""
	}
	log.Printf(ctx, "volumes.list namespace=%s", ns)

	// Check namespace access
	if ns != "" && s.isNamespaceRestricted(ctx) {
		user := auth.UserFromContext(ctx)
		if user != nil && user.Role != "admin" && !auth.UserHasNamespaceAccess(user, ns) {
			return []*volumes.Volume{}, nil
		}
	}

	pvcList, err := s.clientset.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list PVCs: %w", err)
	}

	res = make([]*volumes.Volume, 0, len(pvcList.Items))
	for i := range pvcList.Items {
		res = append(res, pvcToVolume(&pvcList.Items[i]))
	}

	// Filter if listing across all namespaces
	if (p.Namespace == "_all" || p.Namespace == "") && s.isNamespaceRestricted(ctx) {
		res = s.filterVolumesByAccess(ctx, res)
	}

	return res, nil
}

func (s *volumessrvc) filterVolumesByAccess(ctx context.Context, items []*volumes.Volume) []*volumes.Volume {
	user := auth.UserFromContext(ctx)
	if user == nil || user.Role == "admin" {
		return items
	}
	var filtered []*volumes.Volume
	for _, v := range items {
		if auth.UserHasNamespaceAccess(user, v.Namespace) {
			filtered = append(filtered, v)
		}
	}
	if filtered == nil {
		filtered = []*volumes.Volume{}
	}
	return filtered
}

func (s *volumessrvc) isNamespaceRestricted(ctx context.Context) bool {
	if s.authProvider == nil {
		return false
	}
	cfg, err := s.authProvider.GetConfig(ctx)
	if err != nil || cfg == nil {
		return false
	}
	return cfg.Enabled && cfg.RestrictNamespaceAccess
}

// Get a volume by name
func (s *volumessrvc) Get(ctx context.Context, p *volumes.GetPayload) (res *volumes.Volume, err error) {
	log.Printf(ctx, "volumes.get name=%s namespace=%s", p.Name, p.Namespace)

	pvc, err := s.clientset.CoreV1().PersistentVolumeClaims(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
	if err != nil {
		return nil, volumes.NotFound(fmt.Sprintf("volume %s/%s not found", p.Namespace, p.Name))
	}

	return pvcToVolume(pvc), nil
}

const managedLabel = "kubeworkspaces.io/managed"

// Create a new volume (PVC) — idempotent: returns existing PVC if already present.
func (s *volumessrvc) Create(ctx context.Context, p *volumes.CreateVolumePayload) (res *volumes.Volume, err error) {
	log.Printf(ctx, "volumes.create name=%s namespace=%s size=%s", p.Name, p.Namespace, p.Size)

	accessMode := corev1.ReadWriteOnce
	switch p.AccessMode {
	case "ReadWriteMany":
		accessMode = corev1.ReadWriteMany
	case "ReadOnlyMany":
		accessMode = corev1.ReadOnlyMany
	}

	ensureManaged := func(pvc *corev1.PersistentVolumeClaim) {
		if pvc.Labels == nil {
			pvc.Labels = make(map[string]string)
		}
		pvc.Labels[managedLabel] = "true"
	}

	// Check if PVC already exists
	existing, getErr := s.clientset.CoreV1().PersistentVolumeClaims(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
	if getErr == nil {
		// PVC exists — update it
		existing.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{accessMode}
		existing.Spec.Resources = corev1.VolumeResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse(p.Size),
			},
		}
		if p.StorageClass != nil && *p.StorageClass != "" {
			existing.Spec.StorageClassName = p.StorageClass
		}
		ensureManaged(existing)
		updated, updateErr := s.clientset.CoreV1().PersistentVolumeClaims(p.Namespace).Update(ctx, existing, metav1.UpdateOptions{})
		if updateErr != nil {
			return nil, fmt.Errorf("failed to update PVC: %w", updateErr)
		}
		return pvcToVolume(updated), nil
	}

	// PVC doesn't exist — create it
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.Name,
			Namespace: p.Namespace,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{accessMode},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(p.Size),
				},
			},
		},
	}

	if p.StorageClass != nil && *p.StorageClass != "" {
		pvc.Spec.StorageClassName = p.StorageClass
	}

	ensureManaged(pvc)

	created, err := s.clientset.CoreV1().PersistentVolumeClaims(p.Namespace).Create(ctx, pvc, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create PVC: %w", err)
	}

	return pvcToVolume(created), nil
}

// Delete a volume
func (s *volumessrvc) Delete(ctx context.Context, p *volumes.DeletePayload) (err error) {
	log.Printf(ctx, "volumes.delete name=%s namespace=%s", p.Name, p.Namespace)

	err = s.clientset.CoreV1().PersistentVolumeClaims(p.Namespace).Delete(ctx, p.Name, metav1.DeleteOptions{})
	if err != nil {
		return volumes.NotFound(fmt.Sprintf("volume %s/%s not found", p.Namespace, p.Name))
	}
	return nil
}

func pvcToVolume(pvc *corev1.PersistentVolumeClaim) *volumes.Volume {
	vol := &volumes.Volume{
		Name:      pvc.Name,
		Namespace: pvc.Namespace,
		Phase:     string(pvc.Status.Phase),
	}

	// Size
	if storage, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
		size := storage.String()
		vol.Size = size
	}

	// Storage class
	if pvc.Spec.StorageClassName != nil {
		vol.StorageClass = pvc.Spec.StorageClassName
	}

	// Access mode
	if len(pvc.Spec.AccessModes) > 0 {
		am := string(pvc.Spec.AccessModes[0])
		vol.AccessMode = &am
	}

	// Creation timestamp
	createdAt := pvc.CreationTimestamp.Format("2006-01-02T15:04:05Z")
	vol.CreatedAt = &createdAt

	// Labels
	if len(pvc.Labels) > 0 {
		vol.Labels = pvc.Labels
	}

	return vol
}
