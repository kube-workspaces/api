package kubeworkspaces

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/kube-workspaces/api/gen/volumes"
	"github.com/kube-workspaces/api/gen/workspaces"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
)

const vmDiskTypeLabel = "kubeworkspaces.io/volume-type"
const vmDiskOwnerAnnotation = "kubeworkspaces.io/disk-workspace"

var vmDataVolumeGVR = schema.GroupVersionResource{Group: "cdi.kubevirt.io", Version: "v1beta1", Resource: "datavolumes"}
var vmWorkspaceGVR = schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "workspaces"}

func (s *volumessrvc) getVMDataVolume(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	disk, err := s.dynamicClient.Resource(vmDataVolumeGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if disk.GetLabels()[vmDiskTypeLabel] != "vm-disk" {
		return nil, nil
	}
	return disk, nil
}

func dataVolumeToVolume(disk *unstructured.Unstructured) *volumes.Volume {
	size, _, _ := unstructured.NestedString(disk.Object, "spec", "pvc", "resources", "requests", "storage")
	sc, found, _ := unstructured.NestedString(disk.Object, "spec", "pvc", "storageClassName")
	phase, _, _ := unstructured.NestedString(disk.Object, "status", "phase")
	if phase == "" {
		phase = "Pending"
	} else if phase == "Succeeded" {
		phase = "Bound"
	}
	created := disk.GetCreationTimestamp().Format("2006-01-02T15:04:05Z")
	mode := "ReadWriteOnce"
	result := &volumes.Volume{Name: disk.GetName(), Namespace: disk.GetNamespace(), Type: "vm-disk",
		Size: size, Phase: phase, CreatedAt: &created, AccessMode: &mode, Labels: disk.GetLabels()}
	if found {
		result.StorageClass = &sc
	}
	return result
}

func (s *volumessrvc) appendVMDisks(ctx context.Context, namespace string, items *[]*volumes.Volume) error {
	disks, err := s.dynamicClient.Resource(vmDataVolumeGVR).Namespace(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: vmDiskTypeLabel + "=vm-disk",
	})
	if apierrors.IsNotFound(err) {
		return nil // CDI is optional on container-only clusters.
	}
	if err != nil {
		return err
	}
	index := map[string]int{}
	for i, volume := range *items {
		index[volume.Namespace+"/"+volume.Name] = i
	}
	for i := range disks.Items {
		volume := dataVolumeToVolume(&disks.Items[i])
		if position, found := index[volume.Namespace+"/"+volume.Name]; found {
			(*items)[position] = volume
		} else {
			*items = append(*items, volume)
		}
	}
	return nil
}

func (s *volumessrvc) createVMDataVolume(ctx context.Context, p *volumes.CreateVolumePayload) (*volumes.Volume, error) {
	if p.AccessMode != "" && p.AccessMode != "ReadWriteOnce" {
		return nil, fmt.Errorf("VM data disks require ReadWriteOnce")
	}
	if existing, err := s.getVMDataVolume(ctx, p.Namespace, p.Name); err != nil {
		return nil, err
	} else if existing != nil {
		volume := dataVolumeToVolume(existing)
		existingSize, err := resource.ParseQuantity(volume.Size)
		requestedSize, parseErr := resource.ParseQuantity(p.Size)
		if err != nil || parseErr != nil || existingSize.Cmp(requestedSize) != 0 || (p.StorageClass != nil && (volume.StorageClass == nil || *volume.StorageClass != *p.StorageClass)) {
			return nil, fmt.Errorf("VM disk already exists with different size or storage class; resizing is not supported")
		}
		return volume, nil
	}
	if _, err := s.clientset.CoreV1().PersistentVolumeClaims(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{}); err == nil {
		return nil, fmt.Errorf("a PVC with this name already exists; container PVCs cannot be converted to VM disks")
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}
	pvc := map[string]interface{}{"accessModes": []interface{}{"ReadWriteOnce"}, "resources": map[string]interface{}{
		"requests": map[string]interface{}{"storage": p.Size},
	}}
	if p.StorageClass != nil {
		pvc["storageClassName"] = *p.StorageClass
	}
	disk := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cdi.kubevirt.io/v1beta1", "kind": "DataVolume",
		"metadata": map[string]interface{}{"name": p.Name, "namespace": p.Namespace,
			"labels": map[string]interface{}{managedLabel: "true", vmDiskTypeLabel: "vm-disk"}},
		"spec": map[string]interface{}{"source": map[string]interface{}{"blank": map[string]interface{}{}}, "pvc": pvc},
	}}
	created, err := s.dynamicClient.Resource(vmDataVolumeGVR).Namespace(p.Namespace).Create(ctx, disk, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("cannot create VM disk (CDI must be installed): %w", err)
	}
	return dataVolumeToVolume(created), nil
}

func (s *volumessrvc) ensureVMDataVolumeUnused(ctx context.Context, disk *unstructured.Unstructured) error {
	items, err := s.dynamicClient.Resource(vmWorkspaceGVR).Namespace(disk.GetNamespace()).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, ws := range items.Items {
		wsType, _, _ := unstructured.NestedString(ws.Object, "spec", "type")
		containers, _, _ := unstructured.NestedSlice(ws.Object, "spec", "template", "spec", "containers")
		if wsType != "vm" || len(containers) == 0 {
			continue
		}
		mounts, _, _ := unstructured.NestedSlice(containers[0].(map[string]interface{}), "volumeMounts")
		for _, mount := range mounts {
			if mount.(map[string]interface{})["name"] == disk.GetName() {
				return fmt.Errorf("VM disk is attached to workspace %s; delete the workspace before deleting its disk", ws.GetName())
			}
		}
	}
	// A deleted Workspace can still have a terminating VMI using its disk.
	vmiGVR := schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstances"}
	vmis, err := s.dynamicClient.Resource(vmiGVR).Namespace(disk.GetNamespace()).List(ctx, metav1.ListOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if err == nil {
		for _, vmi := range vmis.Items {
			attached, _, _ := unstructured.NestedSlice(vmi.Object, "spec", "volumes")
			for _, volume := range attached {
				name, _, _ := unstructured.NestedString(volume.(map[string]interface{}), "dataVolume", "name")
				if name == disk.GetName() {
					return fmt.Errorf("VM disk is still used by VMI %s", vmi.GetName())
				}
			}
		}
	}
	return nil
}

func validateVMVolumeMounts(ctx context.Context, client dynamic.Interface, p *workspaces.CreateWorkspacePayload) error {
	names, paths := map[string]bool{}, map[string]bool{}
	for _, mount := range p.VolumeMounts {
		if mount == nil || len(validation.IsDNS1123Label(mount.Name)) != 0 || names[mount.Name] {
			return fmt.Errorf("VM disk names must be unique DNS labels")
		}
		if !validGuestMountPath(mount.MountPath) || paths[mount.MountPath] {
			return fmt.Errorf("VM mount paths must be unique clean absolute data paths (system directories are not allowed)")
		}
		names[mount.Name], paths[mount.MountPath] = true, true
		disk, err := client.Resource(vmDataVolumeGVR).Namespace(p.Namespace).Get(ctx, mount.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("VM disk %s is unavailable: %w", mount.Name, err)
		}
		if disk.GetLabels()[vmDiskTypeLabel] != "vm-disk" {
			return fmt.Errorf("%s is not a reusable VM disk; create a volume with type vm-disk", mount.Name)
		}
		if owner := disk.GetAnnotations()[vmDiskOwnerAnnotation]; owner != "" {
			ownerName := strings.SplitN(owner, "/", 2)[0]
			if _, err := client.Resource(vmWorkspaceGVR).Namespace(p.Namespace).Get(ctx, ownerName, metav1.GetOptions{}); err == nil {
				return fmt.Errorf("VM disk %s is already attached to workspace %s", mount.Name, ownerName)
			} else if !apierrors.IsNotFound(err) {
				return err
			}
		}
	}
	return nil
}

func validGuestMountPath(value string) bool {
	if !path.IsAbs(value) || path.Clean(value) != value || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for _, protected := range []string{"/", "/boot", "/dev", "/proc", "/sys", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/run"} {
		if value == protected || (protected != "/" && strings.HasPrefix(value, protected+"/")) {
			return false
		}
	}
	return true
}
