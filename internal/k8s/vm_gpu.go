package k8s

import (
	"context"
	"errors"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
)

var (
	vmGPUPlatformGVR   = schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "platformconfigs"}
	vmGPUVMGVR         = schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachines"}
	vmGPUVMIGVR        = schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstances"}
	ErrVMGPUNotStopped = errors.New("Windows GPU changes require a fully stopped VM and no VMI")
)

// VMGPUProfile mirrors the controller's operator contract without scheme imports.
// This is requested configuration, not observed guest driver/encoder readiness.
type VMGPUProfile struct {
	ID                 string            `json:"id"`
	DisplayName        string            `json:"displayName"`
	ResourceName       string            `json:"resourceName"`
	Kind               string            `json:"kind"`
	Count              int32             `json:"count"`
	NodeSelector       map[string]string `json:"nodeSelector"`
	GuestDriverVersion string            `json:"guestDriverVersion"`
	Experimental       bool              `json:"experimental"`
}

func (p *VMGPUProfile) Validate() error {
	parts := strings.Split(p.ResourceName, "/")
	if len(parts) != 2 || len(p.ResourceName) > 253 || strings.HasPrefix(p.ResourceName, "requests.") || len(validation.IsDNS1123Subdomain(parts[0])) != 0 ||
		len(validation.IsQualifiedName(p.ResourceName)) != 0 ||
		parts[0] == "kubernetes.io" || strings.HasSuffix(parts[0], ".kubernetes.io") ||
		parts[0] == "k8s.io" || strings.HasSuffix(parts[0], ".k8s.io") {
		return fmt.Errorf("VM GPU profile requires a vendor extended resource")
	}
	if len(p.ID) > 63 || len(validation.IsDNS1123Label(p.ID)) != 0 || p.DisplayName == "" ||
		len(p.DisplayName) > 128 || p.GuestDriverVersion == "" || len(p.GuestDriverVersion) > 128 ||
		p.Count != 1 || (p.Kind != "pci" && p.Kind != "mediated") || len(p.NodeSelector) == 0 {
		return fmt.Errorf("invalid versioned VM GPU profile")
	}
	for key, value := range p.NodeSelector {
		if len(validation.IsQualifiedName(key)) != 0 || len(validation.IsValidLabelValue(value)) != 0 {
			return fmt.Errorf("invalid VM GPU worker selector")
		}
	}
	return nil
}

func (c *WorkspaceClient) VMGPUProfiles(ctx context.Context) ([]VMGPUProfile, error) {
	obj, err := c.dynamic.Resource(vmGPUPlatformGVR).Get(ctx, "default", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return []VMGPUProfile{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("VM GPU operator profiles are unavailable: %w", err)
	}
	raw, _, err := unstructured.NestedSlice(obj.Object, "spec", "vmGPUProfiles")
	if err != nil {
		return nil, fmt.Errorf("invalid operator VM GPU profiles")
	}
	profiles := make([]VMGPUProfile, 0, len(raw))
	seen := map[string]bool{}
	for _, item := range raw {
		entry, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid operator VM GPU profile")
		}
		var profile VMGPUProfile
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(entry, &profile); err != nil {
			return nil, fmt.Errorf("invalid operator VM GPU profile")
		}
		if err := profile.Validate(); err != nil {
			return nil, err
		}
		if seen[profile.ID] {
			return nil, fmt.Errorf("duplicate operator VM GPU profile ID")
		}
		seen[profile.ID] = true
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func (c *WorkspaceClient) ResolveVMGPUProfile(ctx context.Context, id string, selector map[string]string) (*VMGPUProfile, error) {
	profiles, err := c.VMGPUProfiles(ctx)
	if err != nil {
		return nil, err
	}
	var profile *VMGPUProfile
	for i := range profiles {
		if profiles[i].ID == id {
			profile = &profiles[i]
			break
		}
	}
	if profile == nil {
		return nil, fmt.Errorf("VM GPU profile is not approved by the operator")
	}
	host := selector["kubernetes.io/hostname"]
	if host == "" {
		return nil, fmt.Errorf("VM GPU requires a certified worker hostname selector")
	}
	nodes, err := c.dynamic.Resource(schema.GroupVersionResource{Version: "v1", Resource: "nodes"}).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{"kubernetes.io/hostname": host}).String(),
	})
	if err != nil || len(nodes.Items) != 1 {
		return nil, fmt.Errorf("VM GPU selected worker is unavailable")
	}
	node := &nodes.Items[0]
	nodeLabels := node.GetLabels()
	if nodeLabels["kubeworkspaces.io/windows11-amd64-eligible"] != "true" || nodeLabels["kubernetes.io/arch"] != "amd64" {
		return nil, fmt.Errorf("VM GPU selected worker is not Windows-certified")
	}
	for key, value := range profile.NodeSelector {
		actual, found := nodeLabels[key]
		if !found || actual != value {
			return nil, fmt.Errorf("selected worker is not eligible for this VM GPU profile")
		}
	}
	unschedulable, _, _ := unstructured.NestedBool(node.Object, "spec", "unschedulable")
	conditions, _, _ := unstructured.NestedSlice(node.Object, "status", "conditions")
	ready := false
	for _, entry := range conditions {
		condition, ok := entry.(map[string]interface{})
		if ok && condition["type"] == "Ready" && condition["status"] == "True" {
			ready = true
		}
	}
	capacity, _, _ := unstructured.NestedString(node.Object, "status", "allocatable", profile.ResourceName)
	quantity, err := resource.ParseQuantity(capacity)
	if err != nil || quantity.Cmp(resource.MustParse("1")) < 0 || !ready || unschedulable {
		return nil, fmt.Errorf("selected worker does not advertise a healthy VM GPU resource")
	}
	installations, err := c.dynamic.Resource(schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "kubevirts"}).List(ctx, metav1.ListOptions{})
	if err != nil || len(installations.Items) != 1 {
		return nil, fmt.Errorf("VM GPU KubeVirt allowlist is unavailable")
	}
	field := "pciHostDevices"
	if profile.Kind == "mediated" {
		field = "mediatedDevices"
	}
	allowed, _, _ := unstructured.NestedSlice(installations.Items[0].Object, "spec", "configuration", "permittedHostDevices", field)
	for _, entry := range allowed {
		if item, ok := entry.(map[string]interface{}); ok && item["resourceName"] == profile.ResourceName {
			return profile, nil
		}
	}
	return nil, fmt.Errorf("VM GPU resource is not in the matching KubeVirt allowlist")
}

func (c *WorkspaceClient) RequireStoppedWindowsVM(ctx context.Context, workspace *unstructured.Unstructured) error {
	if _, stopped := workspace.GetAnnotations()["kubeworkspaces.io/stopped"]; !stopped || workspace.GetDeletionTimestamp() != nil {
		return ErrVMGPUNotStopped
	}
	for _, key := range []string{"kubeworkspaces.io/reset", "kubeworkspaces.io/reboot", "kubeworkspaces.io/windows-detaching-generation"} {
		if workspace.GetAnnotations()[key] != "" {
			return ErrVMGPUNotStopped
		}
	}
	vm, err := c.dynamic.Resource(vmGPUVMGVR).Namespace(workspace.GetNamespace()).Get(ctx, workspace.GetName(), metav1.GetOptions{})
	if err != nil {
		return ErrVMGPUNotStopped
	}
	generation, _, _ := unstructured.NestedString(workspace.Object, "spec", "vmProfile", "generation")
	owned := false
	for _, owner := range vm.GetOwnerReferences() {
		if owner.APIVersion == "kubeworkspaces.io/v1alpha1" && owner.Kind == "Workspace" && owner.UID == workspace.GetUID() && owner.Controller != nil && *owner.Controller {
			owned = true
		}
	}
	running, hasRunning, _ := unstructured.NestedBool(vm.Object, "spec", "running")
	strategy, _, _ := unstructured.NestedString(vm.Object, "spec", "runStrategy")
	if !owned || generation == "" || vm.GetAnnotations()["kubeworkspaces.io/windows-generation"] != generation || vm.GetDeletionTimestamp() != nil ||
		(hasRunning && running) || (!hasRunning && strategy != "Halted") {
		return ErrVMGPUNotStopped
	}
	_, err = c.dynamic.Resource(vmGPUVMIGVR).Namespace(workspace.GetNamespace()).Get(ctx, workspace.GetName(), metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		return ErrVMGPUNotStopped
	}
	return nil
}
