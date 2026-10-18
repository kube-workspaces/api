package qga

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kube-workspaces/api/internal/platform"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
)

// Fail-closed resolver outcomes. ErrDenied means the named workspace is not an
// eligible running, provisioned Windows VM right now; ErrUnavailable means a
// required read could not be completed.
var (
	ErrDenied      = errors.New("QGA target denied")
	ErrUnavailable = errors.New("QGA target unavailable")
)

var (
	workspaceResource = schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "workspaces"}
	vmResource        = schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachines"}
	vmiResource       = schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstances"}
	podResource       = schema.GroupVersionResource{Version: "v1", Resource: "pods"}
)

// windowsProfileID is the only Windows VM profile the pilot admits, matching
// the controller's Windows workspace marker.
const windowsProfileID = "windows11-amd64-v1"

// PolicyReader supplies the fresh controller-owned VM execution policy.
type PolicyReader interface {
	GetVMExecutionPolicy(context.Context) (platform.VMExecutionPolicy, error)
}

// Target is the server-resolved, re-verified launcher identity for one
// execution. Callers must never build it from client-supplied values.
type Target struct {
	Namespace     string
	WorkspaceName string
	WorkspaceUID  string
	// VMUID is the controller-owned VirtualMachine UID: the management
	// provisioning generation (reset/recreation changes it; VMI reboot does not).
	VMUID   string
	PodName string
	PodUID  string
	Domain  string
}

// Resolver performs uncached, bounded reads through the Kubernetes API and
// fail-closes on every ownership, lifecycle, profile, launcher and policy
// check, including a final snapshot re-verification before returning.
type Resolver struct {
	client dynamic.Interface
	policy PolicyReader
}

// NewResolver builds a resolver over the shared dynamic client.
func NewResolver(client dynamic.Interface, policy PolicyReader) (*Resolver, error) {
	if client == nil || policy == nil {
		return nil, ErrUnavailable
	}
	return &Resolver{client: client, policy: policy}, nil
}

func (r *Resolver) eligible(ctx context.Context) error {
	policy, err := r.policy.GetVMExecutionPolicy(ctx)
	if err != nil {
		return ErrUnavailable
	}
	// The pilot executes as SYSTEM only, so both the enable and the
	// separately-granted elevation policy flags must be on.
	if !policy.Enabled || !policy.AllowElevated {
		return ErrDenied
	}
	return nil
}

func lookupError(err error) error {
	if apierrors.IsNotFound(err) {
		return ErrDenied
	}
	return ErrUnavailable
}

// validWorkspace mirrors the enrollment resolver's workspace snapshot checks
// plus the Windows-only pilot profile/provisioning markers.
func validWorkspace(ws *unstructured.Unstructured, namespace, name string) bool {
	if ws.GetNamespace() != namespace || ws.GetName() != name || ws.GetUID() == "" || ws.GetResourceVersion() == "" || ws.GetDeletionTimestamp() != nil {
		return false
	}
	kind, found, err := unstructured.NestedString(ws.Object, "spec", "type")
	if err != nil || !found || kind != "vm" {
		return false
	}
	for _, marker := range []string{"kubeworkspaces.io/reset", "kubeworkspaces.io/stopped", "kubeworkspaces.io/reboot", "kubeworkspaces.io/windows-detaching-generation"} {
		if _, present := ws.GetAnnotations()[marker]; present {
			return false
		}
	}
	profile, found, err := unstructured.NestedMap(ws.Object, "spec", "vmProfile")
	if err != nil || !found {
		return false
	}
	id, _ := profile["id"].(string)
	generation, _ := profile["generation"].(string)
	if id != windowsProfileID || generation == "" {
		return false
	}
	// Provisioned generation markers prove the controller finished the
	// Windows bootstrap/enrollment staging for this incarnation; the guest
	// independently denies an unenrolled identity.
	return ws.GetAnnotations()["kubeworkspaces.io/windows-provisioned-generation"] == generation
}

func ownedVM(ws, vm *unstructured.Unstructured) bool {
	for _, owner := range vm.GetOwnerReferences() {
		if owner.Controller != nil && *owner.Controller && owner.APIVersion == "kubeworkspaces.io/v1alpha1" && owner.Kind == "Workspace" && owner.Name == ws.GetName() && owner.UID == ws.GetUID() {
			return true
		}
	}
	return false
}

func validVM(ws, vm *unstructured.Unstructured) bool {
	if vm.GetNamespace() != ws.GetNamespace() || vm.GetName() != ws.GetName() || vm.GetUID() == "" || vm.GetResourceVersion() == "" || vm.GetDeletionTimestamp() != nil || !ownedVM(ws, vm) {
		return false
	}
	running, found, err := unstructured.NestedBool(vm.Object, "spec", "running")
	if err != nil || !found || !running {
		return false
	}
	generation, _, _ := unstructured.NestedString(ws.Object, "spec", "vmProfile", "generation")
	return generation != "" && vm.GetAnnotations()["kubeworkspaces.io/windows-generation"] == generation
}

func validVMI(vmi *unstructured.Unstructured, namespace, name string) bool {
	if vmi.GetNamespace() != namespace || vmi.GetName() != name || vmi.GetUID() == "" || vmi.GetResourceVersion() == "" || vmi.GetDeletionTimestamp() != nil {
		return false
	}
	phase, _, _ := unstructured.NestedString(vmi.Object, "status", "phase")
	return phase == "Running"
}

// launcherPod resolves the single running virt-launcher pod for the VMI and
// binds it through KubeVirt's own activePods map, so a namespace user's
// lookalike pod label can never be selected.
func (r *Resolver) launcherPod(ctx context.Context, vmi *unstructured.Unstructured, namespace, name string) (*unstructured.Unstructured, error) {
	list, err := r.client.Resource(podResource).Namespace(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set{"vm.kubevirt.io/name": name}.String(),
		Limit:         2,
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	activePods, _, _ := unstructured.NestedStringMap(vmi.Object, "status", "activePods")
	var found *unstructured.Unstructured
	for i := range list.Items {
		pod := &list.Items[i]
		if _, active := activePods[string(pod.GetUID())]; !active {
			continue
		}
		if pod.GetDeletionTimestamp() != nil || pod.GetUID() == "" || pod.GetResourceVersion() == "" {
			continue
		}
		phase, _, _ := unstructured.NestedString(pod.Object, "status", "phase")
		if phase != "Running" {
			continue
		}
		if found != nil {
			// More than one active launcher for one VMI is not a target we
			// can safely pick from.
			return nil, ErrUnavailable
		}
		found = pod
	}
	if found == nil {
		return nil, ErrDenied
	}
	return found, nil
}

func (r *Resolver) snapshot(ctx context.Context, namespace, name string) (Target, error) {
	ws, err := r.client.Resource(workspaceResource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return Target{}, lookupError(err)
	}
	if !validWorkspace(ws, namespace, name) {
		return Target{}, ErrDenied
	}
	vm, err := r.client.Resource(vmResource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return Target{}, lookupError(err)
	}
	if !validVM(ws, vm) {
		return Target{}, ErrDenied
	}
	vmi, err := r.client.Resource(vmiResource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return Target{}, lookupError(err)
	}
	if !validVMI(vmi, namespace, name) {
		return Target{}, ErrDenied
	}
	pod, err := r.launcherPod(ctx, vmi, namespace, name)
	if err != nil {
		return Target{}, err
	}
	return Target{
		Namespace:     namespace,
		WorkspaceName: name,
		WorkspaceUID:  string(ws.GetUID()),
		VMUID:         string(vm.GetUID()),
		PodName:       pod.GetName(),
		PodUID:        string(pod.GetUID()),
		Domain:        namespace + "_" + name,
	}, nil
}

// identityDigestInput is the exact preimage bound into the grant's
// transport_target_sha256: namespace/VM UID/launcher pod UID.
func (t Target) identity() string {
	return t.Namespace + "/" + t.VMUID + "/" + t.PodUID
}

// Resolve returns the current launcher target only after a complete fresh
// snapshot re-verifies identically and policy still admits elevation.
func (r *Resolver) Resolve(ctx context.Context, namespace, name string) (Target, error) {
	if ctx.Err() != nil {
		return Target{}, ErrUnavailable
	}
	if len(validation.IsDNS1123Label(namespace)) != 0 || len(validation.IsDNS1123Subdomain(name)) != 0 {
		return Target{}, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := r.eligible(ctx); err != nil {
		return Target{}, err
	}
	first, err := r.snapshot(ctx, namespace, name)
	if err != nil {
		return Target{}, err
	}
	latest, err := r.snapshot(ctx, namespace, name)
	if err != nil {
		return Target{}, err
	}
	if latest != first {
		return Target{}, fmt.Errorf("%w: target changed during resolution", ErrDenied)
	}
	if err := r.eligible(ctx); err != nil {
		return Target{}, err
	}
	if ctx.Err() != nil {
		return Target{}, ErrUnavailable
	}
	return first, nil
}
