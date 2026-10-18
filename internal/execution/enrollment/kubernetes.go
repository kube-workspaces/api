package enrollment

import (
	"context"
	"time"

	"github.com/kube-workspaces/api/internal/execution/pki"
	"github.com/kube-workspaces/api/internal/platform"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
)

var (
	workspaceResource = schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "workspaces"}
	vmResource        = schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachines"}
)

type executionPolicyReader interface {
	GetVMExecutionPolicy(context.Context) (platform.VMExecutionPolicy, error)
}

// KubernetesResolver performs uncached reads through the Kubernetes API. A VM
// UID is the management incarnation: root reset/recreation changes it, VMI
// restart does not. Nonzero epochs fail until a controller-owned source exists.
type KubernetesResolver struct {
	client dynamic.Interface
	policy executionPolicyReader
}

func NewKubernetesResolver(client dynamic.Interface, policy executionPolicyReader) (*KubernetesResolver, error) {
	if client == nil || policy == nil {
		return nil, ErrUnavailable
	}
	return &KubernetesResolver{client: client, policy: policy}, nil
}

func (r *KubernetesResolver) enabled(ctx context.Context) error {
	policy, err := r.policy.GetVMExecutionPolicy(ctx)
	if err != nil {
		return ErrUnavailable
	}
	if !policy.Enabled {
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
	return true
}

func ownedVM(ws, vm *unstructured.Unstructured) bool {
	for _, owner := range vm.GetOwnerReferences() {
		if owner.Controller != nil && *owner.Controller && owner.APIVersion == "kubeworkspaces.io/v1alpha1" && owner.Kind == "Workspace" && owner.Name == ws.GetName() && owner.UID == ws.GetUID() {
			return true
		}
	}
	return false
}

func resolveIdentity(ws, vm *unstructured.Unstructured) (pki.Identity, error) {
	if vm.GetUID() == "" || vm.GetResourceVersion() == "" || vm.GetDeletionTimestamp() != nil || vm.GetNamespace() != ws.GetNamespace() || vm.GetName() != ws.GetName() || !ownedVM(ws, vm) {
		return pki.Identity{}, ErrDenied
	}
	running, found, err := unstructured.NestedBool(vm.Object, "spec", "running")
	if err != nil || !found || !running {
		return pki.Identity{}, ErrDenied
	}
	profile, found, err := unstructured.NestedMap(ws.Object, "spec", "vmProfile")
	if err != nil {
		return pki.Identity{}, ErrDenied
	}
	if found {
		id, _ := profile["id"].(string)
		generation, _ := profile["generation"].(string)
		if id != "windows11-amd64-v1" || generation == "" || vm.GetAnnotations()["kubeworkspaces.io/windows-generation"] != generation || ws.GetAnnotations()["kubeworkspaces.io/windows-provisioned-generation"] != generation {
			return pki.Identity{}, ErrDenied
		}
	}
	i := pki.Identity{Role: pki.RoleGuest, Namespace: ws.GetNamespace(), WorkspaceName: ws.GetName(), WorkspaceUID: string(ws.GetUID()), Generation: string(vm.GetUID()), RevocationEpoch: 0}
	if _, err := i.URI(); err != nil {
		return pki.Identity{}, ErrDenied
	}
	return i, nil
}

// Resolve is for trusted provisioning and capability selection, not end-user
// permission. Policy is read on both sides of the workspace/VM snapshot; a
// changed resource version denies instead of authorizing a mixed incarnation.
func (r *KubernetesResolver) Resolve(ctx context.Context, namespace, name string) (pki.Identity, error) {
	if ctx.Err() != nil {
		return pki.Identity{}, ErrUnavailable
	}
	if len(validation.IsDNS1123Label(namespace)) != 0 || len(validation.IsDNS1123Subdomain(name)) != 0 {
		return pki.Identity{}, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := r.enabled(ctx); err != nil {
		return pki.Identity{}, err
	}
	ws, err := r.client.Resource(workspaceResource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return pki.Identity{}, lookupError(err)
	}
	if !validWorkspace(ws, namespace, name) {
		return pki.Identity{}, ErrDenied
	}
	vm, err := r.client.Resource(vmResource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return pki.Identity{}, lookupError(err)
	}
	i, err := resolveIdentity(ws, vm)
	if err != nil {
		return pki.Identity{}, err
	}
	latest, err := r.client.Resource(workspaceResource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return pki.Identity{}, lookupError(err)
	}
	if latest.GetUID() != ws.GetUID() || latest.GetResourceVersion() != ws.GetResourceVersion() || !validWorkspace(latest, namespace, name) {
		return pki.Identity{}, ErrDenied
	}
	currentVM, err := r.client.Resource(vmResource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return pki.Identity{}, lookupError(err)
	}
	current, err := resolveIdentity(latest, currentVM)
	if err != nil || current != i || currentVM.GetResourceVersion() != vm.GetResourceVersion() {
		return pki.Identity{}, ErrDenied
	}
	if err := r.enabled(ctx); err != nil {
		return pki.Identity{}, err
	}
	if ctx.Err() != nil {
		return pki.Identity{}, ErrUnavailable
	}
	return i, nil
}

// Authorize can be passed directly as Service.CurrentIdentity. It never trusts
// generation/epoch values supplied by a CSR, request body or certificate alone.
func (r *KubernetesResolver) Authorize(ctx context.Context, expected pki.Identity) error {
	if expected.Role != pki.RoleGuest || expected.RevocationEpoch != 0 {
		return ErrDenied
	}
	if _, err := expected.URI(); err != nil {
		return ErrDenied
	}
	actual, err := r.Resolve(ctx, expected.Namespace, expected.WorkspaceName)
	if err != nil {
		return err
	}
	if actual != expected {
		return ErrDenied
	}
	return nil
}
