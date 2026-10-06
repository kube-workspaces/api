package kubeworkspaces

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	"github.com/kube-workspaces/api/gen/workspaces"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/k8s"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
)

const windowsVMProfile = "windows11-amd64-v1"

var windowsRootDigest = regexp.MustCompile(`^[^\s]+@sha256:[a-f0-9]{64}$`)

func windowsWorkspaceProfile(obj *unstructured.Unstructured) bool {
	id, _, _ := unstructured.NestedString(obj.Object, "spec", "vmProfile", "id")
	return id == windowsVMProfile
}

func buildWindowsProfile(p *workspaces.CreateWorkspacePayload, image *k8s.Image) (map[string]interface{}, error) {
	if p.Type != "vm" || !image.PersistentRootDisk || !windowsRootDigest.MatchString(image.Image) {
		return nil, fmt.Errorf("Windows requires type vm and a catalog-pinned persistent OCI root")
	}
	if p.SharedMemory || len(p.VolumeMounts) != 0 || len(p.Env) != 0 || (p.Container.GpuRequest != nil && *p.Container.GpuRequest != "" && *p.Container.GpuRequest != "0") {
		return nil, fmt.Errorf("Windows supports display-only roots; Linux mounts, environment, shared memory and GPU options are unavailable")
	}
	cpu, err := resource.ParseQuantity(p.Container.CPULimit)
	if err != nil || cpu.Value() < 2 || cpu.MilliValue()%1000 != 0 {
		return nil, fmt.Errorf("Windows requires at least 2 whole guest CPU cores")
	}
	memory, err := resource.ParseQuantity(p.Container.MemoryLimit)
	if err != nil || memory.Cmp(resource.MustParse("4Gi")) < 0 {
		return nil, fmt.Errorf("Windows requires at least 4Gi guest memory")
	}
	if p.NodeSelector["kubernetes.io/hostname"] == "" {
		return nil, fmt.Errorf("Windows requires an operator-certified worker hostname selector")
	}
	if architecture := p.NodeSelector["kubernetes.io/arch"]; architecture != "" && architecture != "amd64" {
		return nil, fmt.Errorf("Windows requires amd64 scheduling")
	}
	root := image.PersistentRootDiskSize
	if root == "" {
		root = "80Gi"
	}
	profile := map[string]interface{}{"id": windowsVMProfile, "image": image.Image, "cpuCores": cpu.Value(), "guestMemory": memory.String()}
	if options := p.VMOptions; options != nil {
		for key, value := range map[string]*string{"importSecretName": options.ImportSecretName, "importCertConfigMapName": options.ImportCertConfigMapName, "storageClassName": options.StorageClassName} {
			if value != nil && *value != "" {
				if len(validation.IsDNS1123Subdomain(*value)) != 0 {
					return nil, fmt.Errorf("invalid Windows import/storage reference")
				}
				profile[key] = *value
			}
		}
		if options.RootDiskSize != nil && *options.RootDiskSize != "" {
			root = *options.RootDiskSize
		}
	}
	disk, err := resource.ParseQuantity(root)
	if err != nil || disk.Cmp(resource.MustParse("80Gi")) < 0 {
		return nil, fmt.Errorf("Windows roots require at least 80Gi")
	}
	profile["rootDiskSize"] = root
	return profile, nil
}

func applyWindowsProfile(ws *unstructured.Unstructured, profile map[string]interface{}) error {
	if err := unstructured.SetNestedMap(ws.Object, profile, "spec", "vmProfile"); err != nil {
		return err
	}
	containers, _, _ := unstructured.NestedSlice(ws.Object, "spec", "template", "spec", "containers")
	if len(containers) != 1 {
		return fmt.Errorf("Windows requires one main container identity")
	}
	container := containers[0].(map[string]interface{})
	if mounts, _, _ := unstructured.NestedSlice(container, "volumeMounts"); len(mounts) > 0 {
		return fmt.Errorf("Windows does not support injected Linux mounts")
	}
	volumes, _, _ := unstructured.NestedSlice(ws.Object, "spec", "template", "spec", "volumes")
	init, _, _ := unstructured.NestedSlice(ws.Object, "spec", "template", "spec", "initContainers")
	if len(volumes) > 0 || len(init) > 0 {
		return fmt.Errorf("Windows does not support Linux PodDefault volumes/init containers")
	}
	for _, field := range []string{"ports", "args", "env", "securityContext"} {
		delete(container, field)
	}
	return unstructured.SetNestedSlice(ws.Object, containers, "spec", "template", "spec", "containers")
}

func (s *workspacessrvc) Credentials(ctx context.Context, p *workspaces.CredentialsPayload) (*workspaces.WorkspaceInitialCredentials, error) {
	user := auth.UserFromContext(ctx)
	if user != nil && (!auth.HasMinimumRole(user.Role, "editor") || !auth.UserHasNamespaceAccess(user, p.Namespace)) {
		return nil, workspaces.Forbidden("initial credentials require namespace editor access")
	}
	ws, err := s.client.GetWorkspace(ctx, p.Namespace, p.Name)
	if err != nil || !windowsWorkspaceProfile(ws) {
		return nil, workspaces.NotFound("Windows workspace not found")
	}
	if ws.GetAnnotations()["kubeworkspaces.io/reset"] != "" {
		return nil, workspaces.Unavailable("Windows initial credentials are changing during Reset")
	}
	generation, _, _ := unstructured.NestedString(ws.Object, "spec", "vmProfile", "generation")
	if generation == "" {
		return nil, workspaces.Unavailable("Windows credentials are being prepared")
	}
	sum := sha256.Sum256([]byte(ws.GetName() + "/" + generation))
	name := ws.GetName()
	if len(name) > 36 {
		name = strings.TrimRight(name[:36], "-")
	}
	secret, err := s.client.GetInitialCredentialSecret(ctx, p.Namespace, fmt.Sprintf("%s-win-%x", name, sum[:6]))
	if err != nil {
		return nil, workspaces.Unavailable("Windows initial credentials are unavailable")
	}
	owned := false
	for _, owner := range secret.OwnerReferences {
		if owner.Kind == "Workspace" && owner.APIVersion == "kubeworkspaces.io/v1alpha1" && owner.UID == ws.GetUID() && owner.Controller != nil && *owner.Controller {
			owned = true
		}
	}
	if !owned || secret.Labels["kubeworkspaces.io/windows-generation"] != generation || len(secret.Data["password"]) == 0 || len(secret.Data["username"]) == 0 {
		return nil, workspaces.Unavailable("Windows initial credentials are unavailable")
	}
	return &workspaces.WorkspaceInitialCredentials{Username: string(secret.Data["username"]), Password: string(secret.Data["password"]), CacheControl: "no-store"}, nil
}
