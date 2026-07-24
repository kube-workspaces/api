package kubeworkspaces

import (
	"context"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/kube-workspaces/api/gen/workspaces"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/k8s"
	"goa.design/clue/log"
)

// workspaces service implementation.
type workspacessrvc struct {
	client           *k8s.WorkspaceClient
	imageClient      *k8s.ImageClient
	coreClient       *k8s.CoreClient
	podDefaultClient *k8s.PodDefaultClient
	authProvider     *auth.ConfigProvider
}

// NewWorkspaces returns the workspaces service implementation.
func NewWorkspaces(client *k8s.WorkspaceClient, imageClient *k8s.ImageClient, coreClient *k8s.CoreClient, authProvider *auth.ConfigProvider, podDefaultClient *k8s.PodDefaultClient) workspaces.Service {
	return &workspacessrvc{client: client, imageClient: imageClient, coreClient: coreClient, authProvider: authProvider, podDefaultClient: podDefaultClient}
}

// List all workspaces
func (s *workspacessrvc) List(ctx context.Context, p *workspaces.ListPayload) (res []*workspaces.Workspace, err error) {
	ns := p.Namespace
	if ns == "_all" {
		ns = ""
	}
	log.Printf(ctx, "workspaces.list namespace=%s", ns)

	// If namespace access is restricted, filter to user's allowed namespaces
	ns, err = s.resolveNamespace(ctx, ns)
	if err != nil {
		return []*workspaces.Workspace{}, nil
	}

	list, err := s.client.ListWorkspaces(ctx, ns)
	if err != nil {
		return nil, fmt.Errorf("failed to list workspaces: %w", err)
	}

	res = make([]*workspaces.Workspace, 0, len(list.Items))
	for i := range list.Items {
		ws := unstructuredToWorkspace(&list.Items[i])
		res = append(res, ws)
	}

	// Filter results if listing across all namespaces
	if p.Namespace == "_all" || p.Namespace == "" {
		res = s.filterWorkspacesByAccess(ctx, res)
	}

	return res, nil
}

// resolveNamespace checks if the user has access to the requested namespace.
// Returns the namespace to query, or error if access denied.
func (s *workspacessrvc) resolveNamespace(ctx context.Context, ns string) (string, error) {
	if !s.isNamespaceRestricted(ctx) {
		return ns, nil
	}
	user := auth.UserFromContext(ctx)
	if user == nil || user.Role == "admin" {
		return ns, nil
	}
	// If a specific namespace is requested, verify access
	if ns != "" {
		if !auth.UserHasNamespaceAccess(user, ns) {
			return "", fmt.Errorf("no access to namespace %s", ns)
		}
	}
	return ns, nil
}

// filterWorkspacesByAccess filters workspaces to those in namespaces the user can access.
func (s *workspacessrvc) filterWorkspacesByAccess(ctx context.Context, items []*workspaces.Workspace) []*workspaces.Workspace {
	if !s.isNamespaceRestricted(ctx) {
		return items
	}
	user := auth.UserFromContext(ctx)
	if user == nil || user.Role == "admin" {
		return items
	}
	var filtered []*workspaces.Workspace
	for _, ws := range items {
		if auth.UserHasNamespaceAccess(user, ws.Namespace) {
			filtered = append(filtered, ws)
		}
	}
	if filtered == nil {
		filtered = []*workspaces.Workspace{}
	}
	return filtered
}

// isNamespaceRestricted checks whether namespace access restriction is enabled.
func (s *workspacessrvc) isNamespaceRestricted(ctx context.Context) bool {
	if s.authProvider == nil {
		return false
	}
	cfg, err := s.authProvider.GetConfig(ctx)
	if err != nil || cfg == nil {
		return false
	}
	return cfg.Enabled && cfg.RestrictNamespaceAccess
}

// Get a workspace by name
func (s *workspacessrvc) Get(ctx context.Context, p *workspaces.GetPayload) (res *workspaces.Workspace, err error) {
	log.Printf(ctx, "workspaces.get name=%s namespace=%s", p.Name, p.Namespace)

	obj, err := s.client.GetWorkspace(ctx, p.Namespace, p.Name)
	if err != nil {
		return nil, workspaces.NotFound(fmt.Sprintf("workspace %s/%s not found", p.Namespace, p.Name))
	}

	return unstructuredToWorkspace(obj), nil
}

// Create a new workspace
func (s *workspacessrvc) Create(ctx context.Context, p *workspaces.CreateWorkspacePayload) (res *workspaces.Workspace, err error) {
	log.Printf(ctx, "workspaces.create name=%s namespace=%s", p.Name, p.Namespace)

	// Determine actor
	actor := "unknown"
	if user := auth.UserFromContext(ctx); user != nil {
		actor = user.Email
	}

	// Build the Workspace CR
	ws := buildWorkspaceCR(p, s.imageClient)

	// Apply PodDefaults from the target namespace
	if s.podDefaultClient != nil {
		log.Printf(ctx, "workspaces.create: applying PodDefaults from namespace=%s", p.Namespace)
		applyPodDefaults(ctx, ws, s.podDefaultClient, p.Namespace)
	} else {
		log.Printf(ctx, "workspaces.create: podDefaultClient is nil, skipping PodDefaults")
	}

	// Set action annotations on the CR before creation
	annotations := ws.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations["kubeworkspaces.io/created-by"] = actor
	annotations["kubeworkspaces.io/last-action"] = "Created"
	annotations["kubeworkspaces.io/last-action-by"] = actor
	annotations["kubeworkspaces.io/last-action-time"] = time.Now().UTC().Format(time.RFC3339)
	ws.SetAnnotations(annotations)

	created, err := s.client.CreateWorkspace(ctx, ws)
	if err != nil {
		return nil, fmt.Errorf("failed to create workspace: %w", err)
	}

	// Emit a Kubernetes Event for the action (best-effort)
	if s.coreClient != nil {
		msg := fmt.Sprintf("Workspace created by %s", actor)
		if evErr := s.coreClient.CreateWorkspaceEvent(ctx, p.Namespace, p.Name, "Created", actor, msg); evErr != nil {
			log.Printf(ctx, "warning: failed to emit workspace event: %v", evErr)
		}
	}

	return unstructuredToWorkspace(created), nil
}

// Delete a workspace
func (s *workspacessrvc) Delete(ctx context.Context, p *workspaces.DeletePayload) (err error) {
	log.Printf(ctx, "workspaces.delete name=%s namespace=%s", p.Name, p.Namespace)

	err = s.client.DeleteWorkspace(ctx, p.Namespace, p.Name)
	if err != nil {
		return workspaces.NotFound(fmt.Sprintf("workspace %s/%s not found", p.Namespace, p.Name))
	}
	return nil
}

// Start a stopped workspace (removes the stopped annotation)
func (s *workspacessrvc) Start(ctx context.Context, p *workspaces.StartPayload) (res *workspaces.Workspace, err error) {
	log.Printf(ctx, "workspaces.start name=%s namespace=%s", p.Name, p.Namespace)

	// Determine actor
	actor := "unknown"
	if user := auth.UserFromContext(ctx); user != nil {
		actor = user.Email
	}

	obj, err := s.client.GetWorkspace(ctx, p.Namespace, p.Name)
	if err != nil {
		return nil, workspaces.NotFound(fmt.Sprintf("workspace %s/%s not found", p.Namespace, p.Name))
	}

	// Remove the stopped annotation and set action annotations
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	delete(annotations, "kubeworkspaces.io/stopped")
	annotations["kubeworkspaces.io/last-action"] = "Started"
	annotations["kubeworkspaces.io/last-action-by"] = actor
	annotations["kubeworkspaces.io/last-action-time"] = time.Now().UTC().Format(time.RFC3339)
	obj.SetAnnotations(annotations)

	updated, err := s.client.UpdateWorkspace(ctx, obj)
	if err != nil {
		return nil, fmt.Errorf("failed to start workspace: %w", err)
	}

	// Emit a Kubernetes Event for the action (best-effort)
	if s.coreClient != nil {
		msg := fmt.Sprintf("Workspace started by %s", actor)
		if evErr := s.coreClient.CreateWorkspaceEvent(ctx, p.Namespace, p.Name, "Started", actor, msg); evErr != nil {
			log.Printf(ctx, "warning: failed to emit workspace event: %v", evErr)
		}
	}

	return unstructuredToWorkspace(updated), nil
}

// Stop a running workspace (adds the stopped annotation)
func (s *workspacessrvc) Stop(ctx context.Context, p *workspaces.StopPayload) (res *workspaces.Workspace, err error) {
	log.Printf(ctx, "workspaces.stop name=%s namespace=%s", p.Name, p.Namespace)

	// Determine actor
	actor := "unknown"
	if user := auth.UserFromContext(ctx); user != nil {
		actor = user.Email
	}

	obj, err := s.client.GetWorkspace(ctx, p.Namespace, p.Name)
	if err != nil {
		return nil, workspaces.NotFound(fmt.Sprintf("workspace %s/%s not found", p.Namespace, p.Name))
	}

	// Add the stopped annotation and set action annotations
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations["kubeworkspaces.io/stopped"] = "true"
	annotations["kubeworkspaces.io/last-action"] = "Stopped"
	annotations["kubeworkspaces.io/last-action-by"] = actor
	annotations["kubeworkspaces.io/last-action-time"] = time.Now().UTC().Format(time.RFC3339)
	obj.SetAnnotations(annotations)

	updated, err := s.client.UpdateWorkspace(ctx, obj)
	if err != nil {
		return nil, fmt.Errorf("failed to stop workspace: %w", err)
	}

	// Emit a Kubernetes Event for the action (best-effort)
	if s.coreClient != nil {
		msg := fmt.Sprintf("Workspace stopped by %s", actor)
		if evErr := s.coreClient.CreateWorkspaceEvent(ctx, p.Namespace, p.Name, "Stopped", actor, msg); evErr != nil {
			log.Printf(ctx, "warning: failed to emit workspace event: %v", evErr)
		}
	}

	return unstructuredToWorkspace(updated), nil
}

// buildWorkspaceCR builds an unstructured Workspace CR from the create payload.
func buildWorkspaceCR(p *workspaces.CreateWorkspacePayload, imageClient *k8s.ImageClient) *unstructured.Unstructured {
	containerPort := int64(p.Container.Port)

	container := map[string]interface{}{
		"name":  p.Container.Name,
		"image": p.Container.Image,
		"ports": []interface{}{
			map[string]interface{}{
				"containerPort": containerPort,
				"name":          "workspace-port",
				"protocol":      "TCP",
			},
		},
		"resources": map[string]interface{}{
			"requests": map[string]interface{}{
				"cpu":    p.Container.CPURequest,
				"memory": p.Container.MemoryRequest,
			},
			"limits": map[string]interface{}{
				"cpu":    p.Container.CPULimit,
				"memory": p.Container.MemoryLimit,
			},
		},
	}

	// Set imagePullPolicy (always set it explicitly on the container spec)
	if p.ImagePullPolicy != "" {
		container["imagePullPolicy"] = p.ImagePullPolicy
	}

	// Look up Image CR for default args/env and security settings
	var defaultUID *int64
	var defaultInitContainers []k8s.ImageInitContainer
	var preservePathPrefix bool
	var additionalPorts []k8s.ImagePort
	if imageClient != nil {
		if img, err := imageClient.GetImageByRef(context.Background(), p.Container.Image); err == nil {
			if len(img.DefaultArgs) > 0 {
				args := make([]interface{}, len(img.DefaultArgs))
				for i, a := range img.DefaultArgs {
					a = strings.ReplaceAll(a, "{{namespace}}", p.Namespace)
					a = strings.ReplaceAll(a, "{{name}}", p.Name)
					args[i] = a
				}
				container["args"] = args
			}
			if len(img.DefaultEnv) > 0 {
				envs := make([]interface{}, 0, len(img.DefaultEnv))
				for _, e := range img.DefaultEnv {
					value := e.Value
					value = strings.ReplaceAll(value, "{{namespace}}", p.Namespace)
					value = strings.ReplaceAll(value, "{{name}}", p.Name)
					envs = append(envs, map[string]interface{}{
						"name":  e.Name,
						"value": value,
					})
				}
				container["env"] = envs
			}
			if img.Privileged {
				container["securityContext"] = map[string]interface{}{
					"privileged": true,
				}
			}
			defaultUID = img.DefaultUID
			defaultInitContainers = img.DefaultInitContainers
			additionalPorts = img.AdditionalPorts
			if img.DefaultSharedMemory {
				p.SharedMemory = true
			}
			if img.ProxyConfig != nil {
				preservePathPrefix = img.ProxyConfig.PreservePathPrefix
			}
		}
	}

	// Merge user-specified custom env vars (appended after image defaults)
	if len(p.Env) > 0 {
		existingEnvs, _ := container["env"].([]interface{})
		if existingEnvs == nil {
			existingEnvs = make([]interface{}, 0)
		}
		for _, e := range p.Env {
			value := e.Value
			value = strings.ReplaceAll(value, "{{namespace}}", p.Namespace)
			value = strings.ReplaceAll(value, "{{name}}", p.Name)
			existingEnvs = append(existingEnvs, map[string]interface{}{
				"name":  e.Name,
				"value": value,
			})
		}
		container["env"] = existingEnvs
	}

	// Add GPU resource limits if requested
	if p.Container.GpuRequest != nil && *p.Container.GpuRequest != "" && *p.Container.GpuRequest != "0" {
		resources := container["resources"].(map[string]interface{})
		limits := resources["limits"].(map[string]interface{})
		gpuVendor := p.Container.GpuVendor
		if gpuVendor == "" {
			gpuVendor = "nvidia.com/gpu"
		}
		limits[gpuVendor] = *p.Container.GpuRequest
	}

	// Add volume mounts if specified
	if len(p.VolumeMounts) > 0 {
		mounts := make([]interface{}, 0, len(p.VolumeMounts))
		for _, vm := range p.VolumeMounts {
			mounts = append(mounts, map[string]interface{}{
				"name":      vm.Name,
				"mountPath": vm.MountPath,
			})
		}
		container["volumeMounts"] = mounts
	}

	// Add additional ports from Image CR
	if len(additionalPorts) > 0 {
		ports := container["ports"].([]interface{})
		for _, ap := range additionalPorts {
			protocol := ap.Protocol
			if protocol == "" {
				protocol = "TCP"
			}
			ports = append(ports, map[string]interface{}{
				"containerPort": int64(ap.Port),
				"name":          ap.Name,
				"protocol":      protocol,
			})
		}
		container["ports"] = ports
	}

	spec := map[string]interface{}{
		"containers": []interface{}{container},
	}

	// Add volumes for any volume mounts (referencing PVCs)
	if len(p.VolumeMounts) > 0 {
		volumes := make([]interface{}, 0, len(p.VolumeMounts))
		for _, vm := range p.VolumeMounts {
			volumes = append(volumes, map[string]interface{}{
				"name": vm.Name,
				"persistentVolumeClaim": map[string]interface{}{
					"claimName": vm.Name,
				},
			})
		}
		spec["volumes"] = volumes
	}

	// Add /dev/shm as emptyDir with medium=Memory when shared_memory is enabled
	if p.SharedMemory {
		shmVolume := map[string]interface{}{
			"name": "dshm",
			"emptyDir": map[string]interface{}{
				"medium": "Memory",
			},
		}
		shmMount := map[string]interface{}{
			"name":      "dshm",
			"mountPath": "/dev/shm",
		}
		// Append to existing volumes or create new list
		if existing, ok := spec["volumes"].([]interface{}); ok {
			spec["volumes"] = append(existing, shmVolume)
		} else {
			spec["volumes"] = []interface{}{shmVolume}
		}
		// Append mount to container
		if existingMounts, ok := container["volumeMounts"].([]interface{}); ok {
			container["volumeMounts"] = append(existingMounts, shmMount)
		} else {
			container["volumeMounts"] = []interface{}{shmMount}
		}
	}

	// Set pod-level securityContext if defaultUID is specified
	if defaultUID != nil {
		spec["securityContext"] = map[string]interface{}{
			"runAsUser": *defaultUID,
			"fsGroup":   *defaultUID,
		}
	}

	// Add init containers if specified by Image CR
	if len(defaultInitContainers) > 0 {
		uidStr := ""
		if defaultUID != nil {
			uidStr = fmt.Sprintf("%d", *defaultUID)
		}
		initContainers := make([]interface{}, 0, len(defaultInitContainers))
		for _, ic := range defaultInitContainers {
			initC := map[string]interface{}{
				"name":  ic.Name,
				"image": ic.Image,
			}
			if len(ic.Command) > 0 {
				cmd := make([]interface{}, len(ic.Command))
				for i, c := range ic.Command {
					c = strings.ReplaceAll(c, "{{namespace}}", p.Namespace)
					c = strings.ReplaceAll(c, "{{name}}", p.Name)
					c = strings.ReplaceAll(c, "{{uid}}", uidStr)
					cmd[i] = c
				}
				initC["command"] = cmd
			}
			if len(ic.Args) > 0 {
				args := make([]interface{}, len(ic.Args))
				for i, a := range ic.Args {
					a = strings.ReplaceAll(a, "{{namespace}}", p.Namespace)
					a = strings.ReplaceAll(a, "{{name}}", p.Name)
					a = strings.ReplaceAll(a, "{{uid}}", uidStr)
					args[i] = a
				}
				initC["args"] = args
			}
			if len(ic.Env) > 0 {
				envs := make([]interface{}, 0, len(ic.Env))
				for _, e := range ic.Env {
					value := e.Value
					value = strings.ReplaceAll(value, "{{namespace}}", p.Namespace)
					value = strings.ReplaceAll(value, "{{name}}", p.Name)
					value = strings.ReplaceAll(value, "{{uid}}", uidStr)
					envs = append(envs, map[string]interface{}{
						"name":  e.Name,
						"value": value,
					})
				}
				initC["env"] = envs
			}
			// If init container has explicit volumeMounts, use them;
			// otherwise, inherit the main container's volumeMounts
			if len(ic.VolumeMounts) > 0 {
				vms := make([]interface{}, 0, len(ic.VolumeMounts))
				for _, vm := range ic.VolumeMounts {
					vms = append(vms, map[string]interface{}{
						"name":      vm.Name,
						"mountPath": vm.MountPath,
					})
				}
				initC["volumeMounts"] = vms
			} else if mounts, ok := container["volumeMounts"]; ok {
				// Inherit main container's volume mounts
				initC["volumeMounts"] = mounts
			}
			// Run init containers as root to allow chown operations
			initC["securityContext"] = map[string]interface{}{
				"runAsUser": int64(0),
			}
			initContainers = append(initContainers, initC)
		}
		spec["initContainers"] = initContainers
	}

	// Add node selector if specified
	if len(p.NodeSelector) > 0 {
		nodeSelector := make(map[string]interface{}, len(p.NodeSelector))
		for k, v := range p.NodeSelector {
			nodeSelector[k] = v
		}
		spec["nodeSelector"] = nodeSelector
	}

	// Add tolerations if specified
	if len(p.Tolerations) > 0 {
		tolerations := make([]interface{}, 0, len(p.Tolerations))
		for _, t := range p.Tolerations {
			tol := map[string]interface{}{
				"key":      t.Key,
				"operator": t.Operator,
			}
			if t.Value != nil && *t.Value != "" {
				tol["value"] = *t.Value
			}
			if t.Effect != nil && *t.Effect != "" {
				tol["effect"] = *t.Effect
			}
			tolerations = append(tolerations, tol)
		}
		spec["tolerations"] = tolerations
	}

	// Auto-add GPU toleration if GPU is requested and not already specified
	if p.Container.GpuRequest != nil && *p.Container.GpuRequest != "" && *p.Container.GpuRequest != "0" {
		gpuVendor := p.Container.GpuVendor
		if gpuVendor == "" {
			gpuVendor = "nvidia.com/gpu"
		}
		// Check if a toleration for this GPU vendor already exists
		hasGPUToleration := false
		for _, t := range p.Tolerations {
			if t.Key == gpuVendor {
				hasGPUToleration = true
				break
			}
		}
		if !hasGPUToleration {
			existingTolerations, _ := spec["tolerations"].([]interface{})
			if existingTolerations == nil {
				existingTolerations = make([]interface{}, 0)
			}
			existingTolerations = append(existingTolerations, map[string]interface{}{
				"key":      gpuVendor,
				"operator": "Exists",
				"effect":   "NoSchedule",
			})
			spec["tolerations"] = existingTolerations
		}
	}

	metadata := map[string]interface{}{
		"name":      p.Name,
		"namespace": p.Namespace,
	}
	// Store proxy config as annotations so the proxy can read them directly
	// from the workspace CR without depending on the current Image CR state.
	if preservePathPrefix {
		metadata["annotations"] = map[string]interface{}{
			"kubeworkspaces.io/preserve-path-prefix": "true",
		}
	}

	ws := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kubeworkspaces.io/v1alpha1",
			"kind":       "Workspace",
			"metadata":   metadata,
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": spec,
				},
			},
		},
	}

	return ws
}

// applyPodDefaults looks up PodDefaults in the target namespace and injects their
// configuration (env, volumes, volumeMounts, annotations, labels) into the workspace CR.
func applyPodDefaults(ctx context.Context, ws *unstructured.Unstructured, pdClient *k8s.PodDefaultClient, namespace string) {
	log.Printf(ctx, "applyPodDefaults: checking namespace=%s", namespace)

	// Get workspace labels (from pod template metadata, if any)
	wsLabels := make(map[string]string)
	if spec, ok := ws.Object["spec"].(map[string]interface{}); ok {
		if template, ok := spec["template"].(map[string]interface{}); ok {
			if podSpec, ok := template["spec"].(map[string]interface{}); ok {
				_ = podSpec // labels come from pod template metadata, not spec
			}
			if meta, ok := template["metadata"].(map[string]interface{}); ok {
				if lbl, ok := meta["labels"].(map[string]interface{}); ok {
					for k, v := range lbl {
						if s, ok := v.(string); ok {
							wsLabels[k] = s
						}
					}
				}
			}
		}
	}

	matching, err := pdClient.GetMatchingPodDefaults(ctx, namespace, wsLabels)
	if err != nil {
		log.Printf(ctx, "applyPodDefaults: error getting PodDefaults: %v", err)
		return
	}
	if len(matching) == 0 {
		log.Printf(ctx, "applyPodDefaults: no matching PodDefaults found in namespace=%s", namespace)
		return
	}
	log.Printf(ctx, "applyPodDefaults: found %d matching PodDefaults", len(matching))

	// Navigate to the pod spec and container
	spec, _ := ws.Object["spec"].(map[string]interface{})
	if spec == nil {
		return
	}
	template, _ := spec["template"].(map[string]interface{})
	if template == nil {
		return
	}
	podSpec, _ := template["spec"].(map[string]interface{})
	if podSpec == nil {
		return
	}

	// Get the first container (workspace container)
	containers, _ := podSpec["containers"].([]interface{})
	if len(containers) == 0 {
		return
	}
	container, _ := containers[0].(map[string]interface{})
	if container == nil {
		return
	}

	for _, pd := range matching {
		// Inject env vars
		if len(pd.Env) > 0 {
			existingEnv, _ := container["env"].([]interface{})
			for _, e := range pd.Env {
				existingEnv = append(existingEnv, map[string]interface{}{
					"name":  e.Name,
					"value": e.Value,
				})
			}
			container["env"] = existingEnv
		}

		// Inject volume mounts
		if len(pd.VolumeMounts) > 0 {
			existingMounts, _ := container["volumeMounts"].([]interface{})
			for _, vm := range pd.VolumeMounts {
				mount := map[string]interface{}{
					"name":      vm.Name,
					"mountPath": vm.MountPath,
				}
				if vm.ReadOnly {
					mount["readOnly"] = true
				}
				existingMounts = append(existingMounts, mount)
			}
			container["volumeMounts"] = existingMounts
		}

		// Inject volumes
		if len(pd.Volumes) > 0 {
			existingVolumes, _ := podSpec["volumes"].([]interface{})
			for _, v := range pd.Volumes {
				existingVolumes = append(existingVolumes, v)
			}
			podSpec["volumes"] = existingVolumes
		}

		// Override service account name
		if pd.ServiceAccountName != "" {
			podSpec["serviceAccountName"] = pd.ServiceAccountName
		}

		// Inject annotations into workspace metadata
		if len(pd.Annotations) > 0 {
			annotations := ws.GetAnnotations()
			if annotations == nil {
				annotations = make(map[string]string)
			}
			for k, v := range pd.Annotations {
				annotations[k] = v
			}
			ws.SetAnnotations(annotations)
		}

		// Inject labels into workspace metadata
		if len(pd.Labels) > 0 {
			existingLabels := ws.GetLabels()
			if existingLabels == nil {
				existingLabels = make(map[string]string)
			}
			for k, v := range pd.Labels {
				existingLabels[k] = v
			}
			ws.SetLabels(existingLabels)
		}
	}
}

// unstructuredToWorkspace converts an unstructured Workspace CR to the API result type.
func unstructuredToWorkspace(obj *unstructured.Unstructured) *workspaces.Workspace {
	ws := &workspaces.Workspace{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
	}

	// Check if stopped
	annotations := obj.GetAnnotations()
	if _, ok := annotations["kubeworkspaces.io/stopped"]; ok {
		ws.Stopped = true
	}

	// Creation timestamp
	createdAt := obj.GetCreationTimestamp().Format("2006-01-02T15:04:05Z")
	ws.CreatedAt = &createdAt

	// Extract container info from spec
	containers, found, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
	if found && len(containers) > 0 {
		container, ok := containers[0].(map[string]interface{})
		if ok {
			if image, ok := container["image"].(string); ok {
				ws.Image = image
			}

			// Extract port
			if ports, ok := container["ports"].([]interface{}); ok && len(ports) > 0 {
				if portMap, ok := ports[0].(map[string]interface{}); ok {
					if port, ok := portMap["containerPort"].(int64); ok {
						portInt := int(port)
						ws.Port = &portInt
					}
				}
			}

			// Extract resources
			if resources, ok := container["resources"].(map[string]interface{}); ok {
				if requests, ok := resources["requests"].(map[string]interface{}); ok {
					if cpu, ok := requests["cpu"].(string); ok {
						ws.CPURequest = &cpu
					}
					if mem, ok := requests["memory"].(string); ok {
						ws.MemoryRequest = &mem
					}
				}
				if limits, ok := resources["limits"].(map[string]interface{}); ok {
					if cpu, ok := limits["cpu"].(string); ok {
						ws.CPULimit = &cpu
					}
					if mem, ok := limits["memory"].(string); ok {
						ws.MemoryLimit = &mem
					}
				}
			}

			// Extract volume mounts
			if volumeMounts, ok := container["volumeMounts"].([]interface{}); ok {
				for _, vm := range volumeMounts {
					if vmMap, ok := vm.(map[string]interface{}); ok {
						name, _ := vmMap["name"].(string)
						mountPath, _ := vmMap["mountPath"].(string)
						if name != "" && mountPath != "" {
							ws.VolumeMounts = append(ws.VolumeMounts, &workspaces.VolumeMount{
								Name:      name,
								MountPath: mountPath,
							})
						}
					}
				}
			}
		}
	}

	// Extract status
	readyReplicas, _, _ := unstructured.NestedInt64(obj.Object, "status", "readyReplicas")
	ws.ReadyReplicas = int(readyReplicas)

	// Container state
	containerState, found, _ := unstructured.NestedMap(obj.Object, "status", "containerState")
	if found && len(containerState) > 0 {
		cs := &workspaces.ContainerState{}
		if _, ok := containerState["running"]; ok {
			state := "running"
			cs.State = &state
			if running, ok := containerState["running"].(map[string]interface{}); ok {
				if startedAt, ok := running["startedAt"].(string); ok {
					cs.StartedAt = &startedAt
				}
			}
		} else if _, ok := containerState["waiting"]; ok {
			state := "waiting"
			cs.State = &state
			if waiting, ok := containerState["waiting"].(map[string]interface{}); ok {
				if reason, ok := waiting["reason"].(string); ok {
					cs.Reason = &reason
				}
				if message, ok := waiting["message"].(string); ok {
					cs.Message = &message
				}
			}
		} else if _, ok := containerState["terminated"]; ok {
			state := "terminated"
			cs.State = &state
			if terminated, ok := containerState["terminated"].(map[string]interface{}); ok {
				if reason, ok := terminated["reason"].(string); ok {
					cs.Reason = &reason
				}
			}
		}
		ws.ContainerState = cs
	}

	return ws
}
