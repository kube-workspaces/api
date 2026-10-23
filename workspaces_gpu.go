package kubeworkspaces

import (
	"context"
	"time"

	"github.com/kube-workspaces/api/gen/workspaces"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/k8s"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func apiVMGPUProfile(profile *k8s.VMGPUProfile) *workspaces.VMGPUProfile {
	return &workspaces.VMGPUProfile{
		ID: profile.ID, DisplayName: profile.DisplayName, ResourceName: profile.ResourceName,
		Kind: profile.Kind, Count: int(profile.Count), NodeSelector: profile.NodeSelector,
		GuestDriverVersion: profile.GuestDriverVersion, Experimental: profile.Experimental,
	}
}

func (s *workspacessrvc) GpuProfiles(ctx context.Context) ([]*workspaces.VMGPUProfile, error) {
	profiles, err := s.client.VMGPUProfiles(ctx)
	if err != nil {
		return nil, workspaces.Unavailable("VM GPU operator profiles are unavailable")
	}
	result := make([]*workspaces.VMGPUProfile, 0, len(profiles))
	for i := range profiles {
		result = append(result, apiVMGPUProfile(&profiles[i]))
	}
	return result, nil
}

func (s *workspacessrvc) SetGpuProfile(ctx context.Context, p *workspaces.SetGpuProfilePayload) (*workspaces.Workspace, error) {
	user := auth.UserFromContext(ctx)
	if user != nil && (!auth.HasMinimumRole(user.Role, "editor") || !auth.UserHasNamespaceAccess(user, p.Namespace)) {
		return nil, workspaces.Forbidden("VM GPU changes require namespace editor access")
	}
	ws, err := s.client.GetWorkspace(ctx, p.Namespace, p.Name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, workspaces.NotFound("Windows workspace not found")
		}
		return nil, workspaces.Unavailable("Windows workspace is unavailable")
	}
	if !windowsWorkspaceProfile(ws) {
		return nil, workspaces.Invalid("typed GPU changes require a Windows VM workspace")
	}
	if err := s.client.RequireStoppedWindowsVM(ctx, ws); err != nil {
		return nil, workspaces.Conflict(err.Error())
	}
	if p.ProfileID == "" {
		unstructured.RemoveNestedField(ws.Object, "spec", "vmProfile", "gpu")
	} else {
		selector, _, _ := unstructured.NestedStringMap(ws.Object, "spec", "template", "spec", "nodeSelector")
		profile, err := s.client.ResolveVMGPUProfile(ctx, p.ProfileID, selector)
		if err != nil {
			return nil, workspaces.Invalid(err.Error())
		}
		value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(profile)
		if err != nil {
			return nil, workspaces.Unavailable("VM GPU profile could not be resolved")
		}
		if err := unstructured.SetNestedMap(ws.Object, value, "spec", "vmProfile", "gpu"); err != nil {
			return nil, err
		}
	}
	annotations := ws.GetAnnotations()
	annotations["kubeworkspaces.io/last-action"] = "GPUProfileChanged"
	annotations["kubeworkspaces.io/last-action-time"] = time.Now().UTC().Format(time.RFC3339)
	if user != nil {
		annotations["kubeworkspaces.io/last-action-by"] = user.Email
	}
	ws.SetAnnotations(annotations)
	// The resourceVersion from the stopped check fences concurrent Start/Reset.
	updated, err := s.client.UpdateWorkspace(ctx, ws)
	if apierrors.IsConflict(err) {
		return nil, workspaces.Conflict("workspace lifecycle changed; refresh before changing its GPU profile")
	}
	if err != nil {
		return nil, workspaces.Unavailable("VM GPU change could not be saved")
	}
	var rd *k8s.ImageRemoteDesktop
	if s.imageClient != nil {
		if image, ok := workspaceImage(updated); ok {
			if img, err := s.imageClient.GetImageByRef(ctx, image); err == nil {
				rd = img.RemoteDesktop
			}
		}
	}
	return unstructuredToWorkspace(updated, rd), nil
}
