package kubeworkspaces

import (
	"context"
	"fmt"
	"strings"

	"github.com/kube-workspaces/api/internal/k8s"
)

func (s *workspacessrvc) validateCloudImage(ctx context.Context, ref, workspaceType string) error {
	if !strings.Contains(ref, "://") {
		return nil
	}
	if workspaceType != "vm" {
		return fmt.Errorf("HTTP(S) cloud images can only be used with vm workspaces")
	}
	img, err := s.imageClient.GetImageByRef(ctx, ref)
	if err != nil {
		return fmt.Errorf("HTTP(S) cloud image must reference a catalog Image")
	}
	return k8s.ValidateCloudImage(ref, img.PersistentRootDisk, img.WorkspaceTypes, img.VMProfile)
}
