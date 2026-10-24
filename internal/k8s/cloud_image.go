package k8s

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// ValidateCloudImage leaves OCI references unchanged. URL sources are only
// meaningful for VM-only catalog images imported into persistent CDI roots.
func ValidateCloudImage(ref string, persistent bool, workspaceTypes []string, profile string) error {
	if !strings.Contains(ref, "://") {
		return nil
	}
	u, err := url.Parse(ref)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.IndexFunc(ref, unicode.IsSpace) >= 0 {
		return fmt.Errorf("cloud image must be an absolute HTTP(S) URL without credentials, whitespace or a fragment")
	}
	if !persistent || profile != "" || len(workspaceTypes) != 1 || workspaceTypes[0] != "vm" {
		return fmt.Errorf("HTTP(S) cloud images require a VM-only Image with persistentRootDisk enabled")
	}
	return nil
}
