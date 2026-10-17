package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
)

// ExecutionPermission mirrors the controller-owned User.executionGrants schema.
type ExecutionPermission string

const (
	PermissionExec           ExecutionPermission = "workspace.exec"
	PermissionShell          ExecutionPermission = "workspace.shell"
	PermissionElevated       ExecutionPermission = "workspace.exec.elevated"
	PermissionManage         ExecutionPermission = "workspace.execution.manage"
	PermissionReadRecordings ExecutionPermission = "workspace.execution.recordings.read"
)

func validExecutionPermission(p ExecutionPermission) bool {
	switch p {
	case PermissionExec, PermissionShell, PermissionElevated, PermissionManage, PermissionReadRecordings:
		return true
	default:
		return false
	}
}

// ExecutionGrant grants no namespace access by itself. Permissions from matching
// unexpired grants are additive, including separately granted elevation.
type ExecutionGrant struct {
	Namespace   string                `json:"namespace"`
	Workspaces  []string              `json:"workspaces,omitempty"`
	Permissions []ExecutionPermission `json:"permissions"`
	ExpiresAt   *time.Time            `json:"expiresAt,omitempty"`
}

// ParseExecutionGrants validates admin input as well as CR data. Strict decoding
// prevents misspelled scope fields from silently widening a grant.
func ParseExecutionGrants(raw interface{}) ([]ExecutionGrant, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid execution grants: %w", err)
	}
	if bytes.Equal(data, []byte("null")) {
		return nil, fmt.Errorf("execution grants must be an array; use [] to revoke all")
	}
	var grants []ExecutionGrant
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&grants); err != nil {
		return nil, fmt.Errorf("invalid execution grants: %w", err)
	}
	if len(grants) > 100 {
		return nil, fmt.Errorf("at most 100 execution grants are allowed")
	}
	for i, grant := range grants {
		if len(validation.IsDNS1123Label(grant.Namespace)) != 0 {
			return nil, fmt.Errorf("execution grant %d requires an exact namespace", i)
		}
		if len(grant.Workspaces) > 100 {
			return nil, fmt.Errorf("execution grant %d has too many workspaces", i)
		}
		for j, name := range grant.Workspaces {
			if len(validation.IsDNS1123Subdomain(name)) != 0 || slices.Contains(grant.Workspaces[:j], name) {
				return nil, fmt.Errorf("execution grant %d has invalid or duplicate workspace names", i)
			}
		}
		if len(grant.Permissions) == 0 || len(grant.Permissions) > 5 {
			return nil, fmt.Errorf("execution grant %d requires 1–5 permissions", i)
		}
		for j, p := range grant.Permissions {
			if !validExecutionPermission(p) || slices.Contains(grant.Permissions[:j], p) {
				return nil, fmt.Errorf("execution grant %d has unknown or duplicate permissions", i)
			}
		}
		if grant.ExpiresAt != nil && grant.ExpiresAt.IsZero() {
			return nil, fmt.Errorf("execution grant %d has an invalid expiry", i)
		}
	}
	return grants, nil
}

func userExecutionGrants(user *unstructured.Unstructured) ([]ExecutionGrant, error) {
	raw, found, err := unstructured.NestedSlice(user.Object, "spec", "executionGrants")
	if err != nil {
		return nil, fmt.Errorf("invalid execution grants: %w", err)
	}
	if !found {
		return nil, nil
	}
	return ParseExecutionGrants(raw)
}

// HasExecutionPermission is deliberately stricter than legacy auth-disabled
// helpers: no nil/anonymous or unbound principal, no implicit editor permission,
// and no grant can manufacture namespace membership. Policy/capability/recording
// admission must additionally be checked by the execution service.
func HasExecutionPermission(user *UserInfo, namespace, workspace string, permission ExecutionPermission, now time.Time) bool {
	if user == nil || user.UID == "" || user.MustChangePassword ||
		!validExecutionPermission(permission) ||
		len(validation.IsDNS1123Label(namespace)) != 0 ||
		len(validation.IsDNS1123Subdomain(workspace)) != 0 ||
		!UserHasNamespaceAccess(user, namespace) {
		return false
	}
	if user.Role == "admin" {
		return true
	}
	for _, grant := range user.ExecutionGrants {
		if grant.Namespace != namespace || (grant.ExpiresAt != nil && !now.Before(*grant.ExpiresAt)) {
			continue
		}
		if len(grant.Workspaces) > 0 && !slices.Contains(grant.Workspaces, workspace) {
			continue
		}
		if slices.Contains(grant.Permissions, permission) {
			return true
		}
	}
	return false
}

// AuthorizeExecution requires a fresh signed credential and a fresh User lookup
// on every invocation (admission AND renewal). It must not accept a caller-built
// UserInfo or a desktop-controller grant as machine execution authority.
func (p *ConfigProvider) AuthorizeExecution(ctx context.Context, token, namespace, workspace string, operation ExecutionPermission, elevated bool, now time.Time) (*UserInfo, error) {
	cfg, err := p.GetConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("execution authentication unavailable: %w", err)
	}
	if !cfg.Enabled {
		return nil, fmt.Errorf("execution requires authentication")
	}
	user, err := validateAndGetUser(ctx, token, cfg, p)
	if err != nil {
		return nil, err
	}
	if user.credentialUserUID == "" || user.credentialUserUID != user.UID {
		return nil, fmt.Errorf("execution requires a user-bound credential; sign in again")
	}
	if operation != PermissionExec && operation != PermissionShell && operation != PermissionManage && operation != PermissionReadRecordings {
		return nil, fmt.Errorf("invalid execution operation")
	}
	if !HasExecutionPermission(user, namespace, workspace, operation, now) ||
		(elevated && !HasExecutionPermission(user, namespace, workspace, PermissionElevated, now)) {
		return nil, fmt.Errorf("execution permission denied")
	}
	return user, nil
}
