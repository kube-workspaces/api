package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// RequireRole is an HTTP middleware that checks the user has at minimum the specified role.
// Role hierarchy: admin > editor > viewer.
func RequireRole(minRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			// If no user in context, auth might be disabled - allow through
			if user == nil {
				next.ServeHTTP(w, r)
				return
			}

			if !hasMinimumRole(user.Role, minRole) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "forbidden",
					"message": fmt.Sprintf("requires %s role", minRole),
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireNamespaceAccess checks that the user has access to the specified namespace.
// Admins have access to all namespaces.
func RequireNamespaceAccess(getNamespace func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			// If no user in context, auth might be disabled - allow through
			if user == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Admins can access everything
			if user.Role == "admin" {
				next.ServeHTTP(w, r)
				return
			}

			namespace := getNamespace(r)
			// If namespace is empty or _all, allow (will be filtered later)
			if namespace == "" || namespace == "_all" {
				next.ServeHTTP(w, r)
				return
			}

			if !UserHasNamespaceAccess(user, namespace) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "forbidden",
					"message": fmt.Sprintf("no access to namespace %q", namespace),
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// FilterNamespaces filters a list of namespaces to only those the user has access to.
// If the user is nil (auth disabled) or admin, all namespaces are returned.
func FilterNamespaces(ctx context.Context, namespaces []string) []string {
	user := UserFromContext(ctx)
	if user == nil || user.Role == "admin" {
		return namespaces
	}

	var filtered []string
	for _, ns := range namespaces {
		if UserHasNamespaceAccess(user, ns) {
			filtered = append(filtered, ns)
		}
	}
	return filtered
}

// FilterWorkspaces filters workspace objects to only those in namespaces the user can access.
func FilterWorkspaces(ctx context.Context, workspaces []map[string]interface{}) []map[string]interface{} {
	user := UserFromContext(ctx)
	if user == nil || user.Role == "admin" {
		return workspaces
	}

	var filtered []map[string]interface{}
	for _, ws := range workspaces {
		ns, _ := ws["namespace"].(string)
		if UserHasNamespaceAccess(user, ns) {
			filtered = append(filtered, ws)
		}
	}
	return filtered
}

// UserHasNamespaceAccess checks if a user has access to a given namespace.
func UserHasNamespaceAccess(user *UserInfo, namespace string) bool {
	if user == nil {
		return true // Auth disabled
	}
	if user.Role == "admin" {
		return true
	}
	if user.PersonalNamespace == namespace {
		return true
	}
	for _, ns := range user.Namespaces {
		if ns == namespace {
			return true
		}
	}
	return false
}

func hasMinimumRole(userRole, minRole string) bool {
	roleLevel := map[string]int{
		"viewer": 1,
		"editor": 2,
		"admin":  3,
	}

	userLevel, ok := roleLevel[userRole]
	if !ok {
		return false
	}
	minLevel, ok := roleLevel[minRole]
	if !ok {
		return false
	}
	return userLevel >= minLevel
}

// HasMinimumRole checks if a user role meets the minimum required role level.
// Role hierarchy: admin > editor > viewer.
func HasMinimumRole(userRole, minRole string) bool {
	return hasMinimumRole(userRole, minRole)
}

// IsAdmin returns true if the user has admin role.
func IsAdmin(ctx context.Context) bool {
	user := UserFromContext(ctx)
	if user == nil {
		return true // Auth disabled, everyone is effectively admin
	}
	return user.Role == "admin"
}

// AuthEnabled returns true if there is a user in the context (meaning auth is active).
func AuthEnabled(ctx context.Context) bool {
	return UserFromContext(ctx) != nil
}

// ProvisionUser creates a User CR for a new user during first login.
func ProvisionUser(ctx context.Context, provider *ConfigProvider, email, displayName, role string, groups []string) error {
	// Slugify email to create the CR name
	name := slugifyEmail(email)

	user := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kubeworkspaces.io/v1alpha1",
			"kind":       "User",
			"metadata": map[string]interface{}{
				"name": name,
				"labels": map[string]interface{}{
					"kubeworkspaces.io/role": role,
				},
			},
			"spec": map[string]interface{}{
				"email":       email,
				"displayName": displayName,
				"role":        role,
				"disabled":    false,
				"groups":      toInterfaceSlice(groups),
			},
		},
	}

	_, err := provider.CreateUser(ctx, user)
	return err
}

func slugifyEmail(email string) string {
	// Convert email to a valid Kubernetes resource name
	s := strings.ToLower(email)
	s = strings.ReplaceAll(s, "@", "-at-")
	s = strings.ReplaceAll(s, ".", "-")
	s = strings.ReplaceAll(s, "_", "-")
	// Remove any remaining invalid characters
	var result []byte
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			result = append(result, c)
		}
	}
	// Trim leading/trailing dashes
	s = strings.Trim(string(result), "-")
	// Ensure max length
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}

func toInterfaceSlice(ss []string) []interface{} {
	result := make([]interface{}, len(ss))
	for i, s := range ss {
		result[i] = s
	}
	return result
}
