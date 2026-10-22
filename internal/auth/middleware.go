package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"goa.design/clue/log"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Middleware creates an HTTP middleware that validates session tokens.
// When auth is disabled, all requests pass through without authentication.
func Middleware(provider *ConfigProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Always allow health check
			if r.URL.Path == "/healthz" {
				next.ServeHTTP(w, r)
				return
			}

			// Always allow auth endpoints (login, callback, config)
			if strings.HasPrefix(r.URL.Path, "/auth/") {
				next.ServeHTTP(w, r)
				return
			}

			// Always allow OpenAPI spec
			if strings.HasPrefix(r.URL.Path, "/openapi") {
				next.ServeHTTP(w, r)
				return
			}

			// Always allow the build/version endpoint. Identifying which version
			// is deployed is diagnostic information, not privileged, and needing
			// a session to read it defeats the purpose during an incident. It
			// exposes no cluster state beyond the component image tags.
			if r.URL.Path == "/platform/version" {
				next.ServeHTTP(w, r)
				return
			}

			// Get auth config
			cfg, err := provider.GetConfig(ctx)
			if err != nil {
				log.Printf(ctx, "auth: failed to get config: %v", err)
				writeJSONError(w, http.StatusServiceUnavailable, "auth_unavailable", "authentication configuration unavailable")
				return
			}

			// If auth is not enabled, pass through
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Extract token from cookie
			cookie, err := r.Cookie(SessionCookieName)
			if err != nil || cookie.Value == "" {
				// Check for Bearer token in Authorization header (API clients)
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
					user, authErr := validateAndGetUser(ctx, tokenStr, cfg, provider)
					if authErr != nil {
						writeUnauthorized(w, r, authErr.Error())
						return
					}
					if user.MustChangePassword {
						writeJSONError(w, http.StatusForbidden, "password_change_required", "change your temporary password before accessing platform resources")
						return
					}
					ctx = ContextWithUser(ctx, user)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}

				writeUnauthorized(w, r, "authentication required")
				return
			}

			// Validate the session token
			user, authErr := validateAndGetUser(ctx, cookie.Value, cfg, provider)
			if authErr != nil {
				writeUnauthorized(w, r, authErr.Error())
				return
			}
			if user.MustChangePassword {
				writeJSONError(w, http.StatusForbidden, "password_change_required", "change your temporary password before accessing platform resources")
				return
			}

			// Add user to context
			ctx = ContextWithUser(ctx, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func validateAndGetUser(ctx context.Context, tokenStr string, cfg *Config, provider *ConfigProvider) (*UserInfo, error) {
	token, err := ValidateSessionTokenWithKeys(tokenStr, cfg.SessionSigningKeys())
	if err != nil {
		return nil, fmt.Errorf("invalid session: %w", err)
	}
	if (token.Type != "" && token.Type != DeviceTokenType) || (token.Type == DeviceTokenType && token.JTI == "") || (token.Type == "" && token.JTI != "") {
		return nil, fmt.Errorf("invalid credential type")
	}

	// Long-lived device tokens are revocable: the backing Secret must exist
	// and be unrevoked. Session tokens skip this check.
	if isDeviceRevoked(ctx, provider, token) {
		return nil, fmt.Errorf("device token has been revoked")
	}

	// Current User state is authoritative. A stale token must not preserve an
	// administrator role or keep a deleted/disabled user authorized.
	userCR, err := provider.GetUserByEmail(ctx, token.Email)
	if err != nil || userCR == nil {
		return nil, fmt.Errorf("current user account unavailable")
	}
	if userCR.GetDeletionTimestamp() != nil {
		return nil, fmt.Errorf("user account is being deleted")
	}
	if token.UserUID != "" && token.UserUID != string(userCR.GetUID()) {
		return nil, fmt.Errorf("session user identity no longer matches")
	}
	disabled, _, err := unstructured.NestedBool(userCR.Object, "spec", "disabled")
	if err != nil || disabled {
		return nil, fmt.Errorf("user account is disabled or invalid")
	}
	role, _, err := unstructured.NestedString(userCR.Object, "spec", "role")
	if err != nil || (role != "admin" && role != "editor" && role != "viewer") {
		return nil, fmt.Errorf("current user role is invalid")
	}
	// Configured admin emails remain an explicit administrator override, but
	// never bypass the current-account existence/disabled checks above.
	for _, adminEmail := range cfg.AdminEmails {
		if strings.EqualFold(adminEmail, token.Email) {
			role = "admin"
			break
		}
	}

	user := &UserInfo{
		credentialUserUID: token.UserUID,
		UID:               string(userCR.GetUID()),
		Email:             token.Email,
		DisplayName:       token.DisplayName,
		Role:              role,
		Groups:            token.Groups,
	}

	personalNS, _, _ := unstructuredNestedString(userCR.Object, "status", "personalNamespace")
	user.PersonalNamespace = personalNS
	avatarURL, _, _ := unstructuredNestedString(userCR.Object, "status", "avatarURL")
	user.AvatarURL = avatarURL
	user.Namespaces = getUserNamespaces(userCR, personalNS)
	mustChangePassword, err := provider.validateProvenance(ctx, token, userCR)
	if err != nil {
		return nil, fmt.Errorf("session credential unavailable or revoked; sign in again")
	}
	user.MustChangePassword = mustChangePassword
	user.AuthMethod = token.AuthMethod
	user.LocalPasswordEnabled, _, _ = unstructured.NestedBool(userCR.Object, "spec", "localAuth", "enabled")
	bindings, bindingErr := identityBindings(userCR)
	if bindingErr != nil {
		return nil, bindingErr
	}
	user.OIDCLinked = len(bindings) > 0
	_, _, refErr := passwordReference(userCR)
	user.CanChangePassword = cfg.LocalAuthEnabled && user.LocalPasswordEnabled && refErr == nil
	user.ExecutionGrants, err = userExecutionGrants(userCR)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func getUserNamespaces(userCR *unstructured.Unstructured, personalNS string) []string {
	var namespaces []string
	if personalNS != "" {
		namespaces = append(namespaces, personalNS)
	}

	access, found, _ := unstructured.NestedSlice(userCR.Object, "spec", "namespaceAccess")
	if found {
		for _, a := range access {
			if m, ok := a.(map[string]interface{}); ok {
				if ns, ok := m["namespace"].(string); ok {
					namespaces = append(namespaces, ns)
				}
			}
		}
	}
	return namespaces
}

func writeUnauthorized(w http.ResponseWriter, r *http.Request, message string) {
	// For API requests, return JSON error
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   "unauthorized",
		"message": message,
	})
}

// unstructuredNestedString is a helper to avoid import conflicts
func unstructuredNestedString(obj map[string]interface{}, fields ...string) (string, bool, error) {
	return unstructured.NestedString(obj, fields...)
}

// unstructuredNestedBool is a helper to avoid import conflicts
func unstructuredNestedBool(obj map[string]interface{}, fields ...string) (bool, bool, error) {
	return unstructured.NestedBool(obj, fields...)
}
