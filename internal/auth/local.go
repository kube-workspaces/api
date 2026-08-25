package auth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"goa.design/clue/log"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	bcryptCost = 12

	// minPasswordLength is the minimum length enforced for new/changed passwords.
	minPasswordLength = 12

	generatedPasswordLength = 20
	passwordCharset         = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	maxFailedAttempts = 5
)

// lockoutBackoff returns the lockout duration for a given number of
// consecutive failed attempts (only applied once attempts >= maxFailedAttempts).
func lockoutBackoff(failedAttempts int) time.Duration {
	switch {
	case failedAttempts >= maxFailedAttempts+15:
		return 30 * time.Minute
	case failedAttempts >= maxFailedAttempts+10:
		return 15 * time.Minute
	case failedAttempts >= maxFailedAttempts+5:
		return 5 * time.Minute
	default:
		return 1 * time.Minute
	}
}

// LocalAuthHandler handles local (username/password) authentication.
type LocalAuthHandler struct {
	provider *ConfigProvider
	limiter  *ipRateLimiter
}

// NewLocalAuthHandler creates a new LocalAuthHandler.
func NewLocalAuthHandler(provider *ConfigProvider) *LocalAuthHandler {
	return &LocalAuthHandler{
		provider: provider,
		limiter:  newIPRateLimiter(10, time.Minute),
	}
}

// GeneratePassword returns a cryptographically random password suitable for
// bootstrap/default use, drawn from passwordCharset.
func GeneratePassword() (string, error) {
	b := make([]byte, generatedPasswordLength)
	maxN := big.NewInt(int64(len(passwordCharset)))
	for i := range b {
		n, err := rand.Int(rand.Reader, maxN)
		if err != nil {
			return "", fmt.Errorf("failed to generate random password: %w", err)
		}
		b[i] = passwordCharset[n.Int64()]
	}
	return string(b), nil
}

// HashPassword bcrypt-hashes the given plaintext password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// ValidatePasswordComplexity enforces a minimum password policy.
func ValidatePasswordComplexity(password string) error {
	if len(password) < minPasswordLength {
		return fmt.Errorf("password must be at least %d characters", minPasswordLength)
	}
	return nil
}

// localAuthSecretName returns the conventional Secret name for a local user's
// password material, given their slugified identifier. Matches the naming
// convention used by the controller's bootstrap-admin reconciliation.
func localAuthSecretName(slug string) string {
	return fmt.Sprintf("kw-user-%s-local-auth", slug)
}

// HandleLocalLogin authenticates a user via email/password and, on success,
// issues the same kind of session token/cookie as the OIDC flow.
func (h *LocalAuthHandler) HandleLocalLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	clientIP := clientIPFromRequest(r)
	if !h.limiter.Allow(clientIP) {
		writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "too many login attempts, try again later")
		return
	}

	cfg, err := h.provider.GetConfig(ctx)
	if err != nil || !cfg.Enabled || !cfg.LocalAuthEnabled {
		writeJSONError(w, http.StatusBadRequest, "local_auth_disabled", "local authentication is not enabled")
		return
	}

	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Password == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "email and password are required")
		return
	}

	userCR, err := h.provider.GetUserByEmail(ctx, body.Email)
	if err != nil {
		// Do not reveal whether the account exists.
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}

	disabled, _, _ := unstructured.NestedBool(userCR.Object, "spec", "disabled")
	if disabled {
		writeJSONError(w, http.StatusForbidden, "account_disabled", "this account is disabled")
		return
	}

	localAuthEnabled, _, _ := unstructured.NestedBool(userCR.Object, "spec", "localAuth", "enabled")
	if !localAuthEnabled {
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}

	// Check lockout
	lockedUntilStr, _, _ := unstructured.NestedString(userCR.Object, "status", "lockedUntil")
	if lockedUntilStr != "" {
		if lockedUntil, err := time.Parse(time.RFC3339, lockedUntilStr); err == nil && time.Now().Before(lockedUntil) {
			writeJSONError(w, http.StatusTooManyRequests, "account_locked",
				fmt.Sprintf("account is temporarily locked until %s", lockedUntil.Format(time.RFC3339)))
			return
		}
	}

	secretName, _, _ := unstructured.NestedString(userCR.Object, "spec", "localAuth", "passwordSecretRef", "name")
	if secretName == "" {
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}

	secret, err := h.provider.GetPasswordSecret(ctx, secretName)
	if err != nil {
		log.Printf(ctx, "auth: failed to load password secret %s: %v", secretName, err)
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}

	hash, err := GetPasswordHash(secret)
	if err != nil {
		log.Printf(ctx, "auth: password secret %s missing hash: %v", secretName, err)
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)); err != nil {
		h.recordFailedLogin(ctx, userCR)
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}

	// Success: reset failure tracking.
	h.resetLoginFailures(ctx, userCR)

	email, _, _ := unstructured.NestedString(userCR.Object, "spec", "email")
	displayName, _, _ := unstructured.NestedString(userCR.Object, "spec", "displayName")
	role, _, _ := unstructured.NestedString(userCR.Object, "spec", "role")
	for _, adminEmail := range cfg.AdminEmails {
		if strings.EqualFold(adminEmail, email) {
			role = "admin"
			break
		}
	}

	sessionToken, err := CreateSessionToken(email, displayName, role, nil, cfg.SigningKey, cfg.TokenExpiry)
	if err != nil {
		log.Printf(ctx, "auth: failed to create session token: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "failed to create session")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   int(cfg.TokenExpiry.Seconds()),
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})

	h.updateLastLogin(ctx, userCR)

	mustChangePassword, _, _ := unstructured.NestedBool(userCR.Object, "spec", "localAuth", "mustChangePassword")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             "ok",
		"mustChangePassword": mustChangePassword,
	})
}

// HandleChangePassword lets an authenticated local user set a new password.
// Note: the auth middleware skips /auth/* paths, so this handler must
// validate the session cookie directly (mirrors OIDCHandler.HandleMe).
func (h *LocalAuthHandler) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cfg, err := h.provider.GetConfig(ctx)
	if err != nil || !cfg.Enabled {
		writeJSONError(w, http.StatusBadRequest, "auth_disabled", "authentication is not enabled")
		return
	}

	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	user, authErr := validateAndGetUser(ctx, cookie.Value, cfg, h.provider)
	if authErr != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.CurrentPassword == "" || body.NewPassword == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "currentPassword and newPassword are required")
		return
	}

	if err := ValidatePasswordComplexity(body.NewPassword); err != nil {
		writeJSONError(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}

	userCR, err := h.provider.GetUserByEmail(ctx, user.Email)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}

	localAuthEnabled, _, _ := unstructured.NestedBool(userCR.Object, "spec", "localAuth", "enabled")
	if !localAuthEnabled {
		writeJSONError(w, http.StatusBadRequest, "local_auth_disabled", "local authentication is not enabled for this account")
		return
	}

	secretName, _, _ := unstructured.NestedString(userCR.Object, "spec", "localAuth", "passwordSecretRef", "name")
	if secretName == "" {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "no password secret configured")
		return
	}

	secret, err := h.provider.GetPasswordSecret(ctx, secretName)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "failed to load password secret")
		return
	}
	hash, err := GetPasswordHash(secret)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "failed to load password hash")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.CurrentPassword)); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials", "current password is incorrect")
		return
	}

	newHash, err := HashPassword(body.NewPassword)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "failed to hash password")
		return
	}

	if err := h.provider.UpdatePasswordHash(ctx, secretName, newHash); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "failed to update password")
		return
	}

	// Clear mustChangePassword.
	spec, _, _ := unstructured.NestedMap(userCR.Object, "spec")
	if spec == nil {
		spec = make(map[string]interface{})
	}
	localAuth, _, _ := unstructured.NestedMap(userCR.Object, "spec", "localAuth")
	if localAuth == nil {
		localAuth = make(map[string]interface{})
	}
	localAuth["mustChangePassword"] = false
	spec["localAuth"] = localAuth
	unstructured.SetNestedMap(userCR.Object, spec, "spec")

	if _, err := h.provider.UpdateUser(ctx, userCR); err != nil {
		log.Printf(ctx, "auth: failed to clear mustChangePassword for %s: %v", user.Email, err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "password changed"})
}

// ProvisionLocalUser creates a User CR with local auth enabled and a password
// Secret. If password is empty, a random one is generated. Returns the
// plaintext password that was set (for one-time display to an admin), the
// User CR name, and any error.
func ProvisionLocalUser(ctx context.Context, provider *ConfigProvider, email, displayName, role, password string, groups []string) (string, string, error) {
	if password == "" {
		p, err := GeneratePassword()
		if err != nil {
			return "", "", err
		}
		password = p
	} else if err := ValidatePasswordComplexity(password); err != nil {
		return "", "", err
	}

	hash, err := HashPassword(password)
	if err != nil {
		return "", "", err
	}

	name := slugifyEmail(email)
	secretName := localAuthSecretName(name)
	if err := provider.CreatePasswordSecret(ctx, secretName, hash, password); err != nil {
		return "", "", fmt.Errorf("failed to create password secret: %w", err)
	}

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
				"localAuth": map[string]interface{}{
					"enabled": true,
					"passwordSecretRef": map[string]interface{}{
						"name": secretName,
						"key":  "passwordHash",
					},
					"mustChangePassword": true,
				},
			},
		},
	}

	if _, err := provider.CreateUser(ctx, user); err != nil {
		return "", "", err
	}

	return password, name, nil
}

// ResetLocalUserPassword generates a new random password for an existing
// local user, updates their password Secret, and sets mustChangePassword.
// Returns the new plaintext password for one-time display to an admin.
func ResetLocalUserPassword(ctx context.Context, provider *ConfigProvider, userName string) (string, error) {
	userCR, err := provider.GetUser(ctx, userName)
	if err != nil {
		return "", err
	}

	localAuthEnabled, _, _ := unstructured.NestedBool(userCR.Object, "spec", "localAuth", "enabled")
	if !localAuthEnabled {
		return "", fmt.Errorf("user %q does not have local auth enabled", userName)
	}

	secretName, _, _ := unstructured.NestedString(userCR.Object, "spec", "localAuth", "passwordSecretRef", "name")
	if secretName == "" {
		return "", fmt.Errorf("user %q has no password secret configured", userName)
	}

	password, err := GeneratePassword()
	if err != nil {
		return "", err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return "", err
	}

	if err := provider.UpdatePasswordHash(ctx, secretName, hash); err != nil {
		return "", err
	}

	spec, _, _ := unstructured.NestedMap(userCR.Object, "spec")
	if spec == nil {
		spec = make(map[string]interface{})
	}
	localAuth, _, _ := unstructured.NestedMap(userCR.Object, "spec", "localAuth")
	if localAuth == nil {
		localAuth = make(map[string]interface{})
	}
	localAuth["mustChangePassword"] = true
	spec["localAuth"] = localAuth
	unstructured.SetNestedMap(userCR.Object, spec, "spec")

	if _, err := provider.UpdateUser(ctx, userCR); err != nil {
		return "", err
	}

	return password, nil
}

func (h *LocalAuthHandler) recordFailedLogin(ctx context.Context, userCR *unstructured.Unstructured) {
	attempts, _, _ := unstructured.NestedInt64(userCR.Object, "status", "failedLoginAttempts")
	attempts++
	unstructured.SetNestedField(userCR.Object, attempts, "status", "failedLoginAttempts")

	if attempts >= maxFailedAttempts {
		lockedUntil := time.Now().Add(lockoutBackoff(int(attempts)))
		unstructured.SetNestedField(userCR.Object, lockedUntil.Format(time.RFC3339), "status", "lockedUntil")
	}

	if _, err := h.provider.UpdateUserStatus(ctx, userCR); err != nil {
		log.Printf(ctx, "auth: failed to record failed login: %v", err)
	}
}

func (h *LocalAuthHandler) resetLoginFailures(ctx context.Context, userCR *unstructured.Unstructured) {
	unstructured.SetNestedField(userCR.Object, int64(0), "status", "failedLoginAttempts")
	unstructured.RemoveNestedField(userCR.Object, "status", "lockedUntil")
	if _, err := h.provider.UpdateUserStatus(ctx, userCR); err != nil {
		log.Printf(ctx, "auth: failed to reset login failures: %v", err)
	}
}

func (h *LocalAuthHandler) updateLastLogin(ctx context.Context, userCR *unstructured.Unstructured) {
	loginCount, _, _ := unstructured.NestedInt64(userCR.Object, "status", "loginCount")
	unstructured.SetNestedField(userCR.Object, loginCount+1, "status", "loginCount")
	unstructured.SetNestedField(userCR.Object, time.Now().Format(time.RFC3339), "status", "lastLogin")
	if _, err := h.provider.UpdateUserStatus(ctx, userCR); err != nil {
		log.Printf(ctx, "auth: failed to update last login: %v", err)
	}
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

// clientIPFromRequest extracts the client IP for rate-limiting purposes,
// preferring X-Forwarded-For (set by the ingress/proxy) over RemoteAddr.
func clientIPFromRequest(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ipRateLimiter is a simple fixed-window in-memory rate limiter keyed by
// client IP, used to blunt distributed password-guessing against
// /auth/login/local. Per-user lockout (see recordFailedLogin) is the primary
// defense; this is a coarse secondary control.
type ipRateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	attempts map[string][]time.Time
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		limit:    limit,
		window:   window,
		attempts: make(map[string][]time.Time),
	}
}

// Allow records an attempt for the given key and returns false if the key has
// exceeded limit attempts within the current window.
func (l *ipRateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	kept := l.attempts[key][:0]
	for _, t := range l.attempts[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}

	if len(kept) >= l.limit {
		l.attempts[key] = kept
		return false
	}

	kept = append(kept, now)
	l.attempts[key] = kept
	return true
}
