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

	"goa.design/clue/log"
	"golang.org/x/crypto/bcrypt"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/util/retry"
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

	_, passwordKey, refErr := passwordReference(userCR)
	if refErr != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}
	hash, err := getSecretDataValue(secret, passwordKey)
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

	email, _, _ := unstructured.NestedString(userCR.Object, "spec", "email")
	displayName, _, _ := unstructured.NestedString(userCR.Object, "spec", "displayName")
	role, _, _ := unstructured.NestedString(userCR.Object, "spec", "role")
	for _, adminEmail := range cfg.AdminEmails {
		if strings.EqualFold(adminEmail, email) {
			role = "admin"
			break
		}
	}

	version, mustChangePassword, err := localCredentialState(userCR, secret)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials", "local credential unavailable")
		return
	}
	sessionToken, err := CreateSessionTokenWithProvenance(email, displayName, role, nil, cfg.SigningKey, cfg.TokenExpiry, string(userCR.GetUID()), SessionProvenance{AuthMethod: "local", CredentialVersion: version})
	if err != nil {
		log.Printf(ctx, "auth: failed to create session token: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "failed to create session")
		return
	}
	if _, err := validateAndGetUser(ctx, sessionToken, cfg, h.provider); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials", "account or credential changed; sign in again")
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             "ok",
		"mustChangePassword": mustChangePassword,
	})
}

// HandleChangePassword lets an authenticated local user set a new password.
// Note: the auth middleware skips /auth/* paths, so this handler must
// validate the session token directly (mirrors OIDCHandler.HandleMe): session
// cookie first, then an Authorization: Bearer header for native/API clients.
func (h *LocalAuthHandler) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cfg, err := h.provider.GetConfig(ctx)
	if err != nil || !cfg.Enabled {
		writeJSONError(w, http.StatusBadRequest, "auth_disabled", "authentication is not enabled")
		return
	}

	tokenStr := sessionTokenFromRequest(r)
	if tokenStr == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	user, authErr := validateAndGetUser(ctx, tokenStr, cfg, h.provider)
	if authErr != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	if !user.CanChangePassword {
		writeJSONError(w, http.StatusBadRequest, "local_auth_disabled", "password change is not available for this account")
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
	_, passwordKey, refErr := passwordReference(userCR)
	if refErr != nil {
		writeJSONError(w, http.StatusBadRequest, "local_auth_disabled", "password reference unavailable")
		return
	}
	hash, err := getSecretDataValue(secret, passwordKey)
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

	if err := h.provider.validateExclusivePassword(ctx, userCR, secret); err != nil {
		writeJSONError(w, http.StatusConflict, "credential_ownership_conflict", err.Error())
		return
	}
	if err := h.provider.replacePasswordHash(ctx, secret, passwordKey, newHash, false); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "failed to update password")
		return
	}

	// The Secret's policy is authoritative and atomic with the new hash.
	// Keep the administrative User flag in sync without overwriting concurrent
	// account edits. A concurrent reset's Secret policy still wins regardless.
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := h.provider.GetUser(ctx, userCR.GetName())
		if err != nil {
			return err
		}
		if current.GetUID() != userCR.GetUID() {
			return fmt.Errorf("account replaced")
		}
		currentName, currentKey, refErr := passwordReference(current)
		if refErr != nil || currentName != secretName || currentKey != passwordKey {
			return fmt.Errorf("credential reference changed again")
		}
		latest, err := h.provider.GetPasswordSecret(ctx, secretName)
		if err != nil {
			return err
		}
		latestHash, err := getSecretDataValue(latest, passwordKey)
		if err != nil || latestHash != newHash {
			return fmt.Errorf("credential changed again")
		}
		_ = unstructured.SetNestedField(current.Object, false, "spec", "localAuth", "mustChangePassword")
		_, err = h.provider.UpdateUser(ctx, current)
		return err
	}); err != nil {
		log.Printf(ctx, "auth: password updated but account policy synchronization failed for %s: %v", userCR.GetName(), err)
	}
	response := map[string]interface{}{"status": "password changed"}
	if user.AuthMethod == "local" {
		version := LocalCredentialVersion(user.UID, secretName, passwordKey, newHash)
		replacement, err := CreateSessionTokenWithProvenance(user.Email, user.DisplayName, user.Role, user.Groups, cfg.SigningKey, cfg.TokenExpiry, user.UID, SessionProvenance{AuthMethod: "local", CredentialVersion: version})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", "password changed; sign in again")
			return
		}
		if _, err := validateAndGetUser(ctx, replacement, cfg, h.provider); err != nil {
			writeJSONError(w, http.StatusConflict, "credential_changed", "password changed again; sign in again")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Value: replacement, Path: "/", MaxAge: int(cfg.TokenExpiry.Seconds()), HttpOnly: true, Secure: isSecureRequest(r), SameSite: http.SameSiteLaxMode})
		if cookie, err := r.Cookie(SessionCookieName); err != nil || cookie.Value == "" {
			// Browser JavaScript must not receive the HttpOnly session value.
			// Bearer-only clients need the replacement in the response body.
			response["token"] = replacement
			response["expires_at"] = time.Now().Add(cfg.TokenExpiry).Unix()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(response)
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

	user, err = provider.CreateUser(ctx, user)
	if err != nil {
		return "", "", err
	}
	secretName, err := provider.CreateOwnedPasswordSecret(ctx, user, hash, password)
	if err != nil {
		return "", "", fmt.Errorf("account created without a local credential; enable its local password to resume: %w", err)
	}
	spec, _, _ := unstructured.NestedMap(user.Object, "spec")
	spec["localAuth"] = map[string]interface{}{"enabled": true, "passwordSecretRef": map[string]interface{}{"name": secretName, "key": "passwordHash"}, "mustChangePassword": true}
	if _, err := provider.UpdateUserSpec(ctx, user, spec); err != nil {
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

	// Reset also migrates legacy/shared credentials without altering the source.
	// Publishing a fresh reference atomically revokes only this UID's local method.
	secretName, err = provider.CreateOwnedPasswordSecret(ctx, userCR, hash, password)
	if err != nil {
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
	localAuth["passwordSecretRef"] = map[string]interface{}{"name": secretName, "key": "passwordHash"}
	spec["localAuth"] = localAuth
	if _, err := provider.UpdateUserSpec(ctx, userCR, spec); err != nil {
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

func (h *LocalAuthHandler) updateLastLogin(ctx context.Context, userCR *unstructured.Unstructured) {
	// Reset failures and record the successful login together. Separate writes
	// using userCR's original resourceVersion conflict with each other, even
	// without concurrent controller activity.
	lastLogin := time.Now().Format(time.RFC3339)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := h.provider.GetUser(ctx, userCR.GetName())
		if err != nil {
			return err
		}
		// Do not apply login metadata to a replacement account with the same name.
		if current.GetUID() != userCR.GetUID() {
			return fmt.Errorf("user was replaced during login")
		}
		loginCount, _, _ := unstructured.NestedInt64(current.Object, "status", "loginCount")
		unstructured.SetNestedField(current.Object, loginCount+1, "status", "loginCount")
		unstructured.SetNestedField(current.Object, lastLogin, "status", "lastLogin")
		unstructured.SetNestedField(current.Object, int64(0), "status", "failedLoginAttempts")
		unstructured.RemoveNestedField(current.Object, "status", "lockedUntil")
		_, err = h.provider.UpdateUserStatus(ctx, current)
		return err
	})
	if err != nil {
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

// clientIPFromRequest extracts the client IP for rate-limiting purposes.
//
// Only the rightmost entry of X-Forwarded-For is trusted. Every trusted
// reverse proxy in the chain appends the address of the hop it actually saw
// to the end of X-Forwarded-For, so the rightmost value is the immediate
// client as observed by the proxy. Anything a client places on the left
// (e.g. "X-Forwarded-For: 203.0.113.5, ...") is attacker-controlled and must
// never be used: honoring the first entry let a client mint an unlimited
// number of fresh per-IP rate-limit keys and defeat the limiter.
//
// When the API is reached without a proxy (no X-Forwarded-For), RemoteAddr is
// the client and is used directly. The same rule must hold for every limiter
// that keys off this value (local login, native token exchange, browser
// session grant).
func clientIPFromRequest(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		last := strings.TrimSpace(parts[len(parts)-1])
		if net.ParseIP(last) != nil {
			return last
		}
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
