package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"goa.design/clue/log"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// OIDCDiscovery holds the endpoints from .well-known/openid-configuration.
type OIDCDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

// TokenResponse represents the OIDC token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// IDTokenClaims represents relevant claims from the ID token.
type IDTokenClaims struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	Picture       string   `json:"picture"`
	Groups        []string `json:"groups"`
}

// OIDCHandler handles the OIDC authentication flow.
type OIDCHandler struct {
	provider *ConfigProvider
	// codes holds authorization codes for in-flight RFC 8252 native logins
	// (see native.go). Empty for ordinary browser logins.
	codes *nativeCodeStore
	// nativeLimiter rate-limits POST /auth/native/token by client IP.
	nativeLimiter *ipRateLimiter
}

// NewOIDCHandler creates a new OIDC handler.
func NewOIDCHandler(provider *ConfigProvider) *OIDCHandler {
	return &OIDCHandler{
		provider:      provider,
		codes:         newNativeCodeStore(nativeCodeTTL, nativeCodeMaxEntries),
		nativeLimiter: newIPRateLimiter(10, time.Minute),
	}
}

// Close releases background resources held by the handler (the native
// authorization code sweeper).
func (h *OIDCHandler) Close() {
	h.codes.Close()
}

// callbackURLFromRequest derives the OIDC callback URL from the incoming request,
// using X-Forwarded-Host/Proto headers if present (behind a proxy), otherwise
// falling back to the Host header.
func callbackURLFromRequest(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	// Determine scheme: localhost is always http, everything else uses
	// the forwarded proto or TLS state
	scheme := "https"
	hostname := strings.Split(host, ":")[0]
	if hostname == "localhost" || hostname == "127.0.0.1" {
		scheme = "http"
	} else if !isSecureRequest(r) {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/auth/callback", scheme, host)
}

// HandleAuthConfig returns public auth configuration for the frontend.
func (h *OIDCHandler) HandleAuthConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg, err := h.provider.GetConfig(ctx)
	if err != nil {
		http.Error(w, "failed to get auth config", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"enabled": cfg.Enabled,
	}
	if cfg.Enabled {
		response["issuerURL"] = cfg.IssuerURL
		response["personalNamespaces"] = map[string]interface{}{
			"enabled":  cfg.PersonalNamespaces.Enabled,
			"template": cfg.PersonalNamespaces.Template,
		}
		response["registration"] = map[string]interface{}{
			"autoProvision": cfg.Registration.AutoProvision,
		}
		response["localAuth"] = map[string]interface{}{
			"enabled": cfg.LocalAuthEnabled,
		}
		// Advertise the RFC 8252 native-app flow so a desktop client can detect
		// support from this document rather than by probing /auth/login with
		// parameters an older build would silently ignore.
		response["nativeAuth"] = map[string]interface{}{
			"enabled": true,
			"methods": []string{"loopback-pkce"},
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleLogin initiates the OIDC login flow.
func (h *OIDCHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg, err := h.provider.GetConfig(ctx)
	if err != nil || !cfg.Enabled {
		http.Error(w, "authentication not enabled", http.StatusBadRequest)
		return
	}

	// RFC 8252 native-app parameters. They are absent for ordinary browser
	// logins, in which case everything below behaves exactly as it always has.
	nativeRedirect := r.URL.Query().Get("native_redirect")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	// The client's own state, echoed back on the loopback redirect so it can
	// perform the RFC 6749 §10.12 check. Ignored (as any unknown parameter is)
	// outside the native flow, so the browser flow is untouched.
	nativeState := r.URL.Query().Get("state")
	if nativeRedirect != "" {
		// SECURITY: validating the loopback redirect is what stops this
		// endpoint becoming an open redirect that hands a session token to an
		// attacker-chosen host. See validateLoopbackRedirect.
		if _, err := validateLoopbackRedirect(nativeRedirect); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := validateCodeChallenge(codeChallenge, codeChallengeMethod); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := validateNativeState(nativeState); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if codeChallenge != "" || codeChallengeMethod != "" {
		// PKCE without a loopback redirect is a confused client: it would get a
		// cookie-only browser session and never be told why its listener was
		// never called. No existing browser sends these parameters, so failing
		// loudly here costs nothing in compatibility.
		http.Error(w, "code_challenge requires native_redirect", http.StatusBadRequest)
		return
	}

	// Discover OIDC endpoints
	discovery, err := discoverOIDC(cfg.IssuerURL)
	if err != nil {
		log.Printf(ctx, "auth: OIDC discovery failed: %v", err)
		http.Error(w, "OIDC provider unavailable", http.StatusServiceUnavailable)
		return
	}

	// Generate state parameter for CSRF protection
	state, err := generateRandomState()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Carry the state — and any native parameters — through the OIDC round trip
	// in the kw-auth-state cookie, signed with the session signing key.
	// SECURITY: the signature is what makes the redirect target non-forgeable.
	// An attacker who plants an arbitrary kw-auth-state cookie cannot produce a
	// valid signature, so they cannot make a victim's completed login redirect
	// anywhere.
	nativeStateValue := nativeState
	if nativeRedirect == "" {
		nativeStateValue = ""
	}
	stateValue, err := encodeAuthState(&authState{
		State:          state,
		NativeRedirect: nativeRedirect,
		CodeChallenge:  codeChallenge,
		NativeState:    nativeStateValue,
		ExpiresAt:      time.Now().Add(authStateTTL).Unix(),
	}, cfg.SigningKey)
	if err != nil {
		log.Printf(ctx, "auth: failed to encode auth state: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Store state in a cookie for verification on callback
	http.SetCookie(w, &http.Cookie{
		Name:     "kw-auth-state",
		Value:    stateValue,
		Path:     "/auth",
		MaxAge:   int(authStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})

	// Build authorization URL
	params := url.Values{
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {callbackURLFromRequest(r)},
		"response_type": {"code"},
		"scope":         {strings.Join(cfg.Scopes, " ")},
		"state":         {state},
	}

	authURL := discovery.AuthorizationEndpoint + "?" + params.Encode()
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleCallback handles the OIDC callback after authentication.
func (h *OIDCHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg, err := h.provider.GetConfig(ctx)
	if err != nil || !cfg.Enabled {
		http.Error(w, "authentication not enabled", http.StatusBadRequest)
		return
	}

	// Verify state
	stateCookie, err := r.Cookie("kw-auth-state")
	if err != nil {
		http.Error(w, "missing state cookie", http.StatusBadRequest)
		return
	}

	// The cookie carries the CSRF state plus any native-flow parameters. The
	// state comparison below is unchanged in substance: the value the provider
	// echoed back must equal the one we minted and stored.
	authSt := parseAuthStateCookie(stateCookie.Value, cfg.SessionSigningKeys())
	queryState := r.URL.Query().Get("state")
	if queryState == "" || queryState != authSt.State {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "kw-auth-state",
		Value:    "",
		Path:     "/auth",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// Check for error from provider
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		log.Printf(ctx, "auth: OIDC error: %s - %s", errParam, errDesc)
		if redirectNativeError(w, r, authSt, errParam, errDesc) {
			return
		}
		http.Error(w, fmt.Sprintf("authentication failed: %s", errDesc), http.StatusUnauthorized)
		return
	}

	// Exchange code for tokens
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	discovery, err := discoverOIDC(cfg.IssuerURL)
	if err != nil {
		http.Error(w, "OIDC provider unavailable", http.StatusServiceUnavailable)
		return
	}

	tokenResp, err := exchangeCode(ctx, discovery.TokenEndpoint, code, cfg.ClientID, cfg.ClientSecret, callbackURLFromRequest(r))
	if err != nil {
		log.Printf(ctx, "auth: token exchange failed: %v", err)
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	// Parse ID token claims (without full JWT validation - trusting the token endpoint response)
	claims, err := parseIDTokenClaims(tokenResp.IDToken)
	if err != nil {
		log.Printf(ctx, "auth: failed to parse ID token: %v", err)
		http.Error(w, "failed to parse identity", http.StatusInternalServerError)
		return
	}

	email := claims.Email
	if email == "" {
		email = claims.Sub
	}

	// Check login restrictions (allowedDomains OR allowedEmails)
	// Admin emails always bypass these restrictions
	hasRestrictions := len(cfg.Registration.AllowedDomains) > 0 || len(cfg.Registration.AllowedEmails) > 0
	if hasRestrictions {
		// Check if user is an admin (admins always bypass)
		isAdmin := false
		for _, adminEmail := range cfg.AdminEmails {
			if strings.EqualFold(adminEmail, email) {
				isAdmin = true
				break
			}
		}

		if !isAdmin {
			allowed := false
			// Check allowedEmails (case-insensitive)
			for _, ae := range cfg.Registration.AllowedEmails {
				if strings.EqualFold(ae, email) {
					allowed = true
					break
				}
			}
			// Check allowedDomains (OR logic — either list can permit)
			if !allowed {
				for _, domain := range cfg.Registration.AllowedDomains {
					if strings.HasSuffix(strings.ToLower(email), "@"+strings.ToLower(domain)) {
						allowed = true
						break
					}
				}
			}
			if !allowed {
				if redirectNativeError(w, r, authSt, "access_denied", "email not allowed") {
					return
				}
				http.Error(w, "email not allowed", http.StatusForbidden)
				return
			}
		}
	}

	// Determine user role
	role := cfg.Registration.DefaultRole
	for _, adminEmail := range cfg.AdminEmails {
		if strings.EqualFold(adminEmail, email) {
			role = "admin"
			break
		}
	}

	// Auto-provision user if enabled
	if cfg.Registration.AutoProvision {
		_, err := h.provider.GetUserByEmail(ctx, email)
		if err != nil {
			// User doesn't exist, create them
			provisionRole := role
			if cfg.Registration.RequireApproval {
				provisionRole = "viewer" // Restricted until approved
			}
			if provErr := ProvisionUser(ctx, h.provider, email, claims.Name, provisionRole, claims.Groups); provErr != nil {
				log.Printf(ctx, "auth: failed to provision user: %v", provErr)
				// Don't fail login if provisioning fails - user can still authenticate
			} else {
				log.Printf(ctx, "auth: provisioned new user %s with role %s", email, provisionRole)
				// Record first login
				h.updateLastLogin(ctx, email)
			}
		} else {
			// Update last login on existing user
			h.updateLastLogin(ctx, email)
		}
	}

	// Resolve and persist avatar URL (async-safe: runs after user exists)
	avatarURL := resolveAvatarURL(ctx, claims, tokenResp.AccessToken, discovery)
	h.updateAvatarURL(ctx, email, avatarURL)

	// Create session token
	sessionToken, err := CreateSessionToken(email, claims.Name, role, claims.Groups, cfg.SigningKey, cfg.TokenExpiry)
	if err != nil {
		log.Printf(ctx, "auth: failed to create session token: %v", err)
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	// Native (RFC 8252) flow: hand the token back to the client's loopback
	// listener via a single-use code instead of setting a browser cookie. The
	// token belongs to the app, not to the browser the user logged in with.
	// Everything above — claims, role resolution, provisioning, expiry — is the
	// shared code path; only delivery differs.
	if authSt.Native() {
		h.completeNativeLogin(w, r, authSt, sessionToken, cfg)
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   int(cfg.TokenExpiry.Seconds()),
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to frontend
	redirectURL := r.URL.Query().Get("redirect")
	if redirectURL == "" {
		redirectURL = "/"
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// HandleLogout clears the session.
func (h *OIDCHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "logged out"})
}

// HandleMe returns the current user's information.
// Note: The auth middleware skips /auth/* paths, so this handler must
// validate the session token directly. It accepts the session cookie (browser)
// or an Authorization: Bearer header (native/API clients, which cannot read an
// HttpOnly cookie); the cookie takes precedence.
func (h *OIDCHandler) HandleMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cfg, _ := h.provider.GetConfig(ctx)
	if cfg == nil || !cfg.Enabled {
		// Auth disabled - return anonymous with admin access
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
			"authEnabled":   false,
		})
		return
	}

	// Validate the session token directly (middleware skips /auth/ paths)
	tokenStr := sessionTokenFromRequest(r)
	if tokenStr == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
			"authEnabled":   true,
		})
		return
	}

	user, authErr := validateAndGetUser(ctx, tokenStr, cfg, h.provider)
	if authErr != nil {
		log.Printf(ctx, "auth: /auth/me token validation failed: %v", authErr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
			"authEnabled":   true,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated":      true,
		"authEnabled":        true,
		"email":              user.Email,
		"displayName":        user.DisplayName,
		"role":               user.Role,
		"groups":             user.Groups,
		"namespaces":         user.Namespaces,
		"personalNamespace":  user.PersonalNamespace,
		"avatarURL":          user.AvatarURL,
		"mustChangePassword": user.MustChangePassword,
	})
}

func (h *OIDCHandler) updateLastLogin(ctx context.Context, email string) {
	userCR, err := h.provider.GetUserByEmail(ctx, email)
	if err != nil {
		return
	}

	// Update login count and last login
	loginCount, _, _ := unstructuredNestedInt64(userCR.Object, "status", "loginCount")
	unstructured.SetNestedField(userCR.Object, loginCount+1, "status", "loginCount")
	unstructured.SetNestedField(userCR.Object, time.Now().Format(time.RFC3339), "status", "lastLogin")

	h.provider.UpdateUserStatus(ctx, userCR)
}

func discoverOIDC(issuerURL string) (*OIDCDiscovery, error) {
	resp, err := http.Get(issuerURL + "/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var discovery OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("failed to decode OIDC discovery: %w", err)
	}
	return &discovery, nil
}

func exchangeCode(ctx context.Context, tokenEndpoint, code, clientID, clientSecret, redirectURI string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
	}
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Google requires Basic Auth for client authentication on the token endpoint
	if clientID != "" && clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}
	return &tokenResp, nil
}

func parseIDTokenClaims(idToken string) (*IDTokenClaims, error) {
	// JWT format: header.payload.signature
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid ID token format")
	}

	// Decode payload (second part)
	payload := parts[1]
	// Add padding if needed
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		// Try without padding
		decoded, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode ID token payload: %w", err)
		}
	}

	var claims IDTokenClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}
	return &claims, nil
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// isSecureRequest checks if the original request was made over HTTPS,
// accounting for reverse proxies that terminate TLS (e.g. Cloudflare, nginx).
func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	// Check X-Forwarded-Proto (set by most reverse proxies)
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "https" {
		return true
	}
	// Check X-Forwarded-Scheme (alternative header)
	if scheme := r.Header.Get("X-Forwarded-Scheme"); scheme == "https" {
		return true
	}
	return false
}

func unstructuredNestedInt64(obj map[string]interface{}, fields ...string) (int64, bool, error) {
	return unstructured.NestedInt64(obj, fields...)
}
