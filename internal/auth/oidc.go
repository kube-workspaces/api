package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"goa.design/clue/log"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// OIDCDiscovery holds the endpoints from .well-known/openid-configuration.
type OIDCDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
	provider              *oidc.Provider
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
	// (see native.go) and for browser-session grants (see browsersession.go).
	// Empty for ordinary browser logins. Backed by K8s Secrets when a dynamic
	// client is available so any replica can redeem (see codestore.go);
	// in-memory otherwise.
	codes     CodeStore
	flows     CodeStore
	adoptions CodeStore
	// nativeLimiter rate-limits POST /auth/native/token by client IP.
	nativeLimiter *ipRateLimiter
	// browserSessionLimiter rate-limits GET /auth/browser-session by client IP.
	browserSessionLimiter *ipRateLimiter
}

// NewOIDCHandler creates a new OIDC handler.
func NewOIDCHandler(provider *ConfigProvider) *OIDCHandler {
	return NewOIDCHandlerWithCodes(provider, newNativeCodeStore(nativeCodeTTL, nativeCodeMaxEntries))
}

// NewOIDCHandlerWithCodes creates a handler with an explicit code store. The
// HTTP wiring passes a K8s-backed store when cluster access exists so native
// and browser-session codes redeem on any replica; tests pass the in-memory
// store (or a fake-backed K8s store) directly.
func NewOIDCHandlerWithCodes(provider *ConfigProvider, codes CodeStore) *OIDCHandler {
	flows := newK8sCodeStore(provider.dynamicClient, authStateTTL, nativeCodeMaxEntries)
	if store, ok := flows.(*k8sCodeStore); ok {
		store.strict = true
	}
	adoptions := newK8sCodeStore(provider.dynamicClient, authStateTTL, nativeCodeMaxEntries)
	if store, ok := adoptions.(*k8sCodeStore); ok {
		store.strict = true
	}
	return &OIDCHandler{
		adoptions:             adoptions,
		flows:                 flows,
		provider:              provider,
		codes:                 codes,
		nativeLimiter:         newIPRateLimiter(10, time.Minute),
		browserSessionLimiter: newIPRateLimiter(10, time.Minute),
	}
}

// Close releases background resources held by the handler (the native
// authorization code sweeper).
func (h *OIDCHandler) Close() {
	h.codes.Close()
	h.flows.Close()
	h.adoptions.Close()
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
		oidcEnabled := cfg.IssuerURL != "" && cfg.ClientID != ""
		nativeMethods := []string{}
		methods := []string{}
		if cfg.LocalAuthEnabled {
			methods = append(methods, "local")
		}
		if oidcEnabled {
			methods = append(methods, "oidc")
			nativeMethods = append(nativeMethods, "loopback-pkce")
		}
		response["methods"] = methods
		response["nativeAuth"] = map[string]interface{}{"enabled": oidcEnabled, "methods": nativeMethods}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleLogin initiates the OIDC login flow.
func (h *OIDCHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	h.startLogin(w, r, nil)
}

func (h *OIDCHandler) startLogin(w http.ResponseWriter, r *http.Request, link *unstructured.Unstructured) {
	h.startLoginWithAdoption(w, r, link, "")
}

func (h *OIDCHandler) startLoginWithAdoption(w http.ResponseWriter, r *http.Request, link *unstructured.Unstructured, adoptionCode string) {
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
	discovery, err := discoverOIDC(ctx, cfg.IssuerURL)
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
	nonce, err := generateRandomState()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	verifier, err := generateRandomState()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	st := &authState{
		AdoptionCode: adoptionCode,
		State:        state,
		Nonce:        nonce, UpstreamVerifier: verifier, Issuer: cfg.IssuerURL, ClientID: cfg.ClientID,
		NativeRedirect: nativeRedirect,
		CodeChallenge:  codeChallenge,
		NativeState:    nativeStateValue,
		ExpiresAt:      time.Now().Add(authStateTTL).Unix(),
	}
	if link != nil {
		st.LinkUserName, st.LinkUserUID = link.GetName(), string(link.GetUID())
		st.LinkSessionHash = sessionHash(sessionTokenFromRequest(r))
	}
	stateValue, err := encodeAuthState(st, cfg.SigningKey)
	if err != nil {
		log.Printf(ctx, "auth: failed to encode auth state: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.flows.Issue(state, nativeAuthCode{token: stateValue}); err != nil {
		http.Error(w, "authentication state storage unavailable", http.StatusServiceUnavailable)
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
		"client_id":             {cfg.ClientID},
		"redirect_uri":          {callbackURLFromRequest(r)},
		"response_type":         {"code"},
		"scope":                 {strings.Join(cfg.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {deriveCodeChallengeS256(verifier)},
		"code_challenge_method": {"S256"},
	}
	if adoptionCode != "" {
		// The administrator may already be signed into a different provider
		// account. Ask the recipient to choose instead of silently using it.
		params.Set("prompt", "select_account")
	}

	authURL := discovery.AuthorizationEndpoint + "?" + params.Encode()
	if link != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]string{"authorizationURL": authURL})
		return
	}
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
	authSt, stateErr := decodeAuthState(stateCookie.Value, cfg.SessionSigningKeys())
	queryState := r.URL.Query().Get("state")
	if stateErr != nil || queryState == "" || queryState != authSt.State || authSt.Issuer != cfg.IssuerURL || authSt.ClientID != cfg.ClientID {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	flow, ok := h.flows.Redeem(authSt.State)
	if !ok || flow.token != stateCookie.Value {
		http.Error(w, "authentication state expired or already used", http.StatusBadRequest)
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

	discovery, err := discoverOIDC(ctx, cfg.IssuerURL)
	if err != nil {
		http.Error(w, "OIDC provider unavailable", http.StatusServiceUnavailable)
		return
	}

	tokenResp, err := exchangeCode(ctx, discovery.TokenEndpoint, code, cfg.ClientID, cfg.ClientSecret, callbackURLFromRequest(r), authSt.UpstreamVerifier)
	if err != nil {
		log.Printf(ctx, "auth: token exchange failed: %v", err)
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	claims, err := verifyOIDCIdentity(ctx, discovery, cfg, authSt, tokenResp.IDToken)
	if err != nil {
		log.Printf(ctx, "auth: failed to parse ID token: %v", err)
		http.Error(w, "invalid provider identity", http.StatusUnauthorized)
		return
	}
	id := ExternalIdentity{Issuer: cfg.IssuerURL, Subject: claims.Sub}
	if authSt.AdoptionCode != "" {
		if err := h.completeIdentityAdoption(ctx, cfg, authSt.AdoptionCode, id, claims); err != nil {
			http.Error(w, "identity adoption denied; ask an administrator for a new invitation and use the approved provider account", http.StatusForbidden)
			return
		}
		// Bind only: do not replace a different account's existing browser session.
		http.Redirect(w, r, "/login?identityLinked=1", http.StatusFound)
		return
	}
	if authSt.LinkUserUID != "" {
		if err := h.completeIdentityLink(ctx, r, cfg, authSt, id); err != nil {
			http.Error(w, "identity linking denied", http.StatusForbidden)
			return
		}
		http.Redirect(w, r, "/admin/users?identityLinked=1", http.StatusFound)
		return
	}
	currentUser, identityErr := h.provider.GetUserByIdentity(ctx, id)
	if identityErr != nil && !errors.Is(identityErr, ErrIdentityNotBound) {
		http.Error(w, "identity binding unavailable or ambiguous", http.StatusForbidden)
		return
	}

	email := claims.Email
	if currentUser != nil {
		email, _, _ = unstructured.NestedString(currentUser.Object, "spec", "email")
	} else if email == "" || !claims.EmailVerified {
		http.Error(w, "a verified email is required for account provisioning", http.StatusForbidden)
		return
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

	if currentUser == nil {
		if !cfg.Registration.AutoProvision {
			http.Error(w, "external identity must be explicitly linked to an account", http.StatusForbidden)
			return
		}
		users, err := h.provider.ListUsers(ctx)
		if err != nil {
			http.Error(w, "account inventory unavailable", http.StatusServiceUnavailable)
			return
		}
		for _, user := range users.Items {
			userEmail, _, _ := unstructured.NestedString(user.Object, "spec", "email")
			if strings.EqualFold(userEmail, email) || user.GetName() == slugifyEmail(email) {
				http.Error(w, "existing account requires explicit identity linking", http.StatusConflict)
				return
			}
		}
		if cfg.Registration.RequireApproval {
			role = "viewer"
		}
		if err := ProvisionUser(ctx, h.provider, email, claims.Name, role, claims.Groups); err != nil {
			http.Error(w, "account provisioning failed", http.StatusConflict)
			return
		}
		currentUser, err = h.provider.GetUser(ctx, slugifyEmail(email))
		if err != nil || h.provider.BindIdentity(ctx, currentUser.GetName(), string(currentUser.GetUID()), id) != nil {
			http.Error(w, "account binding failed", http.StatusConflict)
			return
		}
	}
	h.updateLastLogin(ctx, email)

	// Resolve and persist avatar URL (async-safe: runs after user exists)
	avatarURL := resolveAvatarURL(ctx, claims, tokenResp.AccessToken, discovery)
	h.updateAvatarURL(ctx, email, avatarURL)

	// Create session token
	currentUser, err = h.provider.GetUserByIdentity(ctx, id)
	if err != nil {
		http.Error(w, "current user account unavailable", http.StatusForbidden)
		return
	}
	role, _, _ = unstructuredNestedString(currentUser.Object, "spec", "role")
	for _, adminEmail := range cfg.AdminEmails {
		if strings.EqualFold(adminEmail, email) {
			role = "admin"
			break
		}
	}
	displayName, _, _ := unstructured.NestedString(currentUser.Object, "spec", "displayName")
	groups, _, _ := unstructured.NestedStringSlice(currentUser.Object, "spec", "groups")
	provenance, err := h.provider.identityProvenance(ctx, currentUser, id)
	if err != nil {
		http.Error(w, "identity credential unavailable", http.StatusForbidden)
		return
	}
	sessionToken, err := CreateSessionTokenWithProvenance(email, displayName, role, groups, cfg.SigningKey, cfg.TokenExpiry, string(currentUser.GetUID()), provenance)
	if err != nil {
		log.Printf(ctx, "auth: failed to create session token: %v", err)
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}
	if _, err := validateAndGetUser(ctx, sessionToken, cfg, h.provider); err != nil {
		http.Error(w, "current user account cannot sign in", http.StatusForbidden)
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
	http.Redirect(w, r, "/", http.StatusFound)
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

	cfg, err := h.provider.GetConfig(ctx)
	if err != nil {
		log.Printf(ctx, "auth: /auth/me configuration unavailable: %v", err)
		writeJSONError(w, http.StatusServiceUnavailable, "auth_unavailable", "authentication configuration unavailable")
		return
	}
	if !cfg.Enabled {
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
		"authenticated":        true,
		"authEnabled":          true,
		"email":                user.Email,
		"displayName":          user.DisplayName,
		"role":                 user.Role,
		"groups":               user.Groups,
		"namespaces":           user.Namespaces,
		"personalNamespace":    user.PersonalNamespace,
		"avatarURL":            user.AvatarURL,
		"mustChangePassword":   user.MustChangePassword,
		"authMethod":           user.AuthMethod,
		"localPasswordEnabled": user.LocalPasswordEnabled,
		"oidcLinked":           user.OIDCLinked,
		"canChangePassword":    user.CanChangePassword,
		// UI hints from the current account only; admission reauthorizes every run.
		"executionCredentialBound": user.UID != "" && user.credentialUserUID == user.UID && !user.MustChangePassword,
		"executionGrants":          user.ExecutionGrants,
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

var oidcHTTPClient = &http.Client{Timeout: 10 * time.Second}

func verifyOIDCIdentity(ctx context.Context, discovery *OIDCDiscovery, cfg *Config, state *authState, raw string) (*IDTokenClaims, error) {
	ctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, oidcHTTPClient), 20*time.Second)
	defer cancel()
	if cfg.ClientID == "" || state.Nonce == "" || state.UpstreamVerifier == "" {
		return nil, fmt.Errorf("incomplete OIDC transaction")
	}
	token, err := discovery.provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	if token.Nonce != state.Nonce || token.Subject == "" {
		return nil, fmt.Errorf("invalid nonce or subject")
	}
	var rawClaims map[string]json.RawMessage
	if err := token.Claims(&rawClaims); err != nil {
		return nil, err
	}
	var azp string
	if value, exists := rawClaims["azp"]; exists {
		if json.Unmarshal(value, &azp) != nil || azp != cfg.ClientID {
			return nil, fmt.Errorf("invalid authorized party")
		}
	} else if len(token.Audience) > 1 {
		return nil, fmt.Errorf("missing authorized party")
	}
	var claims IDTokenClaims
	if err := token.Claims(&claims); err != nil {
		return nil, err
	}
	claims.Sub = token.Subject
	if cfg.UsernameClaim != "" && cfg.UsernameClaim != "email" {
		verifiedEmail := claims.Email
		if err := json.Unmarshal(rawClaims[cfg.UsernameClaim], &claims.Email); err != nil {
			return nil, fmt.Errorf("invalid configured username claim")
		}
		// email_verified attests the standard email claim, not arbitrary aliases.
		claims.EmailVerified = claims.EmailVerified && claims.Email == verifiedEmail
	}
	if cfg.GroupsClaim != "" && cfg.GroupsClaim != "groups" {
		if value, exists := rawClaims[cfg.GroupsClaim]; exists {
			if err := json.Unmarshal(value, &claims.Groups); err != nil {
				return nil, fmt.Errorf("invalid configured groups claim")
			}
		} else {
			claims.Groups = nil
		}
	}
	return &claims, nil
}

func discoverOIDC(ctx context.Context, issuerURL string) (*OIDCDiscovery, error) {
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, oidcHTTPClient), issuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	var discovery OIDCDiscovery
	if err := provider.Claims(&discovery); err != nil {
		return nil, fmt.Errorf("failed to decode OIDC discovery: %w", err)
	}
	discovery.provider = provider
	return &discovery, nil
}

func exchangeCode(ctx context.Context, tokenEndpoint, code, clientID, clientSecret, redirectURI, verifier string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
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

	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}
	return &tokenResp, nil
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
