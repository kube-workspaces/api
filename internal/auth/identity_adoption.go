package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Adoption is deliberately narrower than general delegated linking: an admin
// approves one existing, unbound OIDC-only UID and its current email. A verified
// provider round trip must prove that exact email before supplying issuer/sub.
// Neither the invitation nor email equality alone is a login credential.
type identityAdoption struct {
	UserName   string `json:"userName"`
	UserUID    string `json:"userUID"`
	Email      string `json:"email"`
	Issuer     string `json:"issuer"`
	ClientID   string `json:"clientID"`
	AdminToken string `json:"adminToken"`
	ExpiresAt  int64  `json:"expiresAt"`
}

func adoptionAccountMatches(a identityAdoption, u *unstructured.Unstructured) error {
	email, _, emailErr := unstructured.NestedString(u.Object, "spec", "email")
	local, _, localErr := unstructured.NestedBool(u.Object, "spec", "localAuth", "enabled")
	bindings, bindingErr := identityBindings(u)
	if !identityAccountValid(u) || string(u.GetUID()) != a.UserUID || emailErr != nil || email == "" || email != a.Email || localErr != nil || local || bindingErr != nil || len(bindings) != 0 {
		return ErrIdentityConflict
	}
	return nil
}

func (h *OIDCHandler) adoptionTarget(ctx context.Context, a identityAdoption) (*unstructured.Unstructured, error) {
	u, err := h.provider.GetUser(ctx, a.UserName)
	if err != nil {
		return nil, err
	}
	if err := adoptionAccountMatches(a, u); err != nil {
		return nil, err
	}
	// Duplicate/case-variant account emails must be resolved by an operator first.
	users, err := h.provider.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	for _, other := range users.Items {
		otherEmail, _, _ := unstructured.NestedString(other.Object, "spec", "email")
		if strings.EqualFold(otherEmail, a.Email) && (other.GetUID() != u.GetUID() || other.GetName() != u.GetName()) {
			return nil, ErrIdentityConflict
		}
	}
	return u, nil
}

func (h *OIDCHandler) validateAdoption(ctx context.Context, cfg *Config, a identityAdoption) error {
	if a.ExpiresAt <= time.Now().Unix() || a.Issuer != cfg.IssuerURL || a.ClientID != cfg.ClientID {
		return ErrIdentityConflict
	}
	r := &http.Request{Header: make(http.Header)}
	r.Header.Set("Authorization", "Bearer "+a.AdminToken)
	if _, err := h.linkCaller(ctx, r, cfg); err != nil {
		return err
	}
	_, err := h.adoptionTarget(ctx, a)
	return err
}

// HandleCreateIdentityAdoption returns a five-minute, single-use invitation.
// Administrator credentials stay in the server-side Secret store, never URLs
// or the recipient's signed (readable) OIDC state cookie.
func (h *OIDCHandler) HandleCreateIdentityAdoption(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.Header.Get("X-KW-Link-Intent") != "adopt-legacy-identity" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "explicit legacy adoption intent required")
		return
	}
	cfg, err := h.provider.GetConfig(r.Context())
	if err != nil || !cfg.Enabled || cfg.IssuerURL == "" || cfg.ClientID == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "oidc_unavailable", "OIDC is not available")
		return
	}
	if _, err := h.linkCaller(r.Context(), r, cfg); err != nil {
		writeJSONError(w, http.StatusForbidden, "adoption_denied", "a UID-bound administrator session without a required password change is required")
		return
	}
	var body struct {
		UserName string `json:"userName"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil || body.UserName == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "userName is required")
		return
	}
	u, err := h.provider.GetUser(r.Context(), body.UserName)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "adoption_denied", "an existing unbound OIDC-only account is required")
		return
	}
	email, _, _ := unstructured.NestedString(u.Object, "spec", "email")
	a := identityAdoption{UserName: u.GetName(), UserUID: string(u.GetUID()), Email: email, Issuer: cfg.IssuerURL, ClientID: cfg.ClientID, AdminToken: sessionTokenFromRequest(r), ExpiresAt: time.Now().Add(authStateTTL).Unix()}
	if _, err := h.adoptionTarget(r.Context(), a); err != nil {
		writeJSONError(w, http.StatusConflict, "adoption_denied", "an enabled, unambiguous, unbound OIDC-only account is required")
		return
	}
	code, err := h.issueAdoption(a, "adoption-invitation")
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "adoption_unavailable", "adoption storage unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"adoptionURL": "/auth/oidc/adopt?code=" + url.QueryEscape(code), "email": a.Email, "expiresAt": a.ExpiresAt})
}

func (h *OIDCHandler) issueAdoption(a identityAdoption, purpose string) (string, error) {
	code, err := generateNativeCode()
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	return code, h.adoptions.Issue(code, nativeAuthCode{token: string(payload), codeChallenge: purpose})
}

func (h *OIDCHandler) redeemAdoption(code, purpose string) (identityAdoption, error) {
	var a identityAdoption
	entry, ok := h.adoptions.Redeem(code)
	if !ok || entry.codeChallenge != purpose {
		return a, ErrIdentityConflict
	}
	if err := json.Unmarshal([]byte(entry.token), &a); err != nil {
		return a, err
	}
	return a, nil
}

// GET does not consume the invitation (mail scanners/prefetch must not do so).
// The recipient explicitly continues using a POST before the OIDC round trip.
func (h *OIDCHandler) HandleIdentityAdoption(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// no-referrer makes Chromium send Origin: null for the confirmation form.
	// strict-origin hides the invitation path/query without suppressing the
	// same-origin POST's Origin header required by BrowserRequestGuard.
	w.Header().Set("Referrer-Policy", "strict-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	if r.Method == http.MethodGet {
		code := r.URL.Query().Get("code")
		if len(code) != 43 {
			http.Error(w, "invalid adoption invitation", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><html><head><title>Link existing account</title></head><body><h1>Link your existing account</h1><p>Continue with the provider account approved by your administrator. This preserves your existing workspaces and access. The invitation expires after five minutes.</p><form method="post" action="/auth/oidc/adopt"><input type="hidden" name="code" value="%s"><button type="submit">Continue to identity provider</button></form></body></html>`, html.EscapeString(code))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid invitation", http.StatusBadRequest)
		return
	}
	a, err := h.redeemAdoption(r.PostForm.Get("code"), "adoption-invitation")
	cfg, cfgErr := h.provider.GetConfig(r.Context())
	if err != nil || cfgErr != nil || !cfg.Enabled || h.validateAdoption(r.Context(), cfg, a) != nil {
		http.Error(w, "adoption invitation expired or no longer authorized", http.StatusForbidden)
		return
	}
	code, err := h.issueAdoption(a, "adoption-callback")
	if err != nil {
		http.Error(w, "adoption storage unavailable", http.StatusServiceUnavailable)
		return
	}
	copy := r.Clone(r.Context())
	u := *r.URL
	u.RawQuery = "" // invitation cannot supply native redirect or other login parameters
	copy.URL = &u
	h.startLoginWithAdoption(w, copy, nil, code)
}

func (h *OIDCHandler) completeIdentityAdoption(ctx context.Context, cfg *Config, code string, id ExternalIdentity, claims *IDTokenClaims) error {
	a, err := h.redeemAdoption(code, "adoption-callback")
	if err != nil {
		return err
	}
	if err := h.validateAdoption(ctx, cfg, a); err != nil {
		return err
	}
	if !claims.EmailVerified || !strings.EqualFold(claims.Email, a.Email) || id.Issuer != a.Issuer {
		return ErrIdentityConflict
	}
	return h.provider.bindIdentity(ctx, a.UserName, a.UserUID, id, func(u *unstructured.Unstructured) error {
		return adoptionAccountMatches(a, u)
	})
}
