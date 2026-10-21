package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func sessionHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// HandleLinkIdentity starts an explicit administrator-authorized link for the
// administrator's own account. The browser must retain that exact session until
// callback. The external identity is learned only from a verified OIDC roundtrip,
// never from an email or caller-supplied subject. General delegated linking and
// unlink/revocation UI are separate lifecycle operations.
func (h *OIDCHandler) HandleLinkIdentity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// A custom header requires a same-origin fetch (or an explicitly authorized
	// CORS preflight); ordinary cross-origin forms cannot initiate account linking.
	if r.Method != http.MethodPost || r.Header.Get("X-KW-Link-Intent") != "link-own-identity" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "explicit identity linking intent required")
		return
	}
	cfg, err := h.provider.GetConfig(r.Context())
	if err != nil || !cfg.Enabled || cfg.IssuerURL == "" || cfg.ClientID == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "oidc_unavailable", "OIDC is not available")
		return
	}
	target, err := h.linkCaller(r.Context(), r, cfg)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "link_denied", "a UID-bound administrator session without a required password change is required")
		return
	}
	// Linking always uses a browser callback, with no caller-selected redirect.
	copy := r.Clone(r.Context())
	url := *r.URL
	url.RawQuery = ""
	copy.URL = &url
	h.startLogin(w, copy, target)
}

func (h *OIDCHandler) linkCaller(ctx context.Context, r *http.Request, cfg *Config) (*unstructured.Unstructured, error) {
	raw := sessionTokenFromRequest(r)
	caller, err := validateAndGetUser(ctx, raw, cfg, h.provider)
	if err != nil {
		return nil, err
	}
	credential, err := ValidateSessionTokenWithKeys(raw, cfg.SessionSigningKeys())
	if err != nil || credential.Type != "" || credential.UserUID == "" || credential.UserUID != caller.UID || caller.Role != "admin" || caller.MustChangePassword {
		return nil, fmt.Errorf("link caller is not an eligible administrator")
	}
	return h.provider.GetUserByEmail(ctx, caller.Email)
}

func (h *OIDCHandler) completeIdentityLink(ctx context.Context, r *http.Request, cfg *Config, state *authState, id ExternalIdentity) error {
	if state.Native() || state.LinkSessionHash != sessionHash(sessionTokenFromRequest(r)) {
		return fmt.Errorf("link session changed")
	}
	user, err := h.linkCaller(ctx, r, cfg)
	if err != nil {
		return err
	}
	if user.GetName() != state.LinkUserName || string(user.GetUID()) != state.LinkUserUID {
		return ErrIdentityConflict
	}
	return h.provider.BindIdentity(ctx, user.GetName(), string(user.GetUID()), id)
}
