package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/util/retry"
)

func (h *OIDCHandler) hasOtherLoginMethod(ctx context.Context, cfg *Config, user *unstructured.Unstructured, removed ExternalIdentity) bool {
	local, _, err := unstructured.NestedBool(user.Object, "spec", "localAuth", "enabled")
	if err == nil && local && cfg.LocalAuthEnabled {
		locked := false
		if value, _, _ := unstructured.NestedString(user.Object, "status", "lockedUntil"); value != "" {
			until, err := time.Parse(time.RFC3339, value)
			locked = err != nil || time.Now().Before(until)
		}
		if name, key, err := passwordReference(user); err == nil && !locked {
			if secret, err := h.provider.GetPasswordSecret(ctx, name); err == nil {
				hash, hashErr := getSecretDataValue(secret, key)
				_, costErr := bcrypt.Cost([]byte(hash))
				if _, _, err := localCredentialState(user, secret); err == nil && hashErr == nil && costErr == nil {
					return true
				}
			}
		}
	}
	bindings, err := identityBindings(user)
	if err != nil {
		return false
	}
	for _, binding := range bindings {
		if binding == removed || binding.Issuer != cfg.IssuerURL || cfg.ClientID == "" {
			continue
		}
		other, err := h.provider.GetUserByIdentity(ctx, binding)
		if err == nil && other.GetUID() == user.GetUID() && other.GetName() == user.GetName() {
			return true
		}
	}
	return false
}

// Unlink keeps the reservation's UID ownership and rotates its credential
// revision BEFORE removing the binding. A retry/relink can never resurrect old
// credentials. Failed persistence may revoke sessions but cannot transfer identity.
func (h *OIDCHandler) unlinkIdentity(ctx context.Context, cfg *Config, name, uid string, id ExternalIdentity) error {
	if err := id.validate(); err != nil {
		return err
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		user, err := h.provider.GetUser(ctx, name)
		if err != nil {
			return err
		}
		if uid == "" || string(user.GetUID()) != uid || !identityAccountValid(user) {
			return ErrIdentityConflict
		}
		bindings, err := identityBindings(user)
		if err != nil {
			return err
		}
		entries := make([]interface{}, 0, len(bindings))
		found := false
		for _, binding := range bindings {
			if binding == id {
				found = true
				continue
			}
			entries = append(entries, map[string]interface{}{"issuer": binding.Issuer, "subject": binding.Subject})
		}
		if !found {
			return ErrIdentityNotBound
		}
		if !h.hasOtherLoginMethod(ctx, cfg, user, id) {
			return fmt.Errorf("cannot remove the last usable login method")
		}
		secrets := h.provider.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace)
		claim, err := secrets.Get(ctx, id.claimName(), metav1.GetOptions{})
		if err != nil {
			return err
		}
		if !claimMatches(claim, id, user) || claim.GetDeletionTimestamp() != nil {
			return ErrIdentityConflict
		}
		version, err := generateNativeCode()
		if err != nil {
			return err
		}
		a := claim.GetAnnotations()
		a[identityVersionAnnotation] = version
		claim.SetAnnotations(a)
		if _, err := secrets.Update(ctx, claim, metav1.UpdateOptions{}); err != nil {
			return err
		}
		if err := unstructured.SetNestedSlice(user.Object, entries, "spec", "externalIdentities"); err != nil {
			return err
		}
		updated, err := h.provider.UpdateUser(ctx, user)
		if err != nil {
			return err
		}
		persisted, err := identityBindings(updated)
		if err != nil {
			return err
		}
		for _, binding := range persisted {
			if binding == id {
				return fmt.Errorf("identity removal was not persisted")
			}
		}
		return nil
	})
}

func (h *OIDCHandler) HandleUnlinkIdentity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.Header.Get("X-KW-Link-Intent") != "unlink-identity" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "explicit identity unlink intent required")
		return
	}
	cfg, err := h.provider.GetConfig(r.Context())
	if err != nil || !cfg.Enabled {
		writeJSONError(w, http.StatusServiceUnavailable, "auth_unavailable", "authentication unavailable")
		return
	}
	if _, err := h.linkCaller(r.Context(), r, cfg); err != nil {
		writeJSONError(w, http.StatusForbidden, "unlink_denied", "a method-bound administrator session without a required password change is required")
		return
	}
	var body struct {
		UserName string `json:"userName"`
		UserUID  string `json:"userUID"`
		Issuer   string `json:"issuer"`
		Subject  string `json:"subject"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&body); err != nil || body.UserName == "" || body.UserUID == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "userName, userUID, issuer and subject are required")
		return
	}
	id := ExternalIdentity{Issuer: body.Issuer, Subject: body.Subject}
	if err := id.validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid external identity")
		return
	}
	if err := h.unlinkIdentity(r.Context(), cfg, body.UserName, body.UserUID, id); err != nil {
		writeJSONError(w, http.StatusConflict, "unlink_denied", "identity could not be removed; preserve another enabled, usable login method and refresh account state before retrying")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "identity unlinked"})
}
