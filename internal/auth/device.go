package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"

	"goa.design/clue/log"
)

// Device tokens are long-lived, revocable credentials for native clients that
// cannot complete an interactive login every 24h. They reuse the stateless
// session-token construction (base64url(json) + "." + HMAC) with two additions:
// typ=device and a random jti. Revocation is a K8s Secret per device in
// kube-workspaces-system: the token is valid only while its Secret exists and
// is not marked revoked. Session (browser) tokens carry no jti and skip the
// revocation check entirely.

const (
	// DeviceTokenType marks a session token as a revocable device credential.
	DeviceTokenType = "device"
	// defaultDeviceTokenExpiry is used when the AuthConfig does not set
	// spec.session.deviceTokenExpiry. 90 days keeps native clients usable
	// without making a stolen token immortal; revocation covers the rest.
	defaultDeviceTokenExpiry = 90 * 24 * time.Hour
	// deviceIDBytes is the entropy of a device jti (128 bits, hex-encoded).
	deviceIDBytes = 16

	deviceLabelKey   = "kubeworkspaces.io/kind"
	deviceLabelValue = "device-token"
	deviceEmailAnno  = "kubeworkspaces.io/device-email"
	deviceNameAnno   = "kubeworkspaces.io/device-name"
)

// CreateDeviceToken mints a long-lived device token. jti must be fresh random
// hex; name is human metadata (e.g. "ada-laptop") and is not unique.
func CreateDeviceToken(email, displayName, role string, groups []string, deviceName, jti string, signingKey []byte, expiry time.Duration) (string, error) {
	if len(signingKey) == 0 {
		return "", fmt.Errorf("session signing key is not configured")
	}
	if jti == "" {
		return "", fmt.Errorf("device id is required")
	}
	token := SessionToken{
		Email:       email,
		DisplayName: displayName,
		Role:        role,
		Groups:      groups,
		Type:        DeviceTokenType,
		JTI:         jti,
		IssuedAt:    time.Now().Unix(),
		ExpiresAt:   time.Now().Add(expiry).Unix(),
	}
	payload, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token: %w", err)
	}
	encodedPayload, sig, err := signPayload(payload, signingKey)
	if err != nil {
		return "", err
	}
	_ = deviceName
	return encodedPayload + "." + sig, nil
}

func generateDeviceID() (string, error) {
	b := make([]byte, deviceIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func deviceSecretName(jti string) string { return "kw-device-" + jti }

// DeviceInfo is the metadata returned by list/create (never the token itself,
// except on create).
type DeviceInfo struct {
	DeviceID  string `json:"deviceId"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
}

// DeviceStore persists device registrations as Secrets. A nil dynamic client
// (unit tests, local runs) degrades to a closed store: create fails with a
// clear error, revocation checks pass through so session tokens keep working.
type DeviceStore struct{ dyn dynamic.Interface }

// NewDeviceStore creates the store. dyn may be nil.
func NewDeviceStore(dyn dynamic.Interface) *DeviceStore { return &DeviceStore{dyn: dyn} }

func (s *DeviceStore) available() bool { return s != nil && s.dyn != nil }

// Register creates the backing Secret for a freshly minted device token.
func (s *DeviceStore) Register(ctx context.Context, email, name, jti string, createdAt, expiresAt time.Time) error {
	if !s.available() {
		return fmt.Errorf("device tokens require Kubernetes access")
	}
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]interface{}{
				"name":      deviceSecretName(jti),
				"namespace": LocalAuthSystemNamespace,
				"labels": map[string]interface{}{
					deviceLabelKey: deviceLabelValue,
				},
				"annotations": map[string]interface{}{
					deviceEmailAnno: email,
					deviceNameAnno:  name,
				},
			},
			"type": "Opaque",
			"stringData": map[string]interface{}{
				"email":     email,
				"name":      name,
				"createdAt": strconv.FormatInt(createdAt.Unix(), 10),
				"expiresAt": strconv.FormatInt(expiresAt.Unix(), 10),
				"revoked":   "false",
			},
		},
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := s.dyn.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Create(cctx, obj, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to register device: %w", err)
	}
	return nil
}

// Revoked reports whether the device Secret is missing, revoked, expired, or
// bound to a different email. Missing means revoked: deleting the Secret is
// the revoke path.
func (s *DeviceStore) Revoked(ctx context.Context, jti, email string) bool {
	if !s.available() {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	obj, err := s.dyn.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Get(cctx, deviceSecretName(jti), metav1.GetOptions{})
	if err != nil {
		return true
	}
	if anno, _, _ := unstructured.NestedString(obj.Object, "metadata", "annotations", deviceEmailAnno); anno != "" && !strings.EqualFold(anno, email) {
		return true
	}
	data, found, _ := unstructured.NestedMap(obj.Object, "data")
	if !found {
		data, _, _ = unstructured.NestedMap(obj.Object, "stringData")
	}
	get := func(k string) string {
		v, _ := data[k].(string)
		if d, err := decodeSecretValue(v); err == nil {
			return d
		}
		return v
	}
	if get("revoked") == "true" {
		return true
	}
	if get("email") != "" && !strings.EqualFold(get("email"), email) {
		return true
	}
	if exp, err := strconv.ParseInt(get("expiresAt"), 10, 64); err == nil && time.Now().After(time.Unix(exp, 0)) {
		return true
	}
	return false
}

// Revoke marks a device revoked (and deletes the Secret so list stops showing
// it). Callers must already have authorized ownership.
func (s *DeviceStore) Revoke(ctx context.Context, jti string) error {
	if !s.available() {
		return fmt.Errorf("device tokens require Kubernetes access")
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := s.dyn.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Delete(cctx, deviceSecretName(jti), metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		return err
	}
	return nil
}

// List returns the caller's device registrations (metadata only).
func (s *DeviceStore) List(ctx context.Context, email string, isAdmin bool) ([]DeviceInfo, error) {
	if !s.available() {
		return nil, fmt.Errorf("device tokens require Kubernetes access")
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	list, err := s.dyn.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).List(cctx, metav1.ListOptions{
		LabelSelector: deviceLabelKey + "=" + deviceLabelValue,
	})
	if err != nil {
		return nil, err
	}
	var out []DeviceInfo
	for _, item := range list.Items {
		name := item.GetName()
		if !strings.HasPrefix(name, "kw-device-") {
			continue
		}
		jti := strings.TrimPrefix(name, "kw-device-")
		data, found, _ := unstructured.NestedMap(item.Object, "data")
		if !found {
			data, _, _ = unstructured.NestedMap(item.Object, "stringData")
		}
		get := func(k string) string {
			v, _ := data[k].(string)
			if d, err := decodeSecretValue(v); err == nil {
				return d
			}
			return v
		}
		owner := get("email")
		if owner == "" {
			owner, _, _ = unstructured.NestedString(item.Object, "metadata", "annotations", deviceEmailAnno)
		}
		if !isAdmin && !strings.EqualFold(owner, email) {
			continue
		}
		created, _ := strconv.ParseInt(get("createdAt"), 10, 64)
		expires, _ := strconv.ParseInt(get("expiresAt"), 10, 64)
		dname := get("name")
		if dname == "" {
			dname, _, _ = unstructured.NestedString(item.Object, "metadata", "annotations", deviceNameAnno)
		}
		out = append(out, DeviceInfo{DeviceID: jti, Name: dname, CreatedAt: created, ExpiresAt: expires})
	}
	return out, nil
}

// isDeviceRevoked checks a validated token against the store. Session tokens
// (no jti) always pass. It uses the provider's dynamic client directly so the
// middleware signature stays unchanged.
func isDeviceRevoked(ctx context.Context, provider *ConfigProvider, token *SessionToken) bool {
	if token == nil || token.Type != DeviceTokenType || token.JTI == "" {
		return false
	}
	if provider == nil || provider.DynamicClient() == nil {
		return false
	}
	s := NewDeviceStore(provider.DynamicClient())
	return s.Revoked(ctx, token.JTI, token.Email)
}

// DeviceHandler serves the device-token endpoints.
type DeviceHandler struct {
	provider *ConfigProvider
	devices  *DeviceStore
}

// NewDeviceHandler creates the handler. devices may be a nil-client store.
func NewDeviceHandler(provider *ConfigProvider, devices *DeviceStore) *DeviceHandler {
	if devices == nil {
		devices = NewDeviceStore(nil)
	}
	return &DeviceHandler{provider: provider, devices: devices}
}

// HandleDeviceCreate mints a long-lived device token for the caller's own
// session. Body: {"name": "ada-laptop"} (human label, optional).
func (h *DeviceHandler) HandleDeviceCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg, err := h.provider.GetConfig(ctx)
	if err != nil || cfg == nil || !cfg.Enabled {
		writeJSONError(w, http.StatusForbidden, "auth_disabled", "device tokens require authentication")
		return
	}
	tokenStr := sessionTokenFromRequest(r)
	if tokenStr == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	caller, err := validateAndGetUser(ctx, tokenStr, cfg, h.provider)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	claims, err := ValidateSessionTokenWithKeys(tokenStr, cfg.SessionSigningKeys())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body)
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "device"
	}
	if len(name) > 64 {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "device name must be 64 characters or fewer")
		return
	}
	jti, err := generateDeviceID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	expiry := cfg.DeviceTokenExpiry
	if expiry <= 0 {
		expiry = defaultDeviceTokenExpiry
	}
	now := time.Now()
	deviceToken, err := CreateDeviceToken(claims.Email, claims.DisplayName, caller.Role, claims.Groups, name, jti, cfg.SigningKey, expiry)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.devices.Register(ctx, claims.Email, name, jti, now, now.Add(expiry)); err != nil {
		log.Printf(ctx, "auth: device register failed for %s: %v", claims.Email, err)
		http.Error(w, "device tokens are unavailable", http.StatusServiceUnavailable)
		return
	}
	log.Printf(ctx, "auth: device token issued for %s (%s)", claims.Email, name)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      deviceToken,
		"device_id":  jti,
		"name":       name,
		"expires_at": now.Add(expiry).Unix(),
	})
}

// HandleDeviceList returns the caller's device registrations (admins see all).
func (h *DeviceHandler) HandleDeviceList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg, err := h.provider.GetConfig(ctx)
	if err != nil || cfg == nil || !cfg.Enabled {
		writeJSONError(w, http.StatusForbidden, "auth_disabled", "device tokens require authentication")
		return
	}
	tokenStr := sessionTokenFromRequest(r)
	if tokenStr == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	caller, err := validateAndGetUser(ctx, tokenStr, cfg, h.provider)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	devices, err := h.devices.List(ctx, caller.Email, IsAdmin(r.Context()))
	if err != nil {
		http.Error(w, "device tokens are unavailable", http.StatusServiceUnavailable)
		return
	}
	if devices == nil {
		devices = []DeviceInfo{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"devices": devices})
}

// HandleDeviceRevoke deletes a device registration. Body: {"device_id": "..."}.
// Owners revoke their own devices; admins may revoke any.
func (h *DeviceHandler) HandleDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg, err := h.provider.GetConfig(ctx)
	if err != nil || cfg == nil || !cfg.Enabled {
		writeJSONError(w, http.StatusForbidden, "auth_disabled", "device tokens require authentication")
		return
	}
	tokenStr := sessionTokenFromRequest(r)
	if tokenStr == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	caller, err := validateAndGetUser(ctx, tokenStr, cfg, h.provider)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	var body struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil || body.DeviceID == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "device_id is required")
		return
	}
	if !IsAdmin(r.Context()) {
		// Confirm ownership by listing only our own devices.
		own, err := h.devices.List(ctx, caller.Email, false)
		if err != nil {
			http.Error(w, "device tokens are unavailable", http.StatusServiceUnavailable)
			return
		}
		owned := false
		for _, d := range own {
			if d.DeviceID == body.DeviceID {
				owned = true
				break
			}
		}
		if !owned {
			writeJSONError(w, http.StatusNotFound, "not_found", "device not found")
			return
		}
	}
	if err := h.devices.Revoke(ctx, body.DeviceID); err != nil {
		http.Error(w, "failed to revoke device", http.StatusInternalServerError)
		return
	}
	log.Printf(ctx, "auth: device %s revoked by %s", body.DeviceID, caller.Email)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}
