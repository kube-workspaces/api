package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testDeviceConfig() *Config {
	return &Config{
		Enabled:           true,
		SigningKey:        []byte(testSigningKey),
		TokenExpiry:       24 * time.Hour,
		DeviceTokenExpiry: 90 * 24 * time.Hour,
	}
}

func TestDeviceTokenRoundTrip(t *testing.T) {
	dyn := newFakeDynamicClient(t)
	store := NewDeviceStore(dyn)
	ctx := context.Background()

	jti := "abc123def456abc123def456abc12345"
	now := time.Now()
	token, err := CreateDeviceToken("ada@example.com", "Ada", "editor", nil, "laptop", jti, []byte(testSigningKey), 90*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateDeviceToken: %v", err)
	}
	claims, err := ValidateSessionTokenWithKeys(token, [][]byte{[]byte(testSigningKey)})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Type != DeviceTokenType || claims.JTI != jti {
		t.Fatalf("claims = %+v, want type=device jti=%s", claims, jti)
	}
	if err := store.Register(ctx, "ada@example.com", "laptop", jti, now, now.Add(90*24*time.Hour)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if store.Revoked(ctx, jti, "ada@example.com") {
		t.Fatal("Revoked = true before revoke, want false")
	}
	if err := store.Revoke(ctx, jti); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !store.Revoked(ctx, jti, "ada@example.com") {
		t.Fatal("Revoked = false after revoke, want true")
	}
}

func TestDeviceTokenRevocationEnforcedInValidation(t *testing.T) {
	dyn := newFakeDynamicClient(t)
	provider := &ConfigProvider{dynamicClient: dyn, config: testDeviceConfig(), lastFetch: time.Now(), cacheDuration: time.Hour}
	store := NewDeviceStore(dyn)
	ctx := context.Background()

	jti := "deadbeefdeadbeefdeadbeefdeadbeef"
	token, err := CreateDeviceToken("ada@example.com", "", "editor", nil, "d", jti, []byte(testSigningKey), time.Hour)
	if err != nil {
		t.Fatalf("CreateDeviceToken: %v", err)
	}
	claims, err := ValidateSessionTokenWithKeys(token, [][]byte{[]byte(testSigningKey)})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Unregistered device reads as revoked (fail closed).
	if !isDeviceRevoked(ctx, provider, claims) {
		t.Fatal("unregistered device token not treated as revoked")
	}
	if err := store.Register(ctx, "ada@example.com", "d", jti, time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if isDeviceRevoked(ctx, provider, claims) {
		t.Fatal("registered device token treated as revoked")
	}
}

func TestSessionTokenSkipsRevocationCheck(t *testing.T) {
	provider := &ConfigProvider{dynamicClient: newFakeDynamicClient(t)}
	token, err := CreateSessionToken("ada@example.com", "", "editor", nil, []byte(testSigningKey), time.Hour)
	if err != nil {
		t.Fatalf("CreateSessionToken: %v", err)
	}
	claims, err := ValidateSessionTokenWithKeys(token, [][]byte{[]byte(testSigningKey)})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if isDeviceRevoked(context.Background(), provider, claims) {
		t.Fatal("session token hit the device revocation check")
	}
}

func TestDeviceListOwnScopeFiltersAdministratorProfile(t *testing.T) {
	dyn := newFakeDynamicClient(t)
	provider := &ConfigProvider{dynamicClient: dyn, config: testDeviceConfig(), lastFetch: time.Now(), cacheDuration: time.Hour}
	store := NewDeviceStore(dyn)
	ctx := context.Background()
	if _, err := dyn.Resource(userGVR).Create(ctx, executionUserFixture("admin@example.com", "admin"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"admin@example.com", "other@example.com"} {
		if err := store.Register(ctx, email, "laptop", email, time.Now(), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	token, err := CreateSessionToken("admin@example.com", "", "admin", nil, []byte(testSigningKey), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	token = methodBoundTestToken(t, provider, token)
	for _, own := range []bool{false, true} {
		path := "/auth/device/list"
		if own {
			path += "?scope=own"
		}
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		Middleware(provider)(http.HandlerFunc(NewDeviceHandler(provider, store).HandleDeviceList)).ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("list status=%d", rec.Code)
		}
		var out struct {
			Devices []DeviceInfo `json:"devices"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		want := 2
		if own {
			want = 1
		}
		if len(out.Devices) != want {
			t.Fatalf("own=%t got %d devices, want %d", own, len(out.Devices), want)
		}
	}
}

// Auth routes bypass identity middleware, so handlers must use the caller they
// validate themselves. Exercise that wiring without a synthetic user context.
func TestDeviceManagementUsesValidatedCaller(t *testing.T) {
	for _, transport := range []string{"bearer", "cookie"} {
		for _, tt := range []struct {
			name, role, tokenRole string
			adminOverride         bool
			disabled              bool
			unauthenticated       bool
			wantAdmin             bool
		}{
			{name: "viewer", role: "viewer", tokenRole: "viewer"},
			{name: "editor", role: "editor", tokenRole: "editor"},
			{name: "demoted admin", role: "viewer", tokenRole: "admin"},
			{name: "current admin", role: "admin", tokenRole: "viewer", wantAdmin: true},
			{name: "configured admin", role: "viewer", tokenRole: "viewer", adminOverride: true, wantAdmin: true},
			{name: "disabled admin", role: "admin", tokenRole: "admin", disabled: true},
			{name: "anonymous", role: "viewer", tokenRole: "viewer", unauthenticated: true},
		} {
			t.Run(transport+"/"+tt.name, func(t *testing.T) {
				ctx := context.Background()
				dyn := newFakeDynamicClient(t)
				cfg := testDeviceConfig()
				if tt.adminOverride {
					cfg.AdminEmails = []string{"caller@example.com"}
				}
				user := executionUserFixture("caller@example.com", tt.role)
				user.Object["spec"].(map[string]interface{})["disabled"] = tt.disabled
				if _, err := dyn.Resource(userGVR).Create(ctx, user, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
				provider := &ConfigProvider{dynamicClient: dyn, config: cfg, lastFetch: time.Now(), cacheDuration: time.Hour}
				store := NewDeviceStore(dyn)
				for id, email := range map[string]string{"own-device": "caller@example.com", "other-device": "other@example.com"} {
					if err := store.Register(ctx, email, "laptop", id, time.Now(), time.Now().Add(time.Hour)); err != nil {
						t.Fatal(err)
					}
				}
				token, err := CreateSessionToken("caller@example.com", "", tt.tokenRole, nil, cfg.SigningKey, time.Hour, "user-uid")
				if err != nil {
					t.Fatal(err)
				}
				token = methodBoundTestToken(t, provider, token)
				h := NewDeviceHandler(provider, store)
				mux := http.NewServeMux()
				mux.HandleFunc("GET /auth/device/list", h.HandleDeviceList)
				mux.HandleFunc("POST /auth/device/revoke", h.HandleDeviceRevoke)
				router := Middleware(provider)(mux)
				request := func(method, path, body string) *httptest.ResponseRecorder {
					t.Helper()
					req := httptest.NewRequest(method, path, strings.NewReader(body))
					if !tt.unauthenticated {
						if transport == "cookie" {
							req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
						} else {
							req.Header.Set("Authorization", "Bearer "+token)
						}
					}
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					return rec
				}
				for _, scope := range []string{"", "?scope=own"} {
					rec := request("GET", "/auth/device/list"+scope, "")
					if tt.disabled || tt.unauthenticated {
						if rec.Code != http.StatusUnauthorized {
							t.Fatalf("list status=%d, want 401", rec.Code)
						}
						continue
					}
					if rec.Code != http.StatusOK {
						t.Fatalf("list status=%d: %s", rec.Code, rec.Body.String())
					}
					var out struct {
						Devices []DeviceInfo `json:"devices"`
					}
					if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
						t.Fatal(err)
					}
					want := 1
					if tt.wantAdmin && scope == "" {
						want = 2
					}
					if len(out.Devices) != want {
						t.Fatalf("scope=%q got %d devices, want %d", scope, len(out.Devices), want)
					}
					if want == 1 && out.Devices[0].DeviceID != "own-device" {
						t.Fatalf("listed another user's device: %+v", out.Devices)
					}
				}
				for _, id := range []string{"other-device", "own-device"} {
					rec := request("POST", "/auth/device/revoke", `{"device_id":"`+id+`"}`)
					want := http.StatusOK
					if tt.disabled || tt.unauthenticated {
						want = http.StatusUnauthorized
					} else if id == "other-device" && !tt.wantAdmin {
						want = http.StatusNotFound
					}
					if rec.Code != want {
						t.Fatalf("revoke %s status=%d, want %d: %s", id, rec.Code, want, rec.Body.String())
					}
					owner := "caller@example.com"
					if id == "other-device" {
						owner = "other@example.com"
					}
					if revoked := store.Revoked(ctx, id, owner); revoked != (want == http.StatusOK) {
						t.Fatalf("device %s revoked=%t after status %d", id, revoked, rec.Code)
					}
				}
			})
		}
	}
}
