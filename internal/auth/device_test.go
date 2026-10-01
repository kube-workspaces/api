package auth

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
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
	for _, email := range []string{"admin@example.com", "other@example.com"} {
		if err := store.Register(ctx, email, "laptop", email, time.Now(), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	token, err := CreateSessionToken("admin@example.com", "", "admin", nil, []byte(testSigningKey), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, own := range []bool{false, true} {
		path := "/auth/device/list"
		if own {
			path += "?scope=own"
		}
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req = req.WithContext(ContextWithUser(req.Context(), &UserInfo{Email: "admin@example.com", Role: "admin"}))
		rec := httptest.NewRecorder()
		NewDeviceHandler(provider, store).HandleDeviceList(rec, req)
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
