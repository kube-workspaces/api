package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/retry"
)

// The dynamic fake does not enforce resourceVersion, so this reactor models
// Kubernetes status conflicts, including a concurrent successful login.
func TestLocalLoginRecordsStatusWithResourceVersionConflicts(t *testing.T) {
	for _, mode := range []string{"no conflict", "concurrent login", "persistent conflict"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			user := &unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "User",
				"metadata": map[string]interface{}{"name": "admin-at-local", "uid": "original-user", "resourceVersion": "1"},
				"spec": map[string]interface{}{
					"email": "admin@local", "role": "admin",
					"localAuth": map[string]interface{}{"enabled": true, "passwordSecretRef": map[string]interface{}{"name": "password"}},
				},
				"status": map[string]interface{}{"loginCount": int64(4), "failedLoginAttempts": int64(2), "lockedUntil": time.Now().Add(-time.Hour).Format(time.RFC3339), "ready": true},
			}}
			hash, err := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			secret := &unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "v1", "kind": "Secret",
				"metadata": map[string]interface{}{"name": "password", "namespace": LocalAuthSystemNamespace},
				"data":     map[string]interface{}{"passwordHash": base64.StdEncoding.EncodeToString(hash)},
			}}
			client := fake.NewSimpleDynamicClient(runtime.NewScheme(), user, secret)
			writes, conflicts := 0, 0
			client.PrependReactor("update", "users", func(action ktesting.Action) (bool, runtime.Object, error) {
				if action.GetSubresource() != "status" {
					t.Fatalf("unexpected User update outside status")
				}
				writes++
				obj := action.(ktesting.UpdateAction).GetObject().(*unstructured.Unstructured)
				stored, err := client.Tracker().Get(userGVR, "", user.GetName())
				if err != nil {
					t.Fatal(err)
				}
				current := stored.(*unstructured.Unstructured).DeepCopy()
				if mode == "concurrent login" && writes == 1 {
					current.SetResourceVersion("2")
					unstructured.SetNestedField(current.Object, int64(8), "status", "loginCount")
					unstructured.SetNestedField(current.Object, "updated-by-controller", "status", "message")
					if err := client.Tracker().Update(userGVR, current, ""); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "persistent conflict" || obj.GetResourceVersion() != current.GetResourceVersion() {
					conflicts++
					return true, nil, k8serrors.NewConflict(userGVR.GroupResource(), user.GetName(), errors.New("stale resource version"))
				}
				next := obj.DeepCopy()
				rv, _ := strconv.Atoi(current.GetResourceVersion())
				next.SetResourceVersion(strconv.Itoa(rv + 1))
				return true, next, client.Tracker().Update(userGVR, next, "")
			})
			provider := NewConfigProvider(client)
			provider.config = &Config{Enabled: true, LocalAuthEnabled: true, SigningKey: []byte(strings.Repeat("k", 32)), TokenExpiry: time.Hour}
			provider.lastFetch = time.Now()
			handler := NewLocalAuthHandler(provider)
			rec := httptest.NewRecorder()
			handler.HandleLocalLogin(rec, httptest.NewRequest(http.MethodPost, "/auth/login/local", strings.NewReader(`{"email":"admin@local","password":"test-password"}`)))
			if rec.Code != http.StatusOK || len(rec.Result().Cookies()) != 1 {
				t.Fatalf("login = %d %s; expected session cookie", rec.Code, rec.Body.String())
			}
			current, err := provider.GetUser(ctx, user.GetName())
			if err != nil {
				t.Fatal(err)
			}
			if mode == "persistent conflict" {
				if writes != retry.DefaultRetry.Steps {
					t.Fatalf("writes = %d, want bounded retries %d", writes, retry.DefaultRetry.Steps)
				}
				return
			}
			wantCount, wantWrites := int64(5), 1
			if mode == "concurrent login" {
				wantCount, wantWrites = 9, 2
				message, _, _ := unstructured.NestedString(current.Object, "status", "message")
				if message != "updated-by-controller" || conflicts != 1 {
					t.Fatalf("lost concurrent update or did not retry: message=%q conflicts=%d", message, conflicts)
				}
			}
			count, _, _ := unstructured.NestedInt64(current.Object, "status", "loginCount")
			failed, _, _ := unstructured.NestedInt64(current.Object, "status", "failedLoginAttempts")
			lastLogin, _, _ := unstructured.NestedString(current.Object, "status", "lastLogin")
			_, locked, _ := unstructured.NestedString(current.Object, "status", "lockedUntil")
			ready, _, _ := unstructured.NestedBool(current.Object, "status", "ready")
			if count != wantCount || failed != 0 || locked || !ready || writes != wantWrites {
				t.Fatalf("unexpected login status: %+v (writes=%d, want=%d)", current.Object["status"], writes, wantWrites)
			}
			if _, err := time.Parse(time.RFC3339, lastLogin); err != nil {
				t.Fatalf("invalid lastLogin %q: %v", lastLogin, err)
			}
			if user.GetResourceVersion() != "1" {
				t.Fatal("mutated the authenticated User snapshot")
			}
		})
	}
}

func TestGeneratePassword(t *testing.T) {
	p1, err := GeneratePassword()
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}
	if len(p1) != generatedPasswordLength {
		t.Fatalf("GeneratePassword() length = %d, want %d", len(p1), generatedPasswordLength)
	}

	p2, err := GeneratePassword()
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}
	if p1 == p2 {
		t.Fatalf("GeneratePassword() produced identical passwords across calls")
	}

	for _, c := range p1 {
		found := false
		for _, allowed := range passwordCharset {
			if c == allowed {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("GeneratePassword() produced character %q outside charset", c)
		}
	}
}

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("a-reasonably-long-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("a-reasonably-long-password")); err != nil {
		t.Fatalf("bcrypt.CompareHashAndPassword() error = %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong-password")); err == nil {
		t.Fatalf("expected mismatch error for wrong password, got nil")
	}
}

func TestValidatePasswordComplexity(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"too short", "short1", true},
		{"exactly min length", "123456789012", false},
		{"long enough", "a-very-long-and-secure-password", false},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordComplexity(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePasswordComplexity(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
			}
		})
	}
}

func TestLocalAuthSecretName(t *testing.T) {
	got := localAuthSecretName("admin-at-local")
	want := "kw-user-admin-at-local-local-auth"
	if got != want {
		t.Errorf("localAuthSecretName() = %q, want %q", got, want)
	}
}

func TestLockoutBackoff(t *testing.T) {
	tests := []struct {
		attempts int
		want     time.Duration
	}{
		{5, time.Minute},
		{9, time.Minute},
		{10, 5 * time.Minute},
		{14, 5 * time.Minute},
		{15, 15 * time.Minute},
		{19, 15 * time.Minute},
		{20, 30 * time.Minute},
		{100, 30 * time.Minute},
	}
	for _, tt := range tests {
		if got := lockoutBackoff(tt.attempts); got != tt.want {
			t.Errorf("lockoutBackoff(%d) = %v, want %v", tt.attempts, got, tt.want)
		}
	}
}

func TestIPRateLimiter(t *testing.T) {
	l := newIPRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("expected attempt %d to be allowed", i+1)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatalf("expected 4th attempt to be denied")
	}

	// A different key should not be affected.
	if !l.Allow("5.6.7.8") {
		t.Fatalf("expected different key to be allowed")
	}
}

func TestIPRateLimiterWindowExpiry(t *testing.T) {
	l := newIPRateLimiter(1, 10*time.Millisecond)

	if !l.Allow("1.2.3.4") {
		t.Fatalf("expected first attempt to be allowed")
	}
	if l.Allow("1.2.3.4") {
		t.Fatalf("expected second attempt within window to be denied")
	}

	time.Sleep(20 * time.Millisecond)

	if !l.Allow("1.2.3.4") {
		t.Fatalf("expected attempt after window expiry to be allowed")
	}
}

func TestClientIPFromRequest(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"remote addr only", "10.0.0.1:12345", "", "10.0.0.1"},
		{"xff single", "10.0.0.1:12345", "203.0.113.5", "203.0.113.5"},
		{"xff list uses rightmost", "10.0.0.1:12345", "203.0.113.5, 10.0.0.1", "10.0.0.1"},
		{"spoofed leftmost ignored", "10.0.0.1:12345", "203.0.113.5, 198.51.100.7, 10.0.0.1", "10.0.0.1"},
		{"invalid rightmost falls back to remote addr", "10.0.0.1:12345", "203.0.113.5, bogus", "10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/login/local", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := clientIPFromRequest(req); got != tt.want {
				t.Errorf("clientIPFromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}
