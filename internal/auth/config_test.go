package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func authConfigFixture(enabled interface{}) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "AuthConfig",
		"metadata": map[string]interface{}{"name": "default"},
		"spec": map[string]interface{}{
			"enabled": enabled,
			"session": map[string]interface{}{
				"signingKey": map[string]interface{}{"name": "session-key", "key": "key"},
			},
		},
	}}
}

func signingKeyFixture(key string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]interface{}{"name": "session-key", "namespace": LocalAuthSystemNamespace},
		"data":     map[string]interface{}{"key": base64.StdEncoding.EncodeToString([]byte(key))},
	}}
}

func TestAuthSecretsUsePodNamespace(t *testing.T) {
	for _, namespace := range []string{"", "kube-workspaces-system", "custom-install"} {
		t.Run("namespace="+namespace, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", namespace)
			ns := namespace
			if ns == "" {
				ns = LocalAuthSystemNamespace
			}
			config := authConfigFixture(true)
			unstructured.SetNestedMap(config.Object, map[string]interface{}{
				"issuerURL": "https://idp.example.com", "clientID": "client",
				"clientSecret": map[string]interface{}{"name": "oidc", "key": "key"},
			}, "spec", "oidc")
			key := signingKeyFixture("installation-key")
			key.SetNamespace(ns)
			oidc := signingKeyFixture("installation-client-secret")
			oidc.SetName("oidc")
			oidc.SetNamespace(ns)
			client := fake.NewSimpleDynamicClient(runtime.NewScheme(), config, key, oidc)
			provider := NewConfigProvider(client)
			cfg, err := provider.GetConfig(context.Background())
			if err != nil || string(cfg.SigningKey) != "installation-key" || cfg.ClientSecret != "installation-client-secret" {
				t.Fatalf("namespace=%q config=%+v err=%v", namespace, cfg, err)
			}
			for _, action := range client.Actions() {
				if action.GetResource() == secretGVR && action.GetNamespace() != ns {
					t.Fatalf("looked up auth Secret in %q, want %q", action.GetNamespace(), ns)
				}
			}
		})
	}
}

func TestAuthSecretsDoNotFallBackFromExplicitPodNamespace(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "custom-install")
	client := fake.NewSimpleDynamicClient(runtime.NewScheme(), authConfigFixture(true), signingKeyFixture("other-installation-key"))
	provider := NewConfigProvider(client)
	if cfg, err := provider.GetConfig(context.Background()); err == nil || cfg != nil {
		t.Fatalf("used another installation's Secret: cfg=%+v err=%v", cfg, err)
	}
	for _, action := range client.Actions() {
		if action.GetResource() == secretGVR && action.GetNamespace() != "custom-install" {
			t.Fatalf("cross-installation Secret lookup in %q", action.GetNamespace())
		}
	}
}

// Exercise the HTTP boundary rather than just the config parser: a failed read
// must never run the protected handler or advertise anonymous/admin mode.
func TestAuthConfigurationFailureDeniesRequests(t *testing.T) {
	tests := []struct {
		name    string
		objects []runtime.Object
		failure error
	}{
		{name: "missing configuration"},
		{name: "cluster unavailable", failure: errors.New("cluster unavailable")},
		{name: "forbidden", failure: k8serrors.NewForbidden(authConfigGVR.GroupResource(), "default", errors.New("denied"))},
		{name: "malformed enabled", objects: []runtime.Object{authConfigFixture("false")}},
		{name: "missing enabled", objects: []runtime.Object{func() runtime.Object {
			obj := authConfigFixture(false)
			unstructured.RemoveNestedField(obj.Object, "spec", "enabled")
			return obj
		}()}},
		{name: "missing signing secret", objects: []runtime.Object{authConfigFixture(true)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleDynamicClient(runtime.NewScheme(), tt.objects...)
			if tt.failure != nil {
				client.PrependReactor("get", "authconfigs", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, tt.failure
				})
			}
			provider := NewConfigProvider(client)
			called := false
			protected := Middleware(provider)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			me := &OIDCHandler{provider: provider}
			for _, token := range []string{"", "untrusted-token"} {
				for _, path := range []string{"/v1/workspaces", "/auth/me"} {
					req := httptest.NewRequest(http.MethodGet, path, nil)
					if token != "" {
						req.Header.Set("Authorization", "Bearer "+token)
					}
					rec := httptest.NewRecorder()
					if path == "/auth/me" {
						me.HandleMe(rec, req)
					} else {
						protected.ServeHTTP(rec, req)
					}
					if rec.Code != http.StatusServiceUnavailable || called {
						t.Fatalf("%s status=%d handler called=%v", path, rec.Code, called)
					}
					var body map[string]interface{}
					if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
						t.Fatal(err)
					}
					if body["error"] != "auth_unavailable" {
						t.Fatalf("unexpected error response: %v", body)
					}
				}
			}
			// Bound failed refresh load across requests; do not replace failure
			// with a cached Enabled:false on the second request.
			gets := 0
			for _, action := range client.Actions() {
				if action.GetResource() == authConfigGVR {
					gets++
				}
			}
			if gets != 1 {
				t.Fatalf("AuthConfig reads=%d, want one cached failure", gets)
			}
		})
	}
}

func TestAuthConfigurationRecoveryPreservesRotation(t *testing.T) {
	ctx := context.Background()
	for _, initiallyEnabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[initiallyEnabled], func(t *testing.T) {
			client := fake.NewSimpleDynamicClient(runtime.NewScheme(), authConfigFixture(initiallyEnabled), signingKeyFixture("old-key"))
			provider := NewConfigProvider(client)
			if _, err := provider.GetConfig(ctx); err != nil {
				t.Fatal(err)
			}
			outage := true
			client.PrependReactor("get", "authconfigs", func(ktesting.Action) (bool, runtime.Object, error) {
				if outage {
					return true, nil, errors.New("outage")
				}
				return false, nil, nil
			})
			provider.InvalidateCache()
			for range 2 {
				if cfg, err := provider.GetConfig(ctx); err == nil || cfg != nil {
					t.Fatalf("outage returned configuration: %v, %v", cfg, err)
				}
			}
			outage = false
			if _, err := client.Resource(authConfigGVR).Update(ctx, authConfigFixture(true), metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Update(ctx, signingKeyFixture("new-key"), metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			provider.InvalidateCache()
			cfg, err := provider.GetConfig(ctx)
			if err != nil || !cfg.Enabled || string(cfg.SigningKey) != "new-key" {
				t.Fatalf("recovery failed: %v, %v", cfg, err)
			}
			if initiallyEnabled {
				token, err := CreateSessionToken("user@example.com", "User", "editor", nil, []byte("old-key"), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ValidateSessionTokenWithKeys(token, cfg.SessionSigningKeys()); err != nil {
					t.Fatalf("pre-outage session lost after rotation: %v", err)
				}
			}
		})
	}
}

func TestExplicitAuthDisabledAndPublicEndpoints(t *testing.T) {
	client := fake.NewSimpleDynamicClient(runtime.NewScheme(), authConfigFixture(false))
	provider := NewConfigProvider(client)
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler := Middleware(provider)(next)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/workspaces", nil))
	if rec.Code != http.StatusNoContent || !called {
		t.Fatal("explicit disabled configuration did not preserve unauthenticated mode")
	}

	// Liveness/version/schema and login routes remain reachable during an outage.
	client.PrependReactor("get", "authconfigs", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("outage")
	})
	provider.InvalidateCache()
	for _, path := range []string{"/healthz", "/platform/version", "/openapi3.json", "/auth/login"} {
		called = false
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNoContent || !called {
			t.Fatalf("public endpoint %s blocked", path)
		}
	}
}
