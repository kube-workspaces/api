package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

const lifecyclePassword = "Initial-password-123!"

type lifecycleFixture struct {
	h                     *OIDCHandler
	local                 *LocalAuthHandler
	router                http.Handler
	user                  *unstructured.Unstructured
	localToken, oidcToken string
}

func newLifecycleFixture(t *testing.T, temporary bool) *lifecycleFixture {
	t.Helper()
	ctx := context.Background()
	idp := newFakeIDP(t, IDTokenClaims{Email: "user@example.com", EmailVerified: true})
	h := newTestHandler(t, testConfig(idp.URL))
	h.provider.config.LocalAuthEnabled = true
	u, err := h.provider.GetUserByEmail(ctx, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedMap(u.Object, map[string]interface{}{"enabled": true, "mustChangePassword": temporary, "passwordSecretRef": map[string]interface{}{"name": "lifecycle-password", "key": "passwordHash"}}, "spec", "localAuth")
	if _, err := h.provider.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(lifecyclePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.provider.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Create(ctx, &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Secret", "metadata": map[string]interface{}{"name": "lifecycle-password", "namespace": LocalAuthSystemNamespace, "resourceVersion": "1"},
		"data": map[string]interface{}{"passwordHash": base64.StdEncoding.EncodeToString(hash)},
	}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	local := NewLocalAuthHandler(h.provider)
	device := NewDeviceHandler(h.provider, NewDeviceStore(h.provider.DynamicClient()))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/me", h.HandleMe)
	mux.HandleFunc("POST /auth/device/create", device.HandleDeviceCreate)
	mux.HandleFunc("POST /auth/browser-session/grant", h.HandleBrowserSessionGrant)
	mux.HandleFunc("GET /auth/browser-session", h.HandleBrowserSessionRedeem)
	mux.HandleFunc("POST /auth/change-password", local.HandleChangePassword)
	mux.HandleFunc("POST /auth/native/token", h.HandleNativeToken)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	f := &lifecycleFixture{h: h, local: local, router: Middleware(h.provider)(mux), user: u}
	f.localToken = f.loginLocal(t, lifecyclePassword)
	_, cookie := login(t, h, "")
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, callbackRequest(t, cookie))
	if sessionCookie(rec) == nil {
		t.Fatalf("OIDC login: %d %s", rec.Code, rec.Body.String())
	}
	f.oidcToken = sessionCookie(rec).Value
	return f
}

func (f *lifecycleFixture) loginLocal(t *testing.T, password string) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"email": "user@example.com", "password": password})
	rec := httptest.NewRecorder()
	f.local.HandleLocalLogin(rec, httptest.NewRequest("POST", "/auth/login/local", strings.NewReader(string(payload))))
	if sessionCookie(rec) == nil {
		t.Fatalf("local login: %d %s", rec.Code, rec.Body.String())
	}
	return sessionCookie(rec).Value
}

func (f *lifecycleFixture) request(method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func (f *lifecycleFixture) deviceToken(t *testing.T, token string) string {
	t.Helper()
	rec := f.request("POST", "/auth/device/create", token, `{"name":"laptop"}`)
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != 200 || body.Token == "" {
		t.Fatalf("device: %d %s", rec.Code, rec.Body.String())
	}
	return body.Token
}

func TestTemporaryPasswordRestrictionIsMethodSpecificAndServerSide(t *testing.T) {
	f := newLifecycleFixture(t, true)
	for _, token := range []string{f.localToken, f.oidcToken} {
		rec := f.request("GET", "/auth/me", token, "")
		var me UserInfo
		if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil || rec.Code != 200 {
			t.Fatalf("me: %d", rec.Code)
		}
		local := token == f.localToken
		if me.MustChangePassword != local || !me.LocalPasswordEnabled || !me.OIDCLinked || !me.CanChangePassword {
			t.Fatalf("incorrect method/capabilities: %+v", me)
		}
		if local && me.AuthMethod != "local" || !local && me.AuthMethod != "oidc" {
			t.Fatalf("wrong method: %+v", me)
		}
		want := 200
		if local {
			want = 403
		}
		for _, path := range []string{"/v1/workspaces", "/admin/users"} {
			for _, cookie := range []bool{false, true} {
				req := httptest.NewRequest("GET", path, nil)
				if cookie {
					req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
				} else {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				rec := httptest.NewRecorder()
				f.router.ServeHTTP(rec, req)
				if rec.Code != want {
					t.Fatalf("method=%s cookie=%t path=%s: %d", me.AuthMethod, cookie, path, rec.Code)
				}
			}
		}
		for _, path := range []string{"/auth/device/create", "/auth/browser-session/grant"} {
			rec := f.request("POST", path, token, `{"redirect":"/proxy/personal/ws/"}`)
			if rec.Code != want {
				t.Fatalf("method=%s path=%s: %d %s", me.AuthMethod, path, rec.Code, rec.Body.String())
			}
		}
	}
}

func TestPasswordResetRevokesOnlyLocalDerivedCredentials(t *testing.T) {
	f := newLifecycleFixture(t, false)
	localDevice := f.deviceToken(t, f.localToken)
	oidcDevice := f.deviceToken(t, f.oidcToken)
	grant := f.request("POST", "/auth/browser-session/grant", localDevice, `{"redirect":"/proxy/personal/ws/"}`)
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(grant.Body.Bytes(), &body); err != nil || body.Code == "" {
		t.Fatal("missing browser grant")
	}
	newPassword, err := ResetLocalUserPassword(context.Background(), f.h.provider, f.user.GetName())
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{f.localToken, localDevice} {
		if rec := f.request("GET", "/auth/me", token, ""); rec.Code != 401 {
			t.Fatalf("local-derived credential survived reset: %d", rec.Code)
		}
	}
	if rec := f.request("GET", "/auth/browser-session?code="+body.Code, "", ""); rec.Code != 401 || sessionCookie(rec) != nil {
		t.Fatalf("stale browser grant redeemed: %d", rec.Code)
	}
	// No discovery/JWKS call is needed for existing OIDC sessions or devices.
	f.h.provider.config.IssuerURL = "http://127.0.0.1:1/unavailable"
	for _, token := range []string{f.oidcToken, oidcDevice} {
		if rec := f.request("GET", "/v1/workspaces", token, ""); rec.Code != 200 {
			t.Fatalf("OIDC credential affected by local reset/IdP outage: %d", rec.Code)
		}
	}
	temporary := f.loginLocal(t, newPassword)
	if rec := f.request("GET", "/v1/workspaces", temporary, ""); rec.Code != 403 {
		t.Fatal("reset password session was unrestricted")
	}
	payload, _ := json.Marshal(map[string]string{"currentPassword": newPassword, "newPassword": "Replacement-password-456!"})
	rec := f.request("POST", "/auth/change-password", temporary, string(payload))
	if rec.Code != 200 || sessionCookie(rec) == nil {
		t.Fatalf("password change: %d %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Token != sessionCookie(rec).Value {
		t.Fatal("replacement Bearer/cookie credential missing")
	}
	if rec := f.request("GET", "/v1/workspaces", response.Token, ""); rec.Code != 200 {
		t.Fatal("replacement session remained restricted")
	}
	if rec := f.request("GET", "/auth/me", temporary, ""); rec.Code != 401 {
		t.Fatal("temporary session survived password change")
	}
	if rec := f.request("GET", "/v1/workspaces", f.oidcToken, ""); rec.Code != 200 {
		t.Fatal("OIDC session revoked by password change")
	}
	newDevice := f.deviceToken(t, response.Token)
	claims, _ := ValidateSessionToken(newDevice, f.h.provider.config.SigningKey)
	parent, _ := ValidateSessionToken(response.Token, f.h.provider.config.SigningKey)
	if claims.SessionProvenance != parent.SessionProvenance || claims.UserUID != parent.UserUID {
		t.Fatal("device credential lost method or revision")
	}
}

func TestBindingRevisionAndRemovalRevokeOIDCOnly(t *testing.T) {
	f := newLifecycleFixture(t, false)
	device := f.deviceToken(t, f.oidcToken)
	claims, _ := ValidateSessionToken(f.oidcToken, f.h.provider.config.SigningKey)
	id := ExternalIdentity{Issuer: claims.Issuer, Subject: claims.Subject}
	claim, err := f.h.provider.GetPasswordSecret(context.Background(), id.claimName())
	if err != nil {
		t.Fatal(err)
	}
	annotations := claim.GetAnnotations()
	annotations[identityVersionAnnotation] = "new-revision"
	claim.SetAnnotations(annotations)
	if _, err := f.h.provider.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Update(context.Background(), claim, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{f.oidcToken, device} {
		if rec := f.request("GET", "/auth/me", token, ""); rec.Code != 401 {
			t.Fatal("OIDC revision change did not revoke credential")
		}
	}
	if rec := f.request("GET", "/v1/workspaces", f.localToken, ""); rec.Code != 200 {
		t.Fatal("OIDC revision affected local method")
	}
	u, _ := f.h.provider.GetUser(context.Background(), f.user.GetName())
	_ = unstructured.SetNestedSlice(u.Object, []interface{}{}, "spec", "externalIdentities")
	if _, err := f.h.provider.UpdateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	claims.CredentialVersion = "new-revision"
	updated, _ := signSessionToken(*claims, f.h.provider.config.SigningKey)
	if rec := f.request("GET", "/auth/me", updated, ""); rec.Code != 401 {
		t.Fatal("removed binding still authorized")
	}
}

func TestLegacyAndMalformedProvenanceRequireReauthentication(t *testing.T) {
	f := newLifecycleFixture(t, false)
	original, _ := ValidateSessionToken(f.localToken, f.h.provider.config.SigningKey)
	for _, mutate := range []func(*SessionToken){
		func(t *SessionToken) { t.SessionProvenance = SessionProvenance{} },
		func(t *SessionToken) { t.UserUID = "" },
		func(t *SessionToken) { t.AuthMethod = "unknown" },
		func(t *SessionToken) { t.CredentialVersion = "" },
		func(t *SessionToken) { t.Issuer = "https://other.example.com" },
		func(t *SessionToken) { t.Type = "unexpected" },
		func(t *SessionToken) { t.Type = "device"; t.JTI = "" },
	} {
		claims := *original
		mutate(&claims)
		token, _ := signSessionToken(claims, f.h.provider.config.SigningKey)
		if rec := f.request("GET", "/auth/me", token, ""); rec.Code != 401 {
			t.Fatal("legacy/malformed credential accepted")
		}
	}
}

func TestPasswordChangeCannotOverwriteConcurrentReset(t *testing.T) {
	f := newLifecycleFixture(t, false)
	client := f.h.provider.dynamicClient.(*dynamicfake.FakeDynamicClient)
	reset := func() {
		current, err := client.Tracker().Get(secretGVR, LocalAuthSystemNamespace, "lifecycle-password")
		if err != nil {
			t.Fatal(err)
		}
		secret := current.(*unstructured.Unstructured).DeepCopy()
		secret.SetResourceVersion("2")
		_ = unstructured.SetNestedField(secret.Object, base64.StdEncoding.EncodeToString([]byte("concurrent-reset-hash")), "data", "passwordHash")
		_ = unstructured.SetNestedField(secret.Object, base64.StdEncoding.EncodeToString([]byte("true")), "data", "mustChangePassword")
		if err := client.Tracker().Update(secretGVR, secret, LocalAuthSystemNamespace); err != nil {
			t.Fatal(err)
		}
	}
	gets := 0
	client.PrependReactor("get", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
		if action.(clienttesting.GetAction).GetName() == "lifecycle-password" {
			gets++
			// Validation and password proof read the original credential. A
			// helper that incorrectly reloads it afterward sees the reset and
			// could then overwrite it using proof of the old password.
			if gets == 3 {
				reset()
			}
		}
		return false, nil, nil
	})
	client.PrependReactor("update", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
		update := action.(clienttesting.UpdateAction).GetObject().(*unstructured.Unstructured)
		if update.GetName() != "lifecycle-password" {
			return false, nil, nil
		}
		reset()
		if update.GetResourceVersion() == "2" {
			return false, nil, nil
		}
		return true, nil, k8serrors.NewConflict(secretGVR.GroupResource(), update.GetName(), nil)
	})
	rec := f.request("POST", "/auth/change-password", f.localToken, `{"currentPassword":"Initial-password-123!","newPassword":"Replacement-password-456!"}`)
	if rec.Code == 200 || sessionCookie(rec) != nil {
		t.Fatal("stale password proof overwrote concurrent reset")
	}
	secret, _ := f.h.provider.GetPasswordSecret(context.Background(), "lifecycle-password")
	hash, _ := GetPasswordHash(secret)
	if hash != "concurrent-reset-hash" {
		t.Fatal("concurrent reset credential was overwritten")
	}
}

func TestNativeGrantRechecksMethodRevision(t *testing.T) {
	f := newLifecycleFixture(t, false)
	verifier := strings.Repeat("v", 43)
	if err := f.h.codes.Issue("pending-native", nativeAuthCode{token: f.localToken, codeChallenge: deriveCodeChallengeS256(verifier), tokenExpiresAt: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	if _, err := ResetLocalUserPassword(context.Background(), f.h.provider, f.user.GetName()); err != nil {
		t.Fatal(err)
	}
	if rec := exchange(t, f.h, "pending-native", verifier); rec.Code != 401 {
		t.Fatal("native grant survived method revocation")
	}
}

func TestBrowserPasswordChangeKeepsReplacementHttpOnly(t *testing.T) {
	f := newLifecycleFixture(t, false)
	req := httptest.NewRequest("POST", "/auth/change-password", strings.NewReader(`{"currentPassword":"Initial-password-123!","newPassword":"Replacement-password-456!"}`))
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: f.localToken})
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	if rec.Code != 200 || sessionCookie(rec) == nil || !sessionCookie(rec).HttpOnly {
		t.Fatalf("browser password change: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"token"`) || strings.Contains(rec.Body.String(), sessionCookie(rec).Value) {
		t.Fatal("HttpOnly replacement exposed to browser JavaScript")
	}
	if check := f.request("GET", "/auth/me", f.localToken, ""); check.Code != 401 {
		t.Fatal("old browser session survived password change")
	}
}

func TestOIDCPasswordManagementPreservesOIDCSession(t *testing.T) {
	f := newLifecycleFixture(t, false)
	rec := f.request("POST", "/auth/change-password", f.oidcToken, `{"currentPassword":"Initial-password-123!","newPassword":"Replacement-password-456!"}`)
	if rec.Code != 200 || sessionCookie(rec) != nil || strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("OIDC session replaced by password management: %d %s", rec.Code, rec.Body.String())
	}
	if check := f.request("GET", "/v1/workspaces", f.oidcToken, ""); check.Code != 200 {
		t.Fatal("OIDC session lost access after changing local password")
	}
	if check := f.request("GET", "/auth/me", f.localToken, ""); check.Code != 401 {
		t.Fatal("old local session survived OIDC-authenticated password change")
	}
}

func TestExistingIdentityReservationUsesUIDRevision(t *testing.T) {
	f := newLifecycleFixture(t, false)
	claims, _ := ValidateSessionToken(f.oidcToken, f.h.provider.config.SigningKey)
	id := ExternalIdentity{Issuer: claims.Issuer, Subject: claims.Subject}
	claim, _ := f.h.provider.GetPasswordSecret(context.Background(), id.claimName())
	a := claim.GetAnnotations()
	delete(a, identityVersionAnnotation)
	claim.SetAnnotations(a)
	claim.SetUID("legacy-reservation-uid")
	if _, err := f.h.provider.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Update(context.Background(), claim, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	provenance, err := f.h.provider.identityProvenance(context.Background(), f.user, id)
	if err != nil || provenance.CredentialVersion != "uid:legacy-reservation-uid" {
		t.Fatal("existing binding requires destructive migration")
	}
	claims.SessionProvenance = provenance
	token, _ := signSessionToken(*claims, f.h.provider.config.SigningKey)
	if rec := f.request("GET", "/auth/me", token, ""); rec.Code != 200 {
		t.Fatal("existing identity reservation cannot issue a new method-bound session")
	}
}

func TestMethodSessionWireVector(t *testing.T) {
	const raw = "eyJ1c2VyX3VpZCI6ImN1cnJlbnQtdWlkIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwicm9sZSI6ImFkbWluIiwiYXV0aF9tZXRob2QiOiJsb2NhbCIsImNyZWRlbnRpYWxfdmVyc2lvbiI6IjhkZmM2ZThhY2I5YjAzY2U5NzE2ODcwNTliYTNhY2NiODUyOTIzOTBiOTg4ODVkNzM2NzJkMjcwYzVmZDllNGYiLCJpYXQiOjEsImV4cCI6NDEwMjQ0NDgwMH0.BeGHg4QRcZdN-x2S9Vh1VxJwZBX8sFBcdMSC1NM81f0"
	token, err := ValidateSessionToken(raw, []byte("wire-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	if token.AuthMethod != "local" || token.CredentialVersion != "8dfc6e8acb9b03ce971687059ba3accb85292390b98885d73672d270c5fd9e4f" || token.CredentialVersion != LocalCredentialVersion("current-uid", "password", "passwordHash", "test-hash") {
		t.Fatal("API/proxy method wire contract changed")
	}
}

func TestDiscoveryAdvertisesConfiguredMethods(t *testing.T) {
	for _, mode := range []string{"local", "oidc", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			cfg := testConfig("")
			cfg.LocalAuthEnabled = mode != "oidc"
			if mode != "local" {
				cfg.IssuerURL = "https://idp.example.com"
			}
			h := newTestHandler(t, cfg)
			rec := httptest.NewRecorder()
			h.HandleAuthConfig(rec, httptest.NewRequest("GET", "/auth/config", nil))
			var body struct {
				Methods []string `json:"methods"`
				Native  struct {
					Enabled bool     `json:"enabled"`
					Methods []string `json:"methods"`
				} `json:"nativeAuth"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Native.Enabled != (mode != "local") {
				t.Fatal("local-only deployment advertised provider login")
			}
			want := 1
			if mode == "mixed" {
				want = 2
			}
			if len(body.Methods) != want || (mode == "local" && len(body.Native.Methods) != 0) {
				t.Fatalf("incorrect discovery: %+v", body)
			}
		})
	}
}
