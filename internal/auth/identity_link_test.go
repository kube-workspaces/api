package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

func callbackRequest(t *testing.T, cookie *http.Cookie) *http.Request {
	t.Helper()
	st, err := decodeAuthState(cookie.Value, [][]byte{[]byte(testSigningKey)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/auth/callback?code=idp-code&state="+url.QueryEscape(st.State), nil)
	req.Host = "workspaces.example.com"
	req.AddCookie(cookie)
	return req
}

func TestVerifiedOIDCRejectsInvalidClaims(t *testing.T) {
	for name, mutate := range map[string]func(map[string]interface{}){
		"issuer":           func(m map[string]interface{}) { m["iss"] = "https://other.example.com" },
		"audience":         func(m map[string]interface{}) { m["aud"] = "another-client" },
		"expiry":           func(m map[string]interface{}) { m["exp"] = 1 },
		"nonce":            func(m map[string]interface{}) { m["nonce"] = "wrong-nonce" },
		"subject":          func(m map[string]interface{}) { m["sub"] = "" },
		"authorized party": func(m map[string]interface{}) { m["azp"] = "another-client" },
		"multiple audiences without authorized party": func(m map[string]interface{}) { m["aud"] = []string{"kube-workspaces", "another-client"} },
	} {
		t.Run(name, func(t *testing.T) {
			idp := newSignedTestIDP(t, IDTokenClaims{Email: "user@example.com"}, mutate)
			h := newTestHandler(t, testConfig(idp.URL))
			_, cookie := login(t, h, "")
			rec := httptest.NewRecorder()
			h.HandleCallback(rec, callbackRequest(t, cookie))
			if rec.Code != http.StatusUnauthorized || sessionCookie(rec) != nil {
				t.Fatalf("invalid %s accepted: %d %s", name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestVerifiedOIDCRejectsUnsignedToken(t *testing.T) {
	idp := newFakeIDP(t, IDTokenClaims{Email: "user@example.com"})
	cfg := testConfig(idp.URL)
	discovery, err := discoverOIDC(context.Background(), idp.URL)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]interface{}{"iss": idp.URL, "aud": cfg.ClientID, "sub": "test-subject", "exp": 9999999999, "nonce": "nonce"})
	for _, header := range []string{`{"alg":"none"}`, `{"alg":"RS256","kid":"test-key"}`} {
		raw := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".Zm9yZ2Vk"
		if _, err := verifyOIDCIdentity(context.Background(), discovery, cfg, &authState{Nonce: "nonce", UpstreamVerifier: "verifier"}, raw); err == nil {
			t.Fatal("unsigned or forged token accepted")
		}
	}
}

func TestAdministratorLinksOIDCToExistingLocalAccount(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIDP(t, IDTokenClaims{Sub: "external-subject", Email: "different-idp-email@example.net", EmailVerified: true})
	h := newTestHandler(t, testConfig(idp.URL))
	h.provider.config.LocalAuthEnabled = true
	user, err := h.provider.GetUserByEmail(ctx, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedField(user.Object, "admin", "spec", "role")
	_ = unstructured.SetNestedMap(user.Object, map[string]interface{}{"enabled": true, "passwordSecretRef": map[string]interface{}{"name": "existing-password", "key": "passwordHash"}}, "spec", "localAuth")
	if _, err := h.provider.UpdateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	hash, err := HashPassword("Test-local-password-123!")
	if err != nil {
		t.Fatal(err)
	}
	// The dynamic fake does not perform the API server's stringData conversion.
	_, err = h.provider.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Create(ctx, &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]interface{}{"name": "existing-password", "namespace": LocalAuthSystemNamespace},
		"data":     map[string]interface{}{"passwordHash": base64.StdEncoding.EncodeToString([]byte(hash))},
	}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	localHandler := NewLocalAuthHandler(h.provider)
	localLogin := func() string {
		t.Helper()
		response := httptest.NewRecorder()
		localHandler.HandleLocalLogin(response, httptest.NewRequest("POST", "/auth/login/local", strings.NewReader(`{"email":"user@example.com","password":"Test-local-password-123!"}`)))
		if response.Code != 200 || sessionCookie(response) == nil {
			t.Fatalf("local login: %d %s", response.Code, response.Body.String())
		}
		return sessionCookie(response).Value
	}
	session := localLogin()
	start := httptest.NewRequest("POST", "/auth/oidc/link", nil)
	start.Host = "workspaces.example.com"
	start.Header.Set("X-KW-Link-Intent", "link-own-identity")
	start.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
	rec := httptest.NewRecorder()
	h.HandleLinkIdentity(rec, start)
	if rec.Code != 200 {
		t.Fatalf("link start: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		AuthorizationURL string `json:"authorizationURL"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(body.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kw-auth-state" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("missing link state")
	}
	request := callbackRequest(t, cookie)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
	completed := httptest.NewRecorder()
	h.HandleCallback(completed, request)
	if completed.Code != 302 {
		t.Fatalf("link callback: %d %s", completed.Code, completed.Body.String())
	}
	if sessionCookie(completed) != nil {
		t.Fatal("linking replaced the initiating local session")
	}
	// A fresh ordinary OIDC login now reaches the existing LOCAL account even
	// though the IdP email differs. UID, local credentials and workspace NS survive.
	_, loginCookie := login(t, h, "")
	loggedIn := httptest.NewRecorder()
	h.HandleCallback(loggedIn, callbackRequest(t, loginCookie))
	if loggedIn.Code != 302 || sessionCookie(loggedIn) == nil {
		t.Fatalf("OIDC login: %d %s", loggedIn.Code, loggedIn.Body.String())
	}
	claims, err := ValidateSessionToken(sessionCookie(loggedIn).Value, []byte(testSigningKey))
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserUID != string(user.GetUID()) || claims.Email != "user@example.com" || claims.Role != "admin" {
		t.Fatalf("wrong linked account: %+v", claims)
	}
	bound, err := h.provider.GetUserByIdentity(ctx, ExternalIdentity{Issuer: idp.URL, Subject: "external-subject"})
	if err != nil {
		t.Fatal(err)
	}
	local, _, _ := unstructured.NestedBool(bound.Object, "spec", "localAuth", "enabled")
	if !local || bound.GetName() != user.GetName() {
		t.Fatal("local account changed")
	}
	// The IdP being unavailable must not affect local password login.
	h.provider.config.IssuerURL = "http://127.0.0.1:1/unavailable"
	if existing, err := validateAndGetUser(ctx, sessionCookie(loggedIn).Value, h.provider.config, h.provider); err != nil || existing.PersonalNamespace != "personal" {
		t.Fatalf("existing OIDC session depended on provider availability: %v", err)
	}
	localClaims, err := ValidateSessionToken(localLogin(), []byte(testSigningKey))
	if err != nil || localClaims.UserUID != claims.UserUID {
		t.Fatalf("local/OIDC identity differs: %+v %v", localClaims, err)
	}
	h.provider.config.IssuerURL = idp.URL
	// Neither the linking callback nor the ordinary login can be replayed.
	for _, req := range []*http.Request{request, callbackRequest(t, loginCookie)} {
		replay := httptest.NewRecorder()
		h.HandleCallback(replay, req)
		if replay.Code != 400 {
			t.Fatalf("replay accepted: %d", replay.Code)
		}
	}
}

func TestOIDCEmailEqualityDoesNotLinkExistingAccount(t *testing.T) {
	idp := newFakeIDP(t, IDTokenClaims{Sub: "unbound-subject", Email: "user@example.com", EmailVerified: true})
	cfg := testConfig(idp.URL)
	cfg.Registration.AutoProvision = true
	h := newTestHandler(t, cfg)
	_, cookie := login(t, h, "")
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, callbackRequest(t, cookie))
	if rec.Code != http.StatusConflict || sessionCookie(rec) != nil {
		t.Fatalf("email collision adopted: %d %s", rec.Code, rec.Body.String())
	}
}

func TestIdentityLinkRequiresCurrentBoundAdministratorAndIntent(t *testing.T) {
	for _, mode := range []string{"anonymous", "editor", "legacy unbound admin", "temporary password", "missing intent"} {
		t.Run(mode, func(t *testing.T) {
			h := newTestHandler(t, testConfig("https://idp.example.com"))
			u, err := h.provider.GetUserByEmail(context.Background(), "user@example.com")
			if err != nil {
				t.Fatal(err)
			}
			role := "admin"
			if mode == "editor" {
				role = "editor"
			}
			_ = unstructured.SetNestedField(u.Object, role, "spec", "role")
			if mode == "temporary password" {
				_ = unstructured.SetNestedMap(u.Object, map[string]interface{}{"enabled": true, "mustChangePassword": true}, "spec", "localAuth")
			}
			if _, err := h.provider.UpdateUser(context.Background(), u); err != nil {
				t.Fatal(err)
			}
			uid := string(u.GetUID())
			if mode == "legacy unbound admin" {
				uid = ""
			}
			token, _ := CreateSessionToken("user@example.com", "", role, nil, []byte(testSigningKey), h.provider.config.TokenExpiry, uid)
			req := httptest.NewRequest("POST", "/auth/oidc/link", nil)
			if mode != "anonymous" {
				req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
			}
			if mode != "missing intent" {
				req.Header.Set("X-KW-Link-Intent", "link-own-identity")
			}
			rec := httptest.NewRecorder()
			h.HandleLinkIdentity(rec, req)
			if rec.Code != 400 && rec.Code != 403 {
				t.Fatalf("ineligible link started: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestIdentityLinkReauthorizesAtCallback(t *testing.T) {
	for _, mode := range []string{"missing session", "demoted", "disabled", "replacement account"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			idp := newFakeIDP(t, IDTokenClaims{Sub: "new-subject", Email: "provider@example.net", EmailVerified: true})
			h := newTestHandler(t, testConfig(idp.URL))
			u, err := h.provider.GetUserByEmail(ctx, "user@example.com")
			if err != nil {
				t.Fatal(err)
			}
			_ = unstructured.SetNestedField(u.Object, "admin", "spec", "role")
			if _, err := h.provider.UpdateUser(ctx, u); err != nil {
				t.Fatal(err)
			}
			token, _ := CreateSessionToken("user@example.com", "", "admin", nil, []byte(testSigningKey), h.provider.config.TokenExpiry, string(u.GetUID()))
			token = methodBoundTestToken(t, h.provider, token)
			start := httptest.NewRequest("POST", "/auth/oidc/link", nil)
			start.Header.Set("X-KW-Link-Intent", "link-own-identity")
			start.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
			rec := httptest.NewRecorder()
			h.HandleLinkIdentity(rec, start)
			if rec.Code != 200 {
				t.Fatalf("start failed: %d %s", rec.Code, rec.Body.String())
			}
			var response struct {
				AuthorizationURL string `json:"authorizationURL"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			resp, err := http.Get(response.AuthorizationURL)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			var cookie *http.Cookie
			for _, c := range rec.Result().Cookies() {
				if c.Name == "kw-auth-state" {
					cookie = c
				}
			}
			if cookie == nil {
				t.Fatal("missing state")
			}
			switch mode {
			case "demoted":
				_ = unstructured.SetNestedField(u.Object, "editor", "spec", "role")
			case "disabled":
				_ = unstructured.SetNestedField(u.Object, true, "spec", "disabled")
			case "replacement account":
				if err := h.provider.DeleteUser(ctx, u.GetName()); err != nil {
					t.Fatal(err)
				}
				u.SetUID("replacement-uid")
				if _, err := h.provider.CreateUser(ctx, u); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "demoted" || mode == "disabled" {
				if _, err := h.provider.UpdateUser(ctx, u); err != nil {
					t.Fatal(err)
				}
			}
			req := callbackRequest(t, cookie)
			if mode != "missing session" {
				req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
			}
			completed := httptest.NewRecorder()
			h.HandleCallback(completed, req)
			if completed.Code != 403 {
				t.Fatalf("link succeeded after %s: %d %s", mode, completed.Code, completed.Body.String())
			}
			if _, err := h.provider.GetUserByIdentity(ctx, ExternalIdentity{Issuer: idp.URL, Subject: "new-subject"}); err == nil {
				t.Fatal("denied link persisted an identity")
			}
		})
	}
}

func TestOIDCProvisioningRequiresVerifiedEmailAndPersistsIdentity(t *testing.T) {
	for _, verified := range []bool{false, true} {
		t.Run(map[bool]string{false: "unverified denied", true: "verified provisioned"}[verified], func(t *testing.T) {
			idp := newSignedTestIDP(t, IDTokenClaims{Sub: "new-subject", Email: "new@example.net", EmailVerified: verified, Picture: "https://example.net/avatar.png"}, func(m map[string]interface{}) {
				m["mail"], m["teams"] = m["email"], []string{"developers"}
			})
			cfg := testConfig(idp.URL)
			cfg.UsernameClaim, cfg.GroupsClaim = "mail", "teams"
			cfg.Registration.AutoProvision = true
			h := newTestHandler(t, cfg)
			h.provider.dynamicClient.(*dynamicfake.FakeDynamicClient).PrependReactor("create", "users", func(action clienttesting.Action) (bool, runtime.Object, error) {
				action.(clienttesting.CreateAction).GetObject().(*unstructured.Unstructured).SetUID("provisioned-user-uid")
				return false, nil, nil
			})
			_, cookie := login(t, h, "")
			rec := httptest.NewRecorder()
			h.HandleCallback(rec, callbackRequest(t, cookie))
			if !verified {
				if rec.Code != 403 || sessionCookie(rec) != nil {
					t.Fatalf("unverified identity provisioned: %d", rec.Code)
				}
				return
			}
			if rec.Code != 302 || sessionCookie(rec) == nil {
				t.Fatalf("provisioning failed: %d %s", rec.Code, rec.Body.String())
			}
			user, err := h.provider.GetUserByIdentity(context.Background(), ExternalIdentity{Issuer: idp.URL, Subject: "new-subject"})
			if err != nil || user.GetUID() != "provisioned-user-uid" {
				t.Fatalf("binding missing: %v", err)
			}
			groups, _, _ := unstructured.NestedStringSlice(user.Object, "spec", "groups")
			if len(groups) != 1 || groups[0] != "developers" {
				t.Fatalf("configured group claim ignored: %v", groups)
			}
		})
	}
}

func TestConfiguredUsernameCannotBorrowUnrelatedVerifiedEmail(t *testing.T) {
	idp := newSignedTestIDP(t, IDTokenClaims{Sub: "new-subject", Email: "verified@example.net", EmailVerified: true}, func(m map[string]interface{}) { m["alias"] = "another@example.net" })
	cfg := testConfig(idp.URL)
	cfg.UsernameClaim, cfg.Registration.AutoProvision = "alias", true
	h := newTestHandler(t, cfg)
	_, cookie := login(t, h, "")
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, callbackRequest(t, cookie))
	if rec.Code != 403 || sessionCookie(rec) != nil {
		t.Fatalf("email verification transferred to alias: %d", rec.Code)
	}
}
