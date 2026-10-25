package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

func adoptionFixture(t *testing.T, cfg *Config) (*OIDCHandler, string, *unstructured.Unstructured) {
	t.Helper()
	h := newTestHandler(t, cfg)
	admin, _ := h.provider.GetUserByEmail(context.Background(), "user@example.com")
	_ = unstructured.SetNestedField(admin.Object, "admin", "spec", "role")
	if _, err := h.provider.UpdateUser(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	target, _ := h.provider.GetUserByEmail(context.Background(), "cookie@example.com")
	target.SetUID(types.UID("legacy-user-uid"))
	if _, err := h.provider.UpdateUser(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	token, err := CreateSessionToken("user@example.com", "", "admin", nil, cfg.SigningKey, time.Hour, string(admin.GetUID()))
	if err != nil {
		t.Fatal(err)
	}
	return h, methodBoundTestToken(t, h.provider, token), target
}

func createAdoption(t *testing.T, h *OIDCHandler, adminToken, name string) string {
	t.Helper()
	request := httptest.NewRequest("POST", "/auth/oidc/adoptions", strings.NewReader(`{"userName":"`+name+`"}`))
	request.Header.Set("X-KW-Link-Intent", "adopt-legacy-identity")
	request.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	h.HandleCreateIdentityAdoption(rec, request)
	if rec.Code != 200 {
		t.Fatalf("invitation: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), adminToken) {
		t.Fatal("administrator credential exposed")
	}
	var body struct {
		AdoptionURL string `json:"adoptionURL"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(body.AdoptionURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("code")
}

func startAdoption(t *testing.T, h *OIDCHandler, code, adminToken string) *http.Cookie {
	t.Helper()
	for range 2 { // prefetch/GET must not consume or disclose the approval
		rec := httptest.NewRecorder()
		h.HandleIdentityAdoption(rec, httptest.NewRequest("GET", "/auth/oidc/adopt?code="+code, nil))
		if rec.Code != 200 || strings.Contains(rec.Body.String(), adminToken) {
			t.Fatal("unsafe invitation landing page")
		}
		if rec.Header().Get("Referrer-Policy") != "strict-origin" {
			t.Fatal("invitation form must preserve same-origin POST Origin without exposing the code in Referer")
		}
	}
	req := httptest.NewRequest("POST", "/auth/oidc/adopt?native_redirect=http://127.0.0.1:9999", strings.NewReader(url.Values{"code": {code}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "workspaces.example.com"
	rec := httptest.NewRecorder()
	h.HandleIdentityAdoption(rec, req)
	if rec.Code != 302 {
		t.Fatalf("start adoption: %d %s", rec.Code, rec.Body.String())
	}
	authorizationURL, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || authorizationURL.Query().Get("prompt") != "select_account" {
		t.Fatal("adoption did not request provider account selection")
	}
	resp, err := http.Get(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "kw-auth-state" {
			state, err := decodeAuthState(cookie.Value, h.provider.config.SessionSigningKeys())
			if err != nil || state.Native() || state.LinkUserUID != "" || state.AdoptionCode == "" {
				t.Fatal("wrong adoption state")
			}
			raw, _ := json.Marshal(state)
			if strings.Contains(string(raw), adminToken) {
				t.Fatal("admin credential exposed in recipient state")
			}
			return cookie
		}
	}
	t.Fatal("no state cookie")
	return nil
}

// Opt-in real-browser proof for the HTML form and actual origin middleware.
// Point KW_AUTH_BROWSER_MODULE at an installed Playwright index.mjs. Ordinary Go
// tests do not require Node or a browser. No live account/provider is contacted.
func TestIdentityAdoptionBrowserOrigin(t *testing.T) {
	module := os.Getenv("KW_AUTH_BROWSER_MODULE")
	if module == "" {
		t.Skip("set KW_AUTH_BROWSER_MODULE for Chromium adoption-form acceptance")
	}
	h := newTestHandler(t, testConfig("https://idp.example.com"))
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		BrowserRequestGuard([]string{server.URL})(http.HandlerFunc(h.HandleIdentityAdoption)).ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	script := `
const { chromium } = await import(process.argv[1]);
const browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage();
  await page.goto(process.argv[2] + "/auth/oidc/adopt?code=" + "x".repeat(43));
  const [request] = await Promise.all([
    page.waitForRequest(r => r.method() === "POST"),
    page.getByRole("button", {name: "Continue to identity provider"}).click(),
  ]);
  const headers = await request.allHeaders();
  if (headers.origin !== process.argv[2]) throw new Error("form Origin suppressed: " + headers.origin);
  if (headers.referer !== process.argv[2] + "/") throw new Error("invitation path/query leaked in Referer");
  await page.waitForURL(url => !url.search);
  const body = await page.locator("body").innerText();
  if (!body.includes("adoption invitation expired or no longer authorized")) throw new Error("form blocked before adoption handler: " + body);
} finally { await browser.close(); }
`
	if output, err := exec.CommandContext(ctx, "node", "--input-type=module", "-e", script, module, server.URL).CombinedOutput(); err != nil {
		t.Fatalf("Chromium confirmation failed: %v\n%s", err, output)
	}
}

func TestLegacyAdoptionRechecksTargetAfterConcurrentUpdate(t *testing.T) {
	h, token, target := adoptionFixture(t, testConfig("https://idp.example.com"))
	a := identityAdoption{UserName: target.GetName(), UserUID: string(target.GetUID()), Email: "cookie@example.com", Issuer: h.provider.config.IssuerURL, ClientID: h.provider.config.ClientID, AdminToken: token, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	code, err := h.issueAdoption(a, "adoption-callback")
	if err != nil {
		t.Fatal(err)
	}
	client := h.provider.dynamicClient.(*dynamicfake.FakeDynamicClient)
	// Another admin enables a local password between approval validation and
	// persistence. The API server rejects our stale write; retry must recheck
	// the adoption scope, not append a binding to the now-ineligible account.
	client.PrependReactor("update", "users", func(action clienttesting.Action) (bool, runtime.Object, error) {
		update := action.(clienttesting.UpdateAction).GetObject().(*unstructured.Unstructured)
		if update.GetName() != target.GetName() {
			return false, nil, nil
		}
		current := target.DeepCopy()
		_ = unstructured.SetNestedField(current.Object, true, "spec", "localAuth", "enabled")
		if err := client.Tracker().Update(userGVR, current, ""); err != nil {
			t.Fatal(err)
		}
		return true, nil, k8serrors.NewConflict(userGVR.GroupResource(), target.GetName(), ErrIdentityConflict)
	})
	id := ExternalIdentity{Issuer: a.Issuer, Subject: "legacy-subject"}
	if err := h.completeIdentityAdoption(context.Background(), h.provider.config, code, id, &IDTokenClaims{Email: a.Email, EmailVerified: true}); err == nil {
		t.Fatal("concurrent account change escaped approval scope")
	}
	if _, err := h.provider.GetUserByIdentity(context.Background(), id); err == nil {
		t.Fatal("ineligible account bound")
	}
}

func TestLegacyAdoptionRequiresVerifiedIdentityAndPreservesAccount(t *testing.T) {
	idp := newFakeIDP(t, IDTokenClaims{Sub: "legacy-subject", Email: "cookie@example.com", EmailVerified: true})
	h, adminToken, target := adoptionFixture(t, testConfig(idp.URL))
	code := createAdoption(t, h, adminToken, target.GetName())
	cookie := startAdoption(t, h, code, adminToken)
	// A second replica completes the flow using the shared, strict Secret store.
	other := NewOIDCHandler(h.provider)
	t.Cleanup(other.Close)
	rec := httptest.NewRecorder()
	other.HandleCallback(rec, callbackRequest(t, cookie))
	if rec.Code != 302 || rec.Header().Get("Location") != "/login?identityLinked=1" || sessionCookie(rec) != nil {
		t.Fatalf("adoption callback: %d %s", rec.Code, rec.Body.String())
	}
	bound, err := h.provider.GetUserByIdentity(context.Background(), ExternalIdentity{Issuer: idp.URL, Subject: "legacy-subject"})
	if err != nil {
		t.Fatal(err)
	}
	if bound.GetUID() != target.GetUID() || bound.GetName() != target.GetName() || !reflect.DeepEqual(bound.Object["status"], target.Object["status"]) {
		t.Fatal("account ownership changed")
	}
	before, _, _ := unstructured.NestedMap(target.Object, "spec")
	after, _, _ := unstructured.NestedMap(bound.Object, "spec")
	delete(after, "externalIdentities")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("account permissions or credentials changed")
	}
	_, loginCookie := login(t, h, "")
	loggedIn := httptest.NewRecorder()
	h.HandleCallback(loggedIn, callbackRequest(t, loginCookie))
	if sessionCookie(loggedIn) == nil {
		t.Fatalf("adopted login failed: %d", loggedIn.Code)
	}
	claims, err := ValidateSessionToken(sessionCookie(loggedIn).Value, h.provider.config.SigningKey)
	if err != nil || claims.UserUID != string(target.GetUID()) || claims.Email != "cookie@example.com" || claims.Role != "editor" {
		t.Fatal("wrong adopted login identity")
	}
	// Both the invitation and callback are one-use.
	replay := httptest.NewRecorder()
	other.HandleCallback(replay, callbackRequest(t, cookie))
	if replay.Code != 400 {
		t.Fatal("callback replay accepted")
	}
	req := httptest.NewRequest("POST", "/auth/oidc/adopt", strings.NewReader(url.Values{"code": {code}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replay = httptest.NewRecorder()
	h.HandleIdentityAdoption(replay, req)
	if replay.Code != 403 {
		t.Fatal("invitation replay accepted")
	}
}

func TestDelegatedLinkingLocalAndDualAccounts(t *testing.T) {
	for _, mode := range []string{"local", "dual", "wrong-uid", "concurrent-change", "wrong-email"} {
		t.Run(mode, func(t *testing.T) {
			claims := IDTokenClaims{Sub: "delegated-subject", Email: "cookie@example.com", EmailVerified: true}
			if mode == "wrong-email" {
				claims.Email = "different@example.com"
			}
			idp := newFakeIDP(t, claims)
			h, adminToken, target := adoptionFixture(t, testConfig(idp.URL))
			ctx := context.Background()
			_ = unstructured.SetNestedMap(target.Object, map[string]interface{}{"enabled": true, "passwordSecretRef": map[string]interface{}{"name": "retained-password", "key": "passwordHash"}}, "spec", "localAuth")
			if mode == "dual" {
				_ = unstructured.SetNestedSlice(target.Object, []interface{}{map[string]interface{}{"issuer": "https://old.example.com", "subject": "retained-subject"}}, "spec", "externalIdentities")
			}
			var err error
			target, err = h.provider.UpdateUser(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			uid := string(target.GetUID())
			if mode == "wrong-uid" {
				uid = "replacement-uid"
			}
			payload, _ := json.Marshal(map[string]string{"userName": target.GetName(), "userUID": uid})
			req := httptest.NewRequest("POST", "/auth/oidc/adoptions", strings.NewReader(string(payload)))
			req.Header.Set("X-KW-Link-Intent", "link-account-identity")
			req.Header.Set("Authorization", "Bearer "+adminToken)
			rec := httptest.NewRecorder()
			h.HandleCreateIdentityAdoption(rec, req)
			if mode == "wrong-uid" {
				if rec.Code != http.StatusConflict {
					t.Fatal("approval accepted replacement UID")
				}
				return
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("delegated approval: %d %s", rec.Code, rec.Body.String())
			}
			var body struct{ AdoptionURL string }
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(body.AdoptionURL)
			cookie := startAdoption(t, h, u.Query().Get("code"), adminToken)
			if mode == "concurrent-change" {
				changed := target.DeepCopy()
				_ = unstructured.SetNestedField(changed.Object, "viewer", "spec", "role")
				if _, err := h.provider.UpdateUser(ctx, changed); err != nil {
					t.Fatal(err)
				}
			}
			other := NewOIDCHandler(h.provider)
			t.Cleanup(other.Close)
			rec = httptest.NewRecorder()
			other.HandleCallback(rec, callbackRequest(t, cookie))
			bound, err := h.provider.GetUserByIdentity(ctx, ExternalIdentity{Issuer: idp.URL, Subject: "delegated-subject"})
			if mode == "concurrent-change" || mode == "wrong-email" {
				if err == nil {
					t.Fatal("changed approval scope accepted")
				}
				return
			}
			if err != nil || rec.Code != http.StatusFound || sessionCookie(rec) != nil || bound.GetUID() != target.GetUID() {
				t.Fatalf("delegated callback: %d %v", rec.Code, err)
			}
			before, _, _ := unstructured.NestedMap(target.Object, "spec")
			after, _, _ := unstructured.NestedMap(bound.Object, "spec")
			delete(before, "externalIdentities")
			delete(after, "externalIdentities")
			if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(target.Object["status"], bound.Object["status"]) {
				t.Fatal("delegated linking changed credentials, namespace, ownership or grants")
			}
			bindings, _ := identityBindings(bound)
			if (mode == "dual" && len(bindings) != 2) || (mode == "local" && len(bindings) != 1) {
				t.Fatal("delegated linking replaced existing bindings")
			}
		})
	}
}

func TestLegacyAdoptionRevalidatesApprovalAndTarget(t *testing.T) {
	for _, mode := range []string{"wrong email", "unverified email", "admin demoted", "admin disabled", "target disabled", "target replaced", "email changed", "local enabled", "already bound", "expired", "provider changed"} {
		t.Run(mode, func(t *testing.T) {
			claims := IDTokenClaims{Sub: "legacy-subject", Email: "cookie@example.com", EmailVerified: true}
			if mode == "wrong email" {
				claims.Email = "someone@example.com"
			}
			if mode == "unverified email" {
				claims.EmailVerified = false
			}
			idp := newFakeIDP(t, claims)
			h, token, target := adoptionFixture(t, testConfig(idp.URL))
			code := createAdoption(t, h, token, target.GetName())
			cookie := startAdoption(t, h, code, token)
			ctx := context.Background()
			admin, _ := h.provider.GetUserByEmail(ctx, "user@example.com")
			switch mode {
			case "admin demoted":
				_ = unstructured.SetNestedField(admin.Object, "viewer", "spec", "role")
			case "admin disabled":
				_ = unstructured.SetNestedField(admin.Object, true, "spec", "disabled")
			case "target disabled":
				_ = unstructured.SetNestedField(target.Object, true, "spec", "disabled")
			case "target replaced":
				target.SetUID(types.UID("replacement"))
			case "email changed":
				_ = unstructured.SetNestedField(target.Object, "changed@example.com", "spec", "email")
			case "local enabled":
				_ = unstructured.SetNestedField(target.Object, true, "spec", "localAuth", "enabled")
			case "already bound":
				if err := h.provider.BindIdentity(ctx, target.GetName(), string(target.GetUID()), ExternalIdentity{Issuer: idp.URL, Subject: "other-subject"}); err != nil {
					t.Fatal(err)
				}
				target, _ = h.provider.GetUser(ctx, target.GetName())
			case "expired":
				st, _ := decodeAuthState(cookie.Value, h.provider.config.SessionSigningKeys())
				a, err := h.redeemAdoption(st.AdoptionCode, "adoption-callback")
				if err != nil {
					t.Fatal(err)
				}
				a.ExpiresAt = time.Now().Add(-time.Minute).Unix()
				payload, _ := json.Marshal(a)
				if err := h.adoptions.Issue(st.AdoptionCode, nativeAuthCode{token: string(payload), codeChallenge: "adoption-callback"}); err != nil {
					t.Fatal(err)
				}
			case "provider changed":
				h.provider.config.ClientID = "new-client"
			}
			if _, err := h.provider.UpdateUser(ctx, admin); err != nil {
				t.Fatal(err)
			}
			if _, err := h.provider.UpdateUser(ctx, target); err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			h.HandleCallback(rec, callbackRequest(t, cookie))
			if rec.Code != 403 && rec.Code != 400 {
				t.Fatalf("invalid adoption accepted: %d %s", rec.Code, rec.Body.String())
			}
			if sessionCookie(rec) != nil {
				t.Fatal("denied adoption minted session")
			}
			if _, err := h.provider.GetUserByIdentity(ctx, ExternalIdentity{Issuer: idp.URL, Subject: "legacy-subject"}); err == nil {
				t.Fatal("denied adoption bound identity")
			}
		})
	}
}

func TestLegacyAdoptionCreationRequiresAdministratorIntent(t *testing.T) {
	for _, mode := range []string{"anonymous", "editor", "missing intent", "local account", "duplicate email"} {
		t.Run(mode, func(t *testing.T) {
			h, token, target := adoptionFixture(t, testConfig("https://idp.example.com"))
			if mode == "anonymous" {
				token = ""
			}
			if mode == "editor" {
				admin, _ := h.provider.GetUserByEmail(context.Background(), "user@example.com")
				_ = unstructured.SetNestedField(admin.Object, "editor", "spec", "role")
				_, _ = h.provider.UpdateUser(context.Background(), admin)
			}
			if mode == "local account" {
				_ = unstructured.SetNestedField(target.Object, true, "spec", "localAuth", "enabled")
				_, _ = h.provider.UpdateUser(context.Background(), target)
			}
			if mode == "duplicate email" {
				duplicate := executionUserFixture("COOKIE@example.com", "editor")
				duplicate.SetName("duplicate")
				duplicate.SetUID("another-uid")
				if _, err := h.provider.dynamicClient.Resource(userGVR).Create(context.Background(), duplicate, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			req := httptest.NewRequest("POST", "/auth/oidc/adoptions", strings.NewReader(`{"userName":"`+target.GetName()+`"}`))
			req.Header.Set("Authorization", "Bearer "+token)
			if mode != "missing intent" {
				req.Header.Set("X-KW-Link-Intent", "adopt-legacy-identity")
			}
			rec := httptest.NewRecorder()
			h.HandleCreateIdentityAdoption(rec, req)
			if rec.Code != 400 && rec.Code != 403 && rec.Code != 409 {
				t.Fatalf("invalid approval accepted: %d", rec.Code)
			}
		})
	}
}
