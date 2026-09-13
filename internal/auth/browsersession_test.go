package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// grantBrowserSession mints a grant code for the given session token and
// redirect target, returning the response and the code (if any).
func grantBrowserSession(t *testing.T, h *OIDCHandler, token, redirect string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"redirect": redirect})
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-session/grant", strings.NewReader(string(body)))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.HandleBrowserSessionGrant(rec, req)
	return rec
}

// grantCode is grantBrowserSession plus extraction of the issued code.
func grantCode(t *testing.T, h *OIDCHandler, token, redirect string) (string, *httptest.ResponseRecorder) {
	t.Helper()
	rec := grantBrowserSession(t, h, token, redirect)
	if rec.Code != http.StatusOK {
		t.Fatalf("grant status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Code      string `json:"code"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("failed to decode grant response: %v", err)
	}
	if out.Code == "" {
		t.Fatal("grant response carried no code")
	}
	if out.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("expires_at = %d, want a future timestamp", out.ExpiresAt)
	}
	return out.Code, rec
}

// redeemBrowserSession drives GET /auth/browser-session for a code.
func redeemBrowserSession(t *testing.T, h *OIDCHandler, code string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/browser-session?code="+url.QueryEscape(code), nil)
	rec := httptest.NewRecorder()
	h.HandleBrowserSessionRedeem(rec, req)
	return rec
}

// --- grant ---------------------------------------------------------------

func TestBrowserSessionGrant(t *testing.T) {
	h := newTestHandler(t, testConfig("http://127.0.0.1:1/unused"))
	token, _ := CreateSessionToken("user@example.com", "User", "editor", nil, []byte(testSigningKey), time.Hour)

	code, rec := grantCode(t, h, token, "/proxy/team/code/?folder=/workspace")
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}

	redeem := redeemBrowserSession(t, h, code)
	if redeem.Code != http.StatusFound {
		t.Fatalf("redeem status = %d, want %d", redeem.Code, http.StatusFound)
	}
	loc := redeem.Header().Get("Location")
	if loc != "/proxy/team/code/?folder=/workspace" {
		t.Fatalf("Location = %q, want the granted redirect", loc)
	}
	cookie := sessionCookie(redeem)
	if cookie == nil {
		t.Fatal("redeem did not set a session cookie")
	}
	if cookie.Value != token {
		t.Fatalf("cookie value != the session token the grant was bound to")
	}
	if !cookie.HttpOnly {
		t.Fatal("session cookie is not HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.MaxAge <= 0 {
		t.Fatalf("MaxAge = %d, want the token's remaining life", cookie.MaxAge)
	}
}

func TestBrowserSessionGrantAuthentication(t *testing.T) {
	h := newTestHandler(t, testConfig("http://127.0.0.1:1/unused"))

	tests := []struct {
		name  string
		token string
	}{
		{"no credentials", ""},
		{"invalid token", "not-a-real-token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := grantBrowserSession(t, h, tt.token, "/proxy/team/code/")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusUnauthorized, rec.Body.String())
			}
		})
	}
}

func TestBrowserSessionGrantAuthDisabled(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1/unused")
	cfg.Enabled = false
	h := newTestHandler(t, cfg)
	token, _ := CreateSessionToken("user@example.com", "User", "editor", nil, []byte(testSigningKey), time.Hour)

	rec := grantBrowserSession(t, h, token, "/proxy/team/code/")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestBrowserSessionGrantRedirectValidation(t *testing.T) {
	h := newTestHandler(t, testConfig("http://127.0.0.1:1/unused"))
	token, _ := CreateSessionToken("user@example.com", "User", "editor", nil, []byte(testSigningKey), time.Hour)

	tests := []struct {
		name     string
		redirect string
		wantCode int
	}{
		{"valid workspace root", "/proxy/team/code/", http.StatusOK},
		{"valid with default path", "/proxy/team/code/?folder=/workspace", http.StatusOK},
		{"empty", "", http.StatusBadRequest},
		{"external url", "https://evil.com/proxy/team/code/", http.StatusBadRequest},
		{"scheme-relative", "//evil.com/proxy/team/code/", http.StatusBadRequest},
		{"host in path", "/proxy/team/code/@evil.com", http.StatusOK},
		{"backslash", `/proxy/team\code\`, http.StatusBadRequest},
		{"not a proxy path", "/admin", http.StatusBadRequest},
		{"proxy with dotdot escape", "/proxy/../admin", http.StatusBadRequest},
		{"proxy prefix only", "/proxy/", http.StatusBadRequest},
		{"no workspace name", "/proxy/team/", http.StatusBadRequest},
		{"fragment", "/proxy/team/code/#frag", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := grantBrowserSession(t, h, token, tt.redirect)
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tt.wantCode, rec.Body.String())
			}
		})
	}
}

func TestBrowserSessionGrantMalformedBody(t *testing.T) {
	h := newTestHandler(t, testConfig("http://127.0.0.1:1/unused"))
	token, _ := CreateSessionToken("user@example.com", "User", "editor", nil, []byte(testSigningKey), time.Hour)

	req := httptest.NewRequest(http.MethodPost, "/auth/browser-session/grant", strings.NewReader("{"))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.HandleBrowserSessionGrant(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// --- redeem --------------------------------------------------------------

func TestBrowserSessionRedeemRejectsUnknownAndReplay(t *testing.T) {
	h := newTestHandler(t, testConfig("http://127.0.0.1:1/unused"))
	token, _ := CreateSessionToken("user@example.com", "User", "editor", nil, []byte(testSigningKey), time.Hour)

	if rec := redeemBrowserSession(t, h, "unknown-code"); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown code status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	code, _ := grantCode(t, h, token, "/proxy/team/code/")
	first := redeemBrowserSession(t, h, code)
	if first.Code != http.StatusFound {
		t.Fatalf("first redeem status = %d, want %d", first.Code, http.StatusFound)
	}
	if second := redeemBrowserSession(t, h, code); second.Code != http.StatusBadRequest {
		t.Fatalf("replayed redeem status = %d, want %d", second.Code, http.StatusBadRequest)
	}
}

func TestBrowserSessionRedeemMissingCode(t *testing.T) {
	h := newTestHandler(t, testConfig("http://127.0.0.1:1/unused"))
	rec := redeemBrowserSession(t, h, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want an HTML page for the user looking at it", ct)
	}
}

func TestBrowserSessionRedeemRateLimited(t *testing.T) {
	h := newTestHandler(t, testConfig("http://127.0.0.1:1/unused"))
	h.browserSessionLimiter = newIPRateLimiter(2, time.Minute)

	for i := 0; i < 2; i++ {
		if rec := redeemBrowserSession(t, h, "nope"); rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d status = %d, want %d", i+1, rec.Code, http.StatusBadRequest)
		}
	}
	if rec := redeemBrowserSession(t, h, "nope"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
}
