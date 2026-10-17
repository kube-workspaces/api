package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBrowserRequestGuard(t *testing.T) {
	trusted := []string{"https://workspaces.example.com", "http://localhost:3000"}
	for _, tt := range []struct {
		name, method, origin string
		cookie, websocket    bool
		allowed              bool
	}{
		{"trusted mutation", "POST", trusted[0], true, false, true},
		{"trusted socket", "GET", trusted[0], true, true, true},
		{"evil mutation", "POST", "https://evil.example", true, false, false},
		{"evil socket", "GET", "https://evil.example", true, true, false},
		{"same-site untrusted sibling", "GET", "https://guest.example.com", true, true, false},
		{"null origin", "GET", "null", true, true, false},
		{"prefix trick", "GET", trusted[0] + ".evil.example", true, true, false},
		{"path trick", "GET", trusted[0] + "/", true, true, false},
		{"cookie without origin", "POST", "", true, false, false},
		{"cookie socket without origin", "GET", "", true, true, false},
		{"native bearer mutation", "POST", "", false, false, true},
		{"native bearer socket", "GET", "", false, true, true},
		{"safe read", "GET", "", true, false, true},
		{"preflight", "OPTIONS", "https://evil.example", false, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := BrowserRequestGuard(trusted)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequest(tt.method, "/v1/workspaces/vm/exec", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.cookie {
				req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "session"})
			} else {
				req.Header.Set("Authorization", "Bearer native-token")
			}
			if tt.websocket {
				req.Header.Set("Upgrade", "websocket")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if called != tt.allowed || (!tt.allowed && rec.Code != http.StatusForbidden) {
				t.Fatalf("called=%v status=%d, allowed=%v", called, rec.Code, tt.allowed)
			}
		})
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Add("Origin", trusted[0])
	request.Header.Add("Origin", "https://evil.example")
	if BrowserOriginAllowed(request, trusted) {
		t.Fatal("duplicate origins accepted")
	}
	request.Header.Set("Origin", trusted[0])
	t.Setenv("ALLOWED_ORIGINS", "https://workspaces.example.com,http://localhost:3000")
	if !WebSocketOriginAllowed(request) {
		t.Fatal("upgrader rejected configured origin")
	}
	t.Setenv("ALLOWED_ORIGINS", "")
	if WebSocketOriginAllowed(request) {
		t.Fatal("upgrader accepted browser origin without configuration")
	}
}
