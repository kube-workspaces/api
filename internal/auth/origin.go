package auth

import (
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
)

// BrowserOriginAllowed validates an exact browser origin, independently of CORS.
// Headerless native clients may use bearer authentication, but a headerless
// cookie-authenticated WebSocket/mutation is rejected. Host/forwarded headers
// are not accepted as authority for the trusted browser-origin list.
func BrowserOriginAllowed(r *http.Request, allowed []string) bool {
	origins := r.Header.Values("Origin")
	if len(origins) == 0 {
		cookie, err := r.Cookie(SessionCookieName)
		return err != nil || cookie.Value == ""
	}
	if len(origins) != 1 {
		return false
	}
	origin := origins[0]
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.Opaque != "" {
		return false
	}
	return slices.ContainsFunc(allowed, func(candidate string) bool {
		return strings.TrimSpace(candidate) == origin
	})
}

// WebSocketOriginAllowed is also used at the upgrader boundary, so a bridge
// mounted outside the main HTTP stack cannot accidentally skip origin checks.
func WebSocketOriginAllowed(r *http.Request) bool {
	return BrowserOriginAllowed(r, strings.Split(os.Getenv("ALLOWED_ORIGINS"), ","))
}

// BrowserRequestGuard protects WebSocket handshakes and state-changing requests
// before they reach logging, owner forwarding or authentication handlers. Native
// bearer clients do not need browser CSRF tokens; browser clients must supply an
// exact trusted Origin. Safe HTTP reads keep normal CORS response behavior.
func BrowserRequestGuard(allowed []string) func(http.Handler) http.Handler {
	trusted := slices.Clone(allowed)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mutation := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
			websocket := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
			if (mutation || websocket) && !BrowserOriginAllowed(r, trusted) {
				writeJSONError(w, http.StatusForbidden, "origin_forbidden", "untrusted or missing browser origin")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
