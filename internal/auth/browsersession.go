package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"
	"time"

	"goa.design/clue/log"
)

// This file implements the browser-session grant: the app-to-browser half of
// the native-flow story. A desktop client holds a session token its own
// browser never saw — it arrived over the RFC 8252 loopback flow, from a local
// login, or as a --token. Container workspaces open in that browser, and the
// browser's only credential is the kw-session cookie, so "Open in browser"
// would land on a proxy 401 unless something transfers the session across.
//
// The shape is the mirror image of the RFC 8252 native login (native.go):
// there the browser hands the app a single-use code; here the app hands the
// browser one.
//
//  1. the client POSTs /auth/browser-session/grant, authenticated with the
//     session token it already holds, naming the /proxy/... target it wants
//     the browser to end up on,
//  2. the API parks the client's session token behind a single-use code (the
//     same store native.go uses) and returns the code,
//  3. the client opens its system browser at /auth/browser-session?code=...,
//  4. the API redeems the code once, sets the kw-session cookie exactly as a
//     login would, and redirects the browser to the stored /proxy/ target.
//
// The 24-hour bearer token never appears in a URL, in browser history or in a
// Referer header: the browser only ever sees the single-use code, and the
// token arrives in the Set-Cookie header, the same way a login delivers it.
//
// SECURITY, in rough order of importance:
//
//   - validateBrowserRedirect is what keeps /auth/browser-session from
//     becoming an open-redirect/cookie-minter pair. The destination is
//     validated at grant time and stored server-side against the code, so the
//     redeem endpoint never trusts a client-supplied target at all.
//   - Codes are cryptographically random, single-use (deleted under the same
//     lock they are read under), expire after 60s and are bound to the session
//     that requested them: redeeming a stolen code grants no more than the
//     cookie of the user who asked for it, for the code's own TTL.
//   - The granter must already hold a valid session token. The flow never
//     weakens authentication; it only moves an existing session into a cookie.
//   - Nothing in this file logs the session token or the authorization code.

const (
	// browserProxyPrefix is the only prefix a browser-session grant will
	// redirect to. It matches the frontend's /proxy/* route and the proxy's
	// default path prefix.
	browserProxyPrefix = "/proxy/"
)

// HandleBrowserSessionGrant mints a single-use code that, redeemed in a
// browser, sets a session cookie and redirects to the given /proxy/... target.
//
// The endpoint authenticates with the caller's existing session token (Bearer
// header for the desktop client, cookie for a browser) — it never accepts an
// unauthenticated request, because there is no session to grant then.
func (h *OIDCHandler) HandleBrowserSessionGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cfg, err := h.provider.GetConfig(ctx)
	if err != nil || cfg == nil || !cfg.Enabled {
		writeJSONError(w, http.StatusForbidden, "auth_disabled", "browser sessions require authentication")
		return
	}

	tokenStr := sessionTokenFromRequest(r)
	if tokenStr == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	// validateAndGetUser is the same check /auth/me applies: signature,
	// expiry, and a live User CR that is not disabled.
	if _, err := validateAndGetUser(ctx, tokenStr, cfg, h.provider); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	// Read the claims back out of the token the caller presented so the cookie
	// we eventually set carries exactly that token and its real expiry.
	claims, err := ValidateSessionTokenWithKeys(tokenStr, cfg.SessionSigningKeys())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	var body struct {
		Redirect string `json:"redirect"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "request body must be JSON")
		return
	}
	if err := validateBrowserRedirect(body.Redirect); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_redirect", err.Error())
		return
	}

	code, err := generateNativeCode()
	if err != nil {
		log.Printf(ctx, "auth: failed to generate browser session code: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := h.codes.Issue(code, nativeAuthCode{
		token:          tokenStr,
		email:          claims.Email,
		role:           claims.Role,
		tokenExpiresAt: claims.ExpiresAt,
		redirect:       body.Redirect,
	}); err != nil {
		// Security note: fail closed rather than evicting an older grant, so
		// an attacker who can reach this endpoint cannot flush a legitimate
		// pending grant. Same policy as native.go.
		log.Printf(ctx, "auth: browser session grant refused: %v", err)
		http.Error(w, "too many pending grants, try again shortly", http.StatusServiceUnavailable)
		return
	}

	log.Printf(ctx, "auth: browser session grant issued for %s", claims.Email)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":       code,
		"expires_at": time.Now().Add(nativeCodeTTL).Unix(),
	})
}

// HandleBrowserSessionRedeem sets the session cookie for a code issued by
// [OIDCHandler.HandleBrowserSessionGrant] and redirects to the grant's target.
//
// This is a browser navigation, so failures render a small HTML page rather
// than a JSON error: the person looking at it is the user, not an API client.
func (h *OIDCHandler) HandleBrowserSessionRedeem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Coarse per-IP limit, matching the native token exchange: the code is
	// 256 bits of randomness, so guessing it is hopeless; this mainly blunts
	// a flood of empty lookups.
	if !h.browserSessionLimiter.Allow(clientIPFromRequest(r)) {
		writeBrowserSessionError(w, http.StatusTooManyRequests, "Too many attempts. Close this tab and open the workspace from the desktop app again.")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		writeBrowserSessionError(w, http.StatusBadRequest, "This tab needs a one-time code from the desktop app. Close it and open the workspace from the app again.")
		return
	}

	// Redeeming consumes the code even on failure, so the same code cannot be
	// probed twice. Same policy as native.go.
	entry, ok := h.codes.Redeem(code)
	if !ok {
		writeBrowserSessionError(w, http.StatusBadRequest, "This one-time code is unknown, expired or already used. Open the workspace from the desktop app to get a fresh one.")
		return
	}
	if entry.redirect == "" || !strings.HasPrefix(entry.redirect, browserProxyPrefix) {
		writeBrowserSessionError(w, http.StatusBadRequest, "This grant is not bound to a workspace. Open the workspace from the desktop app again.")
		return
	}

	// Set the session cookie exactly as a login would; the browser now holds
	// the same session the desktop client holds. SameSite/Lax and HttpOnly
	// match the login cookie so the two cannot be told apart.
	secsLeft := time.Until(time.Unix(entry.tokenExpiresAt, 0)).Seconds()
	if secsLeft < 1 {
		secsLeft = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    entry.token,
		Path:     "/",
		MaxAge:   int(secsLeft),
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})

	log.Printf(ctx, "auth: browser session granted for %s", entry.email)

	http.Redirect(w, r, entry.redirect, http.StatusFound)
}

// validateBrowserRedirect checks a client-supplied redirect target at grant
// time. The target is stored against the code, so redemption never sees an
// unvalidated value.
//
// The rules keep the redirect on this origin and inside the workspace proxy:
//
//   - "//" would make a browser treat the value as scheme-relative and leave
//     the origin; a backslash is the classic parser-confusion vector into the
//     same hole,
//   - a scheme, host, userinfo or opaque form would redirect off-box,
//   - after cleaning, the path must still start with /proxy/, so ".."
//     segments cannot smuggle the navigation to an arbitrary same-origin page,
//   - the path must name at least a namespace and a workspace name.
func validateBrowserRedirect(raw string) error {
	if raw == "" {
		return fmt.Errorf("redirect is required")
	}
	if strings.HasPrefix(raw, "//") {
		return fmt.Errorf("redirect must be a same-origin path")
	}
	if strings.Contains(raw, "\\") {
		return fmt.Errorf("redirect must not contain a backslash")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect is not a valid path")
	}
	if u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return fmt.Errorf("redirect must be a same-origin path")
	}
	if strings.Contains(raw, "#") {
		return fmt.Errorf("redirect must not contain a fragment")
	}
	if !strings.HasPrefix(pathpkg.Clean(u.Path), browserProxyPrefix) {
		return fmt.Errorf("redirect must point at a /proxy/... workspace URL")
	}
	if parts := strings.Split(strings.Trim(pathpkg.Clean(u.Path), "/"), "/"); len(parts) < 3 {
		return fmt.Errorf("redirect must name the workspace namespace and name")
	}
	return nil
}

// writeBrowserSessionError renders a self-contained HTML page for the user
// looking at /auth/browser-session after a failed redemption.
//
// Only known, static strings reach the page: the message is one of the
// constants above, so there is no HTML to escape.
func writeBrowserSessionError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Kube Workspaces — sign-in problem</title>
<style>
 html{height:100%%}
 body{margin:0;height:100%%;display:flex;align-items:center;justify-content:center;
      font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Ubuntu,sans-serif;
      color:#111;background:#f6f7f9}
 main{max-width:28rem;padding:2.5rem;text-align:center;background:#fff;
      border-radius:14px;box-shadow:0 1px 3px rgba(0,0,0,.08),0 8px 24px rgba(0,0,0,.06)}
 h1{margin:0 0 .5rem;font-size:1.25rem;font-weight:600}
 p{margin:0;color:#555}
 @media (prefers-color-scheme:dark){
  body{color:#e8e8ea;background:#151517} main{background:#1f1f22;box-shadow:none}
  p{color:#a9a9b2}}
</style></head>
<body><main><h1>This tab could not be signed in</h1><p>%s</p></main></body></html>
`, detail)
}
