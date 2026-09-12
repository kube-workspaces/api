package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"goa.design/clue/log"
)

// This file implements the RFC 8252 ("OAuth 2.0 for Native Apps") loopback
// redirect flow, so a native desktop client can obtain a kube-workspaces
// session token.
//
// The shape of the flow is the standard AppAuth pattern:
//
//  1. the client starts a loopback HTTP listener on an ephemeral port and opens
//     the SYSTEM BROWSER at /auth/login?native_redirect=...&code_challenge=...
//  2. the API runs its normal OIDC dance with whatever IdP the administrator
//     configured — the client never talks to the IdP, so it works with any
//     provider,
//  3. /auth/callback mints the session token exactly as it does for a browser
//     login but, instead of setting the kw-session cookie, hands back a
//     single-use authorization code on the loopback redirect,
//  4. the client exchanges that code (plus its PKCE verifier) for the token at
//     POST /auth/native/token.
//
// SECURITY, in rough order of importance:
//
//   - validateLoopbackRedirect is the single most important control here.
//     Without it /auth/login would be an open redirect that leaks a valid
//     session token to whatever host an attacker names.
//   - The native parameters travel through the OIDC round trip inside the
//     existing kw-auth-state cookie, as an HMAC-signed blob (see authState).
//     Signing is what stops an attacker forging a cookie that redirects a
//     victim's completed login to a target of their choosing.
//   - Authorization codes are cryptographically random, single-use (deleted
//     under the same lock they are read under), expire after 60s and are bound
//     to the PKCE challenge supplied at /auth/login.
//   - Nothing in this file logs the session token, the authorization code or
//     the PKCE verifier.

const (
	// nativeCodeTTL is how long an issued authorization code remains
	// redeemable. The client is already listening when the redirect arrives,
	// so this only needs to cover the loopback round trip.
	nativeCodeTTL = 60 * time.Second

	// nativeCodeMaxEntries bounds the memory the code store can consume. Each
	// entry is only created by a fully completed OIDC login, so reaching this
	// is implausible in normal operation.
	nativeCodeMaxEntries = 1024

	// nativeCodeBytes is the entropy of an authorization code (RFC 6749 §10.10
	// requires at least 128 bits; we use 256).
	nativeCodeBytes = 32

	// authStateTTL bounds how long a signed kw-auth-state blob is accepted,
	// matching the cookie's own MaxAge. The cookie MaxAge is advisory (it is
	// enforced by the browser); this is the server-side check.
	authStateTTL = 5 * time.Minute

	// nativeVerifierMinLen/nativeVerifierMaxLen are the RFC 7636 §4.1 bounds
	// on a code verifier.
	nativeVerifierMinLen = 43
	nativeVerifierMaxLen = 128

	// nativeStateMaxLen bounds the opaque client state we echo back on the
	// loopback redirect. 256 is far more than the ~43 chars a sane client
	// needs and keeps the signed cookie small.
	nativeStateMaxLen = 256
)

// authState is the payload carried by the kw-auth-state cookie across the OIDC
// round trip. It holds the CSRF state that has always been there, plus the
// native-flow parameters supplied at /auth/login.
//
// We chose the cookie over encoding the parameters into the OIDC `state`
// query parameter because the cookie never leaves the browser/API pair: it is
// not logged by the IdP, not visible in Referer headers, and not subject to
// provider-specific limits on state length. Either carrier would need to be
// signed, since both are ultimately supplied back to us by the client; the
// cookie simply leaks less.
type authState struct {
	State          string `json:"state"`
	NativeRedirect string `json:"nativeRedirect,omitempty"`
	CodeChallenge  string `json:"codeChallenge,omitempty"`
	// NativeState is the client's own opaque state, echoed verbatim on the
	// loopback redirect. It is distinct from State: State is the CSRF nonce we
	// mint for the IdP round trip and the native client has never seen it, so
	// echoing State would give the client nothing it could actually check.
	NativeState string `json:"nativeState,omitempty"`
	ExpiresAt   int64  `json:"exp"`
}

// Native reports whether this login was started by a native client.
func (s *authState) Native() bool {
	return s != nil && s.NativeRedirect != ""
}

// encodeAuthState serialises and signs an authState using the same
// base64url(json) + "." + base64url(HMAC-SHA256) construction as a session
// token (see token.go), so there is one signing idiom in this package.
func encodeAuthState(st *authState, signingKey []byte) (string, error) {
	if len(signingKey) == 0 {
		return "", fmt.Errorf("session signing key is not configured")
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth state: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// decodeAuthState verifies and decodes a signed auth state blob against any of
// the given signing keys (current first, rotation predecessors after).
func decodeAuthState(value string, signingKeys [][]byte) (*authState, error) {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid auth state format")
	}

	valid := false
	for _, key := range signingKeys {
		if len(key) == 0 {
			continue
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(parts[0]))
		expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if hmac.Equal([]byte(parts[1]), []byte(expected)) {
			valid = true
			break
		}
	}
	if !valid {
		return nil, fmt.Errorf("invalid auth state signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid auth state encoding: %w", err)
	}
	var st authState
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, fmt.Errorf("invalid auth state payload: %w", err)
	}
	if st.ExpiresAt == 0 || time.Now().Unix() > st.ExpiresAt {
		return nil, fmt.Errorf("auth state expired")
	}
	return &st, nil
}

// parseAuthStateCookie decodes a kw-auth-state cookie value, tolerating the
// unsigned cookies issued by older builds so logins started immediately before
// a rollout still complete.
//
// SECURITY: the unsigned fallback deliberately yields no native parameters. An
// attacker who can plant a raw cookie value therefore gains exactly the
// pre-existing (browser-only) behaviour and can never steer a completed login
// at a redirect target of their choosing.
func parseAuthStateCookie(value string, signingKeys [][]byte) *authState {
	if st, err := decodeAuthState(value, signingKeys); err == nil {
		return st
	}
	return &authState{State: value}
}

// validateLoopbackRedirect checks a client-supplied native redirect URI against
// RFC 8252 §7.3/§8.3 and returns the parsed URL.
//
// SECURITY: this is the control that keeps /auth/login from becoming an open
// redirect that leaks session tokens. The rules are deliberately narrow:
//
//   - scheme must be exactly http (loopback is exempt from the HTTPS
//     requirement; anything else could point off-box),
//   - the host must be a loopback IP *literal*. "localhost" is rejected per
//     RFC 8252 §8.3 because it resolves through the OS/DNS and can be pointed
//     at another machine,
//   - any port is allowed — the client binds an ephemeral one,
//   - no userinfo, which is the classic parser-confusion vector
//     (http://evil.example.com@127.0.0.1/ reads as 127.0.0.1 to a URL parser
//     but not necessarily to every consumer),
//   - no query and no fragment, so a caller cannot smuggle or truncate the
//     parameters we append.
func validateLoopbackRedirect(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("native_redirect is required")
	}
	// Checked on the raw string rather than the parsed URL so that "?" or "#"
	// anywhere — including forms the parser would normalise away — is refused.
	if strings.ContainsAny(raw, "?#") {
		return nil, fmt.Errorf("native_redirect must not contain a query or fragment")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("native_redirect is not a valid URL")
	}
	if u.Scheme != "http" {
		return nil, fmt.Errorf("native_redirect must use the http scheme")
	}
	if u.Opaque != "" {
		return nil, fmt.Errorf("native_redirect must not be an opaque URL")
	}
	if u.User != nil {
		return nil, fmt.Errorf("native_redirect must not contain userinfo")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("native_redirect must specify a host")
	}
	switch u.Hostname() {
	case "127.0.0.1", "::1":
	default:
		return nil, fmt.Errorf("native_redirect host must be the loopback literal 127.0.0.1 or [::1]")
	}
	return u, nil
}

// nativeRedirectWithParams builds the final loopback redirect. The redirect
// was validated to carry no query of its own, so this cannot clobber or be
// clobbered by caller-supplied parameters.
func nativeRedirectWithParams(u *url.URL, params url.Values) string {
	redirect := *u
	redirect.RawQuery = params.Encode()
	return redirect.String()
}

// validateCodeChallenge enforces PKCE S256 (RFC 7636). The "plain" method is
// rejected outright: it offers no protection if the challenge is observed, and
// RFC 7636 §4.3 makes it the default when the method is omitted, so an absent
// method is an error rather than an implicit S256.
func validateCodeChallenge(challenge, method string) error {
	if method == "" {
		return fmt.Errorf("code_challenge_method is required and must be S256")
	}
	if method != "S256" {
		return fmt.Errorf("unsupported code_challenge_method %q, only S256 is accepted", method)
	}
	if challenge == "" {
		return fmt.Errorf("code_challenge is required")
	}
	// An S256 challenge is always the unpadded base64url of a 32-byte digest;
	// anything else could never match a verifier, so reject it early with a
	// useful message instead of failing opaquely at exchange time.
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("code_challenge must be the unpadded base64url SHA-256 of the code_verifier")
	}
	return nil
}

// validateNativeState checks the client's opaque state parameter.
//
// The state is echoed verbatim into the loopback redirect's query string, so
// it is restricted to the URL-unreserved characters (RFC 3986 §2.3). That is
// narrower than RFC 6749's VSCHAR, but a client generating a random nonce has
// no reason to need anything else, and it means the value can never need
// escaping — which is exactly the kind of asymmetry that turns into a parser
// confusion bug later.
func validateNativeState(state string) error {
	if state == "" {
		return nil // optional; the client simply gets no state echoed back
	}
	if len(state) > nativeStateMaxLen {
		return fmt.Errorf("state must be at most %d characters", nativeStateMaxLen)
	}
	for _, c := range []byte(state) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return fmt.Errorf("state must only contain unreserved characters (A-Z a-z 0-9 - . _ ~)")
		}
	}
	return nil
}

// nativeCallbackParams builds the query echoed to the client's loopback
// listener, including the client's state only when it supplied one. We never
// echo the server-side OIDC state: it is a CSRF nonce paired with a cookie the
// client cannot see, so sending it would leak a secret to no purpose.
func nativeCallbackParams(st *authState, extra url.Values) url.Values {
	params := url.Values{}
	for k, v := range extra {
		params[k] = v
	}
	if st.NativeState != "" {
		params.Set("state", st.NativeState)
	}
	return params
}

// deriveCodeChallengeS256 computes BASE64URL(SHA256(verifier)) per RFC 7636.
func deriveCodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyCodeVerifier checks a PKCE S256 verifier against the stored challenge
// in constant time.
func verifyCodeVerifier(verifier, challenge string) bool {
	if len(verifier) < nativeVerifierMinLen || len(verifier) > nativeVerifierMaxLen {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(deriveCodeChallengeS256(verifier)), []byte(challenge)) == 1
}

// generateNativeCode returns a fresh authorization code.
func generateNativeCode() (string, error) {
	b := make([]byte, nativeCodeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// nativeAuthCode is a minted-but-unredeemed session token, held only long
// enough for the native client to collect it.
type nativeAuthCode struct {
	token          string
	codeChallenge  string
	email          string
	role           string
	tokenExpiresAt int64
	expiresAt      time.Time
}

// nativeCodeStore is an in-memory, single-use, TTL-bounded store of
// authorization codes. It is deliberately not backed by Kubernetes: the
// entries live for at most a minute and writing session tokens to etcd for
// that convenience would be a poor trade. The consequence is that with more
// than one API replica the client must land on the replica that issued its
// code; the loopback exchange happens milliseconds after the redirect over the
// same keep-alive-eligible connection, and a failed exchange just restarts the
// login.
type nativeCodeStore struct {
	mu    sync.Mutex
	codes map[string]nativeAuthCode
	ttl   time.Duration
	max   int

	stop     chan struct{}
	stopOnce sync.Once
}

func newNativeCodeStore(ttl time.Duration, max int) *nativeCodeStore {
	s := &nativeCodeStore{
		codes: make(map[string]nativeAuthCode),
		ttl:   ttl,
		max:   max,
		stop:  make(chan struct{}),
	}
	go s.sweeper()
	return s
}

// sweeper drops expired entries in the background so an abandoned login (the
// user closes the browser tab) does not hold a session token in memory until
// the next successful exchange.
func (s *nativeCodeStore) sweeper() {
	interval := s.ttl
	if interval < time.Second {
		interval = time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			s.purgeLocked(time.Now())
			s.mu.Unlock()
		case <-s.stop:
			return
		}
	}
}

// Close stops the background sweeper.
func (s *nativeCodeStore) Close() {
	s.stopOnce.Do(func() { close(s.stop) })
}

func (s *nativeCodeStore) purgeLocked(now time.Time) {
	for code, entry := range s.codes {
		if now.After(entry.expiresAt) {
			delete(s.codes, code)
		}
	}
}

// Issue stores a freshly minted code.
//
// SECURITY: when the store is at capacity this fails closed rather than
// evicting the oldest entry. Evicting would let anyone who can reach
// /auth/login flush a legitimate user's pending code; refusing only costs the
// (implausible) flooder a retry.
func (s *nativeCodeStore) Issue(code string, entry nativeAuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.purgeLocked(now)
	if len(s.codes) >= s.max {
		return fmt.Errorf("authorization code store is full (%d entries)", s.max)
	}
	entry.expiresAt = now.Add(s.ttl)
	s.codes[code] = entry
	return nil
}

// Redeem looks up a code and returns it exactly once.
//
// SECURITY: the lookup and the delete happen under a single lock acquisition,
// so two concurrent redemptions of the same code can never both succeed.
func (s *nativeCodeStore) Redeem(code string) (nativeAuthCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.codes[code]
	if !ok {
		return nativeAuthCode{}, false
	}
	delete(s.codes, code)
	if time.Now().After(entry.expiresAt) {
		return nativeAuthCode{}, false
	}
	return entry, true
}

func (s *nativeCodeStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.codes)
}

// HandleNativeToken exchanges a single-use authorization code, issued by the
// native branch of /auth/callback, for the session token it stands for.
//
// Unlike every other token delivery path in this service the token is returned
// in the response body: a native app cannot read an HttpOnly cookie, which is
// the whole reason this endpoint exists.
func (h *OIDCHandler) HandleNativeToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Coarse per-IP limit, matching the local-login pattern. PKCE already makes
	// guessing a verifier hopeless, and a wrong guess burns the code outright;
	// this mainly blunts blind code-guessing.
	if !h.nativeLimiter.Allow(clientIPFromRequest(r)) {
		writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "too many token exchange attempts, try again later")
		return
	}

	var body struct {
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "request body must be JSON")
		return
	}
	if body.Code == "" || body.CodeVerifier == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "code and code_verifier are required")
		return
	}

	// Redeeming consumes the code even if the verifier turns out to be wrong.
	// That is intentional: it makes the PKCE check un-retryable.
	entry, ok := h.codes.Redeem(body.Code)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_code", "authorization code is unknown, expired or already used")
		return
	}

	if !verifyCodeVerifier(body.CodeVerifier, entry.codeChallenge) {
		log.Printf(ctx, "auth: native token exchange rejected: PKCE verifier mismatch")
		writeJSONError(w, http.StatusBadRequest, "invalid_verifier", "code_verifier does not match code_challenge")
		return
	}

	log.Printf(ctx, "auth: native token exchange succeeded for %s", entry.email)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      entry.token,
		"expires_at": entry.tokenExpiresAt,
		"email":      entry.email,
		"role":       entry.role,
	})
}

// completeNativeLogin finishes a native login: it parks the already-minted
// session token behind a single-use code and bounces the browser back to the
// client's loopback listener.
//
// The session token is NOT set as a cookie here — it belongs to the native app,
// not to the system browser the user happened to authenticate in.
func (h *OIDCHandler) completeNativeLogin(w http.ResponseWriter, r *http.Request, st *authState, sessionToken string, cfg *Config) {
	ctx := r.Context()

	// Re-validate the redirect immediately before using it. The state blob is
	// signed so this cannot currently fail, but keeping the check adjacent to
	// the redirect means no future change to the carrier can silently turn this
	// into an open redirect.
	redirectURL, err := validateLoopbackRedirect(st.NativeRedirect)
	if err != nil {
		log.Printf(ctx, "auth: native callback rejected: %v", err)
		http.Error(w, "invalid native redirect", http.StatusBadRequest)
		return
	}

	// Read the claims back out of the token we just minted so the values we
	// report at exchange time are exactly the ones in it.
	claims, err := ValidateSessionTokenWithKeys(sessionToken, cfg.SessionSigningKeys())
	if err != nil {
		log.Printf(ctx, "auth: native callback could not read back session token: %v", err)
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	code, err := generateNativeCode()
	if err != nil {
		log.Printf(ctx, "auth: failed to generate native authorization code: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := h.codes.Issue(code, nativeAuthCode{
		token:          sessionToken,
		codeChallenge:  st.CodeChallenge,
		email:          claims.Email,
		role:           claims.Role,
		tokenExpiresAt: claims.ExpiresAt,
	}); err != nil {
		log.Printf(ctx, "auth: native login refused: %v", err)
		http.Error(w, "too many pending native logins, try again shortly", http.StatusServiceUnavailable)
		return
	}

	log.Printf(ctx, "auth: native login completed for %s", claims.Email)

	http.Redirect(w, r, nativeRedirectWithParams(redirectURL, nativeCallbackParams(st, url.Values{
		"code": {code},
	})), http.StatusFound)
}

// redirectNativeError reports an authentication failure to the client's
// loopback listener instead of rendering it in the browser, so a waiting native
// app fails fast rather than hanging until its own timeout. Returns false if
// this is not a native flow (or the stored redirect is no longer valid), in
// which case the caller should fall back to a plain HTTP error.
func redirectNativeError(w http.ResponseWriter, r *http.Request, st *authState, code, description string) bool {
	if !st.Native() {
		return false
	}
	redirectURL, err := validateLoopbackRedirect(st.NativeRedirect)
	if err != nil {
		return false
	}
	http.Redirect(w, r, nativeRedirectWithParams(redirectURL, nativeCallbackParams(st, url.Values{
		"error":             {code},
		"error_description": {description},
	})), http.StatusFound)
	return true
}

// sessionTokenFromRequest extracts a session token from a request, preferring
// the session cookie and falling back to an Authorization: Bearer header.
//
// The /auth/* routes bypass the auth middleware (see middleware.go), so the
// handlers under it that need an identity must do this themselves.
func sessionTokenFromRequest(r *http.Request) string {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	const prefix = "Bearer "
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > len(prefix) && strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return strings.TrimSpace(authHeader[len(prefix):])
	}
	return ""
}
