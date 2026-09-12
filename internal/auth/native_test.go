package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

const testSigningKey = "test-signing-key-0123456789abcdef"

// --- loopback redirect validation ------------------------------------------

func TestValidateLoopbackRedirect(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"ipv4 loopback with port and path", "http://127.0.0.1:1234/cb", false},
		{"ipv6 loopback with port and path", "http://[::1]:9999/x", false},
		{"ipv4 loopback bare", "http://127.0.0.1:1234", false},
		{"ipv4 loopback no port", "http://127.0.0.1/cb", false},

		{"localhost name is not a loopback literal", "http://localhost:1234/", true},
		{"external https host", "https://evil.com/", true},
		{"fragment", "http://127.0.0.1:1234/#frag", true},
		{"userinfo confusion", "http://example.com@127.0.0.1/", true},
		{"missing scheme", "//127.0.0.1:1234/cb", true},
		{"no scheme at all", "127.0.0.1:1234/cb", true},
		{"query string", "http://127.0.0.1:1234/cb?next=x", true},
		{"empty", "", true},
		{"https loopback", "https://127.0.0.1:1234/cb", true},
		{"non-loopback ipv4", "http://10.0.0.1:1234/cb", true},
		{"other 127/8 address", "http://127.0.0.2:1234/cb", true},
		{"custom scheme", "kw://callback", true},
		{"opaque url", "http:127.0.0.1/cb", true},
		{"header injection attempt", "http://127.0.0.1:1234/cb\r\nX-Evil: 1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateLoopbackRedirect(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateLoopbackRedirect(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
			if err == nil && got == nil {
				t.Fatalf("validateLoopbackRedirect(%q) returned nil URL without error", tt.raw)
			}
		})
	}
}

func TestNativeRedirectWithParams(t *testing.T) {
	u, err := validateLoopbackRedirect("http://127.0.0.1:1234/cb")
	if err != nil {
		t.Fatalf("validateLoopbackRedirect() error = %v", err)
	}
	got := nativeRedirectWithParams(u, url.Values{"code": {"abc"}, "state": {"s t"}})
	want := "http://127.0.0.1:1234/cb?code=abc&state=s+t"
	if got != want {
		t.Fatalf("nativeRedirectWithParams() = %q, want %q", got, want)
	}
}

// --- PKCE -------------------------------------------------------------------

func TestValidateCodeChallenge(t *testing.T) {
	valid := deriveCodeChallengeS256("a-verifier-that-is-at-least-43-characters-long")

	tests := []struct {
		name      string
		challenge string
		method    string
		wantErr   bool
	}{
		{"s256", valid, "S256", false},
		{"plain rejected", valid, "plain", true},
		{"lowercase method rejected", valid, "s256", true},
		{"missing method rejected", valid, "", true},
		{"missing challenge", "", "S256", true},
		{"not base64url", "not valid base64!!", "S256", true},
		{"padded base64", base64.URLEncoding.EncodeToString(make([]byte, 32)), "S256", true},
		{"wrong digest length", base64.RawURLEncoding.EncodeToString(make([]byte, 16)), "S256", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCodeChallenge(tt.challenge, tt.method)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateCodeChallenge(%q, %q) error = %v, wantErr %v", tt.challenge, tt.method, err, tt.wantErr)
			}
		})
	}
}

func TestVerifyCodeVerifier(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-extra"
	challenge := deriveCodeChallengeS256(verifier)

	if !verifyCodeVerifier(verifier, challenge) {
		t.Fatal("verifyCodeVerifier() rejected the correct verifier")
	}
	if verifyCodeVerifier(verifier+"x", challenge) {
		t.Fatal("verifyCodeVerifier() accepted a wrong verifier")
	}
	if verifyCodeVerifier("too-short", challenge) {
		t.Fatal("verifyCodeVerifier() accepted a verifier below the RFC 7636 minimum length")
	}
	if verifyCodeVerifier(strings.Repeat("a", nativeVerifierMaxLen+1), challenge) {
		t.Fatal("verifyCodeVerifier() accepted a verifier above the RFC 7636 maximum length")
	}
	// The "plain" construction must never be accepted by the S256 comparison.
	if verifyCodeVerifier(verifier, verifier) {
		t.Fatal("verifyCodeVerifier() accepted a plain challenge")
	}
}

// --- authorization code store ----------------------------------------------

func newTestCodeStore(t *testing.T, ttl time.Duration, max int) *nativeCodeStore {
	t.Helper()
	s := newNativeCodeStore(ttl, max)
	t.Cleanup(s.Close)
	return s
}

func TestNativeCodeStoreSingleUse(t *testing.T) {
	s := newTestCodeStore(t, time.Minute, 10)

	if err := s.Issue("code-1", nativeAuthCode{token: "tok", email: "a@example.com"}); err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	entry, ok := s.Redeem("code-1")
	if !ok {
		t.Fatal("Redeem() failed on first redemption")
	}
	if entry.token != "tok" {
		t.Fatalf("Redeem() token = %q, want %q", entry.token, "tok")
	}

	if _, ok := s.Redeem("code-1"); ok {
		t.Fatal("Redeem() succeeded on second redemption; codes must be single-use")
	}
	if s.len() != 0 {
		t.Fatalf("store retained %d entries after redemption", s.len())
	}
}

func TestNativeCodeStoreUnknownCode(t *testing.T) {
	s := newTestCodeStore(t, time.Minute, 10)
	if _, ok := s.Redeem("never-issued"); ok {
		t.Fatal("Redeem() accepted an unknown code")
	}
}

func TestNativeCodeStoreTTL(t *testing.T) {
	s := newTestCodeStore(t, 20*time.Millisecond, 10)

	if err := s.Issue("code-1", nativeAuthCode{token: "tok"}); err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	time.Sleep(40 * time.Millisecond)

	if _, ok := s.Redeem("code-1"); ok {
		t.Fatal("Redeem() accepted an expired code")
	}
}

func TestNativeCodeStoreCap(t *testing.T) {
	s := newTestCodeStore(t, time.Minute, 2)

	for i := 0; i < 2; i++ {
		if err := s.Issue(fmt.Sprintf("code-%d", i), nativeAuthCode{token: "tok"}); err != nil {
			t.Fatalf("Issue() %d error = %v", i, err)
		}
	}
	if err := s.Issue("code-overflow", nativeAuthCode{token: "tok"}); err == nil {
		t.Fatal("Issue() accepted an entry beyond the cap")
	}

	// The cap fails closed: existing entries must survive the rejection.
	if _, ok := s.Redeem("code-0"); !ok {
		t.Fatal("Redeem() lost an existing code when the store was full")
	}
	// ...and freeing a slot lets a new code in again.
	if err := s.Issue("code-overflow", nativeAuthCode{token: "tok"}); err != nil {
		t.Fatalf("Issue() after freeing a slot error = %v", err)
	}
}

func TestNativeCodeStoreConcurrentRedeem(t *testing.T) {
	s := newTestCodeStore(t, time.Minute, 10)
	if err := s.Issue("code-1", nativeAuthCode{token: "tok"}); err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	const racers = 64
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
	)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, ok := s.Redeem("code-1"); ok {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if successes != 1 {
		t.Fatalf("concurrent Redeem() yielded %d successes, want exactly 1", successes)
	}
}

// --- signed auth state ------------------------------------------------------

func TestAuthStateRoundTrip(t *testing.T) {
	key := []byte(testSigningKey)
	want := &authState{
		State:          "abc123",
		NativeRedirect: "http://127.0.0.1:1234/cb",
		CodeChallenge:  deriveCodeChallengeS256(strings.Repeat("v", 43)),
		ExpiresAt:      time.Now().Add(authStateTTL).Unix(),
	}

	encoded, err := encodeAuthState(want, key)
	if err != nil {
		t.Fatalf("encodeAuthState() error = %v", err)
	}

	got, err := decodeAuthState(encoded, [][]byte{key})
	if err != nil {
		t.Fatalf("decodeAuthState() error = %v", err)
	}
	if *got != *want {
		t.Fatalf("decodeAuthState() = %+v, want %+v", got, want)
	}
}

func TestAuthStateRejectsTampering(t *testing.T) {
	key := []byte(testSigningKey)
	st := &authState{State: "abc123", NativeRedirect: "http://127.0.0.1:1234/cb", ExpiresAt: time.Now().Add(authStateTTL).Unix()}

	encoded, err := encodeAuthState(st, key)
	if err != nil {
		t.Fatalf("encodeAuthState() error = %v", err)
	}

	// Swap the payload for one pointing at an attacker-controlled host, keeping
	// the original signature. This is the forgery the signature exists to stop.
	forgedPayload, _ := json.Marshal(&authState{State: "abc123", NativeRedirect: "http://evil.example.com/", ExpiresAt: st.ExpiresAt})
	forged := base64.RawURLEncoding.EncodeToString(forgedPayload) + "." + strings.SplitN(encoded, ".", 2)[1]
	if _, err := decodeAuthState(forged, [][]byte{key}); err == nil {
		t.Fatal("decodeAuthState() accepted a forged payload")
	}

	// A different signing key must not validate.
	if _, err := decodeAuthState(encoded, [][]byte{[]byte("some-other-key-aaaaaaaaaaaaaaaaa")}); err == nil {
		t.Fatal("decodeAuthState() accepted a blob signed with a different key")
	}

	// Expired blobs are refused server-side, not just by the cookie MaxAge.
	stale, _ := encodeAuthState(&authState{State: "abc", ExpiresAt: time.Now().Add(-time.Second).Unix()}, key)
	if _, err := decodeAuthState(stale, [][]byte{key}); err == nil {
		t.Fatal("decodeAuthState() accepted an expired blob")
	}
}

func TestParseAuthStateCookieUnsignedFallback(t *testing.T) {
	// A cookie from an older build (or one planted by an attacker) is treated
	// as a bare CSRF state and must never yield native parameters.
	st := parseAuthStateCookie("raw-legacy-state", [][]byte{[]byte(testSigningKey)})
	if st.State != "raw-legacy-state" {
		t.Fatalf("parseAuthStateCookie() state = %q, want %q", st.State, "raw-legacy-state")
	}
	if st.Native() {
		t.Fatal("parseAuthStateCookie() derived native parameters from an unsigned cookie")
	}
}

// --- test scaffolding for the handler tests ---------------------------------

func newFakeDynamicClient(t *testing.T) dynamic.Interface {
	t.Helper()
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			userGVR:       "UserList",
			authConfigGVR: "AuthConfigList",
			secretGVR:     "SecretList",
		})
}

// newTestHandler builds an OIDCHandler over a pre-seeded config cache, so the
// tests never touch a real cluster.
func newTestHandler(t *testing.T, cfg *Config) *OIDCHandler {
	t.Helper()
	provider := &ConfigProvider{
		dynamicClient: newFakeDynamicClient(t),
		config:        cfg,
		lastFetch:     time.Now(),
		cacheDuration: time.Hour,
	}
	h := NewOIDCHandler(provider)
	// Handler tests fire several requests from the same RemoteAddr; the
	// production limit would otherwise trip part-way through.
	h.nativeLimiter = newIPRateLimiter(1000, time.Minute)
	t.Cleanup(h.Close)
	return h
}

// newFakeIDP stands up a minimal OIDC provider: discovery plus a token endpoint
// that returns an unsigned ID token carrying the given claims.
func newFakeIDP(t *testing.T, claims IDTokenClaims) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(OIDCDiscovery{
			AuthorizationEndpoint: srv.URL + "/authorize",
			TokenEndpoint:         srv.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "fake-access-token",
			TokenType:   "Bearer",
			IDToken:     fakeIDToken(t, claims),
		})
	})
	return srv
}

func fakeIDToken(t *testing.T, claims IDTokenClaims) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func testConfig(issuerURL string) *Config {
	return &Config{
		Enabled:     true,
		IssuerURL:   issuerURL,
		ClientID:    "kube-workspaces",
		Scopes:      []string{"openid", "email", "profile"},
		SigningKey:  []byte(testSigningKey),
		TokenExpiry: time.Hour,
		Registration: RegistrationConfig{
			DefaultRole: "editor",
		},
	}
}

// login drives GET /auth/login and returns the kw-auth-state cookie it set.
func login(t *testing.T, h *OIDCHandler, query string) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/login"+query, nil)
	req.Host = "workspaces.example.com"
	rec := httptest.NewRecorder()
	h.HandleLogin(rec, req)

	for _, c := range rec.Result().Cookies() {
		if c.Name == "kw-auth-state" {
			return rec, c
		}
	}
	return rec, nil
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			return c
		}
	}
	return nil
}

// --- /auth/login ------------------------------------------------------------

func TestHandleLoginBrowserFlowUnchanged(t *testing.T) {
	idp := newFakeIDP(t, IDTokenClaims{Email: "user@example.com"})
	h := newTestHandler(t, testConfig(idp.URL))

	rec, stateCookie := login(t, h, "")
	if rec.Code != http.StatusFound {
		t.Fatalf("HandleLogin() status = %d, want %d", rec.Code, http.StatusFound)
	}
	if stateCookie == nil {
		t.Fatal("HandleLogin() did not set the kw-auth-state cookie")
	}

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse Location: %v", err)
	}
	if loc.Path != "/authorize" {
		t.Fatalf("Location path = %q, want /authorize", loc.Path)
	}
	q := loc.Query()
	if q.Get("client_id") != "kube-workspaces" || q.Get("response_type") != "code" {
		t.Fatalf("authorization request lost its existing parameters: %v", q)
	}
	// Still derived from the request host, exactly as before (plain http here
	// because the test request carries no TLS state or X-Forwarded-Proto).
	if want := "http://workspaces.example.com/auth/callback"; q.Get("redirect_uri") != want {
		t.Fatalf("redirect_uri = %q, want %q", q.Get("redirect_uri"), want)
	}

	st, err := decodeAuthState(stateCookie.Value, [][]byte{[]byte(testSigningKey)})
	if err != nil {
		t.Fatalf("decodeAuthState() error = %v", err)
	}
	if st.State != q.Get("state") {
		t.Fatalf("state cookie %q does not match state parameter %q", st.State, q.Get("state"))
	}
	if st.Native() {
		t.Fatal("a plain browser login produced native parameters")
	}
}

func TestHandleLoginNativeParameterValidation(t *testing.T) {
	idp := newFakeIDP(t, IDTokenClaims{Email: "user@example.com"})
	h := newTestHandler(t, testConfig(idp.URL))

	challenge := deriveCodeChallengeS256(strings.Repeat("v", 43))

	tests := []struct {
		name     string
		query    string
		wantCode int
	}{
		{
			name:     "valid native login",
			query:    "?native_redirect=" + url.QueryEscape("http://127.0.0.1:1234/cb") + "&code_challenge=" + challenge + "&code_challenge_method=S256",
			wantCode: http.StatusFound,
		},
		{
			name:     "ipv6 loopback",
			query:    "?native_redirect=" + url.QueryEscape("http://[::1]:9999/x") + "&code_challenge=" + challenge + "&code_challenge_method=S256",
			wantCode: http.StatusFound,
		},
		{
			name:     "localhost rejected",
			query:    "?native_redirect=" + url.QueryEscape("http://localhost:1234/") + "&code_challenge=" + challenge + "&code_challenge_method=S256",
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "external host rejected",
			query:    "?native_redirect=" + url.QueryEscape("https://evil.com/") + "&code_challenge=" + challenge + "&code_challenge_method=S256",
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "plain pkce rejected",
			query:    "?native_redirect=" + url.QueryEscape("http://127.0.0.1:1234/cb") + "&code_challenge=" + challenge + "&code_challenge_method=plain",
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "missing pkce rejected",
			query:    "?native_redirect=" + url.QueryEscape("http://127.0.0.1:1234/cb"),
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "pkce without native_redirect rejected",
			query:    "?code_challenge=" + challenge + "&code_challenge_method=S256",
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "client state accepted",
			query:    "?native_redirect=" + url.QueryEscape("http://127.0.0.1:1234/cb") + "&code_challenge=" + challenge + "&code_challenge_method=S256&state=abc-123_x~y",
			wantCode: http.StatusFound,
		},
		{
			name:     "client state with reserved characters rejected",
			query:    "?native_redirect=" + url.QueryEscape("http://127.0.0.1:1234/cb") + "&code_challenge=" + challenge + "&code_challenge_method=S256&state=" + url.QueryEscape("a&b=c"),
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "over-long client state rejected",
			query:    "?native_redirect=" + url.QueryEscape("http://127.0.0.1:1234/cb") + "&code_challenge=" + challenge + "&code_challenge_method=S256&state=" + strings.Repeat("s", nativeStateMaxLen+1),
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "browser flow still ignores a stray state parameter",
			query:    "?state=ignored-by-the-browser-flow",
			wantCode: http.StatusFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, _ := login(t, h, tt.query)
			if rec.Code != tt.wantCode {
				t.Fatalf("HandleLogin() status = %d, want %d (body: %s)", rec.Code, tt.wantCode, rec.Body.String())
			}
		})
	}
}

func TestValidateNativeState(t *testing.T) {
	tests := []struct {
		name    string
		state   string
		wantErr bool
	}{
		{name: "empty is allowed", state: ""},
		{name: "unreserved", state: "AZaz09-._~"},
		{name: "at the length limit", state: strings.Repeat("s", nativeStateMaxLen)},
		{name: "over the length limit", state: strings.Repeat("s", nativeStateMaxLen+1), wantErr: true},
		{name: "ampersand", state: "a&b", wantErr: true},
		{name: "equals", state: "a=b", wantErr: true},
		{name: "hash", state: "a#b", wantErr: true},
		{name: "percent", state: "a%20b", wantErr: true},
		{name: "space", state: "a b", wantErr: true},
		{name: "newline", state: "a\nb", wantErr: true},
		{name: "non-ascii", state: "aé", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateNativeState(tt.state); (err != nil) != tt.wantErr {
				t.Fatalf("validateNativeState(%q) error = %v, wantErr %v", tt.state, err, tt.wantErr)
			}
		})
	}
}

func TestNativeCallbackParamsOmitsServerState(t *testing.T) {
	// No client state: nothing is echoed. In particular the server's CSRF nonce
	// stays on the server side.
	got := nativeCallbackParams(&authState{State: "server-csrf-nonce"}, url.Values{"code": {"abc"}})
	if got.Has("state") {
		t.Fatalf("nativeCallbackParams() echoed a state the client never supplied: %q", got.Get("state"))
	}
	if got.Get("code") != "abc" {
		t.Fatalf("nativeCallbackParams() dropped the code: %v", got)
	}

	got = nativeCallbackParams(&authState{State: "server-csrf-nonce", NativeState: "client-state"}, url.Values{"code": {"abc"}})
	if got.Get("state") != "client-state" {
		t.Fatalf("nativeCallbackParams() state = %q, want the client's state", got.Get("state"))
	}
}

// --- /auth/callback ---------------------------------------------------------

func TestHandleCallbackBrowserFlowUnchanged(t *testing.T) {
	idp := newFakeIDP(t, IDTokenClaims{Email: "user@example.com", Name: "User", Picture: "https://example.com/a.png"})
	h := newTestHandler(t, testConfig(idp.URL))

	_, stateCookie := login(t, h, "")
	st, err := decodeAuthState(stateCookie.Value, [][]byte{[]byte(testSigningKey)})
	if err != nil {
		t.Fatalf("decodeAuthState() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=idp-code&state="+url.QueryEscape(st.State), nil)
	req.Host = "workspaces.example.com"
	req.AddCookie(stateCookie)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("HandleCallback() status = %d, want %d (body: %s)", rec.Code, http.StatusFound, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("Location = %q, want /", loc)
	}
	sess := sessionCookie(rec)
	if sess == nil {
		t.Fatal("HandleCallback() did not set the session cookie for a browser login")
	}
	claims, err := ValidateSessionToken(sess.Value, []byte(testSigningKey))
	if err != nil {
		t.Fatalf("ValidateSessionToken() error = %v", err)
	}
	if claims.Email != "user@example.com" {
		t.Fatalf("session email = %q, want user@example.com", claims.Email)
	}
}

func TestNativeLoginEndToEnd(t *testing.T) {
	idp := newFakeIDP(t, IDTokenClaims{Email: "user@example.com", Name: "User", Picture: "https://example.com/a.png"})
	h := newTestHandler(t, testConfig(idp.URL))

	verifier := "a-code-verifier-of-at-least-forty-three-chars"
	challenge := deriveCodeChallengeS256(verifier)

	const clientState = "client-chosen-state-value"

	_, stateCookie := login(t, h, "?native_redirect="+url.QueryEscape("http://127.0.0.1:1234/cb")+
		"&code_challenge="+challenge+"&code_challenge_method=S256&state="+clientState)
	if stateCookie == nil {
		t.Fatal("HandleLogin() did not set the kw-auth-state cookie")
	}
	st, err := decodeAuthState(stateCookie.Value, [][]byte{[]byte(testSigningKey)})
	if err != nil {
		t.Fatalf("decodeAuthState() error = %v", err)
	}
	if st.NativeRedirect != "http://127.0.0.1:1234/cb" || st.CodeChallenge != challenge {
		t.Fatalf("native parameters did not survive into the state cookie: %+v", st)
	}
	if st.NativeState != clientState {
		t.Fatalf("client state did not survive into the state cookie: %q", st.NativeState)
	}
	if st.State == clientState {
		t.Fatal("the client's state overwrote the server's CSRF state")
	}

	// Callback: redirected to the loopback listener, no session cookie.
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=idp-code&state="+url.QueryEscape(st.State), nil)
	req.Host = "workspaces.example.com"
	req.AddCookie(stateCookie)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("HandleCallback() status = %d, want %d (body: %s)", rec.Code, http.StatusFound, rec.Body.String())
	}
	if sessionCookie(rec) != nil {
		t.Fatal("HandleCallback() set a session cookie in the native flow; the token belongs to the app")
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse Location: %v", err)
	}
	if loc.Scheme != "http" || loc.Host != "127.0.0.1:1234" || loc.Path != "/cb" {
		t.Fatalf("Location = %q, want the loopback redirect", loc.String())
	}
	// The client's state comes back, and never the server's CSRF nonce: the
	// client has never seen the latter, so it could not check it anyway, and it
	// is paired with a cookie the client cannot read.
	if got := loc.Query().Get("state"); got != clientState {
		t.Fatalf("loopback state = %q, want the client's state %q", got, clientState)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("loopback redirect carried no authorization code")
	}

	// Wrong verifier is rejected...
	resp := exchange(t, h, code, "a-wrong-verifier-of-at-least-forty-three-chars")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("exchange with wrong verifier status = %d, want %d", resp.Code, http.StatusBadRequest)
	}
	if got := errorCode(t, resp); got != "invalid_verifier" {
		t.Fatalf("exchange with wrong verifier error = %q, want invalid_verifier", got)
	}

	// ...and it burned the code, so even the correct verifier cannot retry it.
	resp = exchange(t, h, code, verifier)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("replayed exchange status = %d, want %d", resp.Code, http.StatusBadRequest)
	}
	if got := errorCode(t, resp); got != "invalid_code" {
		t.Fatalf("replayed exchange error = %q, want invalid_code", got)
	}
}

func TestNativeTokenExchangeSuccess(t *testing.T) {
	idp := newFakeIDP(t, IDTokenClaims{Email: "user@example.com", Name: "User", Picture: "https://example.com/a.png"})
	h := newTestHandler(t, testConfig(idp.URL))

	verifier := "a-code-verifier-of-at-least-forty-three-chars"
	code := nativeLoginCode(t, h, verifier)

	resp := exchange(t, h, code, verifier)
	if resp.Code != http.StatusOK {
		t.Fatalf("exchange status = %d, want 200 (body: %s)", resp.Code, resp.Body.String())
	}

	var body struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
		Email     string `json:"email"`
		Role      string `json:"role"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode exchange response: %v", err)
	}
	if body.Email != "user@example.com" {
		t.Fatalf("email = %q, want user@example.com", body.Email)
	}
	if body.Role != "editor" {
		t.Fatalf("role = %q, want editor", body.Role)
	}

	claims, err := ValidateSessionToken(body.Token, []byte(testSigningKey))
	if err != nil {
		t.Fatalf("the exchanged token does not validate: %v", err)
	}
	if claims.ExpiresAt != body.ExpiresAt {
		t.Fatalf("expires_at = %d, want %d (the token's own exp)", body.ExpiresAt, claims.ExpiresAt)
	}

	// Second redemption of the same code must fail.
	if replay := exchange(t, h, code, verifier); replay.Code != http.StatusBadRequest {
		t.Fatalf("replayed exchange status = %d, want %d", replay.Code, http.StatusBadRequest)
	}
}

func TestNativeTokenExchangeMalformed(t *testing.T) {
	h := newTestHandler(t, testConfig("http://127.0.0.1:1/unused"))

	tests := []struct {
		name      string
		body      string
		wantError string
	}{
		{"not json", "{", "invalid_request"},
		{"missing code", `{"code_verifier":"x"}`, "invalid_request"},
		{"missing verifier", `{"code":"x"}`, "invalid_request"},
		{"unknown code", `{"code":"nope","code_verifier":"a-code-verifier-of-at-least-forty-three-chars"}`, "invalid_code"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/native/token", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			h.HandleNativeToken(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if got := errorCode(t, rec); got != tt.wantError {
				t.Fatalf("error = %q, want %q", got, tt.wantError)
			}
		})
	}
}

func TestNativeTokenExchangeRateLimited(t *testing.T) {
	h := newTestHandler(t, testConfig("http://127.0.0.1:1/unused"))
	h.nativeLimiter = newIPRateLimiter(2, time.Minute)

	for i := 0; i < 2; i++ {
		if rec := exchange(t, h, "nope", "verifier"); rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d status = %d, want %d", i+1, rec.Code, http.StatusBadRequest)
		}
	}
	if rec := exchange(t, h, "nope", "verifier"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
}

// nativeLoginCode runs a native login end to end and returns the authorization
// code handed to the loopback redirect.
func nativeLoginCode(t *testing.T, h *OIDCHandler, verifier string) string {
	t.Helper()
	challenge := deriveCodeChallengeS256(verifier)

	_, stateCookie := login(t, h, "?native_redirect="+url.QueryEscape("http://127.0.0.1:1234/cb")+
		"&code_challenge="+challenge+"&code_challenge_method=S256")
	if stateCookie == nil {
		t.Fatal("HandleLogin() did not set the kw-auth-state cookie")
	}
	st, err := decodeAuthState(stateCookie.Value, [][]byte{[]byte(testSigningKey)})
	if err != nil {
		t.Fatalf("decodeAuthState() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=idp-code&state="+url.QueryEscape(st.State), nil)
	req.Host = "workspaces.example.com"
	req.AddCookie(stateCookie)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no authorization code in %q (status %d, body %s)", loc.String(), rec.Code, rec.Body.String())
	}
	return code
}

func exchange(t *testing.T, h *OIDCHandler, code, verifier string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"code": code, "code_verifier": verifier})
	req := httptest.NewRequest(http.MethodPost, "/auth/native/token", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	h.HandleNativeToken(rec, req)
	return rec
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode error response %q: %v", rec.Body.String(), err)
	}
	return body.Error
}

// --- /auth/me ---------------------------------------------------------------

func TestHandleMeAcceptsBearer(t *testing.T) {
	h := newTestHandler(t, testConfig("http://127.0.0.1:1/unused"))

	token, err := CreateSessionToken("user@example.com", "User", "editor", nil, []byte(testSigningKey), time.Hour)
	if err != nil {
		t.Fatalf("CreateSessionToken() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.HandleMe(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HandleMe() status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Authenticated bool   `json:"authenticated"`
		Email         string `json:"email"`
		Role          string `json:"role"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode /auth/me response: %v", err)
	}
	if !body.Authenticated || body.Email != "user@example.com" || body.Role != "editor" {
		t.Fatalf("/auth/me returned %+v", body)
	}
}

func TestHandleMeCookieTakesPrecedence(t *testing.T) {
	h := newTestHandler(t, testConfig("http://127.0.0.1:1/unused"))

	cookieToken, _ := CreateSessionToken("cookie@example.com", "Cookie", "editor", nil, []byte(testSigningKey), time.Hour)
	bearerToken, _ := CreateSessionToken("bearer@example.com", "Bearer", "editor", nil, []byte(testSigningKey), time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookieToken})
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	rec := httptest.NewRecorder()
	h.HandleMe(rec, req)

	var body struct {
		Email string `json:"email"`
	}
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Email != "cookie@example.com" {
		t.Fatalf("/auth/me email = %q, want the cookie identity", body.Email)
	}
}

func TestHandleMeRejectsBadBearer(t *testing.T) {
	h := newTestHandler(t, testConfig("http://127.0.0.1:1/unused"))

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer not-a-token")
	rec := httptest.NewRecorder()
	h.HandleMe(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("HandleMe() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestSessionTokenFromRequest(t *testing.T) {
	tests := []struct {
		name   string
		cookie string
		header string
		want   string
	}{
		{"neither", "", "", ""},
		{"cookie only", "c-token", "", "c-token"},
		{"bearer only", "", "Bearer b-token", "b-token"},
		{"lowercase bearer", "", "bearer b-token", "b-token"},
		{"cookie wins", "c-token", "Bearer b-token", "c-token"},
		{"basic ignored", "", "Basic abc", ""},
		{"empty bearer", "", "Bearer ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
			if tt.cookie != "" {
				req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tt.cookie})
			}
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			if got := sessionTokenFromRequest(req); got != tt.want {
				t.Fatalf("sessionTokenFromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- /auth/config -----------------------------------------------------------

func TestHandleAuthConfigAdvertisesNativeAuth(t *testing.T) {
	h := newTestHandler(t, testConfig("http://127.0.0.1:1/unused"))

	rec := httptest.NewRecorder()
	h.HandleAuthConfig(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))

	var body struct {
		Enabled    bool `json:"enabled"`
		NativeAuth struct {
			Enabled bool     `json:"enabled"`
			Methods []string `json:"methods"`
		} `json:"nativeAuth"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode /auth/config response: %v", err)
	}
	if !body.NativeAuth.Enabled {
		t.Fatal("/auth/config did not advertise nativeAuth")
	}
	if len(body.NativeAuth.Methods) != 1 || body.NativeAuth.Methods[0] != "loopback-pkce" {
		t.Fatalf("nativeAuth.methods = %v, want [loopback-pkce]", body.NativeAuth.Methods)
	}
}
