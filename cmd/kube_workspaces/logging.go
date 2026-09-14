package main

import (
	"context"
	"net/http"
	"net/url"

	"goa.design/clue/log"
)

// httpSensitiveQueryParams are URL query parameter names whose values are
// credentials or single-use secrets and must never appear in request logs.
// They are matched by name rather than by path so the protection stays in
// force even if a sensitive parameter is reused on a different route later.
var httpSensitiveQueryParams = map[string]struct{}{
	"code":          {},
	"token":         {},
	"access_token":  {},
	"id_token":      {},
	"refresh_token": {},
}

// redactedRequestLog wraps the stock request logger with a log function that
// scrubs sensitive query parameters (notably the OIDC authorization code in
// /auth/callback and the single-use browser-session code) before the request
// URL is written to the log.
func redactedRequestLog(logCtx context.Context) func(http.Handler) http.Handler {
	return log.HTTP(logCtx, log.WithRequestLogFunc(redactURLFields))
}

// redactURLFields forwards request log fields to the logger, replacing any
// http.url value with a redacted copy.
func redactURLFields(ctx context.Context, keyvals ...log.Fielder) {
	out := make([]log.Fielder, 0, len(keyvals))
	for _, kv := range keyvals {
		if k, ok := kv.(log.KV); ok && k.K == log.HTTPURLKey {
			if v, ok := k.V.(string); ok {
				out = append(out, log.KV{K: k.K, V: redactedURL(v)})
				continue
			}
		}
		out = append(out, kv)
	}
	log.Print(ctx, out...)
}

// redactedURL returns the given URL with any sensitive query parameter values
// replaced by "[REDACTED]". Non-sensitive parameters (including the public
// PKCE code_challenge) are preserved for diagnostics.
func redactedURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	changed := false
	for name := range httpSensitiveQueryParams {
		if _, ok := q[name]; ok {
			q.Set(name, "[REDACTED]")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}