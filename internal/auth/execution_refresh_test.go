package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestExecutionRefreshRequiresMiddlewareCredential(t *testing.T) {
	ctx := ContextWithUser(context.Background(), &UserInfo{UID: "forged", credentialUserUID: "forged", Role: "admin"})
	if _, err := RefreshExecutionPrincipal(ctx); err == nil {
		t.Fatal("a caller-built principal authorized credential refresh")
	}
}

func TestExecutionRefreshRevalidatesOriginalCredential(t *testing.T) {
	for _, mode := range []string{"bearer", "cookie", "device"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifecycleFixture(t, false)
			raw := f.localToken
			if mode == "device" {
				raw = f.deviceToken(t, raw)
			}
			called := false
			handler := Middleware(f.h.provider)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				called = true
				user, err := RefreshExecutionPrincipal(r.Context())
				if err != nil || user.UID != ExecutionPrincipal(r.Context()).UID {
					t.Fatalf("valid credential refresh failed: %v", err)
				}
				// Rotation revokes the original credential even though both the
				// request's UserInfo and parsed SessionToken are still present.
				hash, err := bcrypt.GenerateFromPassword([]byte("Rotated-password-456!"), bcrypt.MinCost)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.h.provider.UpdatePasswordHash(context.Background(), "lifecycle-password", string(hash)); err != nil {
					t.Fatal(err)
				}
				if _, err := RefreshExecutionPrincipal(r.Context()); err == nil {
					t.Fatal("rotated credential remained authorized at dispatch")
				}
			}))
			req := httptest.NewRequest(http.MethodPost, "/v1/executions/start", nil)
			if mode == "cookie" {
				req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: raw})
			} else {
				req.Header.Set("Authorization", "Bearer "+raw)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if !called {
				t.Fatalf("middleware rejected test credential: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}
