package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestGrantRedemptionRevalidatesCurrentAccount(t *testing.T) {
	for _, transport := range []string{"native", "browser"} {
		for _, mutation := range []string{"disabled", "deleted", "replaced", "expired", "rotated key", "revoked device", "auth disabled", "demoted"} {
			t.Run(transport+"/"+mutation, func(t *testing.T) {
				ctx := context.Background()
				h := newTestHandler(t, testConfig(""))
				cfg := h.provider.config
				user, _ := h.provider.GetUserByEmail(ctx, "user@example.com")
				_ = unstructured.SetNestedField(user.Object, "admin", "spec", "role")
				if _, err := h.provider.UpdateUser(ctx, user); err != nil {
					t.Fatal(err)
				}
				expiry := time.Hour
				if mutation == "expired" {
					expiry = -time.Hour
				}
				token, err := CreateSessionToken("user@example.com", "", "admin", nil, cfg.SigningKey, expiry, string(user.GetUID()))
				if err != nil {
					t.Fatal(err)
				}
				if mutation == "revoked device" {
					token, err = CreateDeviceToken("user@example.com", "", "admin", nil, "device", "revoked", cfg.SigningKey, expiry, string(user.GetUID()))
					if err != nil {
						t.Fatal(err)
					}
					// No backing registration: it has already been revoked.
				}
				token = methodBoundTestToken(t, h.provider, token)
				user, _ = h.provider.GetUserByEmail(ctx, "user@example.com")
				verifier := strings.Repeat("v", 43)
				entry := nativeAuthCode{token: token, email: "user@example.com", role: "admin", tokenExpiresAt: time.Now().Add(expiry).Unix()}
				if transport == "native" {
					entry.codeChallenge = deriveCodeChallengeS256(verifier)
				} else {
					entry.redirect = "/proxy/team/workspace/"
				}
				if err := h.codes.Issue("pending-grant", entry); err != nil {
					t.Fatal(err)
				}
				switch mutation {
				case "disabled":
					_ = unstructured.SetNestedField(user.Object, true, "spec", "disabled")
				case "deleted":
					if err := h.provider.dynamicClient.Resource(userGVR).Delete(ctx, user.GetName(), metav1.DeleteOptions{}); err != nil {
						t.Fatal(err)
					}
				case "replaced":
					user.SetUID("replacement-uid")
				case "rotated key":
					cfg.SigningKey = []byte("new-unrelated-signing-key")
				case "auth disabled":
					cfg.Enabled = false
				case "demoted":
					_ = unstructured.SetNestedField(user.Object, "viewer", "spec", "role")
				}
				if mutation != "deleted" {
					if _, err := h.provider.UpdateUser(ctx, user); err != nil {
						t.Fatal(err)
					}
				}
				redeem := func() *httptest.ResponseRecorder {
					if transport == "native" {
						return exchange(t, h, "pending-grant", verifier)
					}
					rec := httptest.NewRecorder()
					h.HandleBrowserSessionRedeem(rec, httptest.NewRequest("GET", "/auth/browser-session?code=pending-grant", nil))
					return rec
				}
				rec := redeem()
				if mutation == "demoted" {
					if transport == "native" && (rec.Code != 200 || !strings.Contains(rec.Body.String(), `"role":"viewer"`)) {
						t.Fatalf("stale role at redemption: %d %s", rec.Code, rec.Body.String())
					}
					if transport == "browser" && (rec.Code != 302 || sessionCookie(rec) == nil) {
						t.Fatal("valid demoted session rejected")
					}
				} else if rec.Code != http.StatusUnauthorized || sessionCookie(rec) != nil || strings.Contains(rec.Body.String(), token) {
					t.Fatalf("stale grant accepted or disclosed: %d %s", rec.Code, rec.Body.String())
				}
				// Even a denied redemption consumes the code permanently.
				if replay := redeem(); replay.Code != 400 {
					t.Fatalf("grant replay: %d", replay.Code)
				}
			})
		}
	}
}
