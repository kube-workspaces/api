package auth

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

func unlinkRequest(t *testing.T, f *lifecycleFixture, token string, id ExternalIdentity, uid string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"userName": f.user.GetName(), "userUID": uid, "issuer": id.Issuer, "subject": id.Subject})
	req := httptest.NewRequest("POST", "/auth/oidc/unlink", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-KW-Link-Intent", "unlink-identity")
	rec := httptest.NewRecorder()
	f.h.HandleUnlinkIdentity(rec, req)
	return rec
}

func TestUnlinkRevokesBindingCredentialsAndRelinkDoesNotResurrectThem(t *testing.T) {
	f := newLifecycleFixture(t, false)
	f.h.provider.config.AdminEmails = []string{"user@example.com"}
	device := f.deviceToken(t, f.oidcToken)
	grant := f.request("POST", "/auth/browser-session/grant", device, `{"redirect":"/proxy/personal/ws/"}`)
	var pending struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(grant.Body.Bytes(), &pending)
	if pending.Code == "" {
		t.Fatal("no pending browser grant")
	}
	claims, _ := ValidateSessionToken(f.oidcToken, f.h.provider.config.SigningKey)
	id := ExternalIdentity{Issuer: claims.Issuer, Subject: claims.Subject}
	rec := unlinkRequest(t, f, f.localToken, id, string(f.user.GetUID()))
	if rec.Code != 200 {
		t.Fatalf("unlink: %d %s", rec.Code, rec.Body.String())
	}
	for _, token := range []string{f.oidcToken, device} {
		if rec := f.request("GET", "/auth/me", token, ""); rec.Code != 401 {
			t.Fatal("unlinked credential remained valid")
		}
	}
	if rec := f.request("GET", "/auth/browser-session?code="+pending.Code, "", ""); rec.Code != 401 || sessionCookie(rec) != nil {
		t.Fatal("unlinked browser handoff redeemed")
	}
	if rec := f.request("GET", "/v1/workspaces", f.localToken, ""); rec.Code != 200 {
		t.Fatal("unlink revoked local session")
	}
	u, _ := f.h.provider.GetUser(context.Background(), f.user.GetName())
	if u.GetUID() != f.user.GetUID() {
		t.Fatal("unlink changed account identity")
	}
	if err := f.h.provider.BindIdentity(context.Background(), u.GetName(), string(u.GetUID()), id); err != nil {
		t.Fatal(err)
	}
	provenance, err := f.h.provider.identityProvenance(context.Background(), u, id)
	if err != nil || provenance.CredentialVersion == claims.CredentialVersion {
		t.Fatal("unlink failed to rotate retained reservation")
	}
	if rec := f.request("GET", "/auth/me", f.oidcToken, ""); rec.Code != 401 {
		t.Fatal("relink resurrected an old OIDC session")
	}
	claims.SessionProvenance = provenance
	newToken, _ := signSessionToken(*claims, f.h.provider.config.SigningKey)
	if rec := f.request("GET", "/auth/me", newToken, ""); rec.Code != 200 {
		t.Fatal("same-UID verified relink cannot sign in")
	}
}

func TestUnlinkRequiresAdminAndAnotherUsableMethod(t *testing.T) {
	for _, mode := range []string{"non-admin", "anonymous", "replacement UID", "local disabled", "local config disabled", "password missing", "password malformed", "password locked"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifecycleFixture(t, false)
			if mode != "non-admin" {
				f.h.provider.config.AdminEmails = []string{"user@example.com"}
			}
			ctx := context.Background()
			u, _ := f.h.provider.GetUser(ctx, f.user.GetName())
			token, uid := f.oidcToken, string(u.GetUID())
			switch mode {
			case "anonymous":
				token = ""
			case "replacement UID":
				uid = "replacement"
			case "local disabled":
				_ = unstructured.SetNestedField(u.Object, false, "spec", "localAuth", "enabled")
			case "local config disabled":
				f.h.provider.config.LocalAuthEnabled = false
			case "password missing":
				if err := f.h.provider.DeletePasswordSecret(ctx, "lifecycle-password"); err != nil {
					t.Fatal(err)
				}
			case "password malformed":
				if err := f.h.provider.UpdatePasswordHash(ctx, "lifecycle-password", "not-a-bcrypt-hash"); err != nil {
					t.Fatal(err)
				}
			case "password locked":
				_ = unstructured.SetNestedField(u.Object, time.Now().Add(time.Hour).Format(time.RFC3339), "status", "lockedUntil")
			}
			if _, err := f.h.provider.UpdateUser(ctx, u); err != nil {
				t.Fatal(err)
			}
			claims, _ := ValidateSessionToken(f.oidcToken, f.h.provider.config.SigningKey)
			rec := unlinkRequest(t, f, token, ExternalIdentity{Issuer: claims.Issuer, Subject: claims.Subject}, uid)
			if rec.Code != 403 && rec.Code != 409 {
				t.Fatalf("unsafe unlink: %d %s", rec.Code, rec.Body.String())
			}
			if rec := f.request("GET", "/auth/me", f.oidcToken, ""); rec.Code != 200 {
				t.Fatal("denied unlink revoked the only usable credential")
			}
		})
	}
}

func TestUnlinkRechecksLastMethodAfterConcurrentAccountChange(t *testing.T) {
	f := newLifecycleFixture(t, false)
	ctx := context.Background()
	claims, _ := ValidateSessionToken(f.oidcToken, f.h.provider.config.SigningKey)
	first := ExternalIdentity{Issuer: claims.Issuer, Subject: claims.Subject}
	second := ExternalIdentity{Issuer: claims.Issuer, Subject: "another-subject"}
	if err := f.h.provider.BindIdentity(ctx, f.user.GetName(), string(f.user.GetUID()), second); err != nil {
		t.Fatal(err)
	}
	u, _ := f.h.provider.GetUser(ctx, f.user.GetName())
	_ = unstructured.SetNestedField(u.Object, false, "spec", "localAuth", "enabled")
	if _, err := f.h.provider.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	client := f.h.provider.dynamicClient.(*dynamicfake.FakeDynamicClient)
	client.PrependReactor("update", "users", func(action clienttesting.Action) (bool, runtime.Object, error) {
		current := u.DeepCopy()
		_ = unstructured.SetNestedSlice(current.Object, []interface{}{map[string]interface{}{"issuer": first.Issuer, "subject": first.Subject}}, "spec", "externalIdentities")
		if err := client.Tracker().Update(userGVR, current, ""); err != nil {
			t.Fatal(err)
		}
		return true, nil, k8serrors.NewConflict(userGVR.GroupResource(), u.GetName(), ErrIdentityConflict)
	})
	if err := f.h.unlinkIdentity(ctx, f.h.provider.config, u.GetName(), string(u.GetUID()), first); err == nil {
		t.Fatal("concurrent unlink removed the last method")
	}
	retained, err := f.h.provider.GetUserByIdentity(ctx, first)
	if err != nil || retained.GetUID() != u.GetUID() {
		t.Fatal("last binding was lost on conflict retry")
	}
	claim, err := client.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Get(ctx, first.claimName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal("reservation was deleted instead of retained")
	}
	if claim.GetAnnotations()[identityVersionAnnotation] == claims.CredentialVersion {
		t.Fatal("failed removal did not fail closed for prior sessions")
	}
}
