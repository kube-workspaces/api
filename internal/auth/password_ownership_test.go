package auth

import (
	"context"
	"reflect"
	"strings"
	"testing"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestResetMigratesSharedLegacyCredentialWithoutChangingOtherAccount(t *testing.T) {
	f := newLifecycleFixture(t, false)
	ctx := context.Background()
	other := f.user.DeepCopy()
	other.SetName("other-account")
	other.SetUID("other-uid")
	unstructured.RemoveNestedField(other.Object, "spec", "externalIdentities")
	_ = unstructured.SetNestedField(other.Object, "other@example.com", "spec", "email")
	if _, err := f.h.provider.CreateUser(ctx, other); err != nil {
		t.Fatal(err)
	}
	source, err := f.h.provider.GetPasswordSecret(ctx, "lifecycle-password")
	if err != nil {
		t.Fatal(err)
	}
	originalHash, _ := GetPasswordHash(source)
	// Self-service must not change a shared legacy Secret for another account.
	rec := f.request("POST", "/auth/change-password", f.localToken, `{"currentPassword":"Initial-password-123!","newPassword":"Replacement-password-456!"}`)
	if rec.Code != 409 {
		t.Fatalf("shared change: %d %s", rec.Code, rec.Body.String())
	}
	baseline, err := f.h.provider.GetUser(ctx, f.user.GetName())
	if err != nil {
		t.Fatal(err)
	}
	password, err := ResetLocalUserPassword(ctx, f.h.provider, f.user.GetName())
	if err != nil {
		t.Fatal(err)
	}
	updated, _ := f.h.provider.GetUser(ctx, f.user.GetName())
	name, _, _ := passwordReference(updated)
	owned, err := f.h.provider.GetPasswordSecret(ctx, name)
	if err != nil || !strings.HasPrefix(name, "kw-password-") || owned.GetAnnotations()[passwordUserUIDAnnotation] != string(f.user.GetUID()) || len(owned.GetOwnerReferences()) != 1 || owned.GetOwnerReferences()[0].UID != f.user.GetUID() {
		t.Fatalf("reset did not allocate UID-owned material: %v", err)
	}
	if updated.GetUID() != f.user.GetUID() || updated.GetName() != f.user.GetName() {
		t.Fatal("migration replaced account identity")
	}
	beforeSpec, _, _ := unstructured.NestedMap(baseline.Object, "spec")
	afterSpec, _, _ := unstructured.NestedMap(updated.Object, "spec")
	delete(beforeSpec, "localAuth")
	delete(afterSpec, "localAuth")
	if !reflect.DeepEqual(beforeSpec, afterSpec) || !reflect.DeepEqual(baseline.Object["status"], updated.Object["status"]) {
		t.Fatal("migration changed namespaces, grants, external identities or other account settings")
	}
	source, _ = f.h.provider.GetPasswordSecret(ctx, "lifecycle-password")
	if hash, _ := GetPasswordHash(source); hash != originalHash {
		t.Fatal("migration overwrote shared legacy material")
	}
	unchanged, _ := f.h.provider.GetUser(ctx, other.GetName())
	if name, _, _ := passwordReference(unchanged); name != "lifecycle-password" {
		t.Fatal("migration rewrote another account's credential reference")
	}
	if rec := f.request("GET", "/auth/me", f.localToken, ""); rec.Code != 401 {
		t.Fatal("migration did not revoke original local credential")
	}
	f.loginLocal(t, password)
	if rec := f.request("GET", "/auth/me", f.oidcToken, ""); rec.Code != 200 {
		t.Fatal("migration revoked independent OIDC method")
	}
	// A replacement account cannot point at this UID's password material.
	_ = unstructured.SetNestedMap(other.Object, map[string]interface{}{"enabled": true, "passwordSecretRef": map[string]interface{}{"name": name, "key": "passwordHash"}}, "spec", "localAuth")
	if _, _, err := localCredentialState(other, owned); err == nil {
		t.Fatal("another UID reused owned credentials")
	}
}

func TestProvisionedCredentialUsesPersistedUIDAndRejectsSlugCollision(t *testing.T) {
	h := newTestHandler(t, testConfig("https://idp.example.com"))
	cl := h.provider.dynamicClient.(*dynamicfake.FakeDynamicClient)
	cl.PrependReactor("create", "users", func(action clienttesting.Action) (bool, runtime.Object, error) {
		u := action.(clienttesting.CreateAction).GetObject().(*unstructured.Unstructured)
		u.SetUID("persisted-local-uid")
		return false, nil, nil
	})
	cl.PrependReactor("create", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
		secret := action.(clienttesting.CreateAction).GetObject().(*unstructured.Unstructured)
		if secret.GetAnnotations()[passwordUserUIDAnnotation] != "persisted-local-uid" {
			return false, nil, nil
		}
		obj, err := cl.Tracker().Get(userGVR, "", "first-last-at-example-com")
		if err != nil {
			t.Fatal(err)
		}
		user := obj.(*unstructured.Unstructured).DeepCopy()
		// The controller's typed User drops these omitempty zero values when
		// adding its finalizer, unlike the dynamic fake's normal behaviour.
		for _, field := range []string{"displayName", "groups", "disabled"} {
			unstructured.RemoveNestedField(user.Object, "spec", field)
		}
		user.SetFinalizers([]string{"kubeworkspaces.io/user-finalizer"})
		if err := cl.Tracker().Update(userGVR, user, ""); err != nil {
			t.Fatal(err)
		}
		return false, nil, nil
	})
	ctx := context.Background()
	_, name, err := ProvisionLocalUser(ctx, h.provider, "first.last@example.com", "", "editor", "Initial-password-123!", nil)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := h.provider.GetUser(ctx, name)
	ref, _, _ := passwordReference(u)
	secret, err := h.provider.GetPasswordSecret(ctx, ref)
	if err != nil || secret.GetAnnotations()[passwordUserUIDAnnotation] != "persisted-local-uid" {
		t.Fatalf("provisioned ownership: %v", err)
	}
	if _, _, err := ProvisionLocalUser(ctx, h.provider, "first-last@example.com", "", "editor", "Another-password-456!", nil); err == nil {
		t.Fatal("slug-colliding account silently reused existing credentials")
	}
	secrets, err := cl.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	owned := 0
	for _, s := range secrets.Items {
		if s.GetAnnotations()[passwordUserUIDAnnotation] == "persisted-local-uid" {
			owned++
		}
	}
	if owned != 1 {
		t.Fatalf("losing provision allocated credentials: %d", owned)
	}
}

func TestConflictedPasswordResetDoesNotReplaceCredentialOrReportPassword(t *testing.T) {
	f := newLifecycleFixture(t, false)
	ctx := context.Background()
	cl := f.h.provider.dynamicClient.(*dynamicfake.FakeDynamicClient)
	cl.PrependReactor("update", "users", func(action clienttesting.Action) (bool, runtime.Object, error) {
		user := action.(clienttesting.UpdateAction).GetObject().(*unstructured.Unstructured)
		return true, nil, k8serrors.NewConflict(userGVR.GroupResource(), user.GetName(), ErrIdentityConflict)
	})
	password, err := ResetLocalUserPassword(ctx, f.h.provider, f.user.GetName())
	if !k8serrors.IsConflict(err) || password != "" {
		t.Fatalf("conflicted reset reported success/password: %v", err)
	}
	current, err := f.h.provider.GetUser(ctx, f.user.GetName())
	if err != nil {
		t.Fatal(err)
	}
	if name, _, _ := passwordReference(current); name != "lifecycle-password" {
		t.Fatal("losing reset published its new reference")
	}
	if rec := f.request("GET", "/auth/me", f.localToken, ""); rec.Code != 200 {
		t.Fatal("losing reset revoked the active credential")
	}
}

func TestCredentialPublicationRetriesOnlyMetadataAndStatusConflicts(t *testing.T) {
	for _, mode := range []string{"controller-finalizer", "changed-password-reference", "replacement-user"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifecycleFixture(t, false)
			ctx := context.Background()
			cl := f.h.provider.dynamicClient.(*dynamicfake.FakeDynamicClient)
			injected := false
			cl.PrependReactor("update", "users", func(action clienttesting.Action) (bool, runtime.Object, error) {
				if injected {
					return false, nil, nil
				}
				injected = true
				obj, err := cl.Tracker().Get(userGVR, "", f.user.GetName())
				if err != nil {
					t.Fatal(err)
				}
				current := obj.(*unstructured.Unstructured).DeepCopy()
				current.SetFinalizers([]string{"kubeworkspaces.io/user-finalizer"})
				_ = unstructured.SetNestedField(current.Object, "retained-namespace", "status", "personalNamespace")
				if mode == "changed-password-reference" {
					_ = unstructured.SetNestedField(current.Object, "concurrent-reset", "spec", "localAuth", "passwordSecretRef", "name")
				}
				if mode == "replacement-user" {
					current.SetUID("replacement-uid")
				}
				if err := cl.Tracker().Update(userGVR, current, ""); err != nil {
					t.Fatal(err)
				}
				return true, nil, k8serrors.NewConflict(userGVR.GroupResource(), current.GetName(), ErrIdentityConflict)
			})
			password, err := ResetLocalUserPassword(ctx, f.h.provider, f.user.GetName())
			if mode != "controller-finalizer" {
				if err == nil || password != "" {
					t.Fatal("credential publication overwrote a changed account")
				}
				return
			}
			if err != nil || password == "" {
				t.Fatalf("controller-only conflict prevented credential publication: %v", err)
			}
			current, _ := f.h.provider.GetUser(ctx, f.user.GetName())
			personal, _, _ := unstructured.NestedString(current.Object, "status", "personalNamespace")
			if len(current.GetFinalizers()) != 1 || personal != "retained-namespace" {
				t.Fatal("publication overwrote controller finalizer/status")
			}
		})
	}
}
