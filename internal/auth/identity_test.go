package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

func bindingUser(name, email string) *unstructured.Unstructured {
	u := executionUserFixture(email, "editor")
	u.SetName(name)
	u.SetUID(types.UID(name + "-uid"))
	_ = unstructured.SetNestedField(u.Object, "personal-"+name, "status", "personalNamespace")
	return u
}

func bindingProvider(t *testing.T, users ...*unstructured.Unstructured) *ConfigProvider {
	t.Helper()
	p := &ConfigProvider{dynamicClient: newFakeDynamicClient(t)}
	for _, user := range users {
		if _, err := p.CreateUser(context.Background(), user); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func TestIdentityBindingPreservesAccountAndRequiresExactPair(t *testing.T) {
	ctx := context.Background()
	u := bindingUser("existing", "local@example.com")
	_ = unstructured.SetNestedMap(u.Object, map[string]interface{}{"enabled": true, "passwordSecretRef": map[string]interface{}{"name": "existing-password", "key": "passwordHash"}}, "spec", "localAuth")
	p := bindingProvider(t, u)
	id := ExternalIdentity{Issuer: "https://idp.example.com", Subject: "CaseSensitive"}
	if _, err := p.GetUserByIdentity(ctx, id); !errors.Is(err, ErrIdentityNotBound) {
		t.Fatalf("email alone resolved an identity: %v", err)
	}
	for range 2 { // Same authorized operation is resumable/idempotent.
		if err := p.BindIdentity(ctx, u.GetName(), string(u.GetUID()), id); err != nil {
			t.Fatal(err)
		}
	}
	bound, err := p.GetUserByIdentity(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if bound.GetName() != u.GetName() || bound.GetUID() != u.GetUID() {
		t.Fatal("binding replaced the account")
	}
	// Compare every pre-existing field, including local credentials and namespace.
	copy := bound.DeepCopy()
	unstructured.RemoveNestedField(copy.Object, "spec", "externalIdentities")
	want, _ := json.Marshal(u.Object)
	got, _ := json.Marshal(copy.Object)
	if string(got) != string(want) {
		t.Fatalf("existing account changed: %s", got)
	}
	for _, other := range []ExternalIdentity{
		{Issuer: id.Issuer + "/", Subject: id.Subject},
		{Issuer: id.Issuer, Subject: "casesensitive"},
		{Issuer: "https://other.example.com", Subject: id.Subject},
	} {
		if _, err := p.GetUserByIdentity(ctx, other); !errors.Is(err, ErrIdentityNotBound) {
			t.Fatalf("non-exact pair resolved: %v", err)
		}
	}
}

func TestIdentityClaimHasOneWinnerAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	a, b := bindingUser("a", "same@example.com"), bindingUser("b", "same@example.com")
	p := bindingProvider(t, a, b)
	otherReplica := &ConfigProvider{dynamicClient: p.dynamicClient}
	id := ExternalIdentity{Issuer: "https://idp.example.com", Subject: "subject"}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, user := range []*unstructured.Unstructured{a, b} {
		provider := []*ConfigProvider{p, otherReplica}[i]
		wg.Go(func() { results <- provider.BindIdentity(ctx, user.GetName(), string(user.GetUID()), id) })
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrIdentityConflict) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("got %d winners", winners)
	}
	if _, err := otherReplica.GetUserByIdentity(ctx, id); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityBindingFailsClosedOnPartialWritesAndReplacement(t *testing.T) {
	ctx := context.Background()
	u := bindingUser("existing", "user@example.com")
	p := bindingProvider(t, u)
	id := ExternalIdentity{Issuer: "https://idp.example.com", Subject: "subject"}
	client := p.dynamicClient.(*dynamicfake.FakeDynamicClient)
	fail := true
	client.PrependReactor("update", "users", func(action clienttesting.Action) (bool, runtime.Object, error) {
		if fail {
			return true, nil, errors.New("write unavailable")
		}
		return false, nil, nil
	})
	if err := p.BindIdentity(ctx, u.GetName(), string(u.GetUID()), id); err == nil {
		t.Fatal("partial write succeeded")
	}
	if _, err := p.GetUserByIdentity(ctx, id); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("partial write allowed login: %v", err)
	}
	fail = false
	if err := p.BindIdentity(ctx, u.GetName(), string(u.GetUID()), id); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteUser(ctx, u.GetName()); err != nil {
		t.Fatal(err)
	}
	replacement := u.DeepCopy()
	replacement.SetUID("replacement-uid")
	if _, err := p.CreateUser(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	if err := p.BindIdentity(ctx, replacement.GetName(), string(replacement.GetUID()), id); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("replacement adopted old identity: %v", err)
	}
	if _, err := p.GetUserByIdentity(ctx, id); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("replacement resolved old identity: %v", err)
	}
}

func TestIdentityBindingRetriesAndDetectsPrunedSchema(t *testing.T) {
	for _, prune := range []bool{false, true} {
		t.Run(map[bool]string{false: "conflict retry", true: "old CRD prunes binding"}[prune], func(t *testing.T) {
			ctx := context.Background()
			u := bindingUser("existing", "user@example.com")
			p := bindingProvider(t, u)
			client := p.dynamicClient.(*dynamicfake.FakeDynamicClient)
			attempts := 0
			client.PrependReactor("update", "users", func(action clienttesting.Action) (bool, runtime.Object, error) {
				attempts++
				if attempts == 1 && !prune {
					return true, nil, k8serrors.NewConflict(userGVR.GroupResource(), u.GetName(), errors.New("concurrent update"))
				}
				if prune {
					return true, u.DeepCopy(), nil
				}
				return false, nil, nil
			})
			id := ExternalIdentity{Issuer: "https://idp.example.com", Subject: "subject"}
			err := p.BindIdentity(ctx, u.GetName(), string(u.GetUID()), id)
			if prune {
				if err == nil || !strings.Contains(err.Error(), "CRD") {
					t.Fatalf("old schema not detected: %v", err)
				}
			} else if err != nil || attempts != 2 {
				t.Fatalf("retry failed: attempts=%d err=%v", attempts, err)
			}
		})
	}
}

func TestIdentityLookupRejectsDisabledAndDuplicateBindings(t *testing.T) {
	ctx := context.Background()
	u := bindingUser("existing", "user@example.com")
	p := bindingProvider(t, u)
	id := ExternalIdentity{Issuer: "https://idp.example.com", Subject: "subject"}
	if err := p.BindIdentity(ctx, u.GetName(), string(u.GetUID()), id); err != nil {
		t.Fatal(err)
	}
	bound, _ := p.GetUser(ctx, u.GetName())
	_ = unstructured.SetNestedField(bound.Object, true, "spec", "disabled")
	if _, err := p.UpdateUser(ctx, bound); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetUserByIdentity(ctx, id); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("disabled binding resolved: %v", err)
	}
	_ = unstructured.SetNestedField(bound.Object, false, "spec", "disabled")
	if _, err := p.UpdateUser(ctx, bound); err != nil {
		t.Fatal(err)
	}
	duplicate := bound.DeepCopy()
	duplicate.SetName("duplicate")
	duplicate.SetUID("duplicate-uid")
	if _, err := p.CreateUser(ctx, duplicate); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetUserByIdentity(ctx, id); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("duplicate binding resolved: %v", err)
	}
	secrets, err := p.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).List(ctx, metav1.ListOptions{})
	if err != nil || len(secrets.Items) != 1 {
		t.Fatalf("unexpected claim count: %v", err)
	}
}

func TestIdentityInventoryIsReadOnlyAndAdminOnly(t *testing.T) {
	ctx := context.Background()
	a, b := bindingUser("a", "User@example.com"), bindingUser("b", "user@example.com")
	c := bindingUser("c", "user@example.com")
	for _, u := range []*unstructured.Unstructured{a, b, c} {
		_ = unstructured.SetNestedMap(u.Object, map[string]interface{}{"enabled": true, "passwordSecretRef": map[string]interface{}{"name": "shared"}}, "spec", "localAuth")
	}
	p := bindingProvider(t, a, b, c)
	if err := p.CreatePasswordSecret(ctx, "orphan", "secret-hash", "secret-password"); err != nil {
		t.Fatal(err)
	}
	client := p.dynamicClient.(*dynamicfake.FakeDynamicClient)
	before := len(client.Actions())
	report, err := p.InventoryIdentities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, issue := range report.Issues {
		kinds[issue.Kind] = true
	}
	for _, kind := range []string{"duplicate-email", "case-variant-email", "legacy-slug-collision", "shared-password-secret", "missing-password-secret", "orphan-password-secret"} {
		if !kinds[kind] {
			t.Errorf("missing %s", kind)
		}
	}
	data, _ := json.Marshal(report)
	if strings.Contains(string(data), "secret-hash") || strings.Contains(string(data), "secret-password") {
		t.Fatal("inventory exposed credentials")
	}
	for _, action := range client.Actions()[before:] {
		if action.GetVerb() != "list" && action.GetVerb() != "get" {
			t.Fatalf("inventory mutated data: %v", action)
		}
	}
	for _, role := range []string{"editor", "admin"} {
		req := httptest.NewRequest("GET", "/admin/auth-identities/inventory", nil)
		req = req.WithContext(ContextWithUser(req.Context(), &UserInfo{Role: role}))
		rec := httptest.NewRecorder()
		p.HandleIdentityInventory(rec, req)
		want := http.StatusOK
		if role != "admin" {
			want = http.StatusForbidden
		}
		if rec.Code != want {
			t.Fatalf("%s: status %d", role, rec.Code)
		}
	}
}
