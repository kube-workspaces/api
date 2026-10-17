package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func executionUserFixture(email, role string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "User",
		"metadata": map[string]interface{}{"name": slugifyEmail(email), "uid": "user-uid"},
		"spec": map[string]interface{}{
			"email": email, "role": role,
			"namespaceAccess": []interface{}{map[string]interface{}{"namespace": "team", "role": "viewer"}},
			"executionGrants": []interface{}{map[string]interface{}{
				"namespace": "team", "workspaces": []interface{}{"vm"},
				"permissions": []interface{}{string(PermissionExec), string(PermissionShell)},
			}},
		},
		"status": map[string]interface{}{"personalNamespace": "personal"},
	}}
}

func TestExecutionPermissionScopeAndElevation(t *testing.T) {
	now := time.Now()
	expired := now.Add(-time.Second)
	user := &UserInfo{UID: "u", Role: "viewer", Namespaces: []string{"team"}, PersonalNamespace: "personal",
		ExecutionGrants: []ExecutionGrant{
			{Namespace: "team", Workspaces: []string{"vm"}, Permissions: []ExecutionPermission{PermissionShell}},
			{Namespace: "team", Permissions: []ExecutionPermission{PermissionExec}},
			{Namespace: "other", Permissions: []ExecutionPermission{PermissionShell}},
			{Namespace: "team", Permissions: []ExecutionPermission{PermissionElevated}, ExpiresAt: &expired},
		},
	}
	for _, tt := range []struct {
		name, namespace, workspace string
		permission                 ExecutionPermission
		allowed                    bool
	}{
		{"explicit shell", "team", "vm", PermissionShell, true},
		{"namespace exec", "team", "second", PermissionExec, true},
		{"workspace restriction", "team", "second", PermissionShell, false},
		{"no implicit personal permission", "personal", "vm", PermissionShell, false},
		{"grant not membership", "other", "vm", PermissionShell, false},
		{"expired elevation", "team", "vm", PermissionElevated, false},
		{"no recording permission", "team", "vm", PermissionReadRecordings, false},
		{"unknown permission", "team", "vm", "workspace.*", false},
		{"namespace wildcard", "*", "vm", PermissionShell, false},
		{"workspace wildcard", "team", "*", PermissionShell, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasExecutionPermission(user, tt.namespace, tt.workspace, tt.permission, now); got != tt.allowed {
				t.Fatalf("permission=%v, want %v", got, tt.allowed)
			}
		})
	}
	if HasExecutionPermission(nil, "team", "vm", PermissionExec, now) {
		t.Fatal("anonymous user authorized")
	}
	user.Role = "admin"
	if !HasExecutionPermission(user, "other", "vm", PermissionReadRecordings, now) {
		t.Fatal("administrator lacks permission")
	}
	user.MustChangePassword = true
	if HasExecutionPermission(user, "team", "vm", PermissionExec, now) {
		t.Fatal("password-change requirement bypassed")
	}
	user.MustChangePassword, user.UID = false, ""
	if HasExecutionPermission(user, "team", "vm", PermissionExec, now) {
		t.Fatal("unbound principal authorized")
	}
}

func TestParseExecutionGrantsRejectsWideningAndMalformedInput(t *testing.T) {
	for _, raw := range []interface{}{
		nil,
		map[string]interface{}{},
		[]interface{}{map[string]interface{}{"namespace": "*", "permissions": []interface{}{string(PermissionExec)}}},
		[]interface{}{map[string]interface{}{"namespace": "team", "workpaces": []interface{}{"vm"}, "permissions": []interface{}{string(PermissionExec)}}},
		[]interface{}{map[string]interface{}{"namespace": "team", "permissions": []interface{}{"workspace.*"}}},
		[]interface{}{map[string]interface{}{"namespace": "team", "permissions": []interface{}{string(PermissionExec), string(PermissionExec)}}},
		[]interface{}{map[string]interface{}{"namespace": "team", "permissions": []interface{}{string(PermissionExec)}, "expiresAt": "yesterday"}},
		[]interface{}{map[string]interface{}{"namespace": "team", "permissions": []interface{}{string(PermissionExec)}, "workspaces": []interface{}{"*"}}},
	} {
		if _, err := ParseExecutionGrants(raw); err == nil {
			t.Fatalf("accepted invalid grant: %#v", raw)
		}
	}
	if grants, err := ParseExecutionGrants([]interface{}{}); err != nil || len(grants) != 0 {
		t.Fatalf("cannot revoke all grants: %v", err)
	}
}

func TestExecutionAuthorizationRechecksCurrentIdentity(t *testing.T) {
	ctx := context.Background()
	client := newFakeDynamicClient(t)
	user := executionUserFixture("user@example.com", "viewer")
	if _, err := client.Resource(userGVR).Create(ctx, user, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	provider := &ConfigProvider{dynamicClient: client, config: testDeviceConfig(), lastFetch: time.Now(), cacheDuration: time.Hour}
	// The stale admin claim must not elevate the current viewer.
	token, err := CreateSessionToken("user@example.com", "User", "admin", nil, []byte(testSigningKey), time.Hour, "user-uid")
	if err != nil {
		t.Fatal(err)
	}
	authorize := func(op ExecutionPermission, elevated bool) (*UserInfo, error) {
		return provider.AuthorizeExecution(ctx, token, "team", "vm", op, elevated, time.Now())
	}
	if principal, err := authorize(PermissionExec, false); err != nil || principal.Role != "viewer" {
		t.Fatalf("delegated viewer denied or stale role used: %v, %v", principal, err)
	}
	if _, err := authorize(PermissionExec, true); err == nil {
		t.Fatal("ordinary permission allowed elevation")
	}
	if _, err := authorize(PermissionReadRecordings, false); err == nil {
		t.Fatal("execution allowed transcript disclosure")
	}
	update := func() {
		t.Helper()
		if _, err := client.Resource(userGVR).Update(ctx, user, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	grants, _, _ := unstructured.NestedSlice(user.Object, "spec", "executionGrants")
	grants = append(grants, map[string]interface{}{"namespace": "team", "workspaces": []interface{}{"vm"}, "permissions": []interface{}{string(PermissionElevated)}})
	_ = unstructured.SetNestedSlice(user.Object, grants, "spec", "executionGrants")
	update()
	if _, err := authorize(PermissionExec, true); err != nil {
		t.Fatalf("separately granted elevation denied: %v", err)
	}
	// Revoking grants must affect the same still-valid token on its next renewal.
	_ = unstructured.SetNestedSlice(user.Object, []interface{}{}, "spec", "executionGrants")
	update()
	if _, err := authorize(PermissionExec, false); err == nil {
		t.Fatal("grant revocation did not take effect")
	}
	_ = unstructured.SetNestedField(user.Object, "admin", "spec", "role")
	update()
	if _, err := authorize(PermissionShell, true); err != nil {
		t.Fatalf("current admin denied: %v", err)
	}
	_ = unstructured.SetNestedField(user.Object, true, "spec", "disabled")
	update()
	if _, err := authorize(PermissionExec, false); err == nil {
		t.Fatal("disabled admin authorized")
	}
	_ = unstructured.SetNestedField(user.Object, false, "spec", "disabled")
	user.SetUID("replacement-user")
	update()
	if _, err := authorize(PermissionExec, false); err == nil {
		t.Fatal("credential adopted a replacement User")
	}
	if err := client.Resource(userGVR).Delete(ctx, user.GetName(), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := authorize(PermissionExec, false); err == nil {
		t.Fatal("deleted user authorized")
	}
}

func TestExecutionAuthorizationRejectsUnavailableOrUnboundIdentity(t *testing.T) {
	ctx := context.Background()
	client := newFakeDynamicClient(t)
	user := executionUserFixture("admin@example.com", "admin")
	if _, err := client.Resource(userGVR).Create(ctx, user, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	provider := &ConfigProvider{dynamicClient: client, config: testDeviceConfig(), lastFetch: time.Now(), cacheDuration: time.Hour}
	legacyToken, _ := CreateSessionToken("admin@example.com", "Admin", "admin", nil, []byte(testSigningKey), time.Hour)
	if _, err := provider.AuthorizeExecution(ctx, legacyToken, "team", "vm", PermissionExec, true, time.Now()); err == nil {
		t.Fatal("unbound legacy credential authorized execution")
	}
	boundToken, _ := CreateSessionToken("admin@example.com", "Admin", "admin", nil, []byte(testSigningKey), time.Hour, "user-uid")
	provider.config.Enabled = false
	if _, err := provider.AuthorizeExecution(ctx, boundToken, "team", "vm", PermissionExec, true, time.Now()); err == nil {
		t.Fatal("auth-disabled execution authorized")
	}
	provider.config.Enabled = true
	client.(*fake.FakeDynamicClient).PrependReactor("list", "users", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("user lookup outage")
	})
	if _, err := provider.AuthorizeExecution(ctx, boundToken, "team", "vm", PermissionExec, true, time.Now()); err == nil {
		t.Fatal("user lookup failure authorized execution")
	}
}
