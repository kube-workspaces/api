package platform

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestAgentUpgradePolicyIsCurrentAndDefaultOff(t *testing.T) {
	ctx := context.Background()
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "PlatformConfig",
		"metadata": map[string]interface{}{"name": "default"},
		"spec":     map[string]interface{}{},
	}}
	client := fake.NewSimpleDynamicClient(runtime.NewScheme(), obj)
	provider := NewConfigProvider(client)
	// Absent configuration is default-off, never fail-open.
	policy, err := provider.GetAgentUpgradePolicy(ctx)
	if err != nil || policy.Enabled {
		t.Fatalf("absent policy must be default-off: %+v %v", policy, err)
	}
	for _, raw := range []map[string]interface{}{
		{},
		{"enabled": true},
		{"enabled": false},
	} {
		if err := unstructured.SetNestedMap(obj.Object, raw, "spec", "agentUpgrades"); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Resource(platformConfigGVR).Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		policy, err := provider.GetAgentUpgradePolicy(ctx)
		if err != nil || policy.Enabled != (raw["enabled"] == true) {
			t.Fatalf("stale/invalid policy: %v, %v", policy, err)
		}
	}
	// Strict schema: unknown fields and wrong types never enable the surface.
	for _, raw := range []map[string]interface{}{
		{"enabled": "true"},
		{"enable": true},
		{"enabled": true, "somethingElse": true},
	} {
		_ = unstructured.SetNestedMap(obj.Object, raw, "spec", "agentUpgrades")
		if _, err := client.Resource(platformConfigGVR).Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if policy, err := provider.GetAgentUpgradePolicy(ctx); err == nil || policy.Enabled {
			t.Fatalf("malformed policy allowed: %v, %v", policy, err)
		}
	}
	client.PrependReactor("get", "platformconfigs", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("cluster unavailable")
	})
	if policy, err := provider.GetAgentUpgradePolicy(ctx); err == nil || policy.Enabled {
		t.Fatalf("outage allowed upgrades: %v, %v", policy, err)
	}
}
