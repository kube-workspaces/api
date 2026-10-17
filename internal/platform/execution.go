package platform

import (
	"context"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// VMExecutionPolicy mirrors the controller-owned PlatformConfig schema. Full
// recording is mandatory and cannot be disabled by this policy.
type VMExecutionPolicy struct {
	Enabled       bool `json:"enabled"`
	AllowElevated bool `json:"allowElevated"`
}

// GetVMExecutionPolicy deliberately bypasses the legacy fail-open/cache path
// used by maintenance/form configuration. Admission and lease renewal require a
// current policy read; unavailable or malformed configuration never enables exec.
func (p *ConfigProvider) GetVMExecutionPolicy(ctx context.Context) (VMExecutionPolicy, error) {
	obj, err := p.GetPlatformConfig(ctx)
	if err != nil {
		return VMExecutionPolicy{}, fmt.Errorf("VM execution policy unavailable: %w", err)
	}
	raw, found, err := unstructured.NestedMap(obj.Object, "spec", "vmExecution")
	if err != nil {
		return VMExecutionPolicy{}, fmt.Errorf("invalid VM execution policy: %w", err)
	}
	if !found {
		return VMExecutionPolicy{}, nil
	}
	for key, value := range raw {
		if key != "enabled" && key != "allowElevated" {
			return VMExecutionPolicy{}, fmt.Errorf("unknown VM execution policy field %q", key)
		}
		if _, ok := value.(bool); !ok {
			return VMExecutionPolicy{}, fmt.Errorf("VM execution policy %s must be boolean", key)
		}
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return VMExecutionPolicy{}, err
	}
	var policy VMExecutionPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return VMExecutionPolicy{}, err
	}
	return policy, nil
}
