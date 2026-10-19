package platform

import (
	"context"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// AgentUpgradePolicy mirrors the controller-owned PlatformConfig
// spec.agentUpgrades schema. Guest dispatch, artifact verification and fresh
// inventory are mandatory prerequisites, not policy toggles.
type AgentUpgradePolicy struct {
	Enabled bool `json:"enabled"`
}

// GetAgentUpgradePolicy deliberately bypasses the legacy fail-open/cache path
// used by maintenance/form configuration. Agent-upgrade admission requires a
// current policy read; unavailable or malformed configuration never enables
// the surface. Absent configuration is default-off.
func (p *ConfigProvider) GetAgentUpgradePolicy(ctx context.Context) (AgentUpgradePolicy, error) {
	obj, err := p.GetPlatformConfig(ctx)
	if err != nil {
		return AgentUpgradePolicy{}, fmt.Errorf("agent upgrade policy unavailable: %w", err)
	}
	raw, found, err := unstructured.NestedMap(obj.Object, "spec", "agentUpgrades")
	if err != nil {
		return AgentUpgradePolicy{}, fmt.Errorf("invalid agent upgrade policy: %w", err)
	}
	if !found {
		return AgentUpgradePolicy{}, nil
	}
	for key, value := range raw {
		if key != "enabled" {
			return AgentUpgradePolicy{}, fmt.Errorf("unknown agent upgrade policy field %q", key)
		}
		if _, ok := value.(bool); !ok {
			return AgentUpgradePolicy{}, fmt.Errorf("agent upgrade policy %s must be boolean", key)
		}
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return AgentUpgradePolicy{}, err
	}
	var policy AgentUpgradePolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return AgentUpgradePolicy{}, err
	}
	return policy, nil
}
