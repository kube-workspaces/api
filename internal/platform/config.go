package platform

import (
	"context"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var platformConfigGVR = schema.GroupVersionResource{
	Group:    "kubeworkspaces.io",
	Version:  "v1alpha1",
	Resource: "platformconfigs",
}

// Config holds the resolved platform configuration.
type Config struct {
	Maintenance    MaintenanceConfig
	FormFieldLocks []FormFieldLock
}

// MaintenanceConfig holds maintenance mode settings.
type MaintenanceConfig struct {
	Enabled bool   `json:"enabled"`
	Message string `json:"message,omitempty"`
}

// FormFieldLock defines a locked form field and its enforced value.
type FormFieldLock struct {
	Field   string `json:"field"`
	Value   string `json:"value,omitempty"`
	Message string `json:"message,omitempty"`
}

// ConfigProvider loads and caches the PlatformConfig from Kubernetes.
type ConfigProvider struct {
	dynamicClient dynamic.Interface
	mu            sync.RWMutex
	config        *Config
	lastFetch     time.Time
	cacheDuration time.Duration
}

// NewConfigProvider creates a new PlatformConfig provider.
func NewConfigProvider(dynamicClient dynamic.Interface) *ConfigProvider {
	return &ConfigProvider{
		dynamicClient: dynamicClient,
		cacheDuration: 30 * time.Second,
	}
}

// GetConfig returns the current platform configuration, fetching from Kubernetes if needed.
func (p *ConfigProvider) GetConfig(ctx context.Context) (*Config, error) {
	p.mu.RLock()
	if p.config != nil && time.Since(p.lastFetch) < p.cacheDuration {
		cfg := p.config
		p.mu.RUnlock()
		return cfg, nil
	}
	p.mu.RUnlock()

	return p.refresh(ctx)
}

func (p *ConfigProvider) refresh(ctx context.Context) (*Config, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.config != nil && time.Since(p.lastFetch) < p.cacheDuration {
		return p.config, nil
	}

	cfg, err := p.loadFromCluster(ctx)
	if err != nil {
		// If we can't load, return empty config (maintenance off, no locks)
		cfg = &Config{}
	}
	p.config = cfg
	p.lastFetch = time.Now()
	return cfg, nil
}

func (p *ConfigProvider) loadFromCluster(ctx context.Context) (*Config, error) {
	obj, err := p.dynamicClient.Resource(platformConfigGVR).Get(ctx, "default", metav1.GetOptions{})
	if err != nil {
		return &Config{}, nil
	}

	cfg := &Config{}

	// Parse maintenance config
	maintenanceEnabled, _, _ := unstructured.NestedBool(obj.Object, "spec", "maintenance", "enabled")
	maintenanceMessage, _, _ := unstructured.NestedString(obj.Object, "spec", "maintenance", "message")
	cfg.Maintenance = MaintenanceConfig{
		Enabled: maintenanceEnabled,
		Message: maintenanceMessage,
	}

	// Parse form field locks
	lockedFieldsRaw, found, _ := unstructured.NestedSlice(obj.Object, "spec", "form", "lockedFields")
	if found {
		for _, item := range lockedFieldsRaw {
			if m, ok := item.(map[string]interface{}); ok {
				lock := FormFieldLock{}
				if field, ok := m["field"].(string); ok {
					lock.Field = field
				}
				if value, ok := m["value"].(string); ok {
					lock.Value = value
				}
				if message, ok := m["message"].(string); ok {
					lock.Message = message
				}
				if lock.Field != "" {
					cfg.FormFieldLocks = append(cfg.FormFieldLocks, lock)
				}
			}
		}
	}

	return cfg, nil
}

// GetPlatformConfig returns the raw PlatformConfig CR.
func (p *ConfigProvider) GetPlatformConfig(ctx context.Context) (*unstructured.Unstructured, error) {
	return p.dynamicClient.Resource(platformConfigGVR).Get(ctx, "default", metav1.GetOptions{})
}

// UpdatePlatformConfig updates the PlatformConfig CR.
func (p *ConfigProvider) UpdatePlatformConfig(ctx context.Context, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	return p.dynamicClient.Resource(platformConfigGVR).Update(ctx, obj, metav1.UpdateOptions{})
}

// CreatePlatformConfig creates the PlatformConfig CR.
func (p *ConfigProvider) CreatePlatformConfig(ctx context.Context, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	return p.dynamicClient.Resource(platformConfigGVR).Create(ctx, obj, metav1.CreateOptions{})
}

// InvalidateCache forces the config to be reloaded on next access.
func (p *ConfigProvider) InvalidateCache() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastFetch = time.Time{}
}
