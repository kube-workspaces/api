package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var authConfigGVR = schema.GroupVersionResource{
	Group:    "kubeworkspaces.io",
	Version:  "v1alpha1",
	Resource: "authconfigs",
}

var userGVR = schema.GroupVersionResource{
	Group:    "kubeworkspaces.io",
	Version:  "v1alpha1",
	Resource: "users",
}

var secretGVR = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "secrets",
}

// LocalAuthSystemNamespace is where local-auth password Secrets live,
// regardless of a user's personal namespace. Matches the controller's
// bootstrap-admin convention.
const LocalAuthSystemNamespace = "kube-workspaces-system"

// Config holds the resolved authentication configuration.
type Config struct {
	Enabled                 bool
	IssuerURL               string
	ClientID                string
	ClientSecret            string
	Scopes                  []string
	UsernameClaim           string
	GroupsClaim             string
	SigningKey               []byte
	TokenExpiry             time.Duration
	RefreshExpiry           time.Duration
	PersonalNamespaces      PersonalNamespacesConfig
	Registration            RegistrationConfig
	AdminEmails             []string
	RestrictNamespaceAccess bool
	LocalAuthEnabled        bool
}

// PersonalNamespacesConfig holds personal namespace settings.
type PersonalNamespacesConfig struct {
	Enabled  bool
	Template string
}

// RegistrationConfig holds user registration settings.
type RegistrationConfig struct {
	AutoProvision   bool
	DefaultRole     string
	AllowedDomains  []string
	AllowedEmails   []string
	RequireApproval bool
}

// ConfigProvider loads and caches the AuthConfig from Kubernetes.
type ConfigProvider struct {
	dynamicClient dynamic.Interface
	mu            sync.RWMutex
	config        *Config
	lastFetch     time.Time
	cacheDuration time.Duration
}

// NewConfigProvider creates a new ConfigProvider.
func NewConfigProvider(dynamicClient dynamic.Interface) *ConfigProvider {
	return &ConfigProvider{
		dynamicClient: dynamicClient,
		cacheDuration: 30 * time.Second,
	}
}

// GetConfig returns the current auth configuration, fetching from Kubernetes if needed.
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

// Refresh forces a reload of the configuration.
func (p *ConfigProvider) refresh(ctx context.Context) (*Config, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.config != nil && time.Since(p.lastFetch) < p.cacheDuration {
		return p.config, nil
	}

	cfg, err := p.loadFromCluster(ctx)
	if err != nil {
		// If we can't load, default to auth disabled
		cfg = &Config{Enabled: false}
	}
	p.config = cfg
	p.lastFetch = time.Now()
	return cfg, nil
}

func (p *ConfigProvider) loadFromCluster(ctx context.Context) (*Config, error) {
	obj, err := p.dynamicClient.Resource(authConfigGVR).Get(ctx, "default", metav1.GetOptions{})
	if err != nil {
		return &Config{Enabled: false}, nil
	}

	cfg := &Config{
		Enabled:     false,
		TokenExpiry: 24 * time.Hour,
	}

	// Parse spec.enabled
	enabled, _, _ := unstructured.NestedBool(obj.Object, "spec", "enabled")
	cfg.Enabled = enabled

	if !enabled {
		return cfg, nil
	}

	// Parse OIDC config
	issuerURL, _, _ := unstructured.NestedString(obj.Object, "spec", "oidc", "issuerURL")
	cfg.IssuerURL = issuerURL

	clientID, _, _ := unstructured.NestedString(obj.Object, "spec", "oidc", "clientID")
	cfg.ClientID = clientID

	usernameClaim, _, _ := unstructured.NestedString(obj.Object, "spec", "oidc", "usernameClaim")
	if usernameClaim == "" {
		usernameClaim = "email"
	}
	cfg.UsernameClaim = usernameClaim

	groupsClaim, _, _ := unstructured.NestedString(obj.Object, "spec", "oidc", "groupsClaim")
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	cfg.GroupsClaim = groupsClaim

	scopes, _, _ := unstructured.NestedStringSlice(obj.Object, "spec", "oidc", "scopes")
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	cfg.Scopes = scopes

	// Parse session config
	tokenExpiry, _, _ := unstructured.NestedString(obj.Object, "spec", "session", "tokenExpiry")
	if tokenExpiry != "" {
		if d, err := time.ParseDuration(tokenExpiry); err == nil {
			cfg.TokenExpiry = d
		}
	}

	// Parse personal namespaces config
	nsEnabled, _, _ := unstructured.NestedBool(obj.Object, "spec", "personalNamespaces", "enabled")
	nsTemplate, _, _ := unstructured.NestedString(obj.Object, "spec", "personalNamespaces", "template")
	if nsTemplate == "" {
		nsTemplate = "{{username}}"
	}
	cfg.PersonalNamespaces = PersonalNamespacesConfig{
		Enabled:  nsEnabled,
		Template: nsTemplate,
	}

	// Parse registration config
	autoProvision, _, _ := unstructured.NestedBool(obj.Object, "spec", "registration", "autoProvision")
	defaultRole, _, _ := unstructured.NestedString(obj.Object, "spec", "registration", "defaultRole")
	if defaultRole == "" {
		defaultRole = "editor"
	}
	allowedDomains, _, _ := unstructured.NestedStringSlice(obj.Object, "spec", "registration", "allowedDomains")
	allowedEmails, _, _ := unstructured.NestedStringSlice(obj.Object, "spec", "registration", "allowedEmails")
	requireApproval, _, _ := unstructured.NestedBool(obj.Object, "spec", "registration", "requireApproval")
	cfg.Registration = RegistrationConfig{
		AutoProvision:   autoProvision,
		DefaultRole:     defaultRole,
		AllowedDomains:  allowedDomains,
		AllowedEmails:   allowedEmails,
		RequireApproval: requireApproval,
	}

	// Parse admin emails
	adminEmails, _, _ := unstructured.NestedStringSlice(obj.Object, "spec", "adminEmails")
	cfg.AdminEmails = adminEmails

	// Parse authorization config
	restrictNS, _, _ := unstructured.NestedBool(obj.Object, "spec", "authorization", "restrictNamespaceAccess")
	cfg.RestrictNamespaceAccess = restrictNS

	// Parse local auth config
	localAuthEnabled, _, _ := unstructured.NestedBool(obj.Object, "spec", "localAuth", "enabled")
	cfg.LocalAuthEnabled = localAuthEnabled

	// Load secrets (client secret and signing key)
	clientSecretRef, _, _ := unstructured.NestedString(obj.Object, "spec", "oidc", "clientSecret", "name")
	clientSecretKey, _, _ := unstructured.NestedString(obj.Object, "spec", "oidc", "clientSecret", "key")
	if clientSecretRef != "" && clientSecretKey != "" {
		secret, err := p.getSecret(ctx, clientSecretRef, clientSecretKey)
		if err == nil {
			cfg.ClientSecret = secret
		}
	}

	signingKeyRef, _, _ := unstructured.NestedString(obj.Object, "spec", "session", "signingKey", "name")
	signingKeyKey, _, _ := unstructured.NestedString(obj.Object, "spec", "session", "signingKey", "key")
	if signingKeyRef != "" && signingKeyKey != "" {
		secret, err := p.getSecret(ctx, signingKeyRef, signingKeyKey)
		if err == nil {
			cfg.SigningKey = []byte(secret)
		}
	}

	return cfg, nil
}

func (p *ConfigProvider) getSecret(ctx context.Context, name, key string) (string, error) {
	// Try kube-workspaces-system namespace first, then default
	for _, ns := range []string{"kube-workspaces-system", "default"} {
		obj, err := p.dynamicClient.Resource(secretGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			continue
		}

		data, found, _ := unstructured.NestedMap(obj.Object, "data")
		if !found {
			continue
		}

		val, ok := data[key].(string)
		if !ok {
			continue
		}

		// Secret .data values are base64-encoded by the Kubernetes API
		decoded, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			// If decoding fails, the value might already be plain text (e.g. from stringData)
			return val, nil
		}
		return string(decoded), nil
	}
	return "", fmt.Errorf("secret %s/%s not found", name, key)
}

// GetUser fetches a User CR by name.
func (p *ConfigProvider) GetUser(ctx context.Context, name string) (*unstructured.Unstructured, error) {
	return p.dynamicClient.Resource(userGVR).Get(ctx, name, metav1.GetOptions{})
}

// GetUserByEmail fetches a User CR by email (list and filter).
func (p *ConfigProvider) GetUserByEmail(ctx context.Context, email string) (*unstructured.Unstructured, error) {
	list, err := p.dynamicClient.Resource(userGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, item := range list.Items {
		userEmail, _, _ := unstructured.NestedString(item.Object, "spec", "email")
		if userEmail == email {
			return &item, nil
		}
	}
	return nil, fmt.Errorf("user with email %s not found", email)
}

// ListUsers returns all User CRs.
func (p *ConfigProvider) ListUsers(ctx context.Context) (*unstructured.UnstructuredList, error) {
	return p.dynamicClient.Resource(userGVR).List(ctx, metav1.ListOptions{})
}

// CreateUser creates a new User CR.
func (p *ConfigProvider) CreateUser(ctx context.Context, user *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	return p.dynamicClient.Resource(userGVR).Create(ctx, user, metav1.CreateOptions{})
}

// UpdateUser updates an existing User CR.
func (p *ConfigProvider) UpdateUser(ctx context.Context, user *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	return p.dynamicClient.Resource(userGVR).Update(ctx, user, metav1.UpdateOptions{})
}

// UpdateUserStatus updates the status subresource of a User CR.
func (p *ConfigProvider) UpdateUserStatus(ctx context.Context, user *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	return p.dynamicClient.Resource(userGVR).UpdateStatus(ctx, user, metav1.UpdateOptions{})
}

// DeleteUser deletes a User CR by name.
func (p *ConfigProvider) DeleteUser(ctx context.Context, name string) error {
	return p.dynamicClient.Resource(userGVR).Delete(ctx, name, metav1.DeleteOptions{})
}

// GetAuthConfig returns the raw AuthConfig CR.
func (p *ConfigProvider) GetAuthConfig(ctx context.Context) (*unstructured.Unstructured, error) {
	return p.dynamicClient.Resource(authConfigGVR).Get(ctx, "default", metav1.GetOptions{})
}

// UpdateAuthConfig updates the AuthConfig CR.
func (p *ConfigProvider) UpdateAuthConfig(ctx context.Context, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	return p.dynamicClient.Resource(authConfigGVR).Update(ctx, obj, metav1.UpdateOptions{})
}

// InvalidateCache forces the config to be reloaded on next access.
func (p *ConfigProvider) InvalidateCache() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastFetch = time.Time{}
}

// GetPasswordSecret fetches the raw Secret backing a local user's password,
// from LocalAuthSystemNamespace.
func (p *ConfigProvider) GetPasswordSecret(ctx context.Context, name string) (*unstructured.Unstructured, error) {
	return p.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Get(ctx, name, metav1.GetOptions{})
}

// CreatePasswordSecret creates a new Secret holding a local user's bcrypt
// password hash (and, transiently, plaintext password) in LocalAuthSystemNamespace.
func (p *ConfigProvider) CreatePasswordSecret(ctx context.Context, name, passwordHash, plaintextPassword string) error {
	stringData := map[string]interface{}{
		"passwordHash": passwordHash,
	}
	if plaintextPassword != "" {
		stringData["password"] = plaintextPassword
	}
	secret := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": LocalAuthSystemNamespace,
				"labels": map[string]interface{}{
					"kubeworkspaces.io/managed-by": "kube-workspaces-api",
				},
			},
			"type":       "Opaque",
			"stringData": stringData,
		},
	}
	_, err := p.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Create(ctx, secret, metav1.CreateOptions{})
	return err
}

// UpdatePasswordHash replaces the password hash in an existing Secret and
// removes any plaintext password key (used once a user sets their own password).
func (p *ConfigProvider) UpdatePasswordHash(ctx context.Context, name, newHash string) error {
	secret, err := p.GetPasswordSecret(ctx, name)
	if err != nil {
		return err
	}
	// stringData is write-only from the API's perspective once persisted (it
	// gets merged into .data by the API server), so we must operate on .data
	// directly using base64-encoded values.
	data, _, _ := unstructured.NestedMap(secret.Object, "data")
	if data == nil {
		data = make(map[string]interface{})
	}
	data["passwordHash"] = base64.StdEncoding.EncodeToString([]byte(newHash))
	delete(data, "password")
	if err := unstructured.SetNestedMap(secret.Object, data, "data"); err != nil {
		return err
	}
	_, err = p.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

// DeletePasswordSecret deletes a local user's password Secret.
func (p *ConfigProvider) DeletePasswordSecret(ctx context.Context, name string) error {
	err := p.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		return err
	}
	return nil
}

// GetPasswordHash extracts the bcrypt hash from a password Secret's .data.
func GetPasswordHash(secret *unstructured.Unstructured) (string, error) {
	return getSecretDataValue(secret, "passwordHash")
}

func getSecretDataValue(secret *unstructured.Unstructured, key string) (string, error) {
	data, found, _ := unstructured.NestedMap(secret.Object, "data")
	if !found {
		return "", fmt.Errorf("secret has no data")
	}
	val, ok := data[key].(string)
	if !ok {
		return "", fmt.Errorf("secret has no key %q", key)
	}
	decoded, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return val, nil
	}
	return string(decoded), nil
}
