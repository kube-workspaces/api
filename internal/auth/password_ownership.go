package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/util/retry"
)

const passwordUserUIDAnnotation = "kubeworkspaces.io/user-uid"

// UpdateUserSpec publishes an explicitly approved spec without overwriting
// concurrent account edits. Controller finalizer/status writes may be retried,
// but a replacement UID or changed spec requires a fresh administrative decision.
func (p *ConfigProvider) UpdateUserSpec(ctx context.Context, original *unstructured.Unstructured, spec map[string]interface{}) (*unstructured.Unstructured, error) {
	if original.GetUID() == "" {
		return nil, fmt.Errorf("persisted User UID required")
	}
	var updated *unstructured.Unstructured
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := p.GetUser(ctx, original.GetName())
		if err != nil {
			return err
		}
		if current.GetUID() != original.GetUID() || current.GetDeletionTimestamp() != nil || !reflect.DeepEqual(current.Object["spec"], original.Object["spec"]) {
			return fmt.Errorf("account changed; refresh before retrying: %w", ErrIdentityConflict)
		}
		if err := unstructured.SetNestedMap(current.Object, spec, "spec"); err != nil {
			return err
		}
		if role, ok := spec["role"].(string); ok {
			labels := current.GetLabels()
			if labels == nil {
				labels = map[string]string{}
			}
			labels["kubeworkspaces.io/role"] = role
			current.SetLabels(labels)
		}
		updated, err = p.UpdateUser(ctx, current)
		return err
	})
	return updated, err
}

// CreateOwnedPasswordSecret allocates a fresh credential for one persisted UID.
// It never adopts or overwrites an existing Secret. Callers publish its reference
// with a resourceVersion-conditional User update; a losing concurrent operation
// leaves an unreferenced, UID-owned Secret, never another account's credential.
func (p *ConfigProvider) CreateOwnedPasswordSecret(ctx context.Context, user *unstructured.Unstructured, hash, password string) (string, error) {
	if user.GetUID() == "" || user.GetName() == "" || user.GetDeletionTimestamp() != nil {
		return "", fmt.Errorf("a persisted, non-deleting User UID is required")
	}
	nonce, err := generateNativeCode()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(string(user.GetUID()) + ":" + nonce))
	name := fmt.Sprintf("kw-password-%x", sum[:24])
	data := map[string]interface{}{"passwordHash": base64.StdEncoding.EncodeToString([]byte(hash)), "mustChangePassword": base64.StdEncoding.EncodeToString([]byte("true"))}
	if password != "" {
		data["password"] = base64.StdEncoding.EncodeToString([]byte(password))
	}
	secret := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
		"metadata": map[string]interface{}{
			"name": name, "namespace": LocalAuthSystemNamespace,
			"labels":          map[string]interface{}{"kubeworkspaces.io/managed-by": "kube-workspaces-api"},
			"annotations":     map[string]interface{}{passwordUserUIDAnnotation: string(user.GetUID()), "kubeworkspaces.io/user-name": user.GetName()},
			"ownerReferences": []interface{}{map[string]interface{}{"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "User", "name": user.GetName(), "uid": string(user.GetUID())}},
		}, "data": data,
	}}
	_, err = p.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Create(ctx, secret, metav1.CreateOptions{})
	return name, err
}

func validatePasswordOwner(user, secret *unstructured.Unstructured) error {
	uid := secret.GetAnnotations()[passwordUserUIDAnnotation]
	if uid != "" && (uid != string(user.GetUID()) || user.GetUID() == "") {
		return fmt.Errorf("password credential belongs to a different User UID")
	}
	for _, owner := range secret.GetOwnerReferences() {
		if owner.Kind == "User" && (owner.UID != user.GetUID() || owner.Name != user.GetName() || owner.APIVersion != "kubeworkspaces.io/v1alpha1") {
			return fmt.Errorf("password credential owner reference mismatch")
		}
	}
	return nil
}

// Legacy credentials stay readable for upgrades. Mutating shared legacy material
// is refused: an administrative reset migrates just the chosen User instead.
func (p *ConfigProvider) validateExclusivePassword(ctx context.Context, user, secret *unstructured.Unstructured) error {
	if err := validatePasswordOwner(user, secret); err != nil {
		return err
	}
	users, err := p.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, candidate := range users.Items {
		name, _, _ := passwordReference(&candidate)
		if name == secret.GetName() && (candidate.GetUID() != user.GetUID() || candidate.GetName() != user.GetName()) {
			return fmt.Errorf("shared password credential; ask an administrator to reset this account in place")
		}
	}
	return nil
}
