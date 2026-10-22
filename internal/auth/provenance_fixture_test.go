package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Existing transport/authorization fixtures now use credentials with a real
// backing method/revision. Tests specifically exercising legacy rejection keep
// their pre-provenance credentials instead of calling this helper.
func methodBoundTestToken(t *testing.T, p *ConfigProvider, raw string) string {
	t.Helper()
	ctx := context.Background()
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	token := &SessionToken{}
	if err := json.Unmarshal(payload, token); err != nil {
		t.Fatal(err)
	}
	u, err := p.GetUserByEmail(ctx, token.Email)
	if err != nil {
		t.Fatal(err)
	}
	if token.UserUID == "" {
		token.UserUID = string(u.GetUID())
	}
	bindings, err := identityBindings(u)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) > 0 {
		token.SessionProvenance, err = p.identityProvenance(ctx, u, bindings[0])
		if err != nil {
			t.Fatal(err)
		}
	} else {
		name, _, refErr := passwordReference(u)
		if refErr != nil {
			name = "test-password-" + u.GetName()
			_ = unstructured.SetNestedMap(u.Object, map[string]interface{}{"enabled": true, "passwordSecretRef": map[string]interface{}{"name": name, "key": "passwordHash"}}, "spec", "localAuth")
			if _, err := p.UpdateUser(ctx, u); err != nil {
				t.Fatal(err)
			}
			_, err = p.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Create(ctx, &unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "v1", "kind": "Secret", "metadata": map[string]interface{}{"name": name, "namespace": LocalAuthSystemNamespace},
				"data": map[string]interface{}{"passwordHash": base64.StdEncoding.EncodeToString([]byte("test-bcrypt-material"))},
			}}, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
		}
		secret, err := p.GetPasswordSecret(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		version, _, err := localCredentialState(u, secret)
		if err != nil {
			t.Fatal(err)
		}
		token.SessionProvenance = SessionProvenance{AuthMethod: "local", CredentialVersion: version}
	}
	result, err := signSessionToken(*token, p.config.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
