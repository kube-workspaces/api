package kubeworkspaces

import (
	"encoding/base64"

	"github.com/kube-workspaces/api/internal/auth"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func methodCredentialFixture(user *unstructured.Unstructured) (*unstructured.Unstructured, auth.SessionProvenance) {
	name, hash := "fixture-password-"+user.GetName(), "fixture-bcrypt-material"
	_ = unstructured.SetNestedMap(user.Object, map[string]interface{}{"enabled": true, "passwordSecretRef": map[string]interface{}{"name": name, "key": "passwordHash"}}, "spec", "localAuth")
	secret := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Secret", "metadata": map[string]interface{}{"name": name, "namespace": auth.LocalAuthSystemNamespace},
		"data": map[string]interface{}{"passwordHash": base64.StdEncoding.EncodeToString([]byte(hash))},
	}}
	return secret, auth.SessionProvenance{AuthMethod: "local", CredentialVersion: auth.LocalCredentialVersion(string(user.GetUID()), name, "passwordHash", hash)}
}
