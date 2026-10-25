package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const identityVersionAnnotation = "kubeworkspaces.io/credential-version"

// SessionProvenance travels unchanged through native/browser grants and devices.
type SessionProvenance struct {
	AuthMethod        string `json:"auth_method,omitempty"`
	CredentialVersion string `json:"credential_version,omitempty"`
	Issuer            string `json:"issuer,omitempty"`
	Subject           string `json:"subject,omitempty"`
}

// LocalCredentialVersion is an opaque revision, not the password hash itself.
// Keep the wire construction aligned with proxy/internal/auth/provenance.go.
func LocalCredentialVersion(uid, secretName, key, passwordHash string) string {
	data, _ := json.Marshal([]string{uid, secretName, key, passwordHash})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func passwordReference(user *unstructured.Unstructured) (string, string, error) {
	name, _, err := unstructured.NestedString(user.Object, "spec", "localAuth", "passwordSecretRef", "name")
	if err != nil || name == "" {
		return "", "", fmt.Errorf("password reference unavailable")
	}
	key, _, err := unstructured.NestedString(user.Object, "spec", "localAuth", "passwordSecretRef", "key")
	if err != nil {
		return "", "", err
	}
	if key == "" {
		key = "passwordHash"
	}
	return name, key, nil
}

func localCredentialState(user, secret *unstructured.Unstructured) (string, bool, error) {
	if err := validatePasswordOwner(user, secret); err != nil {
		return "", false, err
	}
	if secret.GetDeletionTimestamp() != nil {
		return "", false, fmt.Errorf("password credential deleting")
	}
	name, key, err := passwordReference(user)
	if err != nil {
		return "", false, err
	}
	hash, err := getSecretDataValue(secret, key)
	if err != nil || hash == "" {
		return "", false, fmt.Errorf("password credential unavailable")
	}
	mustChange, _, err := unstructured.NestedBool(user.Object, "spec", "localAuth", "mustChangePassword")
	if err != nil {
		return "", false, err
	}
	// This value changes atomically with the hash. The User flag may tighten
	// policy too, but clearing it cannot bypass a Secret's temporary-password flag.
	_, policyPresent, fieldErr := unstructured.NestedFieldNoCopy(secret.Object, "data", "mustChangePassword")
	if fieldErr != nil {
		return "", false, fieldErr
	}
	if policyPresent {
		policy, policyErr := getSecretDataValue(secret, "mustChangePassword")
		if policyErr != nil {
			return "", false, policyErr
		}
		if policy != "true" && policy != "false" {
			return "", false, fmt.Errorf("invalid password policy")
		}
		mustChange = mustChange || policy == "true"
	}
	return LocalCredentialVersion(string(user.GetUID()), name, key, hash), mustChange, nil
}

func identityCredentialVersion(claim *unstructured.Unstructured) (string, error) {
	if claim.GetDeletionTimestamp() != nil {
		return "", fmt.Errorf("identity credential deleting")
	}
	if version := claim.GetAnnotations()[identityVersionAnnotation]; version != "" {
		return version, nil
	}
	if claim.GetUID() != "" {
		return "uid:" + string(claim.GetUID()), nil
	}
	return "", fmt.Errorf("identity credential version unavailable")
}

func (p *ConfigProvider) identityProvenance(ctx context.Context, user *unstructured.Unstructured, id ExternalIdentity) (SessionProvenance, error) {
	claim, err := p.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Get(ctx, id.claimName(), metav1.GetOptions{})
	if err != nil {
		return SessionProvenance{}, err
	}
	if !claimMatches(claim, id, user) {
		return SessionProvenance{}, ErrIdentityConflict
	}
	version, err := identityCredentialVersion(claim)
	return SessionProvenance{AuthMethod: "oidc", CredentialVersion: version, Issuer: id.Issuer, Subject: id.Subject}, err
}

func (p *ConfigProvider) validateProvenance(ctx context.Context, token *SessionToken, user *unstructured.Unstructured) (bool, error) {
	if token.UserUID == "" || token.UserUID != string(user.GetUID()) || token.CredentialVersion == "" {
		return false, fmt.Errorf("fresh sign-in required for method-bound credentials")
	}
	switch token.AuthMethod {
	case "local":
		if token.Issuer != "" || token.Subject != "" {
			return false, fmt.Errorf("invalid local provenance")
		}
		enabled, _, err := unstructured.NestedBool(user.Object, "spec", "localAuth", "enabled")
		if err != nil || !enabled {
			return false, fmt.Errorf("local credential disabled")
		}
		name, _, err := passwordReference(user)
		if err != nil {
			return false, err
		}
		secret, err := p.GetPasswordSecret(ctx, name)
		if err != nil {
			return false, err
		}
		version, restricted, err := localCredentialState(user, secret)
		if err != nil {
			return false, err
		}
		if token.CredentialVersion != version {
			return false, fmt.Errorf("local credential has been revoked")
		}
		return restricted, nil
	case "oidc":
		id := ExternalIdentity{Issuer: token.Issuer, Subject: token.Subject}
		bound, err := p.GetUserByIdentity(ctx, id)
		if err != nil {
			return false, err
		}
		if bound.GetUID() != user.GetUID() || bound.GetName() != user.GetName() {
			return false, ErrIdentityConflict
		}
		current, err := p.identityProvenance(ctx, bound, id)
		if err != nil {
			return false, err
		}
		if current.CredentialVersion != token.CredentialVersion {
			return false, fmt.Errorf("external credential has been revoked")
		}
		return false, nil
	default:
		return false, fmt.Errorf("fresh sign-in required for method-bound credentials")
	}
}
