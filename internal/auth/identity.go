package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/util/retry"
)

var (
	ErrIdentityNotBound = errors.New("external identity is not bound")
	ErrIdentityConflict = errors.New("external identity ownership conflict")
)

// ExternalIdentity is an exact OIDC issuer/subject pair. Callers must verify the
// ID token and authorize the linking operation before calling BindIdentity.
type ExternalIdentity struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

func (id ExternalIdentity) validate() error {
	u, err := url.Parse(id.Issuer)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(id.Issuer) > 2048 || id.Subject == "" || len(id.Subject) > 255 {
		return fmt.Errorf("invalid external identity")
	}
	return nil
}

func (id ExternalIdentity) claimName() string {
	// JSON avoids delimiter ambiguities; hash the entire exact pair, never email.
	data, _ := json.Marshal(id)
	sum := sha256.Sum256(data)
	return "kw-identity-" + hex.EncodeToString(sum[:])
}

func identityBindings(user *unstructured.Unstructured) ([]ExternalIdentity, error) {
	entries, _, err := unstructured.NestedSlice(user.Object, "spec", "externalIdentities")
	if err != nil {
		return nil, err
	}
	bindings := make([]ExternalIdentity, 0, len(entries))
	seen := make(map[ExternalIdentity]bool)
	if len(entries) > 20 {
		return nil, fmt.Errorf("too many external identities")
	}
	for _, entry := range entries {
		m, ok := entry.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("malformed external identity")
		}
		issuer, _ := m["issuer"].(string)
		subject, _ := m["subject"].(string)
		id := ExternalIdentity{Issuer: issuer, Subject: subject}
		if err := id.validate(); err != nil {
			return nil, err
		}
		if seen[id] {
			return nil, ErrIdentityConflict
		}
		seen[id] = true
		bindings = append(bindings, id)
	}
	return bindings, nil
}

func identityAccountValid(user *unstructured.Unstructured) bool {
	disabled, _, err := unstructured.NestedBool(user.Object, "spec", "disabled")
	role, _, roleErr := unstructured.NestedString(user.Object, "spec", "role")
	return user.GetUID() != "" && user.GetDeletionTimestamp() == nil && err == nil && !disabled && roleErr == nil && (role == "admin" || role == "editor" || role == "viewer")
}

func (p *ConfigProvider) identityOwners(ctx context.Context, id ExternalIdentity) ([]*unstructured.Unstructured, error) {
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	var owners []*unstructured.Unstructured
	for i := range users.Items {
		bindings, err := identityBindings(&users.Items[i])
		if err != nil {
			return nil, fmt.Errorf("invalid bindings on user %s: %w", users.Items[i].GetName(), err)
		}
		for _, binding := range bindings {
			if binding == id {
				owners = append(owners, &users.Items[i])
			}
		}
	}
	return owners, nil
}

func claimMatches(claim *unstructured.Unstructured, id ExternalIdentity, user *unstructured.Unstructured) bool {
	// Claims contain no credentials. An annotation map keeps exact strings intact
	// under both real API and fake-client serialization.
	a := claim.GetAnnotations()
	return a["kubeworkspaces.io/issuer"] == id.Issuer && a["kubeworkspaces.io/subject"] == id.Subject && a["kubeworkspaces.io/user-name"] == user.GetName() && a["kubeworkspaces.io/user-uid"] == string(user.GetUID())
}

// BindIdentity reserves one identity atomically across API replicas, then appends
// it to the existing User using resourceVersion conflict retries. It never
// creates/replaces a User or infers ownership from email. A failed second write
// leaves an inert reservation that only the same User UID can resume; lookup
// requires BOTH the reservation and matching User binding. Claims deliberately
// survive account deletion, preventing implicit adoption by replacement accounts.
// This is a storage primitive, not an unauthenticated linking endpoint.
func (p *ConfigProvider) BindIdentity(ctx context.Context, name, uid string, id ExternalIdentity) error {
	return p.bindIdentity(ctx, name, uid, id, nil)
}

// check scopes a delegated approval to the current account on every conflict
// retry, rather than trusting the snapshot read before reserving the identity.
func (p *ConfigProvider) bindIdentity(ctx context.Context, name, uid string, id ExternalIdentity, check func(*unstructured.Unstructured) error) error {
	if err := id.validate(); err != nil {
		return err
	}
	user, err := p.GetUser(ctx, name)
	if err != nil {
		return err
	}
	if uid == "" || string(user.GetUID()) != uid || !identityAccountValid(user) {
		return ErrIdentityConflict
	}
	if check != nil {
		if err := check(user); err != nil {
			return err
		}
	}
	owners, err := p.identityOwners(ctx, id)
	if err != nil {
		return err
	}
	for _, owner := range owners {
		if owner.GetUID() != user.GetUID() || owner.GetName() != name {
			return ErrIdentityConflict
		}
	}
	bindings, err := identityBindings(user)
	if err != nil {
		return err
	}
	alreadyBound := false
	for _, binding := range bindings {
		alreadyBound = alreadyBound || binding == id
	}
	if len(bindings) >= 20 && !alreadyBound {
		return fmt.Errorf("too many external identities")
	}
	claim := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
		"metadata": map[string]interface{}{
			"name": id.claimName(), "namespace": LocalAuthSystemNamespace,
			"labels": map[string]interface{}{"kubeworkspaces.io/kind": "external-identity"},
			"annotations": map[string]interface{}{
				"kubeworkspaces.io/issuer": id.Issuer, "kubeworkspaces.io/subject": id.Subject,
				"kubeworkspaces.io/user-name": name, "kubeworkspaces.io/user-uid": uid,
			},
		},
	}}
	secrets := p.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace)
	if _, err := secrets.Create(ctx, claim, metav1.CreateOptions{}); err != nil {
		if !k8serrors.IsAlreadyExists(err) {
			return err
		}
		existing, err := secrets.Get(ctx, id.claimName(), metav1.GetOptions{})
		if err != nil {
			return err
		}
		if !claimMatches(existing, id, user) {
			return ErrIdentityConflict
		}
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := p.GetUser(ctx, name)
		if err != nil {
			return err
		}
		if string(current.GetUID()) != uid || !identityAccountValid(current) {
			return ErrIdentityConflict
		}
		if check != nil {
			if err := check(current); err != nil {
				return err
			}
		}
		bindings, err := identityBindings(current)
		if err != nil {
			return err
		}
		entries := make([]interface{}, 0, len(bindings)+1)
		for _, binding := range bindings {
			if binding == id {
				return nil
			}
			entries = append(entries, map[string]interface{}{"issuer": binding.Issuer, "subject": binding.Subject})
		}
		if len(bindings) >= 20 {
			return fmt.Errorf("too many external identities")
		}
		entries = append(entries, map[string]interface{}{"issuer": id.Issuer, "subject": id.Subject})
		if err := unstructured.SetNestedSlice(current.Object, entries, "spec", "externalIdentities"); err != nil {
			return err
		}
		updated, err := p.UpdateUser(ctx, current)
		if err != nil {
			return err
		}
		// A schema not yet upgraded may prune the field without rejecting Update.
		persisted, err := identityBindings(updated)
		if err != nil {
			return err
		}
		for _, binding := range persisted {
			if binding == id {
				return nil
			}
		}
		return fmt.Errorf("identity binding was not persisted; install the updated User CRD first")
	})
}

// GetUserByIdentity resolves only a durably claimed binding, never an email.
// Ambiguous or partially persisted bindings, stale UIDs and disabled accounts
// fail closed. No claim is adopted or repaired as a side effect of login.
func (p *ConfigProvider) GetUserByIdentity(ctx context.Context, id ExternalIdentity) (*unstructured.Unstructured, error) {
	if err := id.validate(); err != nil {
		return nil, err
	}
	claim, err := p.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Get(ctx, id.claimName(), metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return nil, ErrIdentityNotBound
	}
	if err != nil {
		return nil, err
	}
	owners, err := p.identityOwners(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(owners) != 1 || !identityAccountValid(owners[0]) || !claimMatches(claim, id, owners[0]) {
		return nil, ErrIdentityConflict
	}
	return owners[0], nil
}
