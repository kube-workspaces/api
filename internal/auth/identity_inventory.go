package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// IdentityInventory is a read-only pre-migration report. It never returns Secret
// contents, adopts identities, renames Users or changes credentials.
type IdentityInventory struct {
	Users  []IdentityInventoryUser  `json:"users"`
	Issues []IdentityInventoryIssue `json:"issues"`
}

type IdentityInventoryUser struct {
	Name           string             `json:"name"`
	UID            string             `json:"uid"`
	Email          string             `json:"email"`
	LocalEnabled   bool               `json:"localEnabled"`
	PasswordSecret string             `json:"passwordSecret,omitempty"`
	External       []ExternalIdentity `json:"externalIdentities"`
}

type IdentityInventoryIssue struct {
	Kind     string   `json:"kind"`
	Resource string   `json:"resource"`
	Users    []string `json:"users"`
}

func (p *ConfigProvider) InventoryIdentities(ctx context.Context) (*IdentityInventory, error) {
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	secrets, err := p.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err // An incomplete report must not look like a clean inventory.
	}
	report := &IdentityInventory{Users: []IdentityInventoryUser{}, Issues: []IdentityInventoryIssue{}}
	groups := map[string]map[string][]string{
		"duplicate-email": {}, "case-variant-email": {}, "legacy-slug-collision": {}, "shared-password-secret": {},
		"duplicate-identity-binding": {},
	}
	refs := make(map[string][]string)
	secretNames := make(map[string]bool)
	claims := make(map[string]*unstructured.Unstructured)
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		secretNames[secret.GetName()] = true
		if secret.GetLabels()["kubeworkspaces.io/kind"] == "external-identity" {
			claims[secret.GetName()] = secret
		}
	}
	issue := func(kind, resource string, names ...string) {
		sort.Strings(names)
		report.Issues = append(report.Issues, IdentityInventoryIssue{Kind: kind, Resource: resource, Users: names})
	}
	for i := range users.Items {
		u := &users.Items[i]
		email, _, _ := unstructured.NestedString(u.Object, "spec", "email")
		local, _, _ := unstructured.NestedBool(u.Object, "spec", "localAuth", "enabled")
		ref, _, _ := unstructured.NestedString(u.Object, "spec", "localAuth", "passwordSecretRef", "name")
		bindings, err := identityBindings(u)
		if err != nil {
			issue("malformed-bindings", u.GetName(), u.GetName())
			bindings = []ExternalIdentity{}
		}
		report.Users = append(report.Users, IdentityInventoryUser{u.GetName(), string(u.GetUID()), email, local, ref, bindings})
		for kind, key := range map[string]string{"duplicate-email": email, "case-variant-email": strings.ToLower(email), "legacy-slug-collision": slugifyEmail(email)} {
			groups[kind][key] = append(groups[kind][key], u.GetName())
		}
		if ref != "" {
			refs[ref] = append(refs[ref], u.GetName())
			groups["shared-password-secret"][ref] = append(groups["shared-password-secret"][ref], u.GetName())
			if !secretNames[ref] {
				issue("missing-password-secret", ref, u.GetName())
			}
		} else if local {
			issue("missing-password-reference", u.GetName(), u.GetName())
		}
		for _, id := range bindings {
			groups["duplicate-identity-binding"][id.claimName()] = append(groups["duplicate-identity-binding"][id.claimName()], u.GetName())
			claim := claims[id.claimName()]
			if claim == nil || !claimMatches(claim, id, u) {
				issue("unclaimed-binding", id.claimName(), u.GetName())
			}
		}
	}
	for kind, keys := range groups {
		for key, names := range keys {
			if len(names) > 1 {
				issue(kind, key, names...)
			}
		}
	}
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		_, hashData, _ := unstructured.NestedFieldNoCopy(secret.Object, "data", "passwordHash")
		_, hashStringData, _ := unstructured.NestedFieldNoCopy(secret.Object, "stringData", "passwordHash")
		if (hashData || hashStringData) && len(refs[secret.GetName()]) == 0 {
			issue("orphan-password-secret", secret.GetName())
		}
	}
	for name, claim := range claims {
		a := claim.GetAnnotations()
		id := ExternalIdentity{Issuer: a["kubeworkspaces.io/issuer"], Subject: a["kubeworkspaces.io/subject"]}
		found := false
		for i := range users.Items {
			u := &users.Items[i]
			if !claimMatches(claim, id, u) {
				continue
			}
			bindings, _ := identityBindings(u)
			for _, binding := range bindings {
				found = found || (binding == id && id.claimName() == name)
			}
		}
		if !found {
			issue("incomplete-identity-claim", name, a["kubeworkspaces.io/user-name"])
		}
	}
	sort.Slice(report.Users, func(i, j int) bool { return report.Users[i].Name < report.Users[j].Name })
	sort.Slice(report.Issues, func(i, j int) bool {
		a, b := report.Issues[i], report.Issues[j]
		return fmt.Sprint(a.Kind, "\x00", a.Resource, a.Users) < fmt.Sprint(b.Kind, "\x00", b.Resource, b.Users)
	})
	return report, nil
}

func (p *ConfigProvider) HandleIdentityInventory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !IsAdmin(r.Context()) {
		writeJSONError(w, http.StatusForbidden, "forbidden", "admin role required")
		return
	}
	report, err := p.InventoryIdentities(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "inventory_unavailable", "identity inventory unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}
