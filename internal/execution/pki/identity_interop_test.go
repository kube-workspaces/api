package pki

import (
	_ "embed"
	"encoding/json"
	"strings"
	"testing"
)

// Byte-identical with kw-management/fixtures/management-pki-identities-v1.json.
// Only public synthetic identities live here, not certificate/key authority.
//
//go:embed testdata/management-pki-identities-v1.json
var identityVectors []byte

func TestSharedGoRustIdentityVectors(t *testing.T) {
	var vectors struct {
		API     []string `json:"api"`
		Guest   []string `json:"guest"`
		Invalid []string `json:"invalid"`
	}
	if err := json.Unmarshal(identityVectors, &vectors); err != nil {
		t.Fatal(err)
	}
	for role, values := range map[string][]string{RoleAPI: vectors.API, RoleGuest: vectors.Guest} {
		for _, raw := range values {
			i, err := ParseIdentityURI(raw)
			if err != nil || i.Role != role {
				t.Fatalf("valid identity rejected: %s %+v %v", raw, i, err)
			}
			canonical, err := i.URI()
			if err != nil || canonical.String() != raw {
				t.Fatalf("identity did not roundtrip: %s %v", raw, err)
			}
		}
	}
	for _, raw := range vectors.Invalid {
		if i, err := ParseIdentityURI(raw); err == nil {
			t.Fatalf("invalid identity accepted: %s %+v", raw, i)
		}
	}
}

func TestManagementIdentityComponentBounds(t *testing.T) {
	for _, n := range []int{1, 256, 257} {
		part := strings.Repeat("a", n)
		for _, identity := range []Identity{
			{Role: RoleAPI, ReplicaID: part},
			{Role: RoleGuest, Namespace: part, WorkspaceName: part, WorkspaceUID: part, Generation: part, RevocationEpoch: ^uint64(0)},
		} {
			uri, err := identity.URI()
			if n > 256 {
				if err == nil {
					t.Fatal("oversized identity component accepted")
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if actual, err := ParseIdentityURI(uri.String()); err != nil || actual != identity {
				t.Fatalf("boundary identity rejected: %+v %v", actual, err)
			}
		}
	}
}

func FuzzParseIdentityURI(f *testing.F) {
	f.Add("spiffe://kubeworkspaces.io/management/v1/apis/api-1")
	f.Add("spiffe://kubeworkspaces.io/management/v1/workspaces/team/vm/uid-1/gen-2/3")
	f.Add("spiffe://kubeworkspaces.io/management/v1/apis/api-1#")
	f.Fuzz(func(t *testing.T, raw string) {
		identity, err := ParseIdentityURI(raw)
		if err != nil {
			return
		}
		uri, err := identity.URI()
		if err != nil || uri.String() != raw {
			t.Fatal("accepted identity is not canonical")
		}
	})
}
