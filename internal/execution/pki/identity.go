// Package pki defines management-only certificate identities and mutual TLS.
// Enrollment authorization and current identity resolution are caller-owned;
// desktop tickets and locally staged desktop tokens are not issuance authority.
package pki

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	RoleGuest   = "guest"
	RoleAPI     = "api"
	ServerName  = "management.workspace.internal"
	ALPN        = "kw-management/1"
	trustDomain = "kubeworkspaces.io"
)

var (
	ErrIdentity      = errors.New("invalid management certificate identity")
	ErrCertificate   = errors.New("invalid management certificate")
	ErrTrust         = errors.New("management certificate trust unavailable")
	ErrAuthorization = errors.New("management peer authorization unavailable or denied")
	component        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)
)

// Identity is selected from authoritative provisioning state, never from CSR
// subject/SAN requests. API and guest identities have disjoint fields/purposes.
type Identity struct {
	Role            string
	Namespace       string
	WorkspaceName   string
	WorkspaceUID    string
	Generation      string
	RevocationEpoch uint64
	ReplicaID       string
}

func (i Identity) validate() error {
	switch i.Role {
	case RoleGuest:
		if i.ReplicaID != "" {
			return ErrIdentity
		}
		for _, value := range []string{i.Namespace, i.WorkspaceName, i.WorkspaceUID, i.Generation} {
			if !component.MatchString(value) {
				return ErrIdentity
			}
		}
	case RoleAPI:
		if !component.MatchString(i.ReplicaID) || i.Namespace != "" || i.WorkspaceName != "" || i.WorkspaceUID != "" || i.Generation != "" || i.RevocationEpoch != 0 {
			return ErrIdentity
		}
	default:
		return ErrIdentity
	}
	return nil
}

func (i Identity) URI() (*url.URL, error) {
	if err := i.validate(); err != nil {
		return nil, err
	}
	path := "/management/v1/apis/" + i.ReplicaID
	if i.Role == RoleGuest {
		path = "/management/v1/workspaces/" + strings.Join([]string{i.Namespace, i.WorkspaceName, i.WorkspaceUID, i.Generation, strconv.FormatUint(i.RevocationEpoch, 10)}, "/")
	}
	return &url.URL{Scheme: "spiffe", Host: trustDomain, Path: path}, nil
}

func parseIdentity(uri *url.URL) (Identity, error) {
	var i Identity
	if uri == nil || uri.Scheme != "spiffe" || uri.Host != trustDomain || uri.User != nil || uri.RawPath != "" || uri.RawQuery != "" || uri.ForceQuery || uri.Fragment != "" {
		return i, ErrIdentity
	}
	parts := strings.Split(strings.TrimPrefix(uri.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "management" || parts[1] != "v1" {
		return i, ErrIdentity
	}
	switch {
	case len(parts) == 4 && parts[2] == "apis":
		i = Identity{Role: RoleAPI, ReplicaID: parts[3]}
	case len(parts) == 8 && parts[2] == "workspaces":
		epoch, err := strconv.ParseUint(parts[7], 10, 64)
		if err != nil || strconv.FormatUint(epoch, 10) != parts[7] {
			return i, ErrIdentity
		}
		i = Identity{Role: RoleGuest, Namespace: parts[3], WorkspaceName: parts[4], WorkspaceUID: parts[5], Generation: parts[6], RevocationEpoch: epoch}
	default:
		return i, ErrIdentity
	}
	canonical, err := i.URI()
	if err != nil || canonical.String() != uri.String() {
		return Identity{}, ErrIdentity
	}
	return i, nil
}
