// Package auth provides authentication and authorization middleware for
// the kube-workspaces API. It implements OIDC-based login flows, JWT
// session management, role-based access control (admin/editor/viewer),
// and integrates with the AuthConfig and User CRDs for configuration.
// When auth is disabled, all requests are treated as admin-level access.
package auth
