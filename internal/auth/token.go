// Package auth provides authentication and authorization middleware for the kube-workspaces API.
// When auth is disabled (AuthConfig.spec.enabled=false), all middleware passes through transparently.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// contextKey is a private type for context keys in this package.
type contextKey string

const (
	// UserContextKey is the context key for the authenticated user.
	UserContextKey contextKey = "auth-user"
	// SessionCookieName is the name of the session cookie.
	SessionCookieName = "kw-session"
)

// UserInfo represents the authenticated user's identity extracted from the session token.
type UserInfo struct {
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName,omitempty"`
	Role        string   `json:"role"`
	Groups      []string `json:"groups,omitempty"`
	// Namespaces the user has access to (populated at request time)
	Namespaces []string `json:"namespaces,omitempty"`
	// PersonalNamespace is the user's personal namespace
	PersonalNamespace string `json:"personalNamespace,omitempty"`
	// AvatarURL is the URL to the user's avatar image
	AvatarURL string `json:"avatarURL,omitempty"`
}

// SessionToken represents a JWT-like session token.
type SessionToken struct {
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName,omitempty"`
	Role        string   `json:"role"`
	Groups      []string `json:"groups,omitempty"`
	IssuedAt    int64    `json:"iat"`
	ExpiresAt   int64    `json:"exp"`
}

// CreateSessionToken creates a signed session token for the given user.
func CreateSessionToken(email, displayName, role string, groups []string, signingKey []byte, expiry time.Duration) (string, error) {
	token := SessionToken{
		Email:       email,
		DisplayName: displayName,
		Role:        role,
		Groups:      groups,
		IssuedAt:    time.Now().Unix(),
		ExpiresAt:   time.Now().Add(expiry).Unix(),
	}

	payload, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token: %w", err)
	}

	// Base64 encode the payload
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)

	// Create HMAC signature
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(encodedPayload))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return encodedPayload + "." + signature, nil
}

// ValidateSessionToken validates and decodes a session token.
func ValidateSessionToken(tokenStr string, signingKey []byte) (*SessionToken, error) {
	parts := strings.SplitN(tokenStr, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	encodedPayload := parts[0]
	signature := parts[1]

	// Verify signature
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(encodedPayload))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid token signature")
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, fmt.Errorf("invalid token encoding: %w", err)
	}

	var token SessionToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, fmt.Errorf("invalid token payload: %w", err)
	}

	// Check expiry
	if time.Now().Unix() > token.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}

	return &token, nil
}

// UserFromContext extracts the authenticated user from the request context.
// Returns nil if no user is authenticated (auth disabled or unauthenticated request).
func UserFromContext(ctx context.Context) *UserInfo {
	val := ctx.Value(UserContextKey)
	if val == nil {
		return nil
	}
	user, ok := val.(*UserInfo)
	if !ok {
		return nil
	}
	return user
}

// ContextWithUser adds user info to the context.
func ContextWithUser(ctx context.Context, user *UserInfo) context.Context {
	return context.WithValue(ctx, UserContextKey, user)
}
