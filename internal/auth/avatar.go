package auth

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"goa.design/clue/log"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// resolveAvatarURL determines the user's avatar URL using the following priority:
// 1. OIDC ID token "picture" claim
// 2. OIDC UserInfo endpoint "picture" field
// 3. Gravatar (with probe to confirm existence)
// Returns empty string if no avatar can be resolved.
func resolveAvatarURL(ctx context.Context, claims *IDTokenClaims, accessToken string, discovery *OIDCDiscovery) string {
	// 1. Check ID token picture claim
	if claims.Picture != "" {
		return claims.Picture
	}

	// 2. Try UserInfo endpoint
	if accessToken != "" && discovery != nil && discovery.UserinfoEndpoint != "" {
		if picture := fetchUserInfoPicture(ctx, discovery.UserinfoEndpoint, accessToken); picture != "" {
			return picture
		}
	}

	// 3. Gravatar fallback with probe
	email := claims.Email
	if email == "" {
		email = claims.Sub
	}
	if email != "" {
		if url := probeGravatar(ctx, email); url != "" {
			return url
		}
	}

	return ""
}

// fetchUserInfoPicture calls the OIDC UserInfo endpoint and extracts the "picture" field.
func fetchUserInfoPicture(ctx context.Context, userinfoEndpoint, accessToken string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoEndpoint, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf(ctx, "auth: userinfo request failed: %v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var userInfo struct {
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return ""
	}
	return userInfo.Picture
}

// probeGravatar checks if a Gravatar exists for the given email.
// Returns the Gravatar URL if it exists (HTTP 200), empty string otherwise.
func probeGravatar(ctx context.Context, email string) string {
	hash := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(email))))
	gravatarURL := fmt.Sprintf("https://gravatar.com/avatar/%x?d=404&s=128", hash)

	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, gravatarURL, nil)
	if err != nil {
		return ""
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf(ctx, "auth: gravatar probe failed: %v", err)
		return ""
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		// Return without d=404 so the URL works for display (default identicon if needed)
		return fmt.Sprintf("https://gravatar.com/avatar/%x?s=128", hash)
	}
	return ""
}

// updateAvatarURL patches the User CR status with the resolved avatar URL.
func (h *OIDCHandler) updateAvatarURL(ctx context.Context, email, avatarURL string) {
	if avatarURL == "" {
		return
	}

	userCR, err := h.provider.GetUserByEmail(ctx, email)
	if err != nil {
		return
	}

	// Check if avatar URL has changed
	existing, _, _ := unstructuredNestedString(userCR.Object, "status", "avatarURL")
	if existing == avatarURL {
		return // No change needed
	}

	unstructured.SetNestedField(userCR.Object, avatarURL, "status", "avatarURL")
	h.provider.UpdateUserStatus(ctx, userCR)
	log.Printf(ctx, "auth: updated avatar URL for %s", email)
}
