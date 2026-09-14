package main

import "testing"

func TestRedactedURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "redacts oidc code",
			in:   "/auth/callback?code=abc123&state=xyz",
			want: "/auth/callback?code=%5BREDACTED%5D&state=xyz",
		},
		{
			name: "redacts browser-session code",
			in:   "/auth/browser-session?code=single-use-secret",
			want: "/auth/browser-session?code=%5BREDACTED%5D",
		},
		{
			name: "redacts loose token names",
			in:   "/v1/workspaces/x?token=t0ken&access_token=a&id_token=i&refresh_token=r",
			want: "/v1/workspaces/x?access_token=%5BREDACTED%5D&id_token=%5BREDACTED%5D&refresh_token=%5BREDACTED%5D&token=%5BREDACTED%5D",
		},
		{
			name: "keeps public params",
			in:   "/auth/login?native_redirect=http%3A%2F%2F127.0.0.1%3A49152&code_challenge=sha256hash&code_challenge_method=S256",
			want: "/auth/login?native_redirect=http%3A%2F%2F127.0.0.1%3A49152&code_challenge=sha256hash&code_challenge_method=S256",
		},
		{
			name: "plain path untouched",
			in:   "/auth/me",
			want: "/auth/me",
		},
		{
			name: "unparsable url returned as-is",
			in:   "://bad%zz",
			want: "://bad%zz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redactedURL(tt.in); got != tt.want {
				t.Errorf("redactedURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}