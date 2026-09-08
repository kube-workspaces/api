package exec

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/rest"
)

func TestConsoleTokenPrefersFile(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("fresh-file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &rest.Config{
		BearerToken:     "stale-startup-token",
		BearerTokenFile: tokenFile,
	}
	if got := consoleToken(cfg); got != "fresh-file-token" {
		t.Errorf("expected the freshly-read file token, got %q", got)
	}
}

func TestConsoleTokenFallsBackToStatic(t *testing.T) {
	cfg := &rest.Config{BearerToken: "static-token"}
	if got := consoleToken(cfg); got != "static-token" {
		t.Errorf("expected static token fallback, got %q", got)
	}
}

func TestConsoleTokenMissingFile(t *testing.T) {
	cfg := &rest.Config{
		BearerToken:     "static-token",
		BearerTokenFile: "/nonexistent/token",
	}
	if got := consoleToken(cfg); got != "static-token" {
		t.Errorf("expected static token when file is unreadable, got %q", got)
	}
}

func TestConsoleTokenNilConfig(t *testing.T) {
	if got := consoleToken(nil); got != "" {
		t.Errorf("expected empty token for nil config, got %q", got)
	}
}

func TestConsoleTokenWhitespaceOnlyFile(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &rest.Config{
		BearerToken:     "static-token",
		BearerTokenFile: tokenFile,
	}
	if got := consoleToken(cfg); got != "static-token" {
		t.Errorf("expected static token fallback for whitespace-only file, got %q", got)
	}
}
