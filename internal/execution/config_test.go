package execution

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func persistentEnvironment(mode string) map[string]string {
	return map[string]string{
		"KW_EXECUTION_STORAGE_MODE":       mode,
		"KW_EXECUTION_RECORDING_KEY_FILE": "/recording/key",
		"KW_EXECUTION_DATABASE_URL":       "postgresql://execution:test-password@db.example.com/execution?sslmode=verify-full",
		"KW_EXECUTION_S3_ENDPOINT":        "https://s3.example.com",
		"KW_EXECUTION_S3_BUCKET":          "workspace-execution",
		"KW_EXECUTION_S3_ACCESS_KEY":      "test-access-key",
		"KW_EXECUTION_S3_SECRET_KEY":      "test-secret-key",
	}
}

func testKeyFile(path string) ([]byte, error) {
	if path != "/recording/key" {
		return nil, errors.New("file unavailable")
	}
	return []byte(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))), nil
}

func TestExecutionStorageModes(t *testing.T) {
	for _, mode := range []string{"", "disabled", "ephemeral", "external", "bundled"} {
		t.Run(mode, func(t *testing.T) {
			env := map[string]string{"KW_EXECUTION_STORAGE_MODE": mode}
			if mode == "external" || mode == "bundled" {
				env = persistentEnvironment(mode)
			}
			if mode == "bundled" {
				delete(env, "KW_EXECUTION_DATABASE_URL")
				env["KW_EXECUTION_ALLOW_INSECURE_STORAGE_TRANSPORT"] = "true"
				env["KW_EXECUTION_PG_HOST"] = "kw-postgresql.system.svc"
				env["KW_EXECUTION_PG_DATABASE"] = "execution"
				env["KW_EXECUTION_PG_USER"] = "execution"
				env["KW_EXECUTION_PG_PASSWORD"] = "test-password/@:?&=escape"
				env["KW_EXECUTION_S3_ENDPOINT"] = "http://kw-rustfs.system.svc:9000"
				env["KW_EXECUTION_S3_CREATE_BUCKET"] = "true"
			}
			cfg, err := readStorageConfig(func(key string) string { return env[key] }, testKeyFile)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "" {
				mode = "disabled"
			}
			if string(cfg.Mode) != mode || cfg.Persistent() != (mode == "external" || mode == "bundled") {
				t.Fatalf("unexpected mode: %s", cfg)
			}
			if cfg.Persistent() && (len(cfg.recordingKey) != 32 || cfg.KeyID == "" || !cfg.S3.ForcePathStyle) {
				t.Fatal("persistent encryption/S3 configuration missing")
			}
			if mode == "bundled" {
				u, err := url.Parse(cfg.DatabaseURL)
				if err != nil {
					t.Fatal("invalid constructed database URL")
				}
				password, _ := u.User.Password()
				if password != env["KW_EXECUTION_PG_PASSWORD"] || u.Hostname() != env["KW_EXECUTION_PG_HOST"] || !cfg.S3.CreateBucket {
					t.Fatal("bundled credentials were not safely escaped or bucket provisioning missing")
				}
			}
			if mode == "ephemeral" && (cfg.EphemeralDir == "" || cfg.EphemeralMaxBytes <= 0 || cfg.DatabaseURL != "" || len(cfg.recordingKey) != 0) {
				t.Fatal("ephemeral mode incorrectly depends on persistent services/keys")
			}
			for _, logged := range []string{fmt.Sprintf("%+v", cfg), fmt.Sprintf("%+v", cfg.S3)} {
				for _, secret := range []string{"test-password", "test-secret-key", strings.Repeat("k", 32)} {
					if strings.Contains(logged, secret) {
						t.Fatal("configuration logging disclosed credentials")
					}
				}
			}
		})
	}
}

func TestPersistentStorageRejectsUnsafeOrIncompleteConfiguration(t *testing.T) {
	for _, tt := range []struct{ name, key, value string }{
		{"unknown mode", "KW_EXECUTION_STORAGE_MODE", "anything"},
		{"missing key", "KW_EXECUTION_RECORDING_KEY_FILE", ""},
		{"unreadable key", "KW_EXECUTION_RECORDING_KEY_FILE", "/unavailable"},
		{"missing database", "KW_EXECUTION_DATABASE_URL", ""},
		{"malformed database", "KW_EXECUTION_DATABASE_URL", "postgresql://user:test-password@invalid%host/db"},
		{"database TLS downgrade", "KW_EXECUTION_DATABASE_URL", "postgresql://user:test-password@db/db?sslmode=prefer"},
		{"ambiguous TLS mode", "KW_EXECUTION_DATABASE_URL", "postgresql://user:test-password@db/db?sslmode=verify-full&sslmode=disable"},
		{"missing TLS mode", "KW_EXECUTION_DATABASE_URL", "postgresql://user:test-password@db/db"},
		{"plaintext S3", "KW_EXECUTION_S3_ENDPOINT", "http://objects.example.com"},
		{"URL credentials", "KW_EXECUTION_S3_ENDPOINT", "https://user:test-password@objects.example.com"},
		{"invalid endpoint", "KW_EXECUTION_S3_ENDPOINT", "https://objects.example.com/path?secret=test-password"},
		{"missing S3 password", "KW_EXECUTION_S3_SECRET_KEY", ""},
		{"public bucket naming", "KW_EXECUTION_S3_BUCKET", "invalid/*"},
		{"IPv4 bucket", "KW_EXECUTION_S3_BUCKET", "127.0.0.1"},
		{"bad path-style flag", "KW_EXECUTION_S3_FORCE_PATH_STYLE", "maybe"},
		{"missing private CA", "KW_EXECUTION_S3_CA_FILE", "/unavailable"},
		{"invalid retention", "KW_EXECUTION_RETENTION_RECORDINGS", "0h"},
		{"metadata outlives index", "KW_EXECUTION_RETENTION_METADATA", "1h"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := persistentEnvironment("external")
			env[tt.key] = tt.value
			cfg, err := readStorageConfig(func(key string) string { return env[key] }, testKeyFile)
			if err == nil || cfg.Mode == StorageEphemeral {
				t.Fatal("invalid configuration accepted or silently downgraded")
			}
			if strings.Contains(err.Error(), "test-password") || strings.Contains(err.Error(), "test-secret-key") {
				t.Fatal("configuration error disclosed credentials")
			}
		})
	}
	for _, encoded := range []string{"not-base64", base64.StdEncoding.EncodeToString([]byte("too-short"))} {
		env := persistentEnvironment("external")
		if _, err := readStorageConfig(func(key string) string { return env[key] }, func(string) ([]byte, error) { return []byte(encoded), nil }); err == nil {
			t.Fatal("invalid recording key accepted")
		}
	}
}

func TestEphemeralStorageRejectsDowngradeAndUnboundedPaths(t *testing.T) {
	for _, tt := range []struct{ key, value string }{
		{"KW_EXECUTION_DATABASE_URL", "postgresql://unused"},
		{"KW_EXECUTION_RECORDING_KEY_FILE", "/recording/key"},
		{"KW_EXECUTION_S3_ENDPOINT", "https://unused"},
		{"KW_EXECUTION_EPHEMERAL_MAX_BYTES", "-1"},
		{"KW_EXECUTION_EPHEMERAL_MAX_BYTES", "9223372036854775808"},
		{"KW_EXECUTION_EPHEMERAL_DIR", "relative"},
		{"KW_EXECUTION_EPHEMERAL_DIR", "/"},
		{"KW_EXECUTION_EPHEMERAL_DIR", "/recordings/../etc"},
	} {
		env := map[string]string{"KW_EXECUTION_STORAGE_MODE": "ephemeral", tt.key: tt.value}
		if _, err := readStorageConfig(func(key string) string { return env[key] }, testKeyFile); err == nil {
			t.Fatalf("invalid ephemeral configuration accepted for %s", tt.key)
		}
	}
}
