package execution

import (
	"context"
	"errors"
	"testing"

	"github.com/kube-workspaces/api/internal/execution/storage"
)

func TestStorageOptionsTranslateConfig(t *testing.T) {
	env := persistentEnvironment("external")
	cfg, err := readStorageConfig(func(key string) string { return env[key] }, testKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	opts := cfg.StorageOptions()
	if opts.Mode != "external" {
		t.Fatalf("mode = %q", opts.Mode)
	}
	if opts.DatabaseURL != cfg.DatabaseURL || opts.S3.Bucket != cfg.S3.Bucket || opts.S3.Endpoint != cfg.S3.Endpoint {
		t.Fatalf("options not translated: %+v", opts)
	}
	if opts.KeyID != cfg.KeyID || len(opts.RecordingKey) != 32 {
		t.Fatal("recording key/key id not translated")
	}
}

func TestStorageOptionsDisabledIsFailClosed(t *testing.T) {
	env := map[string]string{"KW_EXECUTION_STORAGE_MODE": "disabled"}
	cfg, err := readStorageConfig(func(key string) string { return env[key] }, testKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Open(context.Background(), cfg.StorageOptions()); !errors.Is(err, storage.ErrDisabled) {
		t.Fatalf("disabled mode must not open a store: %v", err)
	}
}

func TestStorageOptionsEphemeralOpensReady(t *testing.T) {
	env := map[string]string{
		"KW_EXECUTION_STORAGE_MODE":  "ephemeral",
		"KW_EXECUTION_EPHEMERAL_DIR": t.TempDir(),
	}
	cfg, err := readStorageConfig(func(key string) string { return env[key] }, testKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	st, err := storage.Open(context.Background(), cfg.StorageOptions())
	if err != nil {
		t.Fatalf("open ephemeral: %v", err)
	}
	defer st.Close()
	if err := st.Ready(context.Background()); err != nil {
		t.Fatalf("ephemeral ready: %v", err)
	}
}
