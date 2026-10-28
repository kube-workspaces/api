// Package execution owns agent-backed machine management, independently of the
// desktop/display grant and the existing serial/SSH/container exec bridges.
package execution

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type StorageMode string

const (
	StorageDisabled  StorageMode = "disabled"
	StorageEphemeral StorageMode = "ephemeral"
	StorageExternal  StorageMode = "external"
	StorageBundled   StorageMode = "bundled"
)

// StorageConfig contains resolved deployment configuration, not runtime storage
// health. A valid configuration alone must never enable execution admission.
type StorageConfig struct {
	Mode                      StorageMode
	RecordingRetention        time.Duration
	RecordingRetentionEnabled bool
	MetadataRetentionEnabled  bool
	MetadataRetention         time.Duration
	EphemeralDir              string
	EphemeralMaxBytes         int64
	DatabaseURL               string `json:"-"`
	S3                        S3Config
	KeyID                     string
	recordingKey              []byte
	previousRecordingKeys     [][]byte
}

type S3Config struct {
	Endpoint       string
	Region         string
	Bucket         string
	ForcePathStyle bool
	CreateBucket   bool
	CAFile         string
	AccessKey      string `json:"-"`
	SecretKey      string `json:"-"`
}

func (c StorageConfig) Persistent() bool {
	return c.Mode == StorageExternal || c.Mode == StorageBundled
}

// String prevents accidental credential/key disclosure through ordinary logging.
func (c StorageConfig) String() string { return fmt.Sprintf("execution storage mode=%s", c.Mode) }
func (c S3Config) String() string      { return "execution S3 configuration (credentials redacted)" }

// RecordingKey returns a copy of the recording encryption key for storage
// engines. The result is secret material; never log it.
func (c StorageConfig) RecordingKey() []byte {
	if len(c.recordingKey) == 0 {
		return nil
	}
	out := make([]byte, len(c.recordingKey))
	copy(out, c.recordingKey)
	return out
}

func StorageConfigFromEnv() (StorageConfig, error) {
	return readStorageConfig(os.Getenv, os.ReadFile)
}

func readStorageConfig(env func(string) string, readFile func(string) ([]byte, error)) (StorageConfig, error) {
	c := StorageConfig{Mode: StorageMode(env("KW_EXECUTION_STORAGE_MODE"))}
	if c.Mode == "" || c.Mode == StorageDisabled {
		c.Mode = StorageDisabled
		return c, nil
	}
	if c.Mode != StorageEphemeral && c.Mode != StorageExternal && c.Mode != StorageBundled {
		return StorageConfig{}, fmt.Errorf("invalid KW_EXECUTION_STORAGE_MODE")
	}
	var err error
	c.RecordingRetentionEnabled, err = envBool(env, "KW_EXECUTION_RETENTION_ENABLED", false)
	if err != nil {
		return StorageConfig{}, err
	}
	if c.RecordingRetentionEnabled && (c.Mode == StorageEphemeral || env("KW_EXECUTION_RETENTION_RECORDINGS") == "") {
		return StorageConfig{}, fmt.Errorf("recording retention requires persistent storage and an explicit recording retention duration")
	}
	c.MetadataRetentionEnabled, err = envBool(env, "KW_EXECUTION_METADATA_RETENTION_ENABLED", false)
	if err != nil {
		return StorageConfig{}, err
	}
	if c.MetadataRetentionEnabled && (!c.RecordingRetentionEnabled || env("KW_EXECUTION_RETENTION_METADATA") == "") {
		return StorageConfig{}, fmt.Errorf("metadata retention requires recording retention and an explicit metadata retention duration")
	}
	c.RecordingRetention, err = positiveDuration(env("KW_EXECUTION_RETENTION_RECORDINGS"), 30*24*time.Hour)
	if err != nil {
		return StorageConfig{}, fmt.Errorf("invalid KW_EXECUTION_RETENTION_RECORDINGS")
	}
	c.MetadataRetention, err = positiveDuration(env("KW_EXECUTION_RETENTION_METADATA"), 365*24*time.Hour)
	if err != nil || c.MetadataRetention < c.RecordingRetention {
		return StorageConfig{}, fmt.Errorf("metadata retention must be positive and at least recording retention")
	}
	if c.Mode == StorageEphemeral {
		// Never interpret broken persistent settings as permission to downgrade.
		for _, key := range []string{"KW_EXECUTION_DATABASE_URL", "KW_EXECUTION_PG_HOST", "KW_EXECUTION_RECORDING_KEY_FILE", "KW_EXECUTION_S3_ENDPOINT", "KW_EXECUTION_S3_ACCESS_KEY", "KW_EXECUTION_S3_SECRET_KEY"} {
			if env(key) != "" {
				return StorageConfig{}, fmt.Errorf("persistent storage settings cannot be used in ephemeral mode")
			}
		}
		c.EphemeralDir = env("KW_EXECUTION_EPHEMERAL_DIR")
		if c.EphemeralDir == "" {
			c.EphemeralDir = "/var/run/kube-workspaces/execution"
		}
		if !filepath.IsAbs(c.EphemeralDir) || filepath.Clean(c.EphemeralDir) != c.EphemeralDir || c.EphemeralDir == string(filepath.Separator) {
			return StorageConfig{}, fmt.Errorf("ephemeral execution directory must be a clean absolute non-root path")
		}
		c.EphemeralMaxBytes = 512 * 1024 * 1024
		if raw := env("KW_EXECUTION_EPHEMERAL_MAX_BYTES"); raw != "" {
			c.EphemeralMaxBytes, err = strconv.ParseInt(raw, 10, 64)
			if err != nil || c.EphemeralMaxBytes < 1024 {
				return StorageConfig{}, fmt.Errorf("ephemeral execution capacity must be at least 1024 bytes")
			}
		}
		return c, nil
	}

	keyPath := env("KW_EXECUTION_RECORDING_KEY_FILE")
	if !filepath.IsAbs(keyPath) {
		return StorageConfig{}, fmt.Errorf("persistent execution storage requires an absolute recording key file path")
	}
	encodedKey, err := readFile(keyPath)
	if err != nil {
		return StorageConfig{}, fmt.Errorf("recording key file unavailable")
	}
	c.recordingKey, c.previousRecordingKeys, err = parseRecordingKeys(encodedKey)
	if err != nil {
		return StorageConfig{}, err
	}
	fingerprint := sha256.Sum256(c.recordingKey)
	c.KeyID = hex.EncodeToString(fingerprint[:16])
	allowInsecure, err := envBool(env, "KW_EXECUTION_ALLOW_INSECURE_STORAGE_TRANSPORT", false)
	if err != nil {
		return StorageConfig{}, err
	}
	if c.Mode == StorageBundled {
		if !allowInsecure {
			return StorageConfig{}, fmt.Errorf("bundled test storage requires explicit insecure-transport opt-in")
		}
		if env("KW_EXECUTION_DATABASE_URL") != "" {
			return StorageConfig{}, fmt.Errorf("bundled storage cannot use an external database URL")
		}
		host, port := env("KW_EXECUTION_PG_HOST"), env("KW_EXECUTION_PG_PORT")
		if port == "" {
			port = "5432"
		}
		portNumber, portErr := strconv.Atoi(port)
		if host == "" || strings.ContainsAny(host, "/@?#\\ \r\n") || portErr != nil || portNumber < 1 || portNumber > 65535 ||
			env("KW_EXECUTION_PG_USER") == "" || env("KW_EXECUTION_PG_PASSWORD") == "" || env("KW_EXECUTION_PG_DATABASE") == "" {
			return StorageConfig{}, fmt.Errorf("bundled PostgreSQL connection settings are incomplete or invalid")
		}
		u := url.URL{Scheme: "postgresql", Host: net.JoinHostPort(host, port),
			User: url.UserPassword(env("KW_EXECUTION_PG_USER"), env("KW_EXECUTION_PG_PASSWORD")),
			Path: "/" + env("KW_EXECUTION_PG_DATABASE"), RawQuery: "sslmode=disable"}
		c.DatabaseURL = u.String()
	} else {
		u, parseErr := url.Parse(env("KW_EXECUTION_DATABASE_URL"))
		if parseErr != nil || u == nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" ||
			u.User == nil || u.User.Username() == "" || len(u.Path) <= 1 || u.Fragment != "" {
			return StorageConfig{}, fmt.Errorf("external PostgreSQL URL is incomplete or invalid")
		}
		query, queryErr := url.ParseQuery(u.RawQuery)
		modes := query["sslmode"]
		if queryErr != nil || len(modes) != 1 || (modes[0] != "verify-full" && !(allowInsecure && modes[0] == "disable")) {
			return StorageConfig{}, fmt.Errorf("external PostgreSQL requires sslmode=verify-full, or explicit insecure transport with sslmode=disable")
		}
		c.DatabaseURL = u.String()
	}

	c.S3 = S3Config{Endpoint: env("KW_EXECUTION_S3_ENDPOINT"), Region: env("KW_EXECUTION_S3_REGION"),
		Bucket: env("KW_EXECUTION_S3_BUCKET"), AccessKey: env("KW_EXECUTION_S3_ACCESS_KEY"), SecretKey: env("KW_EXECUTION_S3_SECRET_KEY"), CAFile: env("KW_EXECUTION_S3_CA_FILE")}
	u, parseErr := url.Parse(c.S3.Endpoint)
	if parseErr != nil || u == nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Scheme != "https" && !(allowInsecure && u.Scheme == "http")) {
		return StorageConfig{}, fmt.Errorf("S3 endpoint must be an HTTPS origin, or explicitly opt into internal HTTP")
	}
	if len(c.S3.Bucket) < 3 || len(c.S3.Bucket) > 63 || !bucketName.MatchString(c.S3.Bucket) || strings.Contains(c.S3.Bucket, "..") || net.ParseIP(c.S3.Bucket) != nil {
		return StorageConfig{}, fmt.Errorf("invalid execution S3 bucket name")
	}
	if c.S3.AccessKey == "" || c.S3.SecretKey == "" {
		return StorageConfig{}, fmt.Errorf("execution S3 credentials are required")
	}
	if c.S3.Region == "" {
		c.S3.Region = "us-east-1"
	}
	c.S3.ForcePathStyle, err = envBool(env, "KW_EXECUTION_S3_FORCE_PATH_STYLE", true)
	if err != nil {
		return StorageConfig{}, err
	}
	c.S3.CreateBucket, err = envBool(env, "KW_EXECUTION_S3_CREATE_BUCKET", false)
	if err != nil {
		return StorageConfig{}, err
	}
	if c.S3.CAFile != "" {
		pem, readErr := readFile(c.S3.CAFile)
		if readErr != nil || !x509.NewCertPool().AppendCertsFromPEM(pem) {
			return StorageConfig{}, fmt.Errorf("execution S3 CA bundle unavailable or invalid")
		}
	}
	return c, nil
}

var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)

func positiveDuration(raw string, fallback time.Duration) (time.Duration, error) {
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	return d, nil
}

func envBool(env func(string) string, key string, fallback bool) (bool, error) {
	if env(key) == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(env(key))
	if err != nil {
		return false, fmt.Errorf("invalid %s", key)
	}
	return b, nil
}
