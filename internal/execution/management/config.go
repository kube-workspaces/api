// Package management wires the opt-in management issuer and trusted bootstrap
// importer. It does not expose a public enrollment or process-start endpoint.
package management

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/kube-workspaces/api/internal/execution/pki"
	"k8s.io/apimachinery/pkg/util/validation"
)

var (
	ErrConfiguration = errors.New("invalid management issuer configuration")
	ErrUnavailable   = errors.New("management issuer unavailable")
	ErrDenied        = errors.New("management enrollment denied")
)

type Config struct {
	Enabled            bool          `json:"enabled"`
	BootstrapNamespace string        `json:"-"`
	LeafLifetime       time.Duration `json:"-"`
	caCertFile         string
	caKeyFile          string
	trustRootsFile     string
}

func (c Config) String() string {
	if c.Enabled {
		return "management issuer enabled (credential locations redacted)"
	}
	return "management issuer disabled"
}
func (c Config) GoString() string { return c.String() }

func ConfigFromEnv() (Config, error) { return readConfig(os.Getenv) }

func readConfig(env func(string) string) (Config, error) {
	c := Config{}
	if value := env("KW_MANAGEMENT_ISSUER_ENABLED"); value != "" {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return Config{}, ErrConfiguration
		}
		c.Enabled = enabled
	}
	settings := []string{"KW_MANAGEMENT_CA_CERT_FILE", "KW_MANAGEMENT_CA_KEY_FILE", "KW_MANAGEMENT_TRUST_ROOTS_FILE", "KW_MANAGEMENT_BOOTSTRAP_NAMESPACE", "KW_MANAGEMENT_CERT_TTL"}
	if !c.Enabled {
		for _, key := range settings {
			if env(key) != "" {
				return Config{}, ErrConfiguration
			}
		}
		return c, nil
	}
	c.BootstrapNamespace = env("KW_MANAGEMENT_BOOTSTRAP_NAMESPACE")
	if len(validation.IsDNS1123Label(c.BootstrapNamespace)) != 0 {
		return Config{}, ErrConfiguration
	}
	c.caCertFile = env("KW_MANAGEMENT_CA_CERT_FILE")
	c.caKeyFile = env("KW_MANAGEMENT_CA_KEY_FILE")
	c.trustRootsFile = env("KW_MANAGEMENT_TRUST_ROOTS_FILE")
	for _, path := range []string{c.caCertFile, c.caKeyFile, c.trustRootsFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
			return Config{}, ErrConfiguration
		}
	}
	if c.caCertFile == c.caKeyFile || c.trustRootsFile == c.caKeyFile {
		return Config{}, ErrConfiguration
	}
	c.LeafLifetime = 10 * time.Minute
	if value := env("KW_MANAGEMENT_CERT_TTL"); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, ErrConfiguration
		}
		c.LeafLifetime = duration
	}
	if c.LeafLifetime < time.Minute || c.LeafLifetime > pki.MaxLeafLifetime {
		return Config{}, ErrConfiguration
	}
	return c, nil
}
