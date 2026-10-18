package management

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig(t *testing.T) (Config, []byte, ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic management issuer"}, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	c := Config{Enabled: true, BootstrapNamespace: "control-system", LeafLifetime: 10 * time.Minute, caCertFile: filepath.Join(dir, "issuer.pem"), caKeyFile: filepath.Join(dir, "issuer-key.pem"), trustRootsFile: filepath.Join(dir, "roots.pem")}
	for path, data := range map[string][]byte{c.caCertFile: certPEM, c.caKeyFile: keyPEM, c.trustRootsFile: certPEM} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return c, keyPEM, key
}

func configEnv(c Config) map[string]string {
	return map[string]string{"KW_MANAGEMENT_ISSUER_ENABLED": "true", "KW_MANAGEMENT_CA_CERT_FILE": c.caCertFile, "KW_MANAGEMENT_CA_KEY_FILE": c.caKeyFile, "KW_MANAGEMENT_TRUST_ROOTS_FILE": c.trustRootsFile, "KW_MANAGEMENT_BOOTSTRAP_NAMESPACE": c.BootstrapNamespace, "KW_MANAGEMENT_CERT_TTL": "10m"}
}

func TestConfigOptInAndRedaction(t *testing.T) {
	disabled, err := readConfig(func(string) string { return "" })
	if err != nil || disabled.Enabled {
		t.Fatal(disabled, err)
	}
	c, _, _ := testConfig(t)
	env := configEnv(c)
	parsed, err := readConfig(func(k string) string { return env[k] })
	if err != nil || parsed.LeafLifetime != 10*time.Minute {
		t.Fatal(parsed, err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, parsed), c.caKeyFile) {
			t.Fatal("credential location logged")
		}
	}
	for name, change := range map[string]func(map[string]string){
		"invalid-optin":          func(m map[string]string) { m["KW_MANAGEMENT_ISSUER_ENABLED"] = "maybe" },
		"disabled-with-settings": func(m map[string]string) { m["KW_MANAGEMENT_ISSUER_ENABLED"] = "false" },
		"relative-key":           func(m map[string]string) { m["KW_MANAGEMENT_CA_KEY_FILE"] = "relative-key" },
		"missing-roots":          func(m map[string]string) { delete(m, "KW_MANAGEMENT_TRUST_ROOTS_FILE") },
		"bad-namespace":          func(m map[string]string) { m["KW_MANAGEMENT_BOOTSTRAP_NAMESPACE"] = "wrong/namespace" },
		"same-key-and-cert":      func(m map[string]string) { m["KW_MANAGEMENT_CA_KEY_FILE"] = m["KW_MANAGEMENT_CA_CERT_FILE"] },
		"ttl-long":               func(m map[string]string) { m["KW_MANAGEMENT_CERT_TTL"] = "2h" },
		"ttl-short":              func(m map[string]string) { m["KW_MANAGEMENT_CERT_TTL"] = "1s" },
	} {
		t.Run(name, func(t *testing.T) {
			m := configEnv(c)
			change(m)
			if _, err := readConfig(func(k string) string { return m[k] }); !errors.Is(err, ErrConfiguration) {
				t.Fatal("unsafe configuration accepted", err)
			}
		})
	}
}

func TestCredentialsLoadedAndNeverFormatted(t *testing.T) {
	c, keyPEM, key := testConfig(t)
	now := time.Now()
	loaded, err := loadCredentials(c, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range []interface{}{loaded, loaded.authority} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			printed := fmt.Sprintf(format, object)
			if bytes.Contains([]byte(printed), keyPEM) || strings.Contains(printed, "BEGIN PRIVATE KEY") || strings.Contains(printed, fmt.Sprint([]byte(key))) {
				t.Fatal("private material formatted")
			}
		}
	}
	if err := loaded.validAt(now.Add(25*time.Hour), c.LeafLifetime); err == nil {
		t.Fatal("expired in-memory issuer remained ready")
	}
	// Projected Kubernetes Secret paths are symlinks to regular files.
	link := filepath.Join(t.TempDir(), "projected-key")
	if err := os.Symlink(c.caKeyFile, link); err != nil {
		t.Skip("symlink creation unavailable")
	}
	c.caKeyFile = link
	if _, err := loadCredentials(c, now); err != nil {
		t.Fatal("projected Secret key refused", err)
	}
}

func TestCredentialsRejectMismatchMalformedExpiredAndOversize(t *testing.T) {
	for _, test := range []string{"mismatched-key", "wrong-root", "multiple-keys", "garbage", "oversize-key", "expired-ca", "short-lived-ca", "not-ca"} {
		t.Run(test, func(t *testing.T) {
			c, keyPEM, key := testConfig(t)
			now := time.Now().UTC().Truncate(time.Second)
			switch test {
			case "mismatched-key", "wrong-root":
				other, _, _ := testConfig(t)
				path := other.caKeyFile
				target := c.caKeyFile
				if test == "wrong-root" {
					path = other.trustRootsFile
					target = c.trustRootsFile
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "multiple-keys":
				if err := os.WriteFile(c.caKeyFile, append(keyPEM, keyPEM...), 0600); err != nil {
					t.Fatal(err)
				}
			case "garbage":
				if err := os.WriteFile(c.caKeyFile, []byte("private-key-marker-not-valid-pem"), 0600); err != nil {
					t.Fatal(err)
				}
			case "oversize-key":
				if err := os.WriteFile(c.caKeyFile, make([]byte, 16*1024+1), 0600); err != nil {
					t.Fatal(err)
				}
			default:
				template := &x509.Certificate{SerialNumber: big.NewInt(2), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
				if test == "expired-ca" {
					template.NotAfter = now.Add(-time.Minute)
				}
				if test == "short-lived-ca" {
					template.NotAfter = now.Add(time.Minute)
				}
				if test == "not-ca" {
					template.IsCA = false
				}
				der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
				if err != nil {
					t.Fatal(err)
				}
				data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
				if err := os.WriteFile(c.caCertFile, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(c.trustRootsFile, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := loadCredentials(c, now); !errors.Is(err, ErrConfiguration) {
				t.Fatal("invalid credentials accepted", err)
			}
		})
	}
}
