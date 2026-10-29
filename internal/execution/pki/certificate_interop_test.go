package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"net/url"
	"os"
	"testing"
	"time"
)

type certificateCase struct {
	Name          string   `json:"name"`
	DER           []byte   `json:"der"`
	URI           string   `json:"uri,omitempty"`
	Valid         bool     `json:"valid"`
	Intermediates [][]byte `json:"intermediates,omitempty"`
	ChainValid    *bool    `json:"chain_valid,omitempty"`
}
type certificateVectors struct {
	Now     int64             `json:"now"`
	RootDER []byte            `json:"root_der"`
	Cases   []certificateCase `json:"cases"`
}

// Regenerate only synthetic public certificates, never private keys:
// KW_UPDATE_CERTIFICATE_VECTORS=1 go test ./internal/execution/pki -run '^TestCertificateProfileInterop$'
// Copy the resulting fixture byte-for-byte into kw-management/fixtures/.
func TestCertificateProfileInterop(t *testing.T) {
	const path = "testdata/management-pki-certificates-v1.json"
	if os.Getenv("KW_UPDATE_CERTIFICATE_VECTORS") == "1" {
		vectors := generateCertificateVectors(t)
		data, err := json.MarshalIndent(vectors, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors certificateVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	root, err := x509.ParseCertificate(vectors.RootDER)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(root)
	for _, test := range vectors.Cases {
		t.Run(test.Name, func(t *testing.T) {
			cert, err := x509.ParseCertificate(test.DER)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := CertificateIdentity(cert)
			if (err == nil) != test.Valid {
				t.Fatalf("profile verdict drifted: %+v %v", identity, err)
			}
			if test.Valid {
				intermediates := x509.NewCertPool()
				for _, der := range test.Intermediates {
					cert, err := x509.ParseCertificate(der)
					if err != nil {
						t.Fatal(err)
					}
					intermediates.AddCert(cert)
				}
				uri, err := identity.URI()
				if err != nil || uri.String() != test.URI {
					t.Fatal("profile identity drifted")
				}
				usage := x509.ExtKeyUsageClientAuth
				if identity.Role == RoleGuest {
					usage = x509.ExtKeyUsageServerAuth
				}
				_, err = cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: time.Unix(vectors.Now, 0), KeyUsages: []x509.ExtKeyUsage{usage}})
				wantChain := true
				if test.ChainValid != nil {
					wantChain = *test.ChainValid
				}
				if (err == nil) != wantChain {
					t.Fatalf("chain verdict drifted: %v", err)
				}
			}
		})
	}
}

func generateCertificateVectors(t *testing.T) certificateVectors {
	t.Helper()
	ca := authority(t)
	// This synthetic root permits one intermediate; the ordinary test helper
	// intentionally permits direct issuance only.
	root, _ := x509.ParseCertificate(ca.der)
	root.MaxPathLen, root.MaxPathLenZero = 1, false
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &ca.key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	ca.der = rootDER
	ca.a, err = NewAuthority(rootDER, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root, _ = x509.ParseCertificate(rootDER)
	intermediateTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic-management-intermediate"}, NotBefore: ca.now.Add(-time.Hour), NotAfter: ca.now.Add(12 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	intermediateIssuer, err := NewAuthority(intermediateDER, key)
	if err != nil {
		t.Fatal(err)
	}
	intermediate := authorityFixture{a: intermediateIssuer, key: key, der: intermediateDER, now: ca.now}
	vectors := certificateVectors{Now: ca.now.Unix(), RootDER: ca.der}
	for _, identity := range []Identity{api(), guest()} {
		uri, _ := identity.URI()
		cert := leaf(t, ca, identity)
		vectors.Cases = append(vectors.Cases, certificateCase{Name: "valid-" + identity.Role, DER: cert.Certificate[0], URI: uri.String(), Valid: true})
		viaIntermediate := leaf(t, intermediate, identity)
		vectors.Cases = append(vectors.Cases, certificateCase{Name: "valid-intermediate-" + identity.Role, DER: viaIntermediate.Certificate[0], URI: uri.String(), Valid: true, Intermediates: [][]byte{intermediateDER}})
		for _, mutation := range []string{"wrong-intermediate-purpose", "expired-intermediate", "unknown-critical-intermediate"} {
			bad := *intermediateTemplate
			if mutation == "wrong-intermediate-purpose" {
				bad.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
			}
			if mutation == "expired-intermediate" {
				bad.NotAfter = ca.now.Add(-time.Second)
			}
			if mutation == "unknown-critical-intermediate" {
				bad.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{0x05, 0}}}
			}
			badDER, err := x509.CreateCertificate(rand.Reader, &bad, root, &key.PublicKey, ca.key)
			if err != nil {
				t.Fatal(err)
			}
			invalid := false
			vectors.Cases = append(vectors.Cases, certificateCase{Name: mutation + "-" + identity.Role, DER: viaIntermediate.Certificate[0], URI: uri.String(), Valid: true, Intermediates: [][]byte{badDER}, ChainValid: &invalid})
		}
		for name, mutate := range map[string]func(*x509.Certificate){
			"missing-purpose": func(c *x509.Certificate) { c.ExtKeyUsage = nil },
			"ca":              func(c *x509.Certificate) { c.IsCA = true },
			"wrong-purpose":   func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning} },
			"extra-purpose":   func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) },
			"any-purpose":     func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} },
			"unknown-purpose": func(c *x509.Certificate) {
				c.ExtKeyUsage = nil
				c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
			},
			"extra-key-usage":   func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageKeyEncipherment },
			"missing-key-usage": func(c *x509.Certificate) { c.KeyUsage = 0 },
			"missing-uri":       func(c *x509.Certificate) { c.URIs = nil },
			"duplicate-uri":     func(c *x509.Certificate) { c.URIs = append(c.URIs, c.URIs[0]) },
			"extra-dns":         func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "other.example") },
			"long-lifetime":     func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(2 * time.Hour) },
			"empty-window":      func(c *x509.Certificate) { c.NotAfter = c.NotBefore },
			"foreign-uri":       func(c *x509.Certificate) { u := *c.URIs[0]; u.Host = "other.example"; c.URIs = []*url.URL{&u} },
		} {
			template, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			mutate(template)
			parent, _ := x509.ParseCertificate(ca.der)
			der, err := x509.CreateCertificate(rand.Reader, template, parent, template.PublicKey, ca.key)
			if err != nil {
				t.Fatal(err)
			}
			vectors.Cases = append(vectors.Cases, certificateCase{Name: name + "-" + identity.Role, DER: der})
		}
		for _, alias := range []string{"uppercase-scheme", "empty-fragment", "unknown-general-name"} {
			rawURI := uri.String()
			if alias == "uppercase-scheme" {
				rawURI = "SPIFFE" + rawURI[len("spiffe"):]
			}
			if alias == "empty-fragment" {
				rawURI += "#"
			}
			names := []asn1.RawValue{{Class: 2, Tag: 6, Bytes: []byte(rawURI)}}
			if identity.Role == RoleGuest {
				names = append(names, asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte(ServerName)})
			}
			if alias == "unknown-general-name" {
				names = append(names, asn1.RawValue{Class: 2, Tag: 8, Bytes: []byte{42, 3}})
			}
			bad := leafWithRawSAN(t, ca, identity, names)
			vectors.Cases = append(vectors.Cases, certificateCase{Name: alias + "-" + identity.Role, DER: bad.Certificate[0]})
		}
	}
	return vectors
}
