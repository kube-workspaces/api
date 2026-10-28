package pki

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
)

func leafWithRawSAN(t *testing.T, ca authorityFixture, identity Identity, names []asn1.RawValue) tls.Certificate {
	t.Helper()
	cert := leaf(t, ca, identity)
	template, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	san, err := asn1.Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san}}
	parent, err := x509.ParseCertificate(ca.der)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, template.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert.Certificate[0] = der
	return cert
}

func TestCertificateIdentityRejectsSANNormalizationAliases(t *testing.T) {
	ca := authority(t)
	for _, role := range []string{RoleAPI, RoleGuest} {
		identity := api()
		if role == RoleGuest {
			identity = guest()
		}
		uri, err := identity.URI()
		if err != nil {
			t.Fatal(err)
		}
		for _, mutation := range []string{"uppercase-scheme", "empty-fragment", "unknown-general-name"} {
			t.Run(role+"/"+mutation, func(t *testing.T) {
				raw := uri.String()
				if mutation == "uppercase-scheme" {
					raw = strings.Replace(raw, "spiffe:", "SPIFFE:", 1)
				}
				if mutation == "empty-fragment" {
					raw += "#"
				}
				names := []asn1.RawValue{{Class: 2, Tag: 6, Bytes: []byte(raw)}}
				if role == RoleGuest {
					names = append(names, asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte(ServerName)})
				}
				if mutation == "unknown-general-name" {
					names = append(names, asn1.RawValue{Class: 2, Tag: 8, Bytes: []byte{42, 3}})
				}
				cert := leafWithRawSAN(t, ca, identity, names)
				parsed, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					t.Fatal(err)
				}
				// The trusted CA signature and parsed URI alone do not detect
				// these lexical aliases / ignored GeneralName types.
				if got, err := parseIdentity(parsed.URIs[0]); err != nil || got != identity {
					t.Fatalf("fixture did not exercise normalization: %+v %v", got, err)
				}
				usage := x509.ExtKeyUsageClientAuth
				if role == RoleGuest {
					usage = x509.ExtKeyUsageServerAuth
				}
				if _, err := parsed.Verify(x509.VerifyOptions{Roots: ca.roots, CurrentTime: ca.now, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
					t.Fatalf("fixture not CA trusted: %v", err)
				}
				if _, err := CertificateIdentity(parsed); !errors.Is(err, ErrCertificate) {
					t.Fatalf("noncanonical SAN accepted: %v", err)
				}
			})
		}
	}
}

func TestMutualTLSRejectsTrustedNoncanonicalAPIIdentity(t *testing.T) {
	ca := authority(t)
	uri, _ := api().URI()
	bad := leafWithRawSAN(t, ca, api(), []asn1.RawValue{{Class: 2, Tag: 6, Bytes: []byte(uri.String() + "#")}})
	client, err := ClientTLS(leaf(t, ca, api()), ca.roots, guest(), func(Identity) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	// Bypass only the local constructor to simulate a trusted but malformed
	// remote client. The actual server TLS verifier must still reject it.
	client.Certificates = []tls.Certificate{bad}
	server, err := ServerTLS(leaf(t, ca, guest()), ca.roots, guest(), func(Identity) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := exchange(client, server); err == nil {
		t.Fatal("trusted normalized client identity completed mutual TLS")
	}
}

func TestCanonicalSANAllowsEitherGeneralNameOrder(t *testing.T) {
	ca := authority(t)
	uri, _ := guest().URI()
	for _, names := range [][]asn1.RawValue{
		{{Class: 2, Tag: 6, Bytes: []byte(uri.String())}, {Class: 2, Tag: 2, Bytes: []byte(ServerName)}},
		{{Class: 2, Tag: 2, Bytes: []byte(ServerName)}, {Class: 2, Tag: 6, Bytes: []byte(uri.String())}},
	} {
		cert := leafWithRawSAN(t, ca, guest(), names)
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if actual, err := CertificateIdentity(parsed); err != nil || actual != guest() {
			t.Fatalf("canonical unordered SAN rejected: %+v %v", actual, err)
		}
	}
}
