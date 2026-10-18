package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

type authorityFixture struct {
	a     *Authority
	key   *ecdsa.PrivateKey
	roots *x509.CertPool
	pem   []byte
	der   []byte
	now   time.Time
}

func authority(t *testing.T) authorityFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-management-root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAuthority(der, key)
	if err != nil {
		t.Fatal(err)
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	roots, err := TrustRoots(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return authorityFixture{a: a, key: key, roots: roots, pem: bundle, der: der, now: now}
}

func guest() Identity {
	return Identity{Role: RoleGuest, Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "uid-1", Generation: "gen-2", RevocationEpoch: 3}
}
func api() Identity { return Identity{Role: RoleAPI, ReplicaID: "api-1"} }

func leaf(t *testing.T, ca authorityFixture, i Identity) tls.Certificate {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	der, err := ca.a.Issue(csr, i, ca.now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The application byte ensures server-side client authentication completed;
// TLS 1.3 client Handshake alone can finish before a server rejects its identity.
func exchange(clientConfig, serverConfig *tls.Config) error {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	serverDone := make(chan error, 1)
	go func() {
		server := tls.Server(b, serverConfig)
		err := server.Handshake()
		if err == nil {
			_, err = server.Write([]byte{1})
		}
		serverDone <- err
	}()
	client := tls.Client(a, clientConfig)
	clientErr := client.Handshake()
	if clientErr == nil {
		var data [1]byte
		_, clientErr = io.ReadFull(client, data[:])
	}
	a.Close()
	serverErr := <-serverDone
	return errors.Join(clientErr, serverErr)
}

func TestMutualTLSRequiresCurrentIdentityOnEveryConnection(t *testing.T) {
	ca := authority(t)
	var clientChecks, serverChecks atomic.Int32
	apiCert := leaf(t, ca, api())
	client, err := ClientTLS(apiCert, ca.roots, guest(), func(i Identity) error {
		clientChecks.Add(1)
		if i != guest() {
			return ErrIdentity
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := ServerTLS(leaf(t, ca, guest()), ca.roots, guest(), func(i Identity) error {
		serverChecks.Add(1)
		if i != api() {
			return ErrIdentity
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := APIClientFingerprint(apiCert)
	if err != nil {
		t.Fatal(err)
	}
	checkPeer := server.VerifyConnection
	server.VerifyConnection = func(state tls.ConnectionState) error {
		if err := checkPeer(state); err != nil {
			return err
		}
		got, err := VerifiedAPIFingerprint(state)
		if err != nil || got != fingerprint {
			return ErrCertificate
		}
		return nil
	}
	for n := 0; n < 2; n++ {
		if err := exchange(client, server); err != nil {
			t.Fatal(err)
		}
	}
	if clientChecks.Load() != 2 || serverChecks.Load() != 2 {
		t.Fatal("current peer authorization was skipped")
	}
	if client.InsecureSkipVerify || client.ClientSessionCache != nil || !server.SessionTicketsDisabled || server.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("unsafe management TLS configuration")
	}
}

func TestTLSRejectsForeignResetRevokedAndAnonymousPeers(t *testing.T) {
	ca, foreign := authority(t), authority(t)
	apiCert, guestCert := leaf(t, ca, api()), leaf(t, ca, guest())
	allow := func(Identity) error { return nil }
	deny := func(Identity) error { return errors.New("current state unavailable or revoked") }
	for _, name := range []string{"foreign-ca", "wrong-workspace", "reset-generation", "revoked-epoch", "api-revoked", "guest-revoked", "anonymous", "tls12", "protocol", "expired"} {
		t.Run(name, func(t *testing.T) {
			expected := guest()
			roots := ca.roots
			switch name {
			case "foreign-ca":
				roots = foreign.roots
			case "wrong-workspace":
				expected.WorkspaceUID += "-other"
			case "reset-generation":
				expected.Generation = "gen-3"
			case "revoked-epoch":
				expected.RevocationEpoch++
			}
			clientAuth, serverAuth := AuthorizePeer(allow), AuthorizePeer(allow)
			if name == "api-revoked" {
				serverAuth = deny
			}
			if name == "guest-revoked" {
				clientAuth = deny
			}
			client, err := ClientTLS(apiCert, roots, expected, clientAuth)
			if err != nil {
				t.Fatal(err)
			}
			server, err := ServerTLS(guestCert, ca.roots, guest(), serverAuth)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "anonymous":
				client.Certificates = nil
			case "tls12":
				client.MinVersion, client.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
			case "protocol":
				client.NextProtos = []string{"desktop/1"}
			case "expired":
				client.Time = func() time.Time { return ca.now.Add(20 * time.Minute) }
			}
			if err := exchange(client, server); err == nil {
				t.Fatal("unauthorized connection accepted")
			}
		})
	}
}

func TestCertificatePurposeAndTrustRotation(t *testing.T) {
	old, next := authority(t), authority(t)
	roots, err := TrustRoots(append(append([]byte(nil), old.pem...), next.pem...))
	if err != nil {
		t.Fatal(err)
	}
	allow := func(Identity) error { return nil }
	for _, issuer := range []authorityFixture{old, next} {
		client, err := ClientTLS(leaf(t, next, api()), roots, guest(), allow)
		if err != nil {
			t.Fatal(err)
		}
		server, err := ServerTLS(leaf(t, issuer, guest()), roots, guest(), allow)
		if err != nil {
			t.Fatal(err)
		}
		if err := exchange(client, server); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ClientTLS(leaf(t, old, guest()), roots, guest(), allow); err == nil {
		t.Fatal("guest certificate used as API authority")
	}
	if _, err := ServerTLS(leaf(t, old, api()), roots, guest(), allow); err == nil {
		t.Fatal("API certificate used as guest authority")
	}
	if _, err := ClientTLS(leaf(t, old, api()), nil, guest(), allow); err == nil {
		t.Fatal("system-root fallback")
	}
	if _, err := ClientTLS(leaf(t, old, api()), roots, guest(), nil); err == nil {
		t.Fatal("missing current authorization accepted")
	}
	client, _ := ClientTLS(leaf(t, next, api()), next.roots, guest(), allow)
	server, _ := ServerTLS(leaf(t, old, guest()), roots, guest(), allow)
	if err := exchange(client, server); err == nil {
		t.Fatal("removed root still trusted")
	}
}

func TestCSRProofAndIdentityRequests(t *testing.T) {
	ca := authority(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	uri, _ := url.Parse("spiffe://foreign/guest")
	for _, request := range []*x509.CertificateRequest{
		{Subject: pkix.Name{CommonName: "chosen-identity"}},
		{DNSNames: []string{"chosen.example.com"}},
		{URIs: []*url.URL{uri}},
		{ExtraExtensions: []pkix.Extension{{Id: []int{2, 5, 29, 19}, Value: []byte{0x30, 0}}}},
	} {
		csr, err := x509.CreateCertificateRequest(rand.Reader, request, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ca.a.Issue(csr, guest(), ca.now, time.Minute); err == nil {
			t.Fatal("CSR supplied certificate authority/identity")
		}
	}
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csr[len(csr)-1] ^= 1
	if _, err := ca.a.Issue(csr, guest(), ca.now, time.Minute); err == nil {
		t.Fatal("invalid proof of possession accepted")
	}
	csr, _ = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	for _, lifetime := range []time.Duration{0, time.Second, MaxLeafLifetime + time.Second} {
		if _, err := ca.a.Issue(csr, guest(), ca.now, lifetime); err == nil {
			t.Fatal("invalid lifetime", lifetime)
		}
	}
	if _, err := ca.a.Issue(csr, guest(), ca.now.Add(25*time.Hour), time.Minute); err == nil {
		t.Fatal("expired issuer accepted")
	}
	caCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, ca.key)
	if _, err := ca.a.Issue(caCSR, guest(), ca.now, time.Minute); err == nil {
		t.Fatal("CA key reused as guest key")
	}
	if _, err := NewAuthority(ca.der, key); err == nil {
		t.Fatal("mismatched issuer private key accepted")
	}
}

func TestIdentityParsingAndExplicitTrust(t *testing.T) {
	for _, i := range []Identity{guest(), api()} {
		u, err := i.URI()
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseIdentity(u)
		if err != nil || got != i {
			t.Fatalf("identity round trip: %+v %v", got, err)
		}
	}
	for _, text := range []string{
		"spiffe://foreign/management/v1/apis/api-1",
		"spiffe://kubeworkspaces.io/management/v1/apis/api-1?role=guest",
		"spiffe://kubeworkspaces.io/management/v1/workspaces/team/vm/uid/gen/00",
		"spiffe://kubeworkspaces.io/management/v1/apis/api-1#extra",
	} {
		u, _ := url.Parse(text)
		if _, err := parseIdentity(u); err == nil {
			t.Fatal("ambiguous URI accepted", text)
		}
	}
	ca := authority(t)
	leafCert := leaf(t, ca, guest())
	for _, bundle := range [][]byte{nil, []byte("garbage"), append([]byte("junk\n"), ca.pem...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Certificate[0]})} {
		if _, err := TrustRoots(bundle); err == nil {
			t.Fatal("invalid trust material accepted")
		}
	}
}
