package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution"
	"github.com/kube-workspaces/api/internal/execution/pki"
	"github.com/kube-workspaces/api/internal/execution/storage"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

var wsResource = schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "workspaces"}
var vmResource = schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachines"}
var policyResource = schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "platformconfigs"}
var authResource = schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "authconfigs"}

type recordingProbe struct{ down atomic.Bool }

func (*recordingProbe) Mode() string                      { return "external" }
func (*recordingProbe) Durability() storage.Durability    { return storage.DurabilityDurable }
func (*recordingProbe) Metadata() storage.MetadataStore   { return nil }
func (*recordingProbe) Recording() storage.RecordingStore { return nil }
func (p *recordingProbe) Ready(ctx context.Context) error {
	if p.down.Load() {
		return storage.ErrNotReady
	}
	return ctx.Err()
}
func (*recordingProbe) Close() error { return nil }

type trackedLedger struct {
	storage.EnrollmentStore
	down   atomic.Bool
	closes atomic.Int32
}

func (s *trackedLedger) Ready(ctx context.Context) error {
	if s.down.Load() {
		return storage.ErrNotReady
	}
	return s.EnrollmentStore.Ready(ctx)
}
func (s *trackedLedger) Close() error { s.closes.Add(1); return s.EnrollmentStore.Close() }

type runtimeFixture struct {
	config    Config
	client    *fake.FakeDynamicClient
	auth      *auth.ConfigProvider
	recording *recordingProbe
	ledger    *trackedLedger
	storage   execution.StorageConfig
}

func newRuntimeFixture(t *testing.T) *runtimeFixture {
	t.Helper()
	c, _, _ := testConfig(t)
	config := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "AuthConfig", "metadata": map[string]interface{}{"name": "default"}, "spec": map[string]interface{}{"enabled": true, "session": map[string]interface{}{"signingKey": map[string]interface{}{"name": "session-key", "key": "key"}}}}}
	key := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]interface{}{"name": "session-key", "namespace": auth.LocalAuthSystemNamespace}, "data": map[string]interface{}{"key": base64.StdEncoding.EncodeToString([]byte("synthetic-session-signing-key-32-bytes"))}}}
	policy := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "PlatformConfig", "metadata": map[string]interface{}{"name": "default"}, "spec": map[string]interface{}{"vmExecution": map[string]interface{}{"enabled": true, "allowElevated": false}}}}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{secretResource: "SecretList"}, config, key, policy)
	ledger, err := storage.NewMemoryEnrollment(128)
	if err != nil {
		t.Fatal(err)
	}
	return &runtimeFixture{config: c, client: client, auth: auth.NewConfigProvider(client), recording: &recordingProbe{}, ledger: &trackedLedger{EnrollmentStore: ledger}, storage: execution.StorageConfig{Mode: execution.StorageExternal, DatabaseURL: "postgres://synthetic-credentials-not-used-by-unit-opener"}}
}

func createObject(t *testing.T, f *runtimeFixture, resource schema.GroupVersionResource, namespace string, obj map[string]interface{}) {
	t.Helper()
	if _, err := f.client.Resource(resource).Namespace(namespace).Create(context.Background(), &unstructured.Unstructured{Object: obj}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func (f *runtimeFixture) addGuest(t *testing.T, name, uid, generation string) string {
	t.Helper()
	createObject(t, f, wsResource, "team", map[string]interface{}{"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Workspace", "metadata": map[string]interface{}{"namespace": "team", "name": name, "uid": uid, "resourceVersion": "1"}, "spec": map[string]interface{}{"type": "vm"}})
	createObject(t, f, vmResource, "team", map[string]interface{}{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine", "metadata": map[string]interface{}{"namespace": "team", "name": name, "uid": generation, "resourceVersion": "1", "ownerReferences": []interface{}{map[string]interface{}{"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Workspace", "name": name, "uid": uid, "controller": true}}}, "spec": map[string]interface{}{"running": true}})
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	doc, err := json.Marshal(map[string]interface{}{"version": 1, "token": token, "namespace": "team", "workspace_name": name, "workspace_uid": uid, "generation": generation, "revocation_epoch": 0, "expires_at": time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(uid + "/" + generation))
	secretName := "kw-mgmt-" + hex.EncodeToString(h[:16])
	createObject(t, f, secretResource, f.config.BootstrapNamespace, map[string]interface{}{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]interface{}{"namespace": f.config.BootstrapNamespace, "name": secretName, "labels": map[string]interface{}{"kubeworkspaces.io/management-bootstrap": "v1", "kubeworkspaces.io/workspace-uid": uid, "kubeworkspaces.io/virtualmachine-uid": generation}, "annotations": map[string]interface{}{"kubeworkspaces.io/workspace-namespace": "team", "kubeworkspaces.io/workspace-name": name}}, "type": "Opaque", "immutable": true, "data": map[string]interface{}{"bootstrap.json": base64.StdEncoding.EncodeToString(doc)}})
	return token
}

func (f *runtimeFixture) open(t *testing.T) *Runtime {
	t.Helper()
	r, err := openRuntime(context.Background(), f.config, f.storage, f.recording, f.client, f.auth, func(context.Context, string) (storage.EnrollmentStore, error) { return f.ledger, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func startRuntime(t *testing.T, r *Runtime) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("issuer worker failed to stop")
		}
	})
	eventually(t, func() bool { return r.Ready(context.Background()) == nil })
}

func eventually(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if check() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("issuer state did not converge")
		case <-tick.C:
		}
	}
}

func tokenHash(token string) string {
	raw, _ := base64.RawURLEncoding.DecodeString(token)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func requestCSR(t *testing.T) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestRuntimeImportsAndIssuesOnlyBoundPublicResults(t *testing.T) {
	f := newRuntimeFixture(t)
	token := f.addGuest(t, "vm", "workspace-uid", "vm-uid")
	r := f.open(t)
	if r.Ready(context.Background()) == nil {
		t.Fatal("issuer ready before bootstrap cache sync")
	}
	startRuntime(t, r)
	eventually(t, func() bool { _, err := f.ledger.Get(context.Background(), tokenHash(token)); return err == nil })
	f.addGuest(t, "other", "other-workspace-uid", "other-vm-uid")
	request := requestCSR(t)
	if _, err := r.Enroll(context.Background(), "team", "other", token, request); !errors.Is(err, ErrDenied) {
		t.Fatal("token redeemed through another scope", err)
	}
	credential, err := f.ledger.Get(context.Background(), tokenHash(token))
	if err != nil || credential.CSRHash != "" {
		t.Fatal("wrong-scope request spent token", err)
	}
	result, err := r.Enroll(context.Background(), "team", "vm", token, request)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(result.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	i, err := pki.CertificateIdentity(cert)
	if err != nil || i.WorkspaceUID != "workspace-uid" || i.Generation != "vm-uid" {
		t.Fatal("unbound certificate", i, err)
	}
	if bytes.Contains(result.IssuerChainPEM, []byte("PRIVATE KEY")) || bytes.Contains(result.TrustRootsPEM, []byte("PRIVATE KEY")) {
		t.Fatal("issuer returned private material")
	}
	again, err := r.Enroll(context.Background(), "team", "vm", token, request)
	if err != nil || !bytes.Equal(result.CertificateDER, again.CertificateDER) {
		t.Fatal("issuer retry changed identity", err)
	}
	for _, action := range f.client.Actions() {
		if (action.GetVerb() == "list" || action.GetVerb() == "watch") && action.GetResource() == secretResource && action.GetNamespace() != f.config.BootstrapNamespace {
			t.Fatal("bootstrap worker watched outside protected namespace")
		}
	}
}

func TestRuntimePrerequisitesAndShutdownFenceIssuance(t *testing.T) {
	for _, test := range []string{"recording", "ledger", "policy", "authentication", "reset", "close"} {
		t.Run(test, func(t *testing.T) {
			f := newRuntimeFixture(t)
			token := f.addGuest(t, "vm", "workspace-uid", "vm-uid")
			r := f.open(t)
			startRuntime(t, r)
			switch test {
			case "recording":
				f.recording.down.Store(true)
			case "ledger":
				f.ledger.down.Store(true)
			case "policy":
				obj, err := f.client.Resource(policyResource).Get(context.Background(), "default", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				unstructured.SetNestedField(obj.Object, false, "spec", "vmExecution", "enabled")
				if _, err := f.client.Resource(policyResource).Update(context.Background(), obj, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "authentication":
				obj, err := f.client.Resource(authResource).Get(context.Background(), "default", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				unstructured.SetNestedField(obj.Object, false, "spec", "enabled")
				if _, err := f.client.Resource(authResource).Update(context.Background(), obj, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				f.auth.InvalidateCache()
			case "reset":
				obj, err := f.client.Resource(wsResource).Namespace("team").Get(context.Background(), "vm", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				obj.SetAnnotations(map[string]string{"kubeworkspaces.io/reset": "pending"})
				if _, err := f.client.Resource(wsResource).Namespace("team").Update(context.Background(), obj, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "close":
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				if f.ledger.closes.Load() != 1 {
					t.Fatal("owned ledger not closed once")
				}
			}
			if _, err := r.Enroll(context.Background(), "team", "vm", token, requestCSR(t)); err == nil {
				t.Fatal("issuer admitted without prerequisites")
			}
		})
	}
}

func TestRuntimeOpenFailsClosedAndCleansOwnedLedger(t *testing.T) {
	f := newRuntimeFixture(t)
	calls := 0
	opener := func(context.Context, string) (storage.EnrollmentStore, error) { calls++; return f.ledger, nil }
	for _, mode := range []execution.StorageMode{execution.StorageDisabled, execution.StorageEphemeral} {
		cfg := f.storage
		cfg.Mode = mode
		if _, err := openRuntime(context.Background(), f.config, cfg, f.recording, f.client, f.auth, opener); !errors.Is(err, ErrConfiguration) {
			t.Fatal("issuer accepted non-durable ledger mode", err)
		}
	}
	if calls != 0 {
		t.Fatal("invalid mode opened a ledger")
	}
	if r, err := openRuntime(context.Background(), Config{}, execution.StorageConfig{}, nil, nil, nil, nil); err != nil || r != nil {
		t.Fatal("disabled issuer had side effects", err)
	}
	_, err := openRuntime(context.Background(), f.config, f.storage, f.recording, f.client, f.auth, func(context.Context, string) (storage.EnrollmentStore, error) {
		return nil, errors.New("private database credential marker")
	})
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "credential marker") {
		t.Fatal("storage initialization disclosed raw error", err)
	}
	f.ledger.down.Store(true)
	if _, err := openRuntime(context.Background(), f.config, f.storage, f.recording, f.client, f.auth, opener); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if f.ledger.closes.Load() != 1 {
		t.Fatal("failed initialization leaked ledger")
	}
}

func TestBootstrapCacheDropsCredentialPayload(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]interface{}{"name": "bootstrap", "namespace": "control-system", "labels": map[string]interface{}{"kubeworkspaces.io/management-bootstrap": "v1"}, "annotations": map[string]interface{}{"kubeworkspaces.io/workspace-namespace": "team", "kubeworkspaces.io/workspace-name": "vm", "unrelated": "private-token-marker"}}, "data": map[string]interface{}{"bootstrap.json": "private-token-marker"}, "stringData": map[string]interface{}{"secret": "private-token-marker"}}}
	filtered, err := metadataOnly(obj)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(filtered)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private-token-marker")) || bytes.Contains(raw, []byte("stringData")) {
		t.Fatal("bootstrap credentials retained in informer cache")
	}
}

func TestInitialCacheFailureNeverBecomesReady(t *testing.T) {
	f := newRuntimeFixture(t)
	r := f.open(t)
	r.syncTimeout = 100 * time.Millisecond
	f.client.PrependReactor("list", "secrets", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(secretResource.GroupResource(), "", errors.New("not permitted"))
	})
	if err := r.Run(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("failed bootstrap sync reported success", err)
	}
	if r.Ready(context.Background()) == nil {
		t.Fatal("issuer ready without protected cache sync")
	}
}

func TestRuntimePostgresIntegration(t *testing.T) {
	dsn := os.Getenv("KW_EXECUTION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set KW_EXECUTION_TEST_DATABASE_URL for disposable PostgreSQL")
	}
	f := newRuntimeFixture(t)
	f.storage.DatabaseURL = dsn
	token := f.addGuest(t, "vm", "workspace-uid", "vm-uid")
	r, err := Open(context.Background(), f.config, f.storage, f.recording, f.client, f.auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	startRuntime(t, r)
	request := requestCSR(t)
	first, err := r.Enroll(context.Background(), "team", "vm", token, request)
	if err != nil {
		t.Fatal(err)
	}
	// A second independently opened issuer shares the ledger and cannot mint
	// another identity from the same bootstrap token, even across restart.
	second, err := Open(context.Background(), f.config, f.storage, f.recording, f.client, f.auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close() })
	startRuntime(t, second)
	retry, err := second.Enroll(context.Background(), "team", "vm", token, request)
	if err != nil || !bytes.Equal(first.CertificateDER, retry.CertificateDER) {
		t.Fatal("cross-replica retry changed certificate", err)
	}
	if _, err := second.Enroll(context.Background(), "team", "vm", token, requestCSR(t)); !errors.Is(err, ErrDenied) {
		t.Fatal("another issuer redeemed a second CSR", err)
	}
}
