package enrollment

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/execution/pki"
	"github.com/kube-workspaces/api/internal/execution/storage"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

var secretResource = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}

func bootstrapFixture(t *testing.T) (*BootstrapImporter, *Service, *fake.FakeDynamicClient, *corev1.Secret) {
	t.Helper()
	ws, vm := kubernetesFixture()
	client := fake.NewSimpleDynamicClient(runtime.NewScheme(), ws, vm)
	r, _ := NewKubernetesResolver(client, enabledPolicy())
	s, _, _ := fixtureAt(t, r.Authorize, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	importer, err := NewBootstrapImporter(client, "control-system", r, s)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/management-bootstrap-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	secret := &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: bootstrapSecretName("workspace-uid", "vm-uid"), Namespace: "control-system", Labels: map[string]string{bootstrapLabel: "v1", "kubeworkspaces.io/workspace-uid": "workspace-uid", "kubeworkspaces.io/virtualmachine-uid": "vm-uid"}, Annotations: map[string]string{"kubeworkspaces.io/workspace-namespace": "team", "kubeworkspaces.io/workspace-name": "vm"}}, Type: corev1.SecretTypeOpaque, Immutable: &yes, Data: map[string][]byte{"bootstrap.json": raw}}
	return importer, s, client, secret
}

func createBootstrap(t *testing.T, client *fake.FakeDynamicClient, secret *corev1.Secret) {
	t.Helper()
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Resource(secretResource).Namespace(secret.Namespace).Create(context.Background(), &unstructured.Unstructured{Object: object}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestControllerBootstrapImportAndEnrollment(t *testing.T) {
	if bootstrapSecretName("workspace-uid", "vm-uid") != "kw-mgmt-f1bbc6ce0ef901c6028526a778156f7f" {
		t.Fatal("management Secret naming contract drift")
	}
	ctx := context.Background()
	b, s, client, secret := bootstrapFixture(t)
	createBootstrap(t, client, secret)
	if err := b.Import(ctx, "team", "vm"); err != nil {
		t.Fatal(err)
	}
	var doc bootstrapDocument
	if err := json.Unmarshal(secret.Data["bootstrap.json"], &doc); err != nil {
		t.Fatal(err)
	}
	request := csr(t)
	certificate, err := s.Enroll(ctx, doc.Token, request)
	if err != nil {
		t.Fatal(err)
	}
	// Re-importing after restart/reconcile must not reset a consumed credential.
	if err := b.Import(ctx, "team", "vm"); err != nil {
		t.Fatal(err)
	}
	again, err := s.Enroll(ctx, doc.Token, request)
	if err != nil || !bytes.Equal(certificate, again) {
		t.Fatal("import reissued/reset the identity", err)
	}
	if _, err := s.Enroll(ctx, doc.Token, csr(t)); !errors.Is(err, ErrDenied) {
		t.Fatal("re-import enabled a second key", err)
	}
}

func TestBootstrapImporterRejectsUntrustedMaterial(t *testing.T) {
	for _, test := range []string{"tenant-namespace", "unlabelled", "mutable", "foreign-label", "foreign-name", "foreign-binding", "epoch", "expired", "overlong", "unknown-field", "legacy-desktop"} {
		t.Run(test, func(t *testing.T) {
			b, s, client, secret := bootstrapFixture(t)
			var doc map[string]interface{}
			if err := json.Unmarshal(secret.Data["bootstrap.json"], &doc); err != nil {
				t.Fatal(err)
			}
			switch test {
			case "tenant-namespace":
				b.namespace = "team"
			case "unlabelled":
				secret.Labels = nil
			case "mutable":
				no := false
				secret.Immutable = &no
			case "foreign-label":
				secret.Labels["kubeworkspaces.io/virtualmachine-uid"] = "other-vm"
			case "foreign-name":
				secret.Annotations["kubeworkspaces.io/workspace-name"] = "other"
			case "foreign-binding":
				doc["workspace_uid"] = "other-workspace"
			case "epoch":
				doc["revocation_epoch"] = float64(1)
			case "expired":
				doc["expires_at"] = "2030-01-01T00:00:00Z"
			case "overlong":
				doc["expires_at"] = "2030-01-01T00:15:01Z"
			case "unknown-field":
				doc["extra_authority"] = true
			case "legacy-desktop":
				doc = map[string]interface{}{"token": "desktop-token", "workspaceUid": "workspace-uid", "workspaceGeneration": "vm-uid", "expiresAt": float64(2000000000)}
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			secret.Data["bootstrap.json"] = raw
			createBootstrap(t, client, secret)
			if err := b.Import(context.Background(), "team", "vm"); err == nil {
				t.Fatal("untrusted bootstrap material imported")
			}
			if _, err := s.store.Get(context.Background(), digest(make([]byte, 32))); !errors.Is(err, storage.ErrNotFound) {
				t.Fatal("denied material reached issuance ledger", err)
			}
		})
	}
}

func TestBootstrapImportRechecksAfterSecretRead(t *testing.T) {
	b, _, client, secret := bootstrapFixture(t)
	createBootstrap(t, client, secret)
	client.PrependReactor("get", "secrets", func(ktesting.Action) (bool, runtime.Object, error) {
		ws, _ := kubernetesFixture()
		ws.SetAnnotations(map[string]string{"kubeworkspaces.io/reset": "pending"})
		if err := client.Tracker().Update(workspaceResource, ws, "team"); err != nil {
			t.Error(err)
		}
		return false, nil, nil
	})
	if err := b.Import(context.Background(), "team", "vm"); !errors.Is(err, ErrDenied) {
		t.Fatal("stale bootstrap snapshot authorized", err)
	}
}

func TestBootstrapRegistrationPreservesCommittedResult(t *testing.T) {
	for _, backend := range []string{"memory", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			s, _, i := fixture(t, func(context.Context, pki.Identity) error { return nil })
			if backend == "postgres" {
				dsn := os.Getenv("KW_EXECUTION_TEST_DATABASE_URL")
				if dsn == "" {
					t.Skip("set KW_EXECUTION_TEST_DATABASE_URL for disposable PostgreSQL")
				}
				store, err := storage.NewPostgresEnrollment(context.Background(), dsn)
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				s.store = store
			}
			ctx := context.Background()
			// Mint a random per-test token via the service, then retrieve its exact
			// registered expiry to test idempotent controller import.
			token, err := s.Mint(ctx, i, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := base64.RawURLEncoding.DecodeString(token)
			if err != nil {
				t.Fatal(err)
			}
			credential, err := s.store.Get(ctx, digest(raw))
			if err != nil {
				t.Fatal(err)
			}
			request := csr(t)
			cert, err := s.Enroll(ctx, token, request)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Register(ctx, i, token, credential.ExpiresAt.Add(17*time.Nanosecond)); err != nil {
				t.Fatal("timestamp precision broke import", err)
			}
			again, err := s.Enroll(ctx, token, request)
			if err != nil || !bytes.Equal(cert, again) {
				t.Fatal("import reset persisted certificate", err)
			}
			if err := s.Register(ctx, i, token, credential.ExpiresAt.Add(time.Second)); !errors.Is(err, ErrDenied) {
				t.Fatal("token expiry extended", err)
			}
			other := i
			other.Generation += "-reset"
			if err := s.Register(ctx, other, token, credential.ExpiresAt); !errors.Is(err, ErrDenied) {
				t.Fatal("token rebound to another incarnation", err)
			}
		})
	}
}
