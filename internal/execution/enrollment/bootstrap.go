package enrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/kube-workspaces/api/internal/execution/pki"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
)

const bootstrapLabel = "kubeworkspaces.io/management-bootstrap"

type bootstrapDocument struct {
	Version         int       `json:"version"`
	Token           string    `json:"token"`
	Namespace       string    `json:"namespace"`
	WorkspaceName   string    `json:"workspace_name"`
	WorkspaceUID    string    `json:"workspace_uid"`
	Generation      string    `json:"generation"`
	RevocationEpoch uint64    `json:"revocation_epoch"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func bootstrapSecretName(workspaceUID, vmUID string) string {
	h := sha256.Sum256([]byte(workspaceUID + "/" + vmUID))
	return "kw-mgmt-" + hex.EncodeToString(h[:16])
}

// BootstrapImporter reads only the configured protected control-plane namespace.
// It never accepts a caller-selected token, Secret namespace or Secret name.
// Construct it only with the production resolver and shared issuance service.
type BootstrapImporter struct {
	client    dynamic.Interface
	namespace string
	resolver  *KubernetesResolver
	service   *Service
}

func NewBootstrapImporter(client dynamic.Interface, namespace string, resolver *KubernetesResolver, service *Service) (*BootstrapImporter, error) {
	if client == nil || len(validation.IsDNS1123Label(namespace)) != 0 || resolver == nil || service == nil {
		return nil, ErrUnavailable
	}
	return &BootstrapImporter{client: client, namespace: namespace, resolver: resolver, service: service}, nil
}

func (b *BootstrapImporter) Import(ctx context.Context, namespace, name string) error {
	if namespace == b.namespace {
		return ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := b.resolver.Resolve(ctx, namespace, name)
	if err != nil {
		return err
	}
	secretName := bootstrapSecretName(i.WorkspaceUID, i.Generation)
	obj, err := b.client.Resource(schema.GroupVersionResource{Version: "v1", Resource: "secrets"}).Namespace(b.namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return lookupError(err)
	}
	var secret corev1.Secret
	if runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &secret) != nil {
		return ErrDenied
	}
	if secret.Namespace != b.namespace || secret.Name != secretName || secret.Type != corev1.SecretTypeOpaque || secret.Immutable == nil || !*secret.Immutable || len(secret.OwnerReferences) != 0 || !secret.DeletionTimestamp.IsZero() || len(secret.Data) != 1 {
		return ErrDenied
	}
	if secret.Labels[bootstrapLabel] != "v1" || secret.Labels["kubeworkspaces.io/workspace-uid"] != i.WorkspaceUID || secret.Labels["kubeworkspaces.io/virtualmachine-uid"] != i.Generation {
		return ErrDenied
	}
	if secret.Annotations["kubeworkspaces.io/workspace-namespace"] != i.Namespace || secret.Annotations["kubeworkspaces.io/workspace-name"] != i.WorkspaceName {
		return ErrDenied
	}
	raw := secret.Data["bootstrap.json"]
	if len(raw) == 0 || len(raw) > 4096 {
		return ErrDenied
	}
	var doc bootstrapDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&doc) != nil || decoder.Decode(new(interface{})) != io.EOF {
		return ErrDenied
	}
	bound := pki.Identity{Role: pki.RoleGuest, Namespace: doc.Namespace, WorkspaceName: doc.WorkspaceName, WorkspaceUID: doc.WorkspaceUID, Generation: doc.Generation, RevocationEpoch: doc.RevocationEpoch}
	if doc.Version != 1 || bound != i {
		return ErrDenied
	}
	return b.service.Register(ctx, i, doc.Token, doc.ExpiresAt)
}
